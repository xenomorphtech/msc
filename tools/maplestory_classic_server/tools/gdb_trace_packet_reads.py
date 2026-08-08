"""Log primitive reads from one live IL2CPP incoming packet.

Source this script after attaching GDB to Maplestory_Classic.exe, then continue.
The breakpoints auto-continue and only log readers whose packet opcode matches
``MAPLE_TRACE_OPCODE`` (default 0).  Set it to ``any`` when a narrow caller-RVA
range already identifies the handler and the packet object's opcode field is
not yet known.  Stop GDB with Ctrl-C after the packet has been dispatched, then
detach.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct

import gdb


READER_RVAS = {
    0x1CD0530: "read_byte",
    0x1CD0560: "reader_1cd0560",
    0x1CD0700: "read_signed_byte",
    0x1CD0760: "reader_1cd0760",
    0x1CD09D0: "reader_1cd09d0",
    0x1CD0B00: "reader_1cd0b00",
    0x1CD0CA0: "reader_1cd0ca0",
}
PACKET_BUFFER_OFFSET = 0x10
PACKET_CURSOR_OFFSET = 0x18
PACKET_OPCODE_OFFSET = 0x1C
MANAGED_ARRAY_LENGTH_OFFSET = 0x18
MANAGED_ARRAY_DATA_OFFSET = 0x20
MAX_DUMP_BYTES = 512
LOGIN_OPCODE4_RESULT_XOR_RVA = 0x6840484
LOGIN_OPCODE4_STATE_ADD_RVA = 0x6840488
LOGIN_OPCODE4_DECISION_RVA = 0xC13108
LOGIN_OPCODE4_SUCCESS_RVA = 0xC13129

inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")


def game_assembly_base() -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if line.rstrip().endswith("/GameAssembly.dll"):
            return int(line.split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped in the selected process")


def read_u16(address: int) -> int:
    return struct.unpack("<H", bytes(inferior.read_memory(address, 2)))[0]


def read_u32(address: int) -> int:
    return struct.unpack("<I", bytes(inferior.read_memory(address, 4)))[0]


def read_u64(address: int) -> int:
    return struct.unpack("<Q", bytes(inferior.read_memory(address, 8)))[0]


target_opcode_text = os.environ.get("MAPLE_TRACE_OPCODE", "0")
target_opcode = (
    None if target_opcode_text.lower() == "any" else int(target_opcode_text, 0)
)
if target_opcode is not None and not 0 <= target_opcode <= 0xFFFF:
    raise gdb.GdbError("MAPLE_TRACE_OPCODE must be a ushort or 'any'")
base = game_assembly_base()
caller_rva_start = int(os.environ.get("MAPLE_TRACE_CALLER_RVA_START", "0"), 0)
caller_rva_end = int(
    os.environ.get("MAPLE_TRACE_CALLER_RVA_END", "0xffffffffffffffff"), 0
)
if caller_rva_start < 0 or caller_rva_end <= caller_rva_start:
    raise gdb.GdbError("MAPLE_TRACE_CALLER_RVA_START/END define an invalid range")


class PacketReadBreakpoint(gdb.Breakpoint):
    def __init__(self, rva: int, label: str) -> None:
        super().__init__(f"*{base + rva:#x}", internal=False)
        self.rva = rva
        self.label = label

    def stop(self) -> bool:
        try:
            packet = int(gdb.parse_and_eval("$rcx"))
            caller = read_u64(int(gdb.parse_and_eval("$rsp")))
            caller_rva = caller - base
            if not caller_rva_start <= caller_rva < caller_rva_end:
                return False
            cursor = read_u32(packet + PACKET_CURSOR_OFFSET)
            buffer_pointer = read_u64(packet + PACKET_BUFFER_OFFSET)
            length = read_u64(buffer_pointer + MANAGED_ARRAY_LENGTH_OFFSET)
            if length > 1_000_000:
                raise ValueError(f"implausible buffer length {length}")
            dumped_length = min(length, MAX_DUMP_BYTES)
            # The login packet object keeps zero in its cached opcode field.
            # The first decrypted frame still has its four-byte encrypted-frame
            # header at the start of the managed buffer, followed by the opcode.
            cached_opcode = read_u16(packet + PACKET_OPCODE_OFFSET)
            frame_opcode = (
                read_u16(buffer_pointer + MANAGED_ARRAY_DATA_OFFSET + 4)
                if length >= 6
                else None
            )
            if target_opcode is not None and frame_opcode != target_opcode:
                return False
            payload = bytes(
                inferior.read_memory(
                    buffer_pointer + MANAGED_ARRAY_DATA_OFFSET, dumped_length
                )
            )
            suffix = "..." if dumped_length < length else ""
            gdb.write(
                f"packet_read label={self.label} rva={self.rva:#x} "
                f"caller_rva={caller_rva:#x} packet={packet:#x} "
                f"cached_opcode={cached_opcode:#x} "
                f"frame_opcode="
                f"{'none' if frame_opcode is None else hex(frame_opcode)} "
                f"cursor={cursor} length={length} "
                f"buffer={payload.hex()}{suffix}\n"
            )
        except Exception as error:  # Keep tracing unrelated/malformed hits.
            gdb.write(
                f"packet_read_error label={self.label} rva={self.rva:#x} "
                f"error={error}\n"
            )
        return False


class Opcode4DecisionBreakpoint(gdb.Breakpoint):
    def __init__(self, rva: int, label: str) -> None:
        super().__init__(f"*{base + rva:#x}", internal=False)
        self.rva = rva
        self.label = label

    def stop(self) -> bool:
        try:
            controller = int(gdb.parse_and_eval("$r14"))
            state = read_u32(controller + 0x98)
            expected_state = (
                0x58899A71 + read_u32(base + LOGIN_OPCODE4_STATE_ADD_RVA)
            ) & 0xFFFFFFFF
            gdb.write(
                f"opcode4_decision label={self.label} rva={self.rva:#x} "
                f"result={int(gdb.parse_and_eval('$ebx')) & 0xFFFFFFFF:#x} "
                f"success_result={int(gdb.parse_and_eval('$esi')) & 0xFFFFFFFF:#x} "
                f"validation={int(gdb.parse_and_eval('$eax')) & 0xFF:#x} "
                f"controller={controller:#x} state={state:#x} "
                f"expected_state={expected_state:#x}\n"
            )
        except Exception as error:
            gdb.write(
                f"opcode4_decision_error label={self.label} rva={self.rva:#x} "
                f"error={error}\n"
            )
        return False


for reader_rva, reader_label in READER_RVAS.items():
    PacketReadBreakpoint(reader_rva, reader_label)
if os.environ.get("MAPLE_TRACE_OPCODE4_DECISIONS", "0") == "1":
    Opcode4DecisionBreakpoint(LOGIN_OPCODE4_DECISION_RVA, "result_check")
    Opcode4DecisionBreakpoint(LOGIN_OPCODE4_SUCCESS_RVA, "success_path")
gdb.write(
    f"packet_read_trace_ready base={base:#x} "
    f"opcode={'any' if target_opcode is None else hex(target_opcode)} "
    f"caller_range={caller_rva_start:#x}:{caller_rva_end:#x} "
    f"readers={len(READER_RVAS)} "
    f"opcode4_result_xor={read_u32(base + LOGIN_OPCODE4_RESULT_XOR_RVA):#x} "
    f"opcode4_success_result="
    f"{read_u32(base + LOGIN_OPCODE4_RESULT_XOR_RVA) ^ 0x7DFCBC3C:#x}\n"
)

"""Log primitive reads from one live IL2CPP incoming packet.

Source this script after attaching GDB to Maplestory_Classic.exe, then continue.
The breakpoints auto-continue and only log readers whose packet opcode matches
``MAPLE_TRACE_OPCODE`` (default 0).  Stop GDB with Ctrl-C after the packet has
been dispatched, then detach.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct

import gdb


READER_RVAS = {
    0x1CD0530: "read_byte",
    0x1CD0560: "reader_1cd0560",
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


target_opcode = int(os.environ.get("MAPLE_TRACE_OPCODE", "0"), 0)
if target_opcode < 0 or target_opcode > 0xFFFF:
    raise gdb.GdbError("MAPLE_TRACE_OPCODE must be a ushort")
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
            opcode = read_u16(packet + PACKET_OPCODE_OFFSET)
            if opcode != target_opcode:
                return False
            cursor = read_u32(packet + PACKET_CURSOR_OFFSET)
            buffer_pointer = read_u64(packet + PACKET_BUFFER_OFFSET)
            length = read_u64(buffer_pointer + MANAGED_ARRAY_LENGTH_OFFSET)
            if length > 1_000_000:
                raise ValueError(f"implausible buffer length {length}")
            dumped_length = min(length, MAX_DUMP_BYTES)
            payload = bytes(
                inferior.read_memory(
                    buffer_pointer + MANAGED_ARRAY_DATA_OFFSET, dumped_length
                )
            )
            suffix = "..." if dumped_length < length else ""
            gdb.write(
                f"packet_read label={self.label} rva={self.rva:#x} "
                f"caller_rva={caller_rva:#x} packet={packet:#x} "
                f"opcode={opcode:#x} cursor={cursor} length={length} "
                f"buffer={payload.hex()}{suffix}\n"
            )
        except Exception as error:  # Keep tracing unrelated/malformed hits.
            gdb.write(
                f"packet_read_error label={self.label} rva={self.rva:#x} "
                f"error={error}\n"
            )
        return False


for reader_rva, reader_label in READER_RVAS.items():
    PacketReadBreakpoint(reader_rva, reader_label)
gdb.write(
    f"packet_read_trace_ready base={base:#x} opcode={target_opcode:#x} "
    f"caller_range={caller_rva_start:#x}:{caller_rva_end:#x} "
    f"readers={len(READER_RVAS)}\n"
)

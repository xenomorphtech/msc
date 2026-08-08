"""Synthesize successful NGSX Run callbacks for diagnostic A/B testing.

This build-specific, process-local patch keeps the normal managed NGSX event
path while redirecting ``NgsxWindows.Run`` to its existing callback and
constructing a successful result. The managed message defaults to empty and
can be set with ``MAPLE_NGSX_RESULT_MESSAGE``. No executable or native proof
data is modified on disk. The validated custom-server flow no longer requires
this patch because it completes the native opcode-6/opcode-23 exchange.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct

import gdb


WINDOWS_RUN_RVA = 0x3FEAF10
ON_RUN_CALLBACK_RVA = 0x3FE9940
READ_RESULT_RVA = 0x3FEA7E0

CODEGEN_INIT_METADATA_RVA = 0x38E3F0
CODEGEN_OBJECT_NEW_RVA = 0x38E830
IL2CPP_STRING_NEW_RVA = 0x4277B0
NGSX_RESULT_TYPE_SLOT_RVA = 0x6961AF0

EXPECTED_RUN_PREFIX = bytes.fromhex("41 56 56 57 53 48 83 ec 58")
EXPECTED_READ_PREFIX = bytes.fromhex("41 56 56 57 55 53 48 83 ec 20")
PATCHED_RUN_PREFIX = bytes.fromhex("48 83 ec 28 31 c9 31 d2 45")
PATCHED_READ_PREFIX = bytes.fromhex("56 48 83 ec 20 48 8d 0d")

message_text = os.environ.get("MAPLE_NGSX_RESULT_MESSAGE", "")
try:
    message_bytes = message_text.encode("utf-8")
except UnicodeEncodeError as error:
    raise gdb.GdbError("MAPLE_NGSX_RESULT_MESSAGE must be UTF-8 encodable") from error
if b"\x00" in message_bytes:
    raise gdb.GdbError("MAPLE_NGSX_RESULT_MESSAGE cannot contain NUL bytes")
if len(message_bytes) > 1024:
    raise gdb.GdbError("MAPLE_NGSX_RESULT_MESSAGE must be at most 1024 bytes")


inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")


def game_assembly_base() -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if line.rstrip().endswith("/GameAssembly.dll"):
            return int(line.split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped in the selected process")


def relative32(next_instruction: int, target: int) -> bytes:
    displacement = target - next_instruction
    try:
        return struct.pack("<i", displacement)
    except struct.error as error:
        raise gdb.GdbError(
            f"Relative branch is out of range: {next_instruction:#x} -> {target:#x}"
        ) from error


def emit_call(code: bytearray, address: int, target: int) -> None:
    code.append(0xE8)
    code.extend(relative32(address + len(code) + 4, target))


def emit_lea_rcx(code: bytearray, address: int, target: int) -> None:
    code.extend(b"\x48\x8d\x0d")
    code.extend(relative32(address + len(code) + 4, target))


def emit_mov_rcx_indirect(code: bytearray, address: int, target: int) -> None:
    code.extend(b"\x48\x8b\x0d")
    code.extend(relative32(address + len(code) + 4, target))


base = game_assembly_base()
windows_run = base + WINDOWS_RUN_RVA
on_run_callback = base + ON_RUN_CALLBACK_RVA
read_result = base + READ_RESULT_RVA
metadata_init = base + CODEGEN_INIT_METADATA_RVA
object_new = base + CODEGEN_OBJECT_NEW_RVA
string_new = base + IL2CPP_STRING_NEW_RVA
result_type_slot = base + NGSX_RESULT_TYPE_SLOT_RVA

actual_run = bytes(inferior.read_memory(windows_run, len(EXPECTED_RUN_PREFIX)))
if actual_run not in (EXPECTED_RUN_PREFIX, PATCHED_RUN_PREFIX):
    raise gdb.GdbError(
        "NgsxWindows.Run prefix mismatch: "
        f"expected={EXPECTED_RUN_PREFIX.hex()} actual={actual_run.hex()}"
    )
actual_read = bytes(inferior.read_memory(read_result, len(EXPECTED_READ_PREFIX)))
if actual_read != EXPECTED_READ_PREFIX and not actual_read.startswith(PATCHED_READ_PREFIX):
    raise gdb.GdbError(
        "NgsxWindows.ReadResult prefix mismatch: "
        f"expected={EXPECTED_READ_PREFIX.hex()} actual={actual_read.hex()}"
    )

# OnRunCallback is static and ignores its ``self`` argument. Both native
# callback arguments and the hidden MethodInfo pointer are cleared.
run_code = bytearray(b"\x48\x83\xec\x28\x31\xc9\x31\xd2\x45\x31\xc0")
emit_call(run_code, windows_run, on_run_callback)
run_code.extend(b"\x48\x83\xc4\x28\xc3")

result_code = bytearray(b"\x56\x48\x83\xec\x20")
emit_lea_rcx(result_code, read_result, result_type_slot)
emit_call(result_code, read_result, metadata_init)
emit_mov_rcx_indirect(result_code, read_result, result_type_slot)
emit_call(result_code, read_result, object_new)
result_code.extend(
    bytes.fromhex(
        "48 89 c6 "
        "c6 46 10 01 "
        "c7 46 14 00 00 00 00"
    )
)
message_lea = len(result_code)
result_code.extend(b"\x48\x8d\x0d\x00\x00\x00\x00")
emit_call(result_code, read_result, string_new)
result_code.extend(bytes.fromhex("48 89 46 18 48 89 f0 48 83 c4 20 5e c3"))
message_address = read_result + len(result_code)
result_code.extend(message_bytes + b"\x00")
lea_next = read_result + message_lea + 7
result_code[message_lea + 3 : message_lea + 7] = relative32(
    lea_next, message_address
)

inferior.write_memory(read_result, result_code)
inferior.write_memory(windows_run, run_code)
gdb.write(
    "ngsx_run_success patched=true "
    f"run={windows_run:#x} read_result={read_result:#x} "
    f"message_bytes={len(message_bytes)}\n"
)

"""Force NGSX callback results to success while preserving native lifecycle.

This build-specific, ephemeral patch leaves ``NgsxWindows.Init`` and the native
NGS service/heartbeat untouched.  It replaces only ``ReadResult`` so managed
callbacks receive ``NgsxResult(IsOK=true, Code=0, Message=null)``.  The client
executable on disk is not modified.
"""

from __future__ import annotations

from pathlib import Path
import struct

import gdb


READ_RESULT_RVA = 0x3FEA7E0
CODEGEN_INIT_METADATA_RVA = 0x38E3F0
CODEGEN_OBJECT_NEW_RVA = 0x38E830
OBJECT_CTOR_RVA = 0x3E99F60
NGSX_RESULT_TYPE_SLOT_RVA = 0x6961AF0

EXPECTED_READ_PREFIX = bytes.fromhex("41 56 56 57 55 53 48 83 ec 20")


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
read_result = base + READ_RESULT_RVA
metadata_init = base + CODEGEN_INIT_METADATA_RVA
object_new = base + CODEGEN_OBJECT_NEW_RVA
object_ctor = base + OBJECT_CTOR_RVA
result_type_slot = base + NGSX_RESULT_TYPE_SLOT_RVA

actual_read = bytes(inferior.read_memory(read_result, len(EXPECTED_READ_PREFIX)))
if actual_read != EXPECTED_READ_PREFIX:
    raise gdb.GdbError(
        "NgsxWindows.ReadResult prefix mismatch: "
        f"expected={EXPECTED_READ_PREFIX.hex()} actual={actual_read.hex()}"
    )

result_code = bytearray(b"\x56\x48\x83\xec\x20")
emit_lea_rcx(result_code, read_result, result_type_slot)
emit_call(result_code, read_result, metadata_init)
emit_mov_rcx_indirect(result_code, read_result, result_type_slot)
emit_call(result_code, read_result, object_new)
result_code.extend(b"\x48\x89\xc6\x48\x89\xf1\x31\xd2")
emit_call(result_code, read_result, object_ctor)
result_code.extend(
    bytes.fromhex(
        "c6 46 10 01 "
        "c7 46 14 00 00 00 00 "
        "48 c7 46 18 00 00 00 00 "
        "48 89 f0 "
        "48 83 c4 20 "
        "5e c3"
    )
)

inferior.write_memory(read_result, result_code)
gdb.write(f"ngsx_result_success patched=true read_result={read_result:#x}\n")

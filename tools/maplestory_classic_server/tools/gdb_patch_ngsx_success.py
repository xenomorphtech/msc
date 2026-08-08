"""Inject an ephemeral synthetic NGSX init-success callback into a live client.

This build-specific custom-server debugging patch preserves the application's
normal managed NGSX run and callback setup.  It redirects ``NgsxWindows.Init``
to the existing static managed callback with null callback arguments, then
redirects ``ReadResult`` to construct an
``NgsxResult(IsOK=true, Code=0, Message=null)`` without loading native NGS.  The
executable on disk is not modified.
"""

from __future__ import annotations

from pathlib import Path
import struct

import gdb


WINDOWS_INIT_RVA = 0x3FEACF0
ON_INIT_CALLBACK_RVA = 0x3FE9840
READ_RESULT_RVA = 0x3FEA7E0

CODEGEN_INIT_METADATA_RVA = 0x38E3F0
CODEGEN_OBJECT_NEW_RVA = 0x38E830
NGSX_RESULT_TYPE_SLOT_RVA = 0x6961AF0

EXPECTED_INIT_PREFIX = bytes.fromhex("56 57 53 48 83 ec 50")
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
windows_init = base + WINDOWS_INIT_RVA
on_init_callback = base + ON_INIT_CALLBACK_RVA
read_result = base + READ_RESULT_RVA
metadata_init = base + CODEGEN_INIT_METADATA_RVA
object_new = base + CODEGEN_OBJECT_NEW_RVA
result_type_slot = base + NGSX_RESULT_TYPE_SLOT_RVA

actual_init = bytes(inferior.read_memory(windows_init, len(EXPECTED_INIT_PREFIX)))
if actual_init != EXPECTED_INIT_PREFIX:
    raise gdb.GdbError(
        "NgsxWindows.Init prefix mismatch: "
        f"expected={EXPECTED_INIT_PREFIX.hex()} actual={actual_init.hex()}"
    )

actual_read = bytes(inferior.read_memory(read_result, len(EXPECTED_READ_PREFIX)))
if actual_read != EXPECTED_READ_PREFIX:
    raise gdb.GdbError(
        "NgsxWindows.ReadResult prefix mismatch: "
        f"expected={EXPECTED_READ_PREFIX.hex()} actual={actual_read.hex()}"
    )

# OnInitCallback is static and does not consume its ``self`` argument.  Clear
# both explicit native callback arguments plus the hidden MethodInfo pointer.
init_code = bytearray(b"\x48\x83\xec\x28\x31\xc9\x31\xd2\x45\x31\xc0")
emit_call(init_code, windows_init, on_init_callback)
init_code.extend(b"\x48\x83\xc4\x28\xc3")

result_code = bytearray(b"\x56\x48\x83\xec\x20")
emit_lea_rcx(result_code, read_result, result_type_slot)
emit_call(result_code, read_result, metadata_init)
emit_mov_rcx_indirect(result_code, read_result, result_type_slot)
emit_call(result_code, read_result, object_new)
result_code.extend(
    bytes.fromhex(
        "48 89 c6 "
        "c6 46 10 01 "
        "c7 46 14 00 00 00 00 "
        "48 c7 46 18 00 00 00 00 "
        "48 89 f0 "
        "48 83 c4 20 "
        "5e c3"
    )
)

inferior.write_memory(read_result, result_code)
inferior.write_memory(windows_init, init_code)
gdb.write(
    "ngsx_success patched=true "
    f"init={windows_init:#x} read_result={read_result:#x}\n"
)

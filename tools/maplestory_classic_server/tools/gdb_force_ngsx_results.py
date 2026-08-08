"""Observe and optionally force the app's NGS init/run callback results.

The probe validates both current-build handler prologues before installing
breakpoints.  It prints only the boolean/code pair from NgsxResult and never
reads its message string.  With MAPLE_NGSX_FORCE_SUCCESS=1, the process-local
result object is changed to IsOK=true and Code=0 before the handler runs.
"""

from __future__ import annotations

import os
from pathlib import Path

import gdb


GAME_ASSEMBLY_NAME = "/GameAssembly.dll"
NGSX_INIT_RESULT_HANDLER_RVA = 0x4A9750
NGSX_RUN_RESULT_HANDLER_RVA = 0x4A9E70
HANDLERS = (
    (
        "init",
        NGSX_INIT_RESULT_HANDLER_RVA,
        bytes.fromhex("41 57 41 56 56 57 53 48 81 ec c0 00 00 00 48 89 d6"),
    ),
    (
        "run",
        NGSX_RUN_RESULT_HANDLER_RVA,
        bytes.fromhex("41 57 41 56 56 57 53 48 81 ec f0 00 00 00 48 89 d6"),
    ),
)


def game_assembly_base(pid: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) < 6 or not columns[5].endswith(GAME_ASSEMBLY_NAME):
            continue
        if int(columns[2], 16) == 0:
            return int(columns[0].split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll image base was not found")


class NgsxResultBreakpoint(gdb.Breakpoint):
    def __init__(self, stage: str, address: int, force_success: bool) -> None:
        super().__init__(f"*0x{address:x}", internal=False)
        self.stage = stage
        self.force_success = force_success

    def stop(self) -> bool:
        inferior = gdb.selected_inferior()
        result = int(gdb.parse_and_eval("$rdx"))
        if result == 0:
            print(f"ngsx_result stage={self.stage} result=null")
        else:
            raw = bytes(inferior.read_memory(result + 0x10, 8))
            is_ok = raw[0] != 0
            code = int.from_bytes(raw[4:8], "little")
            if self.force_success:
                inferior.write_memory(result + 0x10, b"\x01")
                inferior.write_memory(result + 0x14, b"\x00\x00\x00\x00")
            print(
                "ngsx_result "
                f"stage={self.stage} is_ok={str(is_ok).lower()} code={code} "
                f"forced={str(self.force_success).lower()}"
            )
        self.delete()
        return self.stage == "run"


inferior = gdb.selected_inferior()
if inferior.pid <= 0:
    raise gdb.GdbError("No live inferior is attached")

force_success = os.environ.get("MAPLE_NGSX_FORCE_SUCCESS") == "1"
base = game_assembly_base(inferior.pid)
for stage, rva, expected_prefix in HANDLERS:
    address = base + rva
    actual_prefix = bytes(inferior.read_memory(address, len(expected_prefix)))
    if actual_prefix != expected_prefix:
        raise gdb.GdbError(
            f"NGSX {stage} handler prologue mismatch: "
            f"expected={expected_prefix.hex()} actual={actual_prefix.hex()}"
        )
    NgsxResultBreakpoint(stage, address, force_success)

print(
    "ngsx_result_probe "
    f"handlers={len(HANDLERS)} forced={str(force_success).lower()} validated=true"
)
gdb.execute("continue")

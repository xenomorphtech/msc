"""Patch login opcode 1 to invoke a selected controller transition.

This short-lived GDB patch is an experimental probe for discovering login UI
states without fabricating the full account payload.  It validates the exact
handler prologue before replacing it and never changes the executable on disk.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct

import gdb


GAME_ASSEMBLY_NAME = "/GameAssembly.dll"
LOGIN_OPCODE1_HANDLER_RVA = 0xC0E5C0
LOGIN_TRANSITION_RVA = 0xC08230
EXPECTED_PREFIX = bytes.fromhex(
    "41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec 88 01 00 00"
)


def game_assembly_base(pid: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) < 6 or not columns[5].endswith(GAME_ASSEMBLY_NAME):
            continue
        if int(columns[2], 16) == 0:
            return int(columns[0].split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll image base was not found")


inferior = gdb.selected_inferior()
if inferior.pid <= 0:
    raise gdb.GdbError("No live inferior is attached")

forced_state = int(os.environ.get("MAPLE_LOGIN_FORCE_STATE", "2"), 0)
if not 0 <= forced_state <= 5:
    raise gdb.GdbError("Login state must be in the range 0..5")

base = game_assembly_base(inferior.pid)
handler = base + LOGIN_OPCODE1_HANDLER_RVA
transition = base + LOGIN_TRANSITION_RVA
actual_prefix = bytes(inferior.read_memory(handler, len(EXPECTED_PREFIX)))
if actual_prefix != EXPECTED_PREFIX:
    raise gdb.GdbError(
        "Login opcode-1 prologue mismatch: "
        f"expected={EXPECTED_PREFIX.hex()} actual={actual_prefix.hex()}"
    )

# Windows x64 entry alignment is restored around the ordinary transition call.
call_next = handler + 14
relative_call = transition - call_next
patch = (
    b"\x48\x83\xec\x28"
    + b"\xba"
    + struct.pack("<I", forced_state)
    + b"\xe8"
    + struct.pack("<i", relative_call)
    + b"\x48\x83\xc4\x28\xc3"
)
if len(patch) != len(EXPECTED_PREFIX):
    raise gdb.GdbError("Internal login opcode-1 patch length mismatch")

inferior.write_memory(handler, patch)
print(
    "login_opcode1_patch "
    f"forced_state={forced_state} bytes={len(patch)} validated=true"
)

"""Force one login-controller state transition at its method entry.

Source this file from GDB after attaching to Maplestory_Classic.exe.  The
breakpoint is conditional on the original state so startup transitions are
left alone.  When it matches, only EDX (the enum argument) is changed; GDB
then stops so the caller can detach and let the client resume normally.
"""

from __future__ import annotations

import os
from pathlib import Path

import gdb


GAME_ASSEMBLY_NAME = "/GameAssembly.dll"
LOGIN_TRANSITION_RVA = 0xC08230


def game_assembly_base(pid: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) < 6 or not columns[5].endswith(GAME_ASSEMBLY_NAME):
            continue
        if int(columns[2], 16) != 0:
            continue
        return int(columns[0].split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll image base was not found")


class LoginTransitionBreakpoint(gdb.Breakpoint):
    def __init__(self, address: int, source_state: int, forced_state: int) -> None:
        super().__init__(f"*0x{address:x}", internal=False)
        self.condition = f"$edx == {source_state}"
        self.forced_state = forced_state

    def stop(self) -> bool:
        controller = int(gdb.parse_and_eval("$rcx"))
        original_state = int(gdb.parse_and_eval("$edx")) & 0xFFFFFFFF
        gdb.execute(f"set $edx = {self.forced_state}", to_string=True)
        self.delete()
        print(
            "login_transition "
            f"controller=0x{controller:x} "
            f"original_state={original_state} forced_state={self.forced_state}"
        )
        return True


inferior = gdb.selected_inferior()
if inferior.pid <= 0:
    raise gdb.GdbError("No live inferior is attached")

source_state = int(os.environ.get("MAPLE_LOGIN_SOURCE_STATE", "1"), 0)
forced_state = int(os.environ.get("MAPLE_LOGIN_FORCE_STATE", "2"), 0)
if not 0 <= source_state <= 5 or not 0 <= forced_state <= 5:
    raise gdb.GdbError("Login states must be in the range 0..5")

base = game_assembly_base(inferior.pid)
LoginTransitionBreakpoint(
    base + LOGIN_TRANSITION_RVA,
    source_state=source_state,
    forced_state=forced_state,
)
print(
    "login_transition_breakpoint "
    f"source_state={source_state} forced_state={forced_state}"
)

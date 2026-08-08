"""Redirect one incoming login opcode-1 handler to a controller transition.

This is an experimental structural probe.  It skips opcode 1 parsing and
resumes at the controller's normal transition method with a selected state.
No executable on disk is modified.
"""

from __future__ import annotations

import os
from pathlib import Path

import gdb


GAME_ASSEMBLY_NAME = "/GameAssembly.dll"
LOGIN_OPCODE1_HANDLER_RVA = 0xC0E5C0
LOGIN_TRANSITION_RVA = 0xC08230


def game_assembly_base(pid: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) < 6 or not columns[5].endswith(GAME_ASSEMBLY_NAME):
            continue
        if int(columns[2], 16) == 0:
            return int(columns[0].split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll image base was not found")


class Opcode1RedirectBreakpoint(gdb.Breakpoint):
    def __init__(self, handler: int, transition: int, state: int) -> None:
        super().__init__(f"*0x{handler:x}", internal=False)
        self.transition = transition
        self.state = state

    def stop(self) -> bool:
        controller = int(gdb.parse_and_eval("$rcx"))
        gdb.execute(f"set $rip = 0x{self.transition:x}", to_string=True)
        gdb.execute(f"set $edx = {self.state}", to_string=True)
        self.delete()
        print(
            "login_opcode1_redirect "
            f"controller=0x{controller:x} forced_state={self.state}"
        )
        return True


inferior = gdb.selected_inferior()
if inferior.pid <= 0:
    raise gdb.GdbError("No live inferior is attached")

forced_state = int(os.environ.get("MAPLE_LOGIN_FORCE_STATE", "2"), 0)
if not 0 <= forced_state <= 5:
    raise gdb.GdbError("Login state must be in the range 0..5")

base = game_assembly_base(inferior.pid)
Opcode1RedirectBreakpoint(
    base + LOGIN_OPCODE1_HANDLER_RVA,
    base + LOGIN_TRANSITION_RVA,
    forced_state,
)
print(f"login_opcode1_redirect_breakpoint forced_state={forced_state}")

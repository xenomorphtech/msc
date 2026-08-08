"""Read the live login controller state without exposing account data."""

from __future__ import annotations

from pathlib import Path
import struct

import gdb


LOGIN_CONTROLLER_GET_INSTANCE_RVA = 0xC02B40
LOGIN_STATE_OFFSET = 0x98

inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")


def game_assembly_base() -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split()
        if (
            len(fields) >= 6
            and fields[2] == "00000000"
            and fields[-1].endswith("/GameAssembly.dll")
        ):
            return int(fields[0].split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped in the selected process")


register_names = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
)
saved = {
    name: int(gdb.parse_and_eval(f"${name}")) for name in register_names
}
initial_rip = saved["rip"]
call_stack = ((saved["rsp"] - 0x2000) & ~0xF) + 8
inferior.write_memory(call_stack, struct.pack("<Q", initial_rip))

return_breakpoint = gdb.Breakpoint(
    f"*{initial_rip:#x}", temporary=True, internal=True
)
previous_scheduler_locking = gdb.parameter("scheduler-locking")
try:
    for register in ("rcx", "rdx", "r8", "r9"):
        gdb.execute(f"set ${register} = 0", to_string=True)
    gdb.execute(f"set $rsp = {call_stack:#x}", to_string=True)
    gdb.execute(
        f"set $rip = {game_assembly_base() + LOGIN_CONTROLLER_GET_INSTANCE_RVA:#x}",
        to_string=True,
    )
    gdb.execute("set scheduler-locking on", to_string=True)
    gdb.execute("continue", to_string=True)
    controller = int(gdb.parse_and_eval("$rax"))
    if not controller:
        raise gdb.GdbError("Login controller instance is null")
    state = struct.unpack(
        "<i", bytes(inferior.read_memory(controller + LOGIN_STATE_OFFSET, 4))
    )[0]
    gdb.write(f"login_state value={state}\n")
finally:
    gdb.execute(
        f"set scheduler-locking {previous_scheduler_locking}", to_string=True
    )
    if return_breakpoint.is_valid():
        return_breakpoint.delete()
    for register, value in saved.items():
        gdb.execute(f"set ${register} = {value:#x}", to_string=True)

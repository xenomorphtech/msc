"""Trace the first return from NgsxWindows.ReadResult in the current build."""

from __future__ import annotations

from pathlib import Path
import struct

import gdb


READ_RESULT_RVA = 0x3FEA7E0
inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")


def game_assembly_base() -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if line.rstrip().endswith("/GameAssembly.dll"):
            return int(line.split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped")


def register(name: str) -> int:
    return int(gdb.parse_and_eval(f"${name}"))


def read_pointer(address: int) -> int:
    return struct.unpack("<Q", bytes(inferior.read_memory(address, 8)))[0]


class ResultReturnBreakpoint(gdb.Breakpoint):
    def __init__(self, address: int) -> None:
        super().__init__(f"*{address:#x}", temporary=True, internal=True)

    def stop(self) -> bool:
        result = register("rax")
        if not result:
            gdb.write("ngsx_result null=true\n")
            return True
        raw = bytes(inferior.read_memory(result + 0x10, 8))
        is_ok = raw[0] != 0
        code = struct.unpack_from("<I", raw, 4)[0]
        gdb.write(f"ngsx_result is_ok={str(is_ok).lower()} code={code}\n")
        return True


class ResultEntryBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        ResultReturnBreakpoint(read_pointer(register("rsp")))
        return False


address = game_assembly_base() + READ_RESULT_RVA
ResultEntryBreakpoint(f"*{address:#x}", internal=True)
gdb.write(f"ngsx_read_result_breakpoint address={address:#x}\n")

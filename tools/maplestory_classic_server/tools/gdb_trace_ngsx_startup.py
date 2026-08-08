"""Trace synthetic NGSX init delivery through the game's startup handler."""

from __future__ import annotations

from pathlib import Path
import struct

import gdb


ON_INIT_CALLBACK_RVA = 0x3FE9840
READ_RESULT_RVA = 0x3FEA7E0
APP_ON_INIT_RVA = 0x4A9750


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


def describe_result(result: int) -> str:
    if not result:
        return "null=true"
    raw = bytes(inferior.read_memory(result + 0x10, 8))
    is_ok = raw[0] != 0
    code = struct.unpack_from("<I", raw, 4)[0]
    return f"null=false is_ok={str(is_ok).lower()} code={code}"


class ResultReturnBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        gdb.write(f"ngsx_startup read_result {describe_result(register('rax'))}\n")
        return False


class ReadResultBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        ResultReturnBreakpoint(
            f"*{read_pointer(register('rsp')):#x}", temporary=True, internal=True
        )
        return False


class CallbackBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        gdb.write(
            "ngsx_startup callback_entered=true "
            f"native_result_null={str(register('rdx') == 0).lower()}\n"
        )
        return False


class AppHandlerBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        gdb.write(
            "ngsx_startup app_handler_entered=true "
            f"{describe_result(register('rdx'))}\n"
        )
        return True


base = game_assembly_base()
CallbackBreakpoint(f"*{base + ON_INIT_CALLBACK_RVA:#x}", internal=True)
ReadResultBreakpoint(f"*{base + READ_RESULT_RVA:#x}", internal=True)
AppHandlerBreakpoint(f"*{base + APP_ON_INIT_RVA:#x}", internal=True)
gdb.write("ngsx_startup trace_ready=true\n")

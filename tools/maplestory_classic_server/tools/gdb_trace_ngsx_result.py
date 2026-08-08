"""Trace a resolved callback whose second argument is an NgsxResult object.

Source ``gdb_resolve_named_method.py`` first.  This script reads only the
boolean and numeric code fields; it deliberately does not read the message.
"""

from __future__ import annotations

import struct

import gdb


inferior = gdb.selected_inferior()
method_pointer = int(gdb.parse_and_eval("$maple_method_pointer"))


def register(name: str) -> int:
    return int(gdb.parse_and_eval(f"${name}"))


class NgsxResultBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        result = register("rdx")
        if not result:
            gdb.write("ngsx_result null=true\n")
            return False
        raw = bytes(inferior.read_memory(result + 0x10, 8))
        is_ok = raw[0] != 0
        code = struct.unpack_from("<I", raw, 4)[0]
        gdb.write(f"ngsx_result is_ok={str(is_ok).lower()} code={code}\n")
        return False


NgsxResultBreakpoint(f"*{method_pointer:#x}", internal=True)
gdb.write(f"ngsx_result_breakpoint pointer={method_pointer:#x}\n")

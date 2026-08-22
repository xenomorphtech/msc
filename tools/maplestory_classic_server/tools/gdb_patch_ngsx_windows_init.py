"""Disable only the Windows NGSX platform Init call in a live client.

This is an ephemeral, build-specific custom-server debugging patch.  It keeps
NgsxPlugin and the application's managed event setup intact while preventing
the native Windows NGS implementation from starting.  The executable on disk
is never modified.
"""

from __future__ import annotations

from pathlib import Path

import gdb


METHOD_RVA = 0x4023270
EXPECTED_PREFIX = bytes.fromhex("56 57 53 48 83 ec 50")
REPLACEMENT = bytes.fromhex("c3")


inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")


def game_assembly_base() -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if line.rstrip().endswith("/GameAssembly.dll"):
            return int(line.split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped in the selected process")


address = game_assembly_base() + METHOD_RVA
actual = bytes(inferior.read_memory(address, len(EXPECTED_PREFIX)))
if actual != EXPECTED_PREFIX:
    raise gdb.GdbError(
        "NgsxWindows.Init prefix mismatch: "
        f"expected={EXPECTED_PREFIX.hex()} actual={actual.hex()}"
    )

inferior.write_memory(address, REPLACEMENT)
gdb.write(f"ngsx_windows_init patched=true address={address:#x}\n")

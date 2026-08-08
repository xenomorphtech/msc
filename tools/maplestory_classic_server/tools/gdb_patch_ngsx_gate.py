"""Patch the current build's application NGSX gate in memory only."""

from __future__ import annotations

from pathlib import Path

import gdb


GATE_RVA = 0x4A8AA0
EXPECTED = bytes.fromhex("41 56 56 57 53 48 81")
# bool Gate(out uint code): *code = 0; return true
REPLACEMENT = bytes.fromhex("31 c0 89 02 b0 01 c3")

inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")

base = None
for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
    if line.rstrip().endswith("/GameAssembly.dll"):
        base = int(line.split("-", 1)[0], 16)
        break
if base is None:
    raise gdb.GdbError("GameAssembly.dll is not mapped")

address = base + GATE_RVA
actual = bytes(inferior.read_memory(address, len(EXPECTED)))
if actual == REPLACEMENT:
    gdb.write(f"ngsx_gate already_patched=true address={address:#x}\n")
elif actual != EXPECTED:
    raise gdb.GdbError(
        f"refusing NGSX gate patch: unexpected bytes at {address:#x}"
    )
else:
    inferior.write_memory(address, REPLACEMENT)
    gdb.write(f"ngsx_gate patched=true address={address:#x}\n")

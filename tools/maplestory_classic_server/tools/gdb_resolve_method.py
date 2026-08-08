"""Resolve one GameAssembly RVA to neighboring live IL2CPP methods."""

from __future__ import annotations

import os
from pathlib import Path
import struct

import gdb


EXPORT_RVAS = {
    "domain_get": 0x426F00,
    "domain_get_assemblies": 0x426F20,
    "assembly_get_image": 0x3FD740,
    "image_get_name": 0x3FD740,
    "image_get_class_count": 0x427C90,
    "image_get_class": 0x427CA0,
    "class_get_methods": 0x425F50,
    "class_get_name": 0x425F70,
    "method_get_name": 0x425F80,
}

inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")


def game_assembly_base() -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if line.rstrip().endswith("/GameAssembly.dll"):
            return int(line.split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped in the selected process")


def read_pointer(address: int) -> int:
    return struct.unpack("<Q", bytes(inferior.read_memory(address, 8)))[0]


def read_c_string(address: int, *, limit: int = 4096) -> str:
    if not address:
        return "<null>"
    data = bytes(inferior.read_memory(address, limit))
    terminator = data.find(b"\0")
    if terminator < 0:
        raise gdb.GdbError(f"C string at {address:#x} exceeds {limit} bytes")
    return data[:terminator].decode("utf-8", "backslashreplace")


base = game_assembly_base()
initial_rip = int(gdb.parse_and_eval("$rip"))
initial_rsp = int(gdb.parse_and_eval("$rsp"))
call_stack = ((initial_rsp - 0x10000) & ~0xF) + 8


def set_register(name: str, value: int) -> None:
    gdb.execute(f"set ${name} = {value:#x}", to_string=True)


def ms_call(address: int, *arguments: int) -> int:
    return_breakpoint = gdb.Breakpoint(
        f"*{initial_rip:#x}", temporary=True, internal=True
    )
    inferior.write_memory(call_stack, struct.pack("<Q", initial_rip))
    for register, value in zip(("rcx", "rdx", "r8", "r9"), arguments):
        set_register(register, value)
    for register in ("rcx", "rdx", "r8", "r9")[len(arguments) :]:
        set_register(register, 0)
    set_register("rsp", call_stack)
    set_register("rip", address)
    gdb.execute("continue", to_string=True)
    result = int(gdb.parse_and_eval("$rax"))
    if return_breakpoint.is_valid():
        return_breakpoint.delete()
    return result


target_rva = int(os.environ.get("MAPLE_METHOD_TARGET_RVA", "0x1cd8f92"), 0)
target = base + target_rva
assembly_name = os.environ.get("MAPLE_METHOD_ASSEMBLY", "Framework")
if not assembly_name or "\0" in assembly_name:
    raise gdb.GdbError("MAPLE_METHOD_ASSEMBLY must be a non-empty assembly name")
scratch = call_stack + 0x100
inferior.write_memory(scratch, b"\0" * 4096)
context_address = scratch
assembly_name_address = scratch + 0x200
assembly_dll_name_address = scratch + 0x240
inferior.write_memory(assembly_name_address, assembly_name.encode("ascii") + b"\0")
inferior.write_memory(
    assembly_dll_name_address, f"{assembly_name}.dll".encode("ascii") + b"\0"
)

context_values = [
    0,
    *(base + EXPORT_RVAS[name] for name in (
        "domain_get",
        "domain_get_assemblies",
        "assembly_get_image",
        "image_get_name",
        "image_get_class_count",
        "image_get_class",
        "class_get_methods",
        "class_get_name",
        "method_get_name",
    )),
    assembly_name_address,
    assembly_dll_name_address,
    target,
    *(0 for _ in range(17)),
]
if len(context_values) != 30:
    raise gdb.GdbError(f"Unexpected resolver-context qword count: {len(context_values)}")
inferior.write_memory(
    context_address,
    struct.pack("<" + "Q" * len(context_values), *context_values),
)

trampoline_path = Path(__file__).with_name("method_resolver_trampoline.bin")
trampoline = trampoline_path.read_bytes()
trampoline_address = base + 0x74BA000
original_code = bytes(inferior.read_memory(trampoline_address, len(trampoline)))
inferior.write_memory(trampoline_address, trampoline)
try:
    ms_call(trampoline_address, context_address)
finally:
    inferior.write_memory(trampoline_address, original_code)

values = struct.unpack(
    "<" + "Q" * len(context_values),
    bytes(inferior.read_memory(context_address, 8 * len(context_values))),
)
stage = values[0]
class_count = values[18]
visited_methods = values[19]
gdb.write(
    f"method_resolver stage={stage} base={base:#x} target_rva={target_rva:#x} "
    f"assembly={assembly_name} classes={class_count} methods={visited_methods}\n"
)
if stage != 100:
    raise gdb.GdbError(f"Method resolver stopped at stage {stage}")

for label, method_info, method_pointer, class_name_pointer, method_name_pointer in (
    ("before", values[21], values[22], values[26], values[27]),
    ("after", values[24], values[25], values[28], values[29]),
):
    gdb.write(
        f"method_{label} class={read_c_string(class_name_pointer)} "
        f"method={read_c_string(method_name_pointer)} "
        f"method_info={method_info:#x} pointer={method_pointer:#x} "
        f"rva={method_pointer - base:#x} distance={method_pointer - target:+#x}\n"
    )

"""Resolve a live IL2CPP method by assembly, class, name, and arity.

Environment variables:
  MAPLE_METHOD_ASSEMBLY   Assembly name without .dll (default: Framework)
  MAPLE_METHOD_NAMESPACE  IL2CPP namespace (default: empty)
  MAPLE_METHOD_CLASS      Required class name
  MAPLE_METHOD_NAME       Required method name
  MAPLE_METHOD_ARG_COUNT  Declared argument count (default: 0)

The script leaves ``$maple_method_pointer`` and ``$maple_game_assembly_base``
available to subsequent GDB commands.
"""

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
    "class_from_name": 0x425EC0,
    "class_get_method_from_name": 0x425F60,
    "class_get_methods": 0x425F50,
    "method_get_name": 0x425F80,
    "method_get_param_count": 0x427550,
}

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
            return int(line.split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped in the selected process")


def game_assembly_executable_scratch(size: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split()
        if (
            len(fields) >= 6
            and "x" in fields[1]
            and fields[-1].endswith("/GameAssembly.dll")
        ):
            start_text, end_text = fields[0].split("-", 1)
            start = int(start_text, 16)
            end = int(end_text, 16)
            address = start + 0x100
            if address + size <= end:
                return address
    raise gdb.GdbError("GameAssembly.dll has no executable scratch mapping")


def set_register(name: str, value: int) -> None:
    gdb.execute(f"set ${name} = {value:#x}", to_string=True)


def text_setting(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or "\0" in value:
        raise gdb.GdbError(f"{name} must be set to a valid string")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise gdb.GdbError(f"{name} must contain ASCII only") from error
    return value


base = game_assembly_base()
initial_registers = {
    name: int(gdb.parse_and_eval(f"${name}"))
    for name in (
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
    )
}
initial_rip = initial_registers["rip"]
# Stay within the currently committed Wine thread stack.  Subtracting 64 KiB
# can land on a mapped guard page even when GDB can write the synthetic return
# slot itself; the trampoline then faults on its first stack spill.
call_stack = ((initial_registers["rsp"] - 0x2000) & ~0xF) + 8


def ms_call(address: int, *arguments: int) -> int:
    previous_scheduler_locking = gdb.parameter("scheduler-locking")
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
    try:
        # Several Wine threads commonly share the same host-side stop address.
        # Without locking, a different thread can hit the synthetic return
        # breakpoint before the hijacked thread finishes the trampoline.
        gdb.execute("set scheduler-locking on", to_string=True)
        gdb.execute("continue", to_string=True)
        return int(gdb.parse_and_eval("$rax"))
    finally:
        gdb.execute(
            f"set scheduler-locking {previous_scheduler_locking}", to_string=True
        )
        if return_breakpoint.is_valid():
            return_breakpoint.delete()


assembly_name = text_setting("MAPLE_METHOD_ASSEMBLY", "Framework")
namespace_name = text_setting("MAPLE_METHOD_NAMESPACE", "")
class_name = text_setting("MAPLE_METHOD_CLASS")
method_name = text_setting("MAPLE_METHOD_NAME")
try:
    argument_count = int(os.environ.get("MAPLE_METHOD_ARG_COUNT", "0"), 0)
except ValueError as error:
    raise gdb.GdbError("MAPLE_METHOD_ARG_COUNT must be an integer") from error
if argument_count < 0 or argument_count > 1024:
    raise gdb.GdbError("MAPLE_METHOD_ARG_COUNT is outside the valid range")

scratch = call_stack + 0x100
inferior.write_memory(scratch, b"\0" * 4096)
context_address = scratch
cursor = scratch + 0x200


def allocate_string(value: str) -> int:
    global cursor
    encoded = value.encode("ascii") + b"\0"
    address = cursor
    inferior.write_memory(address, encoded)
    cursor += len(encoded)
    return address


context_values = [
    0,
    *(base + EXPORT_RVAS[name] for name in (
        "domain_get",
        "domain_get_assemblies",
        "assembly_get_image",
        "image_get_name",
        "class_from_name",
        "class_get_method_from_name",
    )),
    allocate_string(assembly_name),
    allocate_string(f"{assembly_name}.dll"),
    allocate_string(namespace_name),
    allocate_string(class_name),
    allocate_string(method_name),
    argument_count,
    *(0 for _ in range(8)),
]
if len(context_values) != 21:
    raise gdb.GdbError(
        f"Unexpected named-method context qword count: {len(context_values)}"
    )
inferior.write_memory(
    context_address,
    struct.pack("<" + "Q" * len(context_values), *context_values),
)

trampoline_path = Path(__file__).with_name("named_method_resolver_trampoline.bin")
trampoline = trampoline_path.read_bytes()
if len(trampoline) > 4096:
    raise gdb.GdbError(f"Named-method trampoline is too large: {len(trampoline)}")
# Derive the Wine PE section mapping rather than assuming it has the same
# relocation delta as the image headers.  Wine can independently align the
# file-backed executable section between launches.
trampoline_address = game_assembly_executable_scratch(len(trampoline))
original_code = bytes(inferior.read_memory(trampoline_address, len(trampoline)))
inferior.write_memory(trampoline_address, trampoline)
try:
    ms_call(trampoline_address, context_address)
finally:
    inferior.write_memory(trampoline_address, original_code)
    for register, value in initial_registers.items():
        set_register(register, value)

values = struct.unpack(
    "<" + "Q" * len(context_values),
    bytes(inferior.read_memory(context_address, 8 * len(context_values))),
)
stage = values[0]
if stage != 100:
    if os.environ.get("MAPLE_ENUMERATE_ON_MISS") == "1" and values[18]:
        iterator_address = scratch + 0xF00
        inferior.write_memory(iterator_address, struct.pack("<Q", 0))
        gdb.write("named_method_candidates_begin\n")
        try:
            for _ in range(512):
                candidate = ms_call(
                    base + EXPORT_RVAS["class_get_methods"],
                    values[18],
                    iterator_address,
                )
                if not candidate:
                    break
                name_address = ms_call(
                    base + EXPORT_RVAS["method_get_name"], candidate
                )
                parameter_count = ms_call(
                    base + EXPORT_RVAS["method_get_param_count"], candidate
                ) & 0xFFFFFFFF
                if name_address:
                    raw_name = bytes(inferior.read_memory(name_address, 512))
                    name = raw_name.split(b"\0", 1)[0].decode("utf-8", "replace")
                else:
                    name = "<null>"
                gdb.write(
                    f"named_method_candidate name={name!r} "
                    f"args={parameter_count} method_info={candidate:#x}\n"
                )
        finally:
            for register, value in initial_registers.items():
                set_register(register, value)
        gdb.write("named_method_candidates_end\n")
    raise gdb.GdbError(
        f"Named-method resolver stopped at stage {stage} for "
        f"{assembly_name}:{namespace_name}.{class_name}.{method_name}/"
        f"{argument_count}"
    )
method_info = values[19]
method_pointer = values[20]
gdb.execute(f"set $maple_game_assembly_base = {base:#x}", to_string=True)
gdb.execute(f"set $maple_method_pointer = {method_pointer:#x}", to_string=True)
gdb.write(
    f"named_method assembly={assembly_name} namespace={namespace_name!r} "
    f"class={class_name} method={method_name} args={argument_count} "
    f"method_info={method_info:#x} pointer={method_pointer:#x} "
    f"rva={method_pointer - base:#x}\n"
)

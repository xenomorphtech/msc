"""Dump VecCtrl/User/Mob IL2CPP field and method maps via a brief GDB attach."""

from __future__ import annotations

import json
import os
from pathlib import Path
import struct

import gdb


EXPORT_RVAS = {
    "domain_get": 0x426F00,
    "domain_assembly_open": 0x426F10,
    "assembly_get_image": 0x3FD740,
    "class_from_name": 0x425EC0,
    "class_get_fields": 0x425EF0,
    "class_get_methods": 0x425F50,
    "class_get_name": 0x425F70,
    "class_get_namespace": 0x425F80,
    "class_get_parent": 0x425F90,
    "class_get_nested_types": 0x425F00,
    "class_instance_size": 0x425FB0,
    "field_get_name": 0x3FD740,
    "field_get_offset": 0x4271E0,
    "field_get_type": 0x4271F0,
    "field_get_flags": 0x4271C0,
    "method_get_name": 0x425F80,
    "method_get_param_count": 0x427550,
    "type_get_name": 0x427910,
    "type_get_type": 0x4278F0,
    "thread_attach": 0x427810,
    "runtime_class_init": 0x38E700,
    "free": 0x3ABBA0,
}

TARGETS = (
    ("Msc.Game.Object.Control", "VecCtrl"),
    ("Msc.Game.Object.Control", "VecCtrlUser"),
    ("Msc.Game.Object.Control", "VecCtrlMob"),
    ("Msc.Game.Object.Control", "MovePath"),
    ("Msc.Game", "PhysicalSpace2D"),
    ("Msc.Game", "Foothold"),
    ("Msc.Data", "StaticFoothold"),
    ("Msc.Data", "LadderOrRope"),
    ("Msc.Game.Object", "UserLocal"),
    ("Msc.Game.Object", "Mob"),
    ("Msc.Game.Object", "MobPool"),
    ("Msc.Game.Object", "VecCtrlOwner"),
)

NESTED = (
    ("Msc.Game.Object.Control", "VecCtrl", "AbsPos"),
    ("Msc.Game.Object.Control", "VecCtrl", "RelPos"),
    ("Msc.Game.Object.Control", "VecCtrl", "FallDownData"),
    ("Msc.Game.Object.Control", "VecCtrl", "ImpactNext"),
    ("Msc.Game.Object.Control", "VecCtrlMob", "MoveCtx"),
)

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
    raise gdb.GdbError("GameAssembly.dll is not mapped")


def set_register(name: str, value: int) -> None:
    gdb.execute(f"set ${name} = {value:#x}", to_string=True)


base = game_assembly_base()
initial_registers = {
    name: int(gdb.parse_and_eval(f"${name}"))
    for name in (
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
    )
}
initial_rip = initial_registers["rip"]
call_stack = ((initial_registers["rsp"] - 0x2000) & ~0xF) + 8
scratch = call_stack + 0x100
inferior.write_memory(scratch, b"\0" * 8192)
string_cursor = scratch + 0x400


def allocate_string(value: str) -> int:
    global string_cursor
    encoded = value.encode("ascii") + b"\0"
    address = string_cursor
    inferior.write_memory(address, encoded)
    string_cursor += (len(encoded) + 15) & ~15
    return address


def read_c_string(address: int) -> str | None:
    if address == 0:
        return None
    raw = bytes(inferior.read_memory(address, 512))
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def ms_call(address: int, *arguments: int) -> int:
    previous = gdb.parameter("scheduler-locking")
    breakpoint = gdb.Breakpoint(f"*{initial_rip:#x}", temporary=True, internal=True)
    inferior.write_memory(call_stack, struct.pack("<Q", initial_rip))
    for register, value in zip(("rcx", "rdx", "r8", "r9"), arguments):
        set_register(register, value)
    for register in ("rcx", "rdx", "r8", "r9")[len(arguments):]:
        set_register(register, 0)
    set_register("rsp", call_stack)
    set_register("rip", address)
    try:
        gdb.execute("set scheduler-locking on", to_string=True)
        gdb.execute("continue", to_string=True)
        return int(gdb.parse_and_eval("$rax")) & ((1 << 64) - 1)
    finally:
        gdb.execute(f"set scheduler-locking {previous}", to_string=True)
        if breakpoint.is_valid():
            breakpoint.delete()


def api(name: str) -> int:
    return base + EXPORT_RVAS[name]


def dump_fields(klass: int) -> list[dict[str, object]]:
    iterator = scratch + 0x200
    inferior.write_memory(iterator, struct.pack("<Q", 0))
    fields: list[dict[str, object]] = []
    for _ in range(256):
        field = ms_call(api("class_get_fields"), klass, iterator)
        if field == 0:
            break
        type_pointer = ms_call(api("field_get_type"), field)
        type_name = None
        type_enum = None
        if type_pointer:
            allocated = ms_call(api("type_get_name"), type_pointer)
            type_name = read_c_string(allocated)
            if allocated:
                ms_call(api("free"), allocated)
            type_enum = ms_call(api("type_get_type"), type_pointer) & 0xFFFFFFFF
        offset = ms_call(api("field_get_offset"), field)
        if offset >= 2**63:
            offset -= 2**64
        fields.append(
            {
                "name": read_c_string(ms_call(api("field_get_name"), field)),
                "offset": offset,
                "flags": ms_call(api("field_get_flags"), field) & 0xFFFFFFFF,
                "type_enum": type_enum,
                "type": type_name,
            }
        )
    return fields


def dump_methods(klass: int) -> list[dict[str, object]]:
    iterator = scratch + 0x208
    inferior.write_memory(iterator, struct.pack("<Q", 0))
    methods: list[dict[str, object]] = []
    for _ in range(256):
        method = ms_call(api("class_get_methods"), klass, iterator)
        if method == 0:
            break
        pointer = int.from_bytes(bytes(inferior.read_memory(method, 8)), "little")
        methods.append(
            {
                "name": read_c_string(ms_call(api("method_get_name"), method)),
                "argc": ms_call(api("method_get_param_count"), method) & 0xFFFFFFFF,
                "method_info": method,
                "pointer": pointer or None,
                "rva": (pointer - base) if pointer else None,
            }
        )
    return methods


def dump_class(klass: int) -> dict[str, object]:
    parent = ms_call(api("class_get_parent"), klass)
    parent_name = None
    if parent:
        parent_name = (
            f"{read_c_string(ms_call(api('class_get_namespace'), parent))}."
            f"{read_c_string(ms_call(api('class_get_name'), parent))}"
        )
    ms_call(api("runtime_class_init"), klass)
    return {
        "namespace": read_c_string(ms_call(api("class_get_namespace"), klass)),
        "name": read_c_string(ms_call(api("class_get_name"), klass)),
        "parent": parent_name,
        "address": klass,
        "instance_size": ms_call(api("class_instance_size"), klass) & 0xFFFFFFFF,
        "fields": dump_fields(klass),
        "methods": dump_methods(klass),
    }


try:
    domain = ms_call(api("domain_get"))
    if domain == 0:
        raise gdb.GdbError("il2cpp_domain_get returned null")
    ms_call(api("thread_attach"), domain)
    image = 0
    image_name = None
    for name in ("Assembly-CSharp.dll", "Assembly-CSharp"):
        assembly = ms_call(api("domain_assembly_open"), domain, allocate_string(name))
        if assembly == 0:
            continue
        image = ms_call(api("assembly_get_image"), assembly)
        if image:
            image_name = name
            break
    if image == 0:
        raise gdb.GdbError("Assembly-CSharp was not found")

    classes: list[dict[str, object]] = []
    klass_by_key: dict[str, int] = {}
    for namespace, name in TARGETS:
        klass = ms_call(
            api("class_from_name"),
            image,
            allocate_string(namespace),
            allocate_string(name),
        )
        if klass == 0:
            classes.append({"namespace": namespace, "name": name, "missing": True})
            continue
        dumped = dump_class(klass)
        classes.append(dumped)
        klass_by_key[f"{namespace}.{name}"] = klass

    for namespace, parent_name, nested_name in NESTED:
        parent = klass_by_key.get(f"{namespace}.{parent_name}")
        if parent is None:
            classes.append(
                {
                    "namespace": f"{namespace}.{parent_name}",
                    "name": nested_name,
                    "missing": True,
                }
            )
            continue
        iterator = scratch + 0x210
        inferior.write_memory(iterator, struct.pack("<Q", 0))
        found = 0
        for _ in range(64):
            nested = ms_call(api("class_get_nested_types"), parent, iterator)
            if nested == 0:
                break
            if read_c_string(ms_call(api("class_get_name"), nested)) == nested_name:
                found = nested
                break
        if found == 0:
            classes.append(
                {
                    "namespace": f"{namespace}.{parent_name}",
                    "name": nested_name,
                    "missing": True,
                }
            )
            continue
        classes.append(dump_class(found))

    report = {
        "type": "map",
        "base": base,
        "image": image_name,
        "classes": classes,
    }
    output = os.environ.get("MAPLE_PHYSICS_MAP")
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if output:
        Path(output).write_text(encoded + "\n", encoding="utf-8")
        os.chmod(output, 0o600)
    gdb.write(encoded + "\n")
finally:
    for register, value in initial_registers.items():
        set_register(register, value)

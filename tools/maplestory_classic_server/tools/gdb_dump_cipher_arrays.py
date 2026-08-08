"""Dump initialized IL2CPP AESCipher static arrays from a stopped Wine client.

Run this inside GDB after stopping at a breakpoint in GameAssembly.dll. The
target uses the Windows x64 ABI even though GDB is attached to Wine on Linux.
``ms_call`` enters a one-shot freestanding trampoline because Wine does not
preserve a debugger-hijacked guest thread across multiple continue/stop cycles.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct

import gdb


CLASS_NAME = "b9e4d430c4a28790f54a8a9fe532d8350c30e9e1a98f418c9035a0543963dbd"
BYTE_ARRAY_FIELDS = (
    "ecb3d34e8cde36985207208f8b876fe9e7734063d80e6d5eaa459428f84074e",
    "bf399f18fa8f54a7ebc0632f985b7077ee0bf74e31b1c69a396ef59656912d5",
    "fbdcb21ddbd60e1ad7d516ab7f01d2b7da31d24c44eff30b2495e66c7501ec2",
    "c580e7accba370372b979ae53076accb4a41dee89b07ae39cfbee759ed565c3",
    "ef25d1812c7a31dc9364d1063ec19d5238318f914f9c19f3f64161ccd2854ad",
)
UINT_ARRAY_FIELDS = (
    "c870d0b355fb42339814f2b305609476df76f5f74ed0bda194d11e80d6c0776",
)

EXPORT_RVAS = {
    "alloc": 0x425DC0,
    "assembly_get_image": 0x3FD740,
    "class_from_name": 0x425EC0,
    "class_get_field_from_name": 0x425F40,
    "class_get_method_from_name": 0x425F60,
    "class_get_name": 0x425F70,
    "class_get_namespace": 0x425F80,
    "domain_get": 0x426F00,
    "domain_get_assemblies": 0x426F20,
    "field_static_get_value": 0x427250,
    "image_get_name": 0x3FD740,
    "image_get_class": 0x427CA0,
    "image_get_class_count": 0x427C90,
    "runtime_class_init": 0x38E700,
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


base = game_assembly_base()
initial_rip = int(gdb.parse_and_eval("$rip"))
initial_rsp = int(gdb.parse_and_eval("$rsp"))
call_stack = ((initial_rsp - 0x10000) & ~0xF) + 8


def set_register(name: str, value: int) -> None:
    gdb.execute(f"set ${name} = {value:#x}", to_string=True)


def ms_call(address: int, *arguments: int) -> int:
    if len(arguments) > 4:
        raise gdb.GdbError("ms_call currently supports up to four register arguments")

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


def write_c_string(address: int, value: str) -> int:
    encoded = value.encode("ascii") + b"\0"
    inferior.write_memory(address, encoded)
    return address + len(encoded)


def read_pointer(address: int) -> int:
    return struct.unpack("<Q", bytes(inferior.read_memory(address, 8)))[0]


def read_c_string(address: int, *, limit: int = 4096) -> str:
    if address == 0:
        return "<null>"
    data = bytes(inferior.read_memory(address, limit))
    terminator = data.find(b"\0")
    if terminator < 0:
        raise gdb.GdbError(f"C string at {address:#x} exceeds {limit} bytes")
    return data[:terminator].decode("utf-8", "backslashreplace")


def read_managed_array(address: int, element_size: int) -> tuple[int, bytes]:
    if address == 0:
        raise gdb.GdbError("Static field contains a null array")
    length = read_pointer(address + 0x18)
    if length > 1_000_000:
        raise gdb.GdbError(f"Implausible managed-array length: {length}")
    payload = bytes(inferior.read_memory(address + 0x20, length * element_size))
    return length, payload


addresses = {name: base + rva for name, rva in EXPORT_RVAS.items()}
# Use the mapped stack region above the synthetic call frame for debugger-owned
# strings and out parameters.  Calling il2cpp_alloc from an arbitrary stopped
# Wine thread can legitimately return null when that thread is not attached to
# the IL2CPP runtime, while these metadata APIs only require native buffers.
scratch = call_stack + 0x100
inferior.write_memory(scratch, b"\0" * 8192)
context_address = scratch
cursor = context_address + 0x400


def allocate_string(value: str) -> int:
    global cursor
    address = cursor
    cursor = write_c_string(cursor, value)
    return address


empty_namespace = allocate_string("")
class_name = allocate_string(CLASS_NAME)
framework_name = allocate_string("Framework")
framework_dll_name = allocate_string("Framework.dll")
fields = (
    *((name, 1) for name in BYTE_ARRAY_FIELDS),
    *((name, 4) for name in UINT_ARRAY_FIELDS),
)
field_name_addresses = [allocate_string(name) for name, _ in fields]
transform_names = (
    "e4147b0bf6aa0519dafd1586e1ff642f720b76696e228fe89d41a46568a7e5e",
    "bab383098ecad1bfe745a29f2ff90755e712c9343a5aafdc3bda37cc57b408c",
)
transform_name_addresses = [allocate_string(name) for name in transform_names]
inno_class_name = allocate_string(
    "dfd720eb92098e5f57828e9d010d1e6027d22c2abfde17f67508206f70c6c2c"
)
inno_methods = (
    ("d70d4b6ba8c9487cec42040c1cec3752d30ac46bbcbbfe104811906fddab8dd", 2),
    ("f2debdb3edc18abd85c2764e10c79fcb38ca9d8f046a18880268078cc0b3e2f", 3),
    ("bb2eec59d69738c374515ec17e2736685e7fd76c76b94b2746ae49efa82334e", 4),
    ("dde5e40d49d1da8b3f457696e05d9162368a0235a5a078a80d3749ecca4a2e0", 3),
    ("e31b97b0e2ba27aefee2af23931184781437e72010b78d264c24d595542f8f3", 4),
    ("e7f8b59ef16900a86636d708d84df4f0661918b8a148aa711136da2b5490070", 2),
)
inno_method_name_addresses = [
    allocate_string(name) for name, _ in inno_methods
]

# Keep this qword layout synchronized with struct dump_context in the C source.
context_values = [
    0,
    addresses["domain_get"],
    addresses["domain_get_assemblies"],
    addresses["assembly_get_image"],
    addresses["image_get_name"],
    addresses["class_from_name"],
    addresses["runtime_class_init"],
    addresses["class_get_field_from_name"],
    addresses["field_static_get_value"],
    empty_namespace,
    class_name,
    framework_name,
    framework_dll_name,
    *field_name_addresses,
    *(0 for _ in range(18)),
    addresses["class_get_method_from_name"],
    *transform_name_addresses,
    *(0 for _ in range(4)),
    inno_class_name,
    *inno_method_name_addresses,
    *(argument_count for _, argument_count in inno_methods),
    *(0 for _ in range(13)),
]
if len(context_values) != 70:
    raise gdb.GdbError(f"Unexpected dump-context qword count: {len(context_values)}")
inferior.write_memory(
    context_address,
    struct.pack("<" + "Q" * len(context_values), *context_values),
)

trampoline_path = Path(__file__).with_name("cipher_dump_trampoline.bin")
if not trampoline_path.exists():
    raise gdb.GdbError(
        f"Missing {trampoline_path}; compile cipher_dump_trampoline.c first"
    )
trampoline = trampoline_path.read_bytes()
if len(trampoline) > 4096:
    raise gdb.GdbError(f"Cipher dump trampoline is too large: {len(trampoline)} bytes")

# The start of the build-specific executable .7yz section is used only while
# every other thread is stopped. Restore it even when the trampoline fails.
trampoline_address = base + 0x74BA000
original_code = bytes(inferior.read_memory(trampoline_address, len(trampoline)))
inferior.write_memory(trampoline_address, trampoline)
try:
    ms_call(trampoline_address, context_address)
finally:
    inferior.write_memory(trampoline_address, original_code)

stage = read_pointer(context_address)
domain = read_pointer(context_address + 19 * 8)
assemblies = read_pointer(context_address + 20 * 8)
assembly_count = read_pointer(context_address + 21 * 8)
assembly = read_pointer(context_address + 22 * 8)
image = read_pointer(context_address + 23 * 8)
class_pointer = read_pointer(context_address + 24 * 8)
gdb.write(
    f"game_assembly_base={base:#x} stage={stage} domain={domain:#x} "
    f"assemblies={assemblies:#x} count={assembly_count} "
    f"assembly={assembly:#x} image={image:#x} class={class_pointer:#x}\n"
)
if stage != 100:
    raise gdb.GdbError(f"Cipher dump trampoline stopped at stage {stage}")

workspace = Path(__file__).parents[3]
output_directory = workspace / "downloads/maplestory_classic_il2cpp/cipher_arrays"
output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
output_directory.chmod(0o700)
owner_uid = int(os.environ.get("SUDO_UID", os.getuid()))
owner_gid = int(os.environ.get("SUDO_GID", os.getgid()))
os.chown(output_directory, owner_uid, owner_gid)
summaries: list[dict[str, object]] = []

for field_index, (field_name, element_size) in enumerate(fields):
    array_pointer = read_pointer(context_address + (25 + field_index) * 8)
    recorded_length = read_pointer(context_address + (31 + field_index) * 8)
    length, payload = read_managed_array(array_pointer, element_size)
    if length != recorded_length:
        raise gdb.GdbError(
            f"Array length changed during dump: {recorded_length} -> {length}"
        )
    digest = hashlib.sha256(payload).hexdigest()
    preview = payload if len(payload) <= 64 else payload[:64]
    output_path = output_directory / f"{field_name}.bin"
    descriptor = os.open(
        output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
    )
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    os.chown(output_path, owner_uid, owner_gid)
    summaries.append(
        {
            "field": field_name,
            "element_size": element_size,
            "elements": length,
            "bytes": len(payload),
            "sha256": digest,
            "preview": preview.hex(),
            "path": str(output_path),
        }
    )
    gdb.write(
        f"field={field_name} elements={length} bytes={len(payload)} "
        f"sha256={digest} preview={preview.hex()}\n"
    )

summary_path = output_directory / "summary.json"
descriptor = os.open(
    summary_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
)
try:
    os.write(
        descriptor,
        (json.dumps(summaries, indent=2, sort_keys=True) + "\n").encode(),
    )
finally:
    os.close(descriptor)
os.chown(summary_path, owner_uid, owner_gid)
method_summaries = []
for method_index, method_name in enumerate(transform_names):
    method_info = read_pointer(context_address + (40 + method_index) * 8)
    method_pointer = read_pointer(context_address + (42 + method_index) * 8)
    method_summaries.append(
        {
            "name": method_name,
            "method_info": f"0x{method_info:x}",
            "method_pointer": f"0x{method_pointer:x}",
            "rva": f"0x{method_pointer - base:x}",
        }
    )
    gdb.write(
        f"transform={method_name} method_info={method_info:#x} "
        f"method_pointer={method_pointer:#x} rva={method_pointer - base:#x}\n"
    )
method_summary_path = output_directory / "method_addresses.json"
descriptor = os.open(
    method_summary_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
)
try:
    os.write(
        descriptor,
        (json.dumps(method_summaries, indent=2, sort_keys=True) + "\n").encode(),
    )
finally:
    os.close(descriptor)
os.chown(method_summary_path, owner_uid, owner_gid)
inno_method_summaries = []
for method_index, (method_name, argument_count) in enumerate(inno_methods):
    method_info = read_pointer(context_address + (58 + method_index) * 8)
    method_pointer = read_pointer(context_address + (64 + method_index) * 8)
    inno_method_summaries.append(
        {
            "name": method_name,
            "argument_count": argument_count,
            "method_info": f"0x{method_info:x}",
            "method_pointer": f"0x{method_pointer:x}",
            "rva": f"0x{method_pointer - base:x}",
        }
    )
    gdb.write(
        f"inno_transform={method_name} args={argument_count} "
        f"method_info={method_info:#x} method_pointer={method_pointer:#x} "
        f"rva={method_pointer - base:#x}\n"
    )
inno_summary_path = output_directory / "inno_method_addresses.json"
descriptor = os.open(
    inno_summary_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
)
try:
    os.write(
        descriptor,
        (json.dumps(inno_method_summaries, indent=2, sort_keys=True) + "\n").encode(),
    )
finally:
    os.close(descriptor)
os.chown(inno_summary_path, owner_uid, owner_gid)
gdb.write(f"cipher_array_dump_complete summary={summary_path}\n")

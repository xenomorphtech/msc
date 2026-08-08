"""Capture the login controller and world-parser entry without leaving GDB attached.

The ``arm`` action redirects the validated opcode-2 prologue through a small
trampoline in zero-filled executable image padding.  The trampoline saves the
controller pointer, executes the exact displaced prologue, and jumps back, so
the same packet continues through the unmodified handler.  A second transparent
trampoline does the same for the world-record parser and captures its world and
stream arguments.  ``restore`` puts all patched regions back byte-for-byte.
Finally, ``dump`` reports both the controller list and the captured world object
after normal parsing.

Set ``MAPLE_OPCODE2_CAPTURE_ACTION`` to ``arm``, ``status``, ``restore``, or
``dump``.
The on-disk executable is never modified.
"""

from __future__ import annotations

import os
from pathlib import Path
import struct

import gdb


GAME_ASSEMBLY_NAME = "/GameAssembly.dll"
OPCODE2_HANDLER_RVA = 0xC10630
WORLD_PARSER_RVA = 0x12CB2E0
# Zero-filled executable padding at the end of the current build's il2cpp
# section.  The next section begins at RVA 0x52DF000.
HANDLER_TRAMPOLINE_RVA = 0x52DE900
WORLD_TRAMPOLINE_RVA = 0x52DE940
# Last 128 bytes of the current build's zero-filled writable .data section.
CAPTURE_SCRATCH_RVA = 0x6BE5B80
EXPECTED_HANDLER_PREFIX = bytes.fromhex(
    "41 57 41 56 41 54 56 57 55 53 48 81 ec 10 02 00 00 48 89 d7"
)
EXPECTED_WORLD_PREFIX = bytes.fromhex(
    "41 57 41 56 41 55 41 54 56 57 55 53 48 81 ec 48 01 00 00 "
    "48 89 d6 48 89 cf"
)


def game_assembly_base(pid: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        columns = line.split(maxsplit=5)
        if len(columns) < 6 or not columns[5].endswith(GAME_ASSEMBLY_NAME):
            continue
        if int(columns[2], 16) == 0:
            return int(columns[0].split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll image base was not found")


inferior = gdb.selected_inferior()
if inferior.pid <= 0:
    raise gdb.GdbError("No live inferior is attached")


def unsigned(address: int, size: int) -> int:
    return int.from_bytes(inferior.read_memory(address, size), "little")


def managed_string(address: int) -> tuple[int, str]:
    if address == 0:
        return 0, ""
    length = unsigned(address + 0x10, 4)
    if length > 256:
        return length, "<oversized>"
    value = bytes(inferior.read_memory(address + 0x14, length * 2)).decode(
        "utf-16-le", errors="replace"
    )
    return length, value


def c_string(address: int) -> str:
    if address == 0:
        return ""
    raw = bytes(inferior.read_memory(address, 128))
    return raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def object_type(address: int) -> str:
    if address == 0:
        return "<null>"
    klass = unsigned(address, 8)
    name = c_string(unsigned(klass + 0x10, 8))
    namespace = c_string(unsigned(klass + 0x18, 8))
    return f"{namespace}.{name}" if namespace else name


base = game_assembly_base(inferior.pid)
handler = base + OPCODE2_HANDLER_RVA
world_parser = base + WORLD_PARSER_RVA
handler_trampoline = base + HANDLER_TRAMPOLINE_RVA
world_trampoline = base + WORLD_TRAMPOLINE_RVA
scratch = base + CAPTURE_SCRATCH_RVA


def capture_trampoline(
    trampoline: int,
    target: int,
    prefix: bytes,
    first_scratch: int,
    second_scratch: int,
) -> bytes:
    """Store RCX/RDX, run the displaced prologue, then return to the target."""

    stores = (
        b"\x48\x89\x0d"
        + struct.pack("<i", first_scratch - (trampoline + 7))
        + b"\x48\x89\x15"
        + struct.pack("<i", second_scratch - (trampoline + 14))
    )
    patch_length = len(stores) + len(prefix) + 5
    relative_return = (target + len(prefix)) - (trampoline + patch_length)
    return stores + prefix + b"\xe9" + struct.pack("<i", relative_return)


handler_trampoline_patch = capture_trampoline(
    handler_trampoline, handler, EXPECTED_HANDLER_PREFIX, scratch, scratch + 8
)
world_trampoline_patch = capture_trampoline(
    world_trampoline,
    world_parser,
    EXPECTED_WORLD_PREFIX,
    scratch + 16,
    scratch + 24,
)
original_handler_trampoline = bytes(len(handler_trampoline_patch))
original_world_trampoline = bytes(len(world_trampoline_patch))
handler_patch = (
    b"\xe9"
    + struct.pack("<i", handler_trampoline - (handler + 5))
    + b"\x90" * (len(EXPECTED_HANDLER_PREFIX) - 5)
)
world_patch = (
    b"\xe9"
    + struct.pack("<i", world_trampoline - (world_parser + 5))
    + b"\x90" * (len(EXPECTED_WORLD_PREFIX) - 5)
)
action = os.environ.get("MAPLE_OPCODE2_CAPTURE_ACTION", "dump")

if action == "arm":
    actual = bytes(inferior.read_memory(handler, len(EXPECTED_HANDLER_PREFIX)))
    if actual != EXPECTED_HANDLER_PREFIX:
        raise gdb.GdbError(
            "Login opcode-2 prologue mismatch before arm: "
            f"expected={EXPECTED_HANDLER_PREFIX.hex()} actual={actual.hex()}"
        )
    actual = bytes(inferior.read_memory(world_parser, len(EXPECTED_WORLD_PREFIX)))
    if actual != EXPECTED_WORLD_PREFIX:
        raise gdb.GdbError(
            "World parser prologue mismatch before arm: "
            f"expected={EXPECTED_WORLD_PREFIX.hex()} actual={actual.hex()}"
        )
    actual_handler_trampoline = bytes(
        inferior.read_memory(handler_trampoline, len(original_handler_trampoline))
    )
    if actual_handler_trampoline != original_handler_trampoline:
        raise gdb.GdbError(
            "Opcode-2 trampoline padding is not zero-filled: "
            f"actual={actual_handler_trampoline.hex()}"
        )
    actual_world_trampoline = bytes(
        inferior.read_memory(world_trampoline, len(original_world_trampoline))
    )
    if actual_world_trampoline != original_world_trampoline:
        raise gdb.GdbError(
            "World-parser trampoline padding is not zero-filled: "
            f"actual={actual_world_trampoline.hex()}"
        )
    inferior.write_memory(scratch, bytes(32))
    inferior.write_memory(handler_trampoline, handler_trampoline_patch)
    inferior.write_memory(world_trampoline, world_trampoline_patch)
    inferior.write_memory(handler, handler_patch)
    inferior.write_memory(world_parser, world_patch)
    print("opcode2_controller_capture action=arm handler=true parser=true validated=true")
elif action == "restore":
    actual = bytes(inferior.read_memory(handler, len(handler_patch)))
    if actual != handler_patch:
        raise gdb.GdbError(
            "Login opcode-2 capture patch mismatch before restore: "
            f"expected={handler_patch.hex()} actual={actual.hex()}"
        )
    actual = bytes(inferior.read_memory(world_parser, len(world_patch)))
    if actual != world_patch:
        raise gdb.GdbError("World-parser capture patch mismatch before restore")
    actual_handler_trampoline = bytes(
        inferior.read_memory(handler_trampoline, len(handler_trampoline_patch))
    )
    if actual_handler_trampoline != handler_trampoline_patch:
        raise gdb.GdbError("Opcode-2 trampoline mismatch before restore")
    actual_world_trampoline = bytes(
        inferior.read_memory(world_trampoline, len(world_trampoline_patch))
    )
    if actual_world_trampoline != world_trampoline_patch:
        raise gdb.GdbError("World-parser trampoline mismatch before restore")
    inferior.write_memory(handler, EXPECTED_HANDLER_PREFIX)
    inferior.write_memory(world_parser, EXPECTED_WORLD_PREFIX)
    inferior.write_memory(handler_trampoline, original_handler_trampoline)
    inferior.write_memory(world_trampoline, original_world_trampoline)
    controller = unsigned(scratch, 8)
    world = unsigned(scratch + 16, 8)
    print(
        "opcode2_controller_capture "
        f"action=restore captured={controller != 0} "
        f"controller={controller:#x} parser_called={world != 0} validated=true"
    )
elif action == "status":
    actual = bytes(inferior.read_memory(handler, len(handler_patch)))
    if actual != handler_patch:
        raise gdb.GdbError("Login opcode-2 capture patch is not armed")
    actual = bytes(inferior.read_memory(world_parser, len(world_patch)))
    if actual != world_patch:
        raise gdb.GdbError("World-parser capture patch is not armed")
    controller = unsigned(scratch, 8)
    world = unsigned(scratch + 16, 8)
    print(
        "opcode2_controller_capture "
        f"action=status captured={controller != 0} controller={controller:#x} "
        f"parser_called={world != 0}"
    )
elif action == "dump":
    actual = bytes(inferior.read_memory(handler, len(EXPECTED_HANDLER_PREFIX)))
    if actual != EXPECTED_HANDLER_PREFIX:
        raise gdb.GdbError("Login opcode-2 handler was not restored before dump")
    actual = bytes(inferior.read_memory(world_parser, len(EXPECTED_WORLD_PREFIX)))
    if actual != EXPECTED_WORLD_PREFIX:
        raise gdb.GdbError("World parser was not restored before dump")
    controller = unsigned(scratch, 8)
    if controller == 0:
        raise gdb.GdbError("Opcode-2 controller was not captured")
    world = unsigned(scratch + 16, 8)
    world_list = unsigned(controller + 0xC8, 8)
    world_count = unsigned(world_list + 0x18, 4) if world_list else -1
    print(
        "opcode2_controller_capture "
        f"action=dump controller_field_present={world_list != 0} "
        f"controller_field_type={object_type(world_list)!r} "
        f"field_value_at_18={world_count} "
        f"parser_called={world != 0}"
    )
    if world:
        world_name = managed_string(unsigned(world + 0x18, 8))
        channel_list = unsigned(world + 0x38, 8)
        channel_count = unsigned(channel_list + 0x18, 4) if channel_list else -1
        print(
            "opcode2_parser_world_dump "
            f"id={unsigned(world + 0x10, 4)} "
            f"name_length={world_name[0]} name={world_name[1]!r} "
            f"channels={channel_count}"
        )
        if channel_count > 0:
            channel_array = unsigned(channel_list + 0x10, 8)
            channel = unsigned(channel_array + 0x20, 8)
            channel_name = managed_string(unsigned(channel + 0x10, 8))
            print(
                "opcode2_parser_channel_dump "
                f"name_length={channel_name[0]} name={channel_name[1]!r} "
                f"population={unsigned(channel + 0x18, 4)} "
                f"world_id={unsigned(channel + 0x1C, 1)} "
                f"channel_id={unsigned(channel + 0x1D, 1)} "
                f"adult={unsigned(channel + 0x1E, 1)} "
                f"unknown={unsigned(channel + 0x20, 4)}"
            )
    elif world_count > 0:
        world_array = unsigned(world_list + 0x10, 8)
        world = unsigned(world_array + 0x20, 8)
        world_name = managed_string(unsigned(world + 0x18, 8))
        channel_list = unsigned(world + 0x38, 8)
        channel_count = unsigned(channel_list + 0x18, 4) if channel_list else -1
        print(
            "opcode2_world_dump "
            f"id={unsigned(world + 0x10, 4)} "
            f"name_length={world_name[0]} name={world_name[1]!r} "
            f"channels={channel_count}"
        )
        if channel_count > 0:
            channel_array = unsigned(channel_list + 0x10, 8)
            channel = unsigned(channel_array + 0x20, 8)
            channel_name = managed_string(unsigned(channel + 0x10, 8))
            print(
                "opcode2_channel_dump "
                f"name_length={channel_name[0]} name={channel_name[1]!r} "
                f"population={unsigned(channel + 0x18, 4)} "
                f"world_id={unsigned(channel + 0x1C, 1)} "
                f"channel_id={unsigned(channel + 0x1D, 1)}"
            )
else:
    raise gdb.GdbError(
        "MAPLE_OPCODE2_CAPTURE_ACTION must be arm, status, restore, or dump"
    )

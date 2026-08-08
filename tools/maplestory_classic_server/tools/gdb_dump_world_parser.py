"""Dump the parsed login-world object after the opcode-2 parser returns.

This is a short-lived Wine/GDB probe for the current client build.  It does
not modify the executable and prints only structural world/channel fields.
"""

from __future__ import annotations

from pathlib import Path
import struct

import gdb


GAME_ASSEMBLY_NAME = "/GameAssembly.dll"
WORLD_PARSER_RVA = 0x12CB2E0
WORLD_PARSER_RETURN_RVA = 0xC10E3F
OPCODE2_HANDLER_RVA = 0xC10630
OPCODE2_ID_READY_RVA = 0xC10DD5
OPCODE2_SENTINEL_BRANCH_RVA = 0xC10E72


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


base = game_assembly_base(inferior.pid)
world_object = 0
controller = 0
parser_seen = False
opcode2_calls = 0


class ParserReturnBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        world_name_ptr = unsigned(world_object + 0x18, 8)
        event_name_ptr = unsigned(world_object + 0x28, 8)
        channel_list = unsigned(world_object + 0x38, 8)
        balloon_list = unsigned(world_object + 0x48, 8)
        world_name = managed_string(world_name_ptr)
        event_name = managed_string(event_name_ptr)
        channel_count = unsigned(channel_list + 0x18, 4) if channel_list else -1
        balloon_count = unsigned(balloon_list + 0x18, 4) if balloon_list else -1
        print(
            "world_parser_dump "
            f"id={unsigned(world_object + 0x10, 4)} "
            f"name_length={world_name[0]} name={world_name[1]!r} "
            f"flag={unsigned(world_object + 0x20, 1)} "
            f"event_length={event_name[0]} event={event_name[1]!r} "
            f"field30={unsigned(world_object + 0x30, 2)} "
            f"field32={unsigned(world_object + 0x32, 2)} "
            f"channels={channel_count} balloons={balloon_count}"
        )

        if channel_count > 0:
            channel_array = unsigned(channel_list + 0x10, 8)
            channel = unsigned(channel_array + 0x20, 8)
            channel_name = managed_string(unsigned(channel + 0x10, 8))
            print(
                "world_channel_dump "
                f"name_length={channel_name[0]} name={channel_name[1]!r} "
                f"field18={unsigned(channel + 0x18, 4)} "
                f"field1c={unsigned(channel + 0x1C, 1)} "
                f"field1d={unsigned(channel + 0x1D, 1)} "
                f"field1e={unsigned(channel + 0x1E, 1)} "
                f"field20={unsigned(channel + 0x20, 4)}"
            )

        # This breakpoint fires before the handler adds the object to its list.
        controller_list = unsigned(controller + 0xC8, 8)
        controller_count = (
            unsigned(controller_list + 0x18, 4) if controller_list else -1
        )
        print(
            "world_controller_dump "
            f"world_list_present={controller_list != 0} "
            f"worlds_before_add={controller_count}"
        )
        gdb.execute("detach", to_string=True)
        return True


class ParserEntryBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        global world_object, controller, parser_seen
        parser_seen = True
        world_object = int(gdb.parse_and_eval("$rcx"))
        controller = int(gdb.parse_and_eval("$rsi"))
        ParserReturnBreakpoint(
            f"*{base + WORLD_PARSER_RETURN_RVA:#x}",
            temporary=True,
            internal=True,
        )
        self.delete()
        return False


class Opcode2EntryBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        global opcode2_calls, controller
        opcode2_calls += 1
        controller = int(gdb.parse_and_eval("$rcx"))
        world_list = unsigned(controller + 0xC8, 8)
        world_count = unsigned(world_list + 0x18, 4) if world_list else -1
        print(
            "opcode2_handler_dump "
            f"call={opcode2_calls} world_list_present={world_list != 0} "
            f"worlds={world_count}"
        )
        return False


class Opcode2IdBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        raw_id = int(gdb.parse_and_eval("$ebp")) & 0xFFFFFFFF
        signed_id = raw_id if raw_id < 0x80000000 else raw_id - 0x100000000
        print(f"opcode2_id_dump call={opcode2_calls} id={signed_id}")
        return False


class Opcode2SentinelBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        print(
            "opcode2_sentinel_dump "
            f"call={opcode2_calls} parser_seen={parser_seen}"
        )
        if not parser_seen:
            gdb.execute("detach", to_string=True)
            return True
        return False


ParserEntryBreakpoint(
    f"*{base + WORLD_PARSER_RVA:#x}", temporary=True, internal=True
)
Opcode2EntryBreakpoint(f"*{base + OPCODE2_HANDLER_RVA:#x}", internal=True)
Opcode2IdBreakpoint(f"*{base + OPCODE2_ID_READY_RVA:#x}", internal=True)
Opcode2SentinelBreakpoint(f"*{base + OPCODE2_SENTINEL_BRANCH_RVA:#x}", internal=True)
print("world_parser_probe armed=true")
gdb.execute("continue")

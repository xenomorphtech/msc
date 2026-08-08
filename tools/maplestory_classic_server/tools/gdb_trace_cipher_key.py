"""Capture AES-OFB block inputs and the live client round-key schedule."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import time

import gdb


KEY_SETUP_RVA = 0x1CBA280
MAX_KEY_BYTES = 1024
TARGET_CAPTURES = int(os.environ.get("MAPLE_AES_KEY_TRACE_COUNT", "1"))
if TARGET_CAPTURES <= 0:
    raise gdb.GdbError("MAPLE_AES_KEY_TRACE_COUNT must be positive")
inferior = gdb.selected_inferior()
pid = inferior.pid
if pid <= 0:
    raise gdb.GdbError("Attach to Maplestory_Classic.exe before loading this script")


def game_assembly_base() -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if line.rstrip().endswith("/GameAssembly.dll"):
            return int(line.split("-", 1)[0], 16)
    raise gdb.GdbError("GameAssembly.dll is not mapped in the selected process")


def register(name: str) -> int:
    return int(gdb.parse_and_eval(f"${name}"))


def read_pointer(address: int) -> int:
    return struct.unpack("<Q", bytes(inferior.read_memory(address, 8)))[0]


def read_uint32(address: int) -> int:
    return struct.unpack("<I", bytes(inferior.read_memory(address, 4)))[0]


workspace = Path(__file__).parents[3]
output_directory = workspace / "downloads/maplestory_classic_il2cpp/cipher_key_traces"
output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
output_directory.chmod(0o700)
owner_uid = int(os.environ.get("SUDO_UID", os.getuid()))
owner_gid = int(os.environ.get("SUDO_GID", os.getgid()))
os.chown(output_directory, owner_uid, owner_gid)
base = game_assembly_base()
capture_count = 0


class KeySetupBreakpoint(gdb.Breakpoint):
    def stop(self) -> bool:
        global capture_count
        context_pointer = register("rcx")
        array_pointer = register("rdx")
        if not array_pointer:
            raise gdb.GdbError("AES key array pointer is null")
        length = read_pointer(array_pointer + 0x18)
        if length > MAX_KEY_BYTES:
            raise gdb.GdbError(f"Implausible AES key length: {length}")
        key = bytes(inferior.read_memory(array_pointer + 0x20, length))
        rounds = read_uint32(context_pointer + 0x10)
        schedule_pointer = read_pointer(context_pointer + 0x18)
        schedule_length = read_pointer(schedule_pointer + 0x18)
        if schedule_length > 256:
            raise gdb.GdbError(
                f"Implausible AES round-key schedule length: {schedule_length}"
            )
        schedule = bytes(
            inferior.read_memory(schedule_pointer + 0x20, schedule_length * 4)
        )
        prefix = f"{time.time_ns()}_aes_block_{capture_count}_{length}"
        key_path = output_directory / f"{prefix}.bin"
        descriptor = os.open(
            key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        try:
            os.write(descriptor, key)
        finally:
            os.close(descriptor)
        os.chown(key_path, owner_uid, owner_gid)
        metadata = {
            "method_rva": f"0x{KEY_SETUP_RVA:x}",
            "context_pointer": f"0x{context_pointer:x}",
            "array_pointer": f"0x{array_pointer:x}",
            "length": length,
            "block_path": str(key_path),
            "block_hex": key.hex(),
            "block_sha256": hashlib.sha256(key).hexdigest(),
            "rounds": rounds,
            "schedule_pointer": f"0x{schedule_pointer:x}",
            "schedule_length": schedule_length,
            "schedule_hex_little_endian_words": schedule.hex(),
            "schedule_sha256": hashlib.sha256(schedule).hexdigest(),
        }
        metadata_path = output_directory / f"{prefix}.json"
        descriptor = os.open(
            metadata_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        try:
            os.write(
                descriptor,
                (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode(),
            )
        finally:
            os.close(descriptor)
        os.chown(metadata_path, owner_uid, owner_gid)
        gdb.write(
            f"cipher_block_complete length={length} "
            f"block_sha256={metadata['block_sha256']} rounds={rounds} "
            f"schedule_length={schedule_length} block={key.hex()} "
            f"metadata={metadata_path}\n"
        )
        capture_count += 1
        return capture_count >= TARGET_CAPTURES


KeySetupBreakpoint(f"*{base + KEY_SETUP_RVA:#x}", internal=True)
gdb.write(f"cipher_key_breakpoint={base + KEY_SETUP_RVA:#x}\n")
gdb.write(f"cipher_key_target_captures={TARGET_CAPTURES}\n")

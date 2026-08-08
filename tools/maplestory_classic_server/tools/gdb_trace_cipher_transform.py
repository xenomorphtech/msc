"""Capture one live AESCipher Span<byte> input/output pair under Wine GDB.

Load this script after attaching, then continue. It installs breakpoints on the
two resolved public transform methods for the current GameAssembly.dll build.
The first invocation records the mutable span before and after the method and
stops GDB at the return breakpoint so a batch invocation can detach cleanly.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import time

import gdb


TRANSFORMS = {
    "e4147b0bf6aa0519dafd1586e1ff642f720b76696e228fe89d41a46568a7e5e": 0x1CA6BC0,
    "bab383098ecad1bfe745a29f2ff90755e712c9343a5aafdc3bda37cc57b408c": 0x1CA7D50,
}
MAX_SPAN_BYTES = 16 * 1024 * 1024
TARGET_CAPTURES = int(os.environ.get("MAPLE_CIPHER_TRACE_COUNT", "1"))
if TARGET_CAPTURES <= 0:
    raise gdb.GdbError("MAPLE_CIPHER_TRACE_COUNT must be positive")

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


def write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    os.chown(path, owner_uid, owner_gid)


workspace = Path(__file__).parents[3]
output_directory = (
    workspace / "downloads/maplestory_classic_il2cpp/cipher_transform_traces"
)
output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
output_directory.chmod(0o700)
owner_uid = int(os.environ.get("SUDO_UID", os.getuid()))
owner_gid = int(os.environ.get("SUDO_GID", os.getgid()))
os.chown(output_directory, owner_uid, owner_gid)
base = game_assembly_base()
entry_breakpoints: list[gdb.Breakpoint] = []
capture_count = 0


class TransformReturnBreakpoint(gdb.Breakpoint):
    def __init__(
        self,
        return_address: int,
        *,
        label: str,
        data_address: int,
        length: int,
        iv: int,
        before: bytes,
        prefix: str,
    ) -> None:
        super().__init__(f"*{return_address:#x}", temporary=True, internal=True)
        self.label = label
        self.data_address = data_address
        self.length = length
        self.iv = iv
        self.before = before
        self.prefix = prefix

    def stop(self) -> bool:
        global capture_count
        after = bytes(inferior.read_memory(self.data_address, self.length))
        before_path = output_directory / f"{self.prefix}_before.bin"
        after_path = output_directory / f"{self.prefix}_after.bin"
        write_private(before_path, self.before)
        write_private(after_path, after)
        metadata = {
            "method": self.label,
            "iv": self.iv,
            "length": self.length,
            "data_address": f"0x{self.data_address:x}",
            "before_path": str(before_path),
            "before_sha256": hashlib.sha256(self.before).hexdigest(),
            "before_preview": self.before[:64].hex(),
            "after_path": str(after_path),
            "after_sha256": hashlib.sha256(after).hexdigest(),
            "after_preview": after[:64].hex(),
        }
        metadata_path = output_directory / f"{self.prefix}.json"
        write_private(
            metadata_path,
            (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode(),
        )
        gdb.write(
            f"cipher_transform_complete method={self.label} iv={self.iv:#x} "
            f"length={self.length} before_sha256={metadata['before_sha256']} "
            f"after_sha256={metadata['after_sha256']} metadata={metadata_path}\n"
        )
        capture_count += 1
        if capture_count >= TARGET_CAPTURES:
            return True
        for breakpoint in entry_breakpoints:
            breakpoint.enabled = True
        return False


class TransformEntryBreakpoint(gdb.Breakpoint):
    def __init__(self, label: str, address: int) -> None:
        super().__init__(f"*{address:#x}", internal=True)
        self.label = label

    def stop(self) -> bool:
        span_address = int(gdb.parse_and_eval("$rcx"))
        iv = int(gdb.parse_and_eval("$rdx")) & 0xFFFFFFFF
        stack_pointer = int(gdb.parse_and_eval("$rsp"))
        span = bytes(inferior.read_memory(span_address, 16))
        data_address, length = struct.unpack("<QQ", span)
        if not data_address or length > MAX_SPAN_BYTES:
            raise gdb.GdbError(
                f"Invalid Span<byte> at {span_address:#x}: "
                f"data={data_address:#x} length={length} raw={span.hex()}"
            )
        before = bytes(inferior.read_memory(data_address, length))
        return_address = read_pointer(stack_pointer)
        prefix = f"{time.time_ns()}_{self.label[:12]}_{length}_{iv:08x}"
        for breakpoint in entry_breakpoints:
            breakpoint.enabled = False
        TransformReturnBreakpoint(
            return_address,
            label=self.label,
            data_address=data_address,
            length=length,
            iv=iv,
            before=before,
            prefix=prefix,
        )
        gdb.write(
            f"cipher_transform_entry method={self.label} iv={iv:#x} "
            f"length={length} data={data_address:#x} return={return_address:#x}\n"
        )
        return False


for transform_name, transform_rva in TRANSFORMS.items():
    entry_breakpoints.append(
        TransformEntryBreakpoint(transform_name, base + transform_rva)
    )
gdb.write(
    "cipher_transform_breakpoints="
    + ",".join(f"{name}:{base + rva:#x}" for name, rva in TRANSFORMS.items())
    + "\n"
)
gdb.write(f"cipher_transform_target_captures={TARGET_CAPTURES}\n")

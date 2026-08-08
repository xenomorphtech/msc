"""Capture live InnoGuardCipher inputs and outputs from the Wine client.

Load this script in GDB after attaching to Maplestory_Classic.exe, then
continue.  The RVAs are build-specific and come from
``gdb_dump_cipher_arrays.py``.  Captures include managed byte arrays and the
underlying array slice for ``ArraySegment<byte>`` arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import time

import gdb


TRANSFORMS = {
    "d70d4b6ba8c9487cec42040c1cec3752d30ac46bbcbbfe104811906fddab8dd": (
        0x1CC14A0,
        "array_state",
    ),
    "f2debdb3edc18abd85c2764e10c79fcb38ca9d8f046a18880268078cc0b3e2f": (
        0x1CC1FB0,
        "segment",
    ),
    "bb2eec59d69738c374515ec17e2736685e7fd76c76b94b2746ae49efa82334e": (
        0x1CC2440,
        "array_pair",
    ),
    "dde5e40d49d1da8b3f457696e05d9162368a0235a5a078a80d3749ecca4a2e0": (
        0x1CC2BE0,
        "segment",
    ),
    "e31b97b0e2ba27aefee2af23931184781437e72010b78d264c24d595542f8f3": (
        0x1CC3030,
        "array_pair",
    ),
}
MAX_BUFFER_BYTES = 16 * 1024 * 1024
TARGET_CAPTURES = int(os.environ.get("MAPLE_INNO_TRACE_COUNT", "1"))
if TARGET_CAPTURES <= 0:
    raise gdb.GdbError("MAPLE_INNO_TRACE_COUNT must be positive")

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


def signed_int32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    os.chown(path, owner_uid, owner_gid)


@dataclass(frozen=True)
class Buffer:
    role: str
    address: int
    length: int
    before: bytes


def managed_array(array_pointer: int, role: str) -> Buffer:
    if not array_pointer:
        raise ValueError(f"{role} managed-array pointer is null")
    length = read_pointer(array_pointer + 0x18)
    if length > MAX_BUFFER_BYTES:
        raise ValueError(
            f"{role} managed-array length is implausible: {length} "
            f"at {array_pointer:#x}"
        )
    address = array_pointer + 0x20
    return Buffer(
        role=role,
        address=address,
        length=length,
        before=bytes(inferior.read_memory(address, length)),
    )


workspace = Path(__file__).parents[3]
output_directory = (
    workspace / "downloads/maplestory_classic_il2cpp/innoguard_transform_traces"
)
output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
output_directory.chmod(0o700)
owner_uid = int(os.environ.get("SUDO_UID", os.getuid()))
owner_gid = int(os.environ.get("SUDO_GID", os.getgid()))
os.chown(output_directory, owner_uid, owner_gid)
base = game_assembly_base()
capture_count = 0


class TransformReturnBreakpoint(gdb.Breakpoint):
    def __init__(
        self,
        return_address: int,
        *,
        label: str,
        kind: str,
        arguments: dict[str, object],
        buffers: list[Buffer],
        prefix: str,
    ) -> None:
        super().__init__(f"*{return_address:#x}", temporary=True, internal=True)
        self.label = label
        self.kind = kind
        self.arguments = arguments
        self.buffers = buffers
        self.prefix = prefix

    def stop(self) -> bool:
        global capture_count
        buffer_metadata: list[dict[str, object]] = []
        for buffer in self.buffers:
            after = bytes(inferior.read_memory(buffer.address, buffer.length))
            before_path = output_directory / f"{self.prefix}_{buffer.role}_before.bin"
            after_path = output_directory / f"{self.prefix}_{buffer.role}_after.bin"
            write_private(before_path, buffer.before)
            write_private(after_path, after)
            buffer_metadata.append(
                {
                    "role": buffer.role,
                    "address": f"0x{buffer.address:x}",
                    "length": buffer.length,
                    "changed_bytes": sum(
                        left != right for left, right in zip(buffer.before, after)
                    ),
                    "before_path": str(before_path),
                    "before_sha256": hashlib.sha256(buffer.before).hexdigest(),
                    "before_preview": buffer.before[:64].hex(),
                    "after_path": str(after_path),
                    "after_sha256": hashlib.sha256(after).hexdigest(),
                    "after_preview": after[:64].hex(),
                }
            )
        metadata = {
            "method": self.label,
            "kind": self.kind,
            "return_value": register("rax") & 0xFFFFFFFF,
            "arguments": self.arguments,
            "buffers": buffer_metadata,
        }
        metadata_path = output_directory / f"{self.prefix}.json"
        write_private(
            metadata_path,
            (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode(),
        )
        capture_count += 1
        changed = ",".join(
            f"{item['role']}:{item['changed_bytes']}" for item in buffer_metadata
        )
        gdb.write(
            f"innoguard_transform_complete method={self.label} kind={self.kind} "
            f"return={metadata['return_value']:#x} changed={changed} "
            f"metadata={metadata_path}\n"
        )
        return capture_count >= TARGET_CAPTURES


class TransformEntryBreakpoint(gdb.Breakpoint):
    def __init__(self, label: str, address: int, kind: str) -> None:
        super().__init__(f"*{address:#x}", internal=True)
        self.label = label
        self.kind = kind

    def stop(self) -> bool:
        try:
            rcx = register("rcx")
            rdx = register("rdx")
            r8 = register("r8")
            r9 = register("r9")
            return_address = read_pointer(register("rsp"))
            arguments: dict[str, object] = {
                "rcx": f"0x{rcx:x}",
                "rdx": f"0x{rdx:x}",
                "r8": f"0x{r8:x}",
                "r9": f"0x{r9:x}",
            }
            if self.kind == "array_state":
                buffers = [managed_array(rcx, "array")]
                arguments["value"] = signed_int32(rdx)
                iv = 0
            elif self.kind == "array_pair":
                buffers = [
                    managed_array(rcx, "source"),
                    managed_array(rdx, "destination"),
                ]
                arguments["length"] = signed_int32(r8)
                arguments["iv"] = r9 & 0xFFFFFFFF
                iv = r9 & 0xFFFFFFFF
            elif self.kind == "segment":
                segment_raw = bytes(inferior.read_memory(rcx, 16))
                array_pointer, offset, count = struct.unpack("<Qii", segment_raw)
                array_buffer = managed_array(array_pointer, "segment_array")
                if offset < 0 or count < 0 or offset + count > array_buffer.length:
                    raise ValueError(
                        f"invalid ArraySegment at {rcx:#x}: array={array_pointer:#x} "
                        f"offset={offset} count={count} array_length={array_buffer.length}"
                    )
                segment_address = array_buffer.address + offset
                buffers = [
                    array_buffer,
                    Buffer(
                        role="segment",
                        address=segment_address,
                        length=count,
                        before=bytes(inferior.read_memory(segment_address, count)),
                    ),
                ]
                arguments.update(
                    {
                        "array_pointer": f"0x{array_pointer:x}",
                        "offset": offset,
                        "count": count,
                        "length": signed_int32(rdx),
                        "iv": r8 & 0xFFFFFFFF,
                    }
                )
                iv = r8 & 0xFFFFFFFF
            else:
                raise ValueError(f"unsupported transform kind: {self.kind}")
            prefix = f"{time.time_ns()}_{self.label[:12]}_{self.kind}_{iv:08x}"
            TransformReturnBreakpoint(
                return_address,
                label=self.label,
                kind=self.kind,
                arguments=arguments,
                buffers=buffers,
                prefix=prefix,
            )
            gdb.write(
                f"innoguard_transform_entry method={self.label} kind={self.kind} "
                f"return={return_address:#x} arguments={json.dumps(arguments, sort_keys=True)}\n"
            )
        except (gdb.error, OSError, struct.error, ValueError) as error:
            gdb.write(
                f"innoguard_transform_decode_error method={self.label} "
                f"kind={self.kind} error={error}\n"
            )
        return False


for transform_name, (transform_rva, transform_kind) in TRANSFORMS.items():
    TransformEntryBreakpoint(
        transform_name, base + transform_rva, transform_kind
    )
gdb.write(
    "innoguard_transform_breakpoints="
    + ",".join(
        f"{name}:{base + rva:#x}:{kind}"
        for name, (rva, kind) in TRANSFORMS.items()
    )
    + "\n"
)
gdb.write(f"innoguard_transform_target_captures={TARGET_CAPTURES}\n")

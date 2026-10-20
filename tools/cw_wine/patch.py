#!/usr/bin/env python3
"""Apply version-pinned local Wine patches to a separate client executable."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


ORIGINAL_SHA256 = "4384087a6df1991cb59fea6d1ef086dbe746c7a5af0705bfc39769f4cc56e276"
PATCHES = {
    "loopback-login": (
        0x349ABA8, b"44.234.162.36\0", b"127.0.0.1\0\0\0\0\0",
        "Allow loopback in the GameLaunching/IPPORT login-address list.",
    ),
    "early-log-null-guard": (
        0x2CA2050, bytes.fromhex("8b4160c3cccccccccccccccccccccccc"),
        bytes.fromhex("4885c974048b4160c331c0c3cccccccc"),
        "Return zero when startup error logging queries a missing application object.",
    ),
    "local-ngsx-run-failure": (
        0xCF6268, bytes.fromhex("488b442448"), bytes.fromhex("e91e000000"),
        "In the offline client, keep NGSX not-ready on failure and return instead of throwing CSecurityNGSXRunFailed.",
    ),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def rva_to_offset(data, rva):
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_length = struct.unpack_from("<H", data, pe + 20)[0]
    sections = pe + 24 + optional_length
    for i in range(count):
        at = sections + i * 40
        virtual_size, address, raw_size, raw_offset = struct.unpack_from("<4I", data, at + 8)
        if address <= rva < address + min(raw_size, max(virtual_size, raw_size)):
            return raw_offset + rva - address
    raise ValueError(f"RVA {rva:#x} is not file-backed")


def patch(source, selected):
    if digest(source) != ORIGINAL_SHA256:
        raise ValueError("source hash differs from the pinned original MapleStory.exe")
    result = bytearray(source)
    manifest = []
    for name in selected:
        rva, expected, replacement, purpose = PATCHES[name]
        if len(expected) != len(replacement):
            raise ValueError(f"patch {name} changes file length")
        offset = rva_to_offset(source, rva)
        if source[offset:offset + len(expected)] != expected:
            raise ValueError(f"patch {name} has an unexpected original byte sequence")
        result[offset:offset + len(expected)] = replacement
        manifest.append({"name": name, "rva": hex(rva), "file_offset": hex(offset),
                         "original_hex": expected.hex(), "replacement_hex": replacement.hex(),
                         "purpose": purpose})
    return bytes(result), manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="unmodified reference MapleStory.exe")
    parser.add_argument("output", type=Path, help="executable in a separate working client directory")
    parser.add_argument("--guard-early-logging", action="store_true")
    parser.add_argument("--local-ngsx", action="store_true", help="suppress the failed NGSX startup exception for offline Wine")
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("source and output must differ; preserve the reference binary")
    selected = ["loopback-login"]
    if args.guard_early_logging:
        selected.append("early-log-null-guard")
    if args.local_ngsx:
        selected.append("local-ngsx-run-failure")
    source = args.source.read_bytes()
    result, changes = patch(source, selected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result)
    report = {"original_sha256": digest(source), "patched_sha256": digest(result), "patches": changes}
    args.output.with_suffix(".patches.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Offline native MapleStory capture exporter; never opens a game connection."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from Crypto.Cipher import AES


# ZLZ64.dll initializes 32 DWORDs at RVA 0x83030 (initializer 0x3a60).
# Its key expansion (RVA 0x4250; executable equivalent 0xcc1970) reads
# DWORDs at offsets 0,16,...,112, rather than eight consecutive DWORDs.
AES_KEY = bytes.fromhex(
    "0f0000001b000000c500000046000000f3000000be000000ff00000075000000"
)
SHUFFLE = bytes.fromhex(
    "ec3f77a445d071bfb79820fc4be9b3e15c22f70c441b81bd638dd4c3f21019e"
    "0fba16e66eaaed6ce06184eeb7895dbbab6427a2a830b54676de865e72f07f3aa"
    "277b85b026fd8ba9fabea8d7cbcc92daf993602dddd2a29b395f82214c69f831"
    "87ee8ead8c6abcb56b5913f10400f65a3579488f15cd9757123e37ff9d4f51f5"
    "a370bb1475c2b872c0ed7d68c92e0d624617114d6cc47e53c125c79a1c88582c"
    "89dc026440015d38a5e2af55d5ef1a7ca75ba66f869f73e60ade2b994a479cdf"
    "09769e300ee4b294a03b341d280f36e323b403d890c83cfe5e3224501f3a438a"
    "964174ac5233f0d92980b116d3ab91b9847f611ecfc5d1563dcaf405c6e50849"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shuffle_iv(iv: bytes) -> bytes:
    state = bytearray.fromhex("f25350c6")
    for value in iv:
        state[0] = (state[0] + SHUFFLE[state[1]] - value) & 255
        state[1] = (state[1] - (state[2] ^ SHUFFLE[value])) & 255
        state[2] ^= (SHUFFLE[state[3]] + value) & 255
        state[3] = (state[3] - state[0] + SHUFFLE[value]) & 255
        word = int.from_bytes(state, "little")
        state[:] = ((word << 3 | word >> 29) & 0xffffffff).to_bytes(4, "little")
    return bytes(state)


def crypt_aes(data: bytes, iv: bytes) -> bytes:
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    output = bytearray(data)
    offset, size = 0, 0x5b0 if len(data) <= 0xff00 else 0x5ac
    while offset < len(data):
        end = min(offset + size, len(data))
        block = iv * 4
        for pos in range(offset, end, 16):
            block = cipher.encrypt(block)
            for j in range(min(16, end - pos)):
                output[pos + j] ^= block[j]
        offset, size = end, 0x5b4
    return bytes(output)


def decode_structural_fields(plain: bytes, stream: int, direction: str) -> dict | None:
    """Exact observed ASCII envelopes; no old-version field semantics assumed."""
    opcode = int.from_bytes(plain[:2], "little")
    if direction != "server_to_client" or not (
        opcode in [57, 58] or (stream == 61 and opcode in [43, 44])
    ):
        return None
    cursor = 2

    def integer():
        nonlocal cursor
        if cursor + 4 > len(plain):
            raise ValueError("short counted envelope integer")
        value = struct.unpack_from("<i", plain, cursor)[0]
        cursor += 4
        return value

    def text():
        nonlocal cursor
        if cursor + 2 > len(plain):
            raise ValueError("short counted ASCII length")
        length = struct.unpack_from("<H", plain, cursor)[0]
        cursor += 2
        if cursor + length > len(plain):
            raise ValueError("short counted ASCII body")
        value = plain[cursor:cursor + length].decode("ascii")
        cursor += length
        return value

    count = integer()
    if not 0 <= count <= len(plain):
        raise ValueError("invalid counted envelope size")
    entries = []
    for _ in range(count):
        if opcode in [43, 44]:
            entries.append({"path": text()})
        else:
            entries.append({"neutral_i32_values": [integer() for _ in range(3 if opcode == 57 else 2)],
                            "text": [text() for _ in range(1 if opcode == 57 else 2)]})
    if cursor != len(plain):
        raise ValueError("counted envelope has trailing bytes")
    return {"kind": "file_list" if opcode in [43, 44] else "neutral_text_ledger",
            "coverage": "full_structural", "consumed_bytes": cursor,
            "entries": entries}


@dataclass
class Segment:
    number: int
    time_ns: int
    source: str
    destination: str
    seq: int
    payload: bytes


def read_segments(capture: Path) -> dict[int, list[Segment]]:
    fields = ["tcp.stream", "frame.number", "frame.time_epoch", "ip.src",
              "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.seq_raw", "tcp.payload"]
    # stdin also works under Ubuntu's tshark AppArmor profile, which can deny
    # opening captures directly in a home directory.
    command = ["tshark", "-n", "-r", "-", "-Y", "tcp.len > 0 && ip",
               "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        command += ["-e", field]
    with capture.open("rb") as source:
        result = subprocess.run(command, stdin=source, capture_output=True,
                                text=True, check=True)
    streams = defaultdict(list)
    for line in result.stdout.splitlines():
        stream, frame, timestamp, src, sport, dst, dport, seq, payload = line.split("\t")
        streams[int(stream)].append(Segment(
            int(frame), int(Decimal(timestamp) * 1_000_000_000),
            f"{src}:{sport}", f"{dst}:{dport}", int(seq), bytes.fromhex(payload),
        ))
    return dict(streams)


def reassemble(segments: list[Segment]) -> tuple[bytes, list[tuple[int, int, Segment]], dict]:
    """Reject gaps/conflicting retransmissions; retain first-arrival provenance."""
    first_seq = segments[0].seq
    relative = lambda s: (s.seq - first_seq + (1 << 31)) % (1 << 32) - (1 << 31)
    first = min(relative(s) for s in segments)
    last = max(relative(s) + len(s.payload) for s in segments)
    if last - first > 256 * 1024 * 1024:
        raise ValueError("implausible TCP sequence span")
    data, seen = bytearray(last - first), bytearray(last - first)
    spans = []
    overlap = 0
    for segment in sorted(segments, key=lambda s: s.number):
        start = relative(segment) - first
        novel_start = None
        for j, value in enumerate(segment.payload):
            pos = start + j
            if seen[pos]:
                if data[pos] != value:
                    raise ValueError(f"conflicting retransmission in frame {segment.number}")
                overlap += 1
                if novel_start is not None:
                    spans.append((novel_start, pos, segment))
                    novel_start = None
            else:
                data[pos], seen[pos] = value, 1
                if novel_start is None:
                    novel_start = pos
        if novel_start is not None:
            spans.append((novel_start, start + len(segment.payload), segment))
    if 0 in seen:
        raise ValueError(f"TCP gap at reassembled byte {seen.index(0)}")
    return bytes(data), sorted(spans, key=lambda item: item[0]), {
        "tcp_payload_segments": len(segments), "wire_bytes": len(data),
        "identical_overlap_bytes": overlap, "gaps": 0, "conflicting_overlaps": 0,
    }


def parse_greeting(data: bytes) -> dict:
    if len(data) < 18:
        raise ValueError("short greeting")
    length, version = struct.unpack_from("<HH", data)
    if not 0 < version < 1000 or not 16 <= length <= 256 or len(data) < length + 2:
        raise ValueError("not a bounded Maple greeting")
    # Native legacy greeting: u16 version, counted ASCII, IVs, locale.
    count = struct.unpack_from("<H", data, 4)[0]
    style, patch, cursor = "legacy_ascii", None, 6
    if not (0 < count < 32 and cursor + count + 9 <= length + 2
            and all(32 <= v < 127 for v in data[cursor:cursor + count])):
        # Native extended greeting: u16 version, u32 patch, counted ASCII.
        patch, count = struct.unpack_from("<IH", data, 4)
        style, cursor = "extended_ascii", 10
    if not (0 < count < 32 and cursor + count + 9 <= length + 2):
        raise ValueError("bad greeting text width")
    text = data[cursor:cursor + count].decode("ascii")
    if not text.isprintable():
        raise ValueError("bad greeting text")
    cursor += count
    return {"wire_length": length + 2, "version": version, "patch": patch,
            "subversion": text, "style": style,
            "client_iv": data[cursor:cursor + 4],
            "server_iv": data[cursor + 4:cursor + 8], "locale": data[cursor + 8],
            "trailing_hex": data[cursor + 9:length + 2].hex()}


def decrypt_direction(data: bytes, start: int, iv: bytes, mode: str,
                      mask: int, stream: int, direction: str,
                      spans: list[tuple[int, int, Segment]]) -> list[dict]:
    rows, cursor, span_index = [], start, 0
    while cursor < len(data):
        if cursor + 4 > len(data):
            raise ValueError(f"stream {stream} {direction}: partial frame header")
        header = data[cursor:cursor + 4]
        first, second = struct.unpack("<HH", header)
        if first ^ int.from_bytes(iv[2:], "little") != mask:
            raise ValueError(f"stream {stream} {direction}: IV/header mismatch at {cursor}")
        length = first ^ second
        if length >= 0xff00:
            raise ValueError("extended-length framing is not yet supported")
        end = cursor + 4 + length
        if end > len(data):
            raise ValueError(f"stream {stream} {direction}: incomplete payload at {cursor}")
        cipher = data[cursor + 4:end]
        plain = (crypt_aes(cipher, iv) if mode == "aes256_ofb"
                 else bytes((value - iv[0]) & 255 for value in cipher))
        if len(plain) < 2:
            raise ValueError("payload has no complete opcode")
        encoded = (crypt_aes(plain, iv) if mode == "aes256_ofb"
                   else bytes((value + iv[0]) & 255 for value in plain))
        if encoded != cipher:
            raise ValueError("cipher round-trip failed")
        while spans[span_index][1] <= cursor:
            span_index += 1
        covered, index = [], span_index
        while index < len(spans) and spans[index][0] < end:
            covered.append(spans[index][2])
            index += 1
        # Reassembly can complete after the segment containing the last byte.
        complete = max(covered, key=lambda segment: segment.number)
        row = {
            "stream": stream, "direction": direction, "index": len(rows),
            "timestamp_ns": complete.time_ns, "capture_frame": complete.number,
            "capture_frames": sorted({s.number for s in covered}),
            "wire_offset": cursor, "wire_length": length + 4,
            "header_hex": header.hex(), "header_valid": True,
            "cipher": mode, "opcode": int.from_bytes(plain[:2], "little"),
            "length": length, "plaintext_sha256": sha256(plain),
            "plaintext_hex": plain.hex(), "cipher_roundtrip_valid": True,
        }
        decoded_fields = decode_structural_fields(plain, stream, direction)
        if decoded_fields is not None:
            row["decoded_fields"] = decoded_fields
        rows.append(row)
        cursor, iv = end, shuffle_iv(iv)
    return rows


def decode_stream(stream: int, segments: list[Segment]) -> tuple[list[dict], dict]:
    sources = sorted({s.source for s in segments})
    if len(sources) != 2:
        raise ValueError("expected two TCP endpoints")
    assembled = {source: reassemble([s for s in segments if s.source == source])
                 for source in sources}
    greetings = []
    for source, (data, spans, evidence) in assembled.items():
        try:
            greetings.append((source, parse_greeting(data)))
        except (ValueError, UnicodeError, struct.error):
            pass
    if len(greetings) != 1:
        raise ValueError("no unique native Maple greeting")
    server, greeting = greetings[0]
    legacy_profile = (greeting["style"] == "legacy_ascii"
                      and greeting["version"] == 1 and greeting["locale"] == 1
                      and greeting["subversion"] == "0:0" and greeting["wire_length"] == 54)
    extended_profile = (greeting["style"] == "extended_ascii"
                        and greeting["version"] == 1 and greeting["patch"] == 1
                        and greeting["locale"] == 1 and greeting["subversion"] == "0"
                        and greeting["wire_length"] == 21 and greeting["trailing_hex"] == "04")
    if not (legacy_profile or extended_profile):
        raise ValueError("unsupported native greeting/cipher profile")
    client = next(source for source in sources if source != server)
    rows, directions = [], {}
    for direction, source, start, iv, mask in [
        ("client_to_server", client, 0, greeting["client_iv"], 0xdf),
        ("server_to_client", server, greeting["wire_length"], greeting["server_iv"],
         (~greeting["version"]) & 0xffff),
    ]:
        data, spans, evidence = assembled[source]
        # These two modes are directly present in the native client. Port 8541's
        # extended greeting selects additive receive, whereas legacy 8484 uses AES.
        mode = ("add_iv_byte" if direction == "server_to_client"
                and extended_profile else "aes256_ofb")
        decoded = decrypt_direction(data, start, iv, mode, mask, stream, direction, spans)
        rows.extend(decoded)
        counts = Counter((row["opcode"], row["length"]) for row in decoded)
        directions[direction] = {
            **evidence, "cipher": mode, "header_mask": mask,
            "frames": len(decoded), "plaintext_bytes": sum(r["length"] for r in decoded),
            "full_structural_packets": sum("decoded_fields" in r for r in decoded),
            "distinct_opcodes": len({r["opcode"] for r in decoded}),
            "opcode_lengths": [{"opcode": opcode, "length": length, "count": count}
                               for (opcode, length), count in sorted(counts.items())],
        }
    rows.sort(key=lambda row: (row["capture_frame"], row["wire_offset"], row["direction"]))
    safe_greeting = {k: v for k, v in greeting.items() if k not in ["client_iv", "server_iv"]}
    return rows, {"stream": stream, "client": client, "server": server,
                  "greeting": safe_greeting, "directions": directions,
                  "first_payload_timestamp_ns": min(s.time_ns for s in segments),
                  "last_payload_timestamp_ns": max(s.time_ns for s in segments),
                  "all_frame_headers_valid": True, "all_cipher_roundtrips_valid": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--stream", action="append", type=int,
                        help="tshark TCP stream number; default: discover native Maple greetings")
    parser.add_argument("--binary-dir", type=Path,
                        help="record hashes of the reference MapleStory.exe and ZLZ64.dll")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.output.chmod(0o700)
    streams = read_segments(args.capture)
    summaries, errors = [], {}
    capture_hash = sha256(args.capture.read_bytes())
    for stream in args.stream if args.stream else sorted(streams):
        # Inspect only small first server messages during automatic discovery;
        # avoid reassembling unrelated browser/download traffic.
        if not args.stream:
            candidates = []
            for source in {s.source for s in streams[stream]}:
                first = next(s for s in streams[stream] if s.source == source)
                try:
                    parse_greeting(first.payload)
                    candidates.append(source)
                except (ValueError, UnicodeError, struct.error):
                    pass
            if not candidates:
                continue
        try:
            rows, summary = decode_stream(stream, streams[stream])
        except (ValueError, KeyError) as error:
            errors[stream] = str(error)
            continue
        name = args.output / f"stream-{stream}.jsonl"
        with name.open("w") as target:
            for row in rows:
                row["capture_sha256"] = capture_hash
                target.write(json.dumps(row, separators=(",", ":")) + "\n")
        name.chmod(0o600)
        summaries.append(summary)
    result = {"capture": args.capture.name, "capture_sha256": capture_hash,
              "reference_binaries": {}, "streams": summaries,
              "errors": errors, "total_packets": sum(
                  d["frames"] for s in summaries for d in s["directions"].values()),
              "scope": "Complete transport plaintext; packet body semantics and original client opcode mapping are separate."}
    if args.binary_dir:
        result["reference_binaries"] = {name: sha256((args.binary_dir / name).read_bytes())
                                         for name in ["MapleStory.exe", "ZLZ64.dll"]}
    (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"streams": [s["stream"] for s in summaries],
                      "packets": result["total_packets"], "errors": errors}))
    if errors or not summaries:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

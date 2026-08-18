#!/usr/bin/env python3
"""Run or capture-verify the native subtype-1 Unicorn reproducer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gamestate import decode_transcript  # noqa: E402
from maple_server.pcap import load_pcap_tcp_stream  # noqa: E402
from maple_server.protocol import shuffle_iv  # noqa: E402
from maple_server.security_type1 import (  # noqa: E402
    SecurityType1Unicorn,
    build_security_type1_packet,
    security_type1_triggered,
    security_type1_value,
)


DEFAULT_GAME_ASSEMBLY = (
    Path(__file__).parents[3]
    / "downloads/maplestory_classic_wine_prefix/drive_c/Program Files/Gamania"
    / "maplestory_classic/GameAssembly.dll"
)


def parse_iv(text: str) -> bytes:
    compact = text.removeprefix("0x").replace(" ", "")
    try:
        value = bytes.fromhex(compact)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid IV hex: {text}") from error
    if len(value) != 4:
        raise argparse.ArgumentTypeError("IV must contain exactly four bytes")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iv", nargs="*", type=parse_iv, help="four-byte IV hex")
    parser.add_argument(
        "--game-assembly",
        type=Path,
        default=DEFAULT_GAME_ASSEMBLY,
        help="matching Windows GameAssembly.dll",
    )
    parser.add_argument("--pcap", type=Path, help="capture to verify")
    parser.add_argument("--stream", type=int, help="tcp.stream inside --pcap")
    arguments = parser.parse_args()
    if not arguments.iv and arguments.pcap is None:
        parser.error("provide at least one IV or --pcap/--stream")
    if (arguments.pcap is None) != (arguments.stream is None):
        parser.error("--pcap and --stream must be provided together")
    return arguments


def verify_capture(
    emulator: SecurityType1Unicorn, pcap: Path, stream: int
) -> dict[str, object]:
    decoded = decode_transcript(load_pcap_tcp_stream(pcap, stream))
    iv = decoded.handshake.first_iv
    checked = 0
    mismatches: list[dict[str, object]] = []
    client_frames = sorted(
        (frame for frame in decoded.frames if frame.direction == "client_to_server"),
        key=lambda frame: frame.direction_index,
    )
    for frame in client_frames:
        plaintext = frame.plaintext
        if len(plaintext) == 11 and plaintext[:3] == b"\x0d\x00\x01":
            checked += 1
            expected = emulator.packet(iv)
            reference = build_security_type1_packet(iv)
            if (
                plaintext != expected
                or expected != reference
                or not security_type1_triggered(iv)
            ):
                mismatches.append(
                    {
                        "direction_index": frame.direction_index,
                        "iv": iv.hex(),
                        "actual": plaintext.hex(),
                        "native": expected.hex(),
                        "reference": reference.hex(),
                        "triggered": security_type1_triggered(iv),
                    }
                )
        iv = shuffle_iv(iv)
    return {
        "pcap": str(pcap),
        "stream": stream,
        "checked": checked,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }


def main() -> int:
    arguments = parse_args()
    emulator = SecurityType1Unicorn(arguments.game_assembly)
    failed = False
    for iv in arguments.iv:
        native_value = emulator.compute(iv)
        reference_value = security_type1_value(iv)
        packet = emulator.packet(iv)
        result = {
            "iv": iv.hex(),
            "triggered": security_type1_triggered(iv),
            "native_value": f"{native_value:08x}",
            "reference_value": f"{reference_value:08x}",
            "packet": packet.hex(),
            "match": native_value == reference_value,
        }
        failed |= not result["match"]
        print(json.dumps(result, sort_keys=True))
    if arguments.pcap is not None:
        result = verify_capture(emulator, arguments.pcap, arguments.stream)
        failed |= result["mismatch_count"] != 0 or result["checked"] == 0
        print(json.dumps(result, sort_keys=True))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

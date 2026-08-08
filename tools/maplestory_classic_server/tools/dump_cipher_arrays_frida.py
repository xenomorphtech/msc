"""Attach Frida to the Wine client and persist AESCipher static arrays."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import threading

import frida


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="PID of Maplestory_Classic.exe")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("cipher_arrays"),
        help="private directory for raw arrays and summary.json",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser.parse_args()


def write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.output_dir.chmod(0o700)
    source = Path(__file__).with_name("frida_dump_cipher_arrays.js").read_text()
    completed = threading.Event()
    failure: list[str] = []
    summaries: list[dict[str, object]] = []

    session = frida.attach(args.pid)
    script = session.create_script(source)

    def on_message(message: dict[str, object], data: bytes | None) -> None:
        if message.get("type") == "error":
            failure.append(str(message))
            completed.set()
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        message_type = payload.get("type")
        if message_type == "status":
            print(payload.get("message"), flush=True)
        elif message_type == "error":
            failure.append(str(payload.get("message")))
            completed.set()
        elif message_type == "array":
            if data is None:
                failure.append(f"array message had no data: {payload}")
                completed.set()
                return
            field = str(payload["field"])
            path = args.output_dir / f"{field}.bin"
            write_private(path, data)
            summary = {
                **payload,
                "path": str(path),
                "sha256": hashlib.sha256(data).hexdigest(),
                "preview": data[:64].hex(),
            }
            summaries.append(summary)
            print(
                f"field={field} elements={payload['elements']} bytes={len(data)} "
                f"sha256={summary['sha256']} preview={summary['preview']}",
                flush=True,
            )
        elif message_type == "complete":
            completed.set()

    script.on("message", on_message)
    script.load()
    if not completed.wait(args.timeout):
        failure.append(f"timed out after {args.timeout:g} seconds")
    script.unload()
    session.detach()

    if failure:
        raise SystemExit("\n".join(failure))
    summary_path = args.output_dir / "summary.json"
    write_private(
        summary_path,
        (json.dumps(summaries, indent=2, sort_keys=True) + "\n").encode(),
    )
    print(f"cipher_array_dump_complete summary={summary_path}", flush=True)


if __name__ == "__main__":
    main()

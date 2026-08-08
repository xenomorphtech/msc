"""Attach to MapleStory and print the first NGSX result code safely."""

from __future__ import annotations

import argparse
from pathlib import Path
import threading

import frida


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    parser.add_argument("--timeout", type=float, default=35.0)
    args = parser.parse_args()

    completed = threading.Event()
    failures: list[str] = []
    source = Path(__file__).with_name("frida_trace_ngsx_result.js").read_text()
    session = frida.attach(args.pid)
    script = session.create_script(source)

    def on_message(message: dict[str, object], _data: bytes | None) -> None:
        if message.get("type") == "error":
            failures.append(str(message))
            completed.set()
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        if payload.get("type") == "status":
            print(payload.get("message"), flush=True)
        elif payload.get("type") == "error":
            failures.append(str(payload.get("message")))
            completed.set()
        elif payload.get("type") == "result":
            if payload.get("null_result"):
                print("ngsx_result null=true", flush=True)
            else:
                print(
                    f"ngsx_result is_ok={str(payload['is_ok']).lower()} "
                    f"code={payload['code']}",
                    flush=True,
                )
            completed.set()

    script.on("message", on_message)
    script.load()
    if not completed.wait(args.timeout):
        failures.append(f"timed out after {args.timeout:g} seconds")
    script.unload()
    session.detach()
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()

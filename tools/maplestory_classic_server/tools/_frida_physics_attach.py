#!/usr/bin/env python3
"""Attach Frida and publish normalized frame JSON to durable and live sinks."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time


SERVER_ROOT = Path(__file__).resolve().parents[1]
PHYSICS_SOURCE = SERVER_ROOT / "maple_server/physics.py"
PHYSICS_SPEC = importlib.util.spec_from_file_location("_maple_physics", PHYSICS_SOURCE)
if PHYSICS_SPEC is None or PHYSICS_SPEC.loader is None:
    raise RuntimeError(f"cannot load physics normalizer from {PHYSICS_SOURCE}")
PHYSICS_MODULE = importlib.util.module_from_spec(PHYSICS_SPEC)
sys.modules[PHYSICS_SPEC.name] = PHYSICS_MODULE
PHYSICS_SPEC.loader.exec_module(PHYSICS_MODULE)
PhysicsFrameNormalizer = PHYSICS_MODULE.PhysicsFrameNormalizer


OUTPUT_UID = int(os.environ.get("SUDO_UID", os.getuid()))
OUTPUT_GID = int(os.environ.get("SUDO_GID", os.getgid()))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int)
    target.add_argument("--process-name")
    parser.add_argument(
        "--remote",
        help="Frida remote endpoint, e.g. 127.0.0.1:27042 for Windows server in Wine",
    )
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--pipe", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--jsonl", type=Path, required=True)
    parser.add_argument("--latest", type=Path, required=True)
    return parser.parse_args()


def open_pipe(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        os.mkfifo(path, 0o600)
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_NONBLOCK), "w", buffering=1)


def open_jsonl(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(descriptor, 0o600)
    if os.geteuid() == 0:
        os.fchown(descriptor, OUTPUT_UID, OUTPUT_GID)
    return os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)


def write_latest(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(line + "\n")
        os.replace(temporary, path)
        if os.geteuid() == 0:
            os.chown(path, OUTPUT_UID, OUTPUT_GID)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    arguments = parse_args()
    import frida

    if arguments.remote:
        device = frida.get_device_manager().add_remote_device(arguments.remote)
    else:
        device = frida.get_local_device()
    target: int | str = arguments.pid or arguments.process_name
    session = device.attach(target)
    script = session.create_script(arguments.script.read_text(encoding="utf-8"))
    pipe = None
    jsonl = open_jsonl(arguments.jsonl)
    normalizer = PhysicsFrameNormalizer()
    failures: list[str] = []

    def emit(record: dict[str, object]) -> None:
        nonlocal pipe
        record = normalizer.normalize(record)
        line = json.dumps(record, separators=(",", ":"))
        jsonl.write(line + "\n")
        jsonl.flush()
        if record.get("type") == "frame":
            write_latest(arguments.latest, line)
        if pipe is None:
            try:
                pipe = open_pipe(arguments.pipe)
            except OSError:
                return
        try:
            pipe.write(line + "\n")
            pipe.flush()
        except OSError:
            try:
                pipe.close()
            except OSError:
                pass
            pipe = None

    def on_message(message: dict[str, object], _data: bytes | None) -> None:
        if message.get("type") == "error":
            failures.append(str(message.get("description") or message))
            emit({"type": "error", "message": failures[-1]})
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        kind = payload.get("type")
        if kind == "map":
            arguments.map.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.chmod(arguments.map, 0o600)
            if os.geteuid() == 0:
                os.chown(arguments.map, OUTPUT_UID, OUTPUT_GID)
            print(
                f"il2cpp_map classes={len(payload.get('classes') or [])} "
                f"path={arguments.map}",
                flush=True,
            )
        elif kind == "error":
            failures.append(str(payload.get("message")))
            print(f"frida_error {payload.get('message')}", file=sys.stderr, flush=True)
        elif kind == "status":
            print(payload.get("message"), flush=True)
        elif kind == "hooks":
            print(f"hooks {json.dumps(payload.get('hooked'))}", flush=True)
        if kind in {"frame", "map", "hooks", "status", "error"}:
            emit(payload)

    script.on("message", on_message)
    script.load()
    print(
        f"frida_attached target={target} remote={arguments.remote or 'local'} "
        f"pipe={arguments.pipe}",
        flush=True,
    )
    try:
        while True:
            time.sleep(1.0)
            if failures:
                return 1
    except KeyboardInterrupt:
        return 0
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass
        jsonl.close()


if __name__ == "__main__":
    raise SystemExit(main())

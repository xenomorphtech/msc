#!/usr/bin/env python3
"""Observe natural IL2CPP static guards without attaching a debugger.

Each guarded method sets its one-byte metadata-initialization flag on first
entry.  Reading those bytes through /proc provides a low-impact way to confirm
whether the NGS callback, plugin Update loop, and game callback ran.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import time


MARKERS = {
    "plugin_update": 0x6EFE9C6,
    "on_init_callback": 0x6EFE9FA,
    "app_on_init": 0x6BE5EA2,
    "bootstrap_task": 0x6E02D18,
    "bootstrap_awake": 0x6E02D19,
    "bootstrap_af0f6": 0x6E02D1A,
    "bootstrap_load_game_object": 0x6E02D1B,
    "bootstrap_ba2e2": 0x6E02D1C,
    "bootstrap_a6c89": 0x6E02D1D,
    "bootstrap_update": 0x6E02D1E,
    "bootstrap_c4b9f": 0x6E02D1F,
    "bootstrap_d0509": 0x6E02D20,
    "bootstrap_e5e46": 0x6E02D21,
    "bootstrap_ngsx_gate": 0x6E02D22,
    "bootstrap_e8b8b": 0x6E02D23,
    "bootstrap_b36e7": 0x6E02D24,
    "bootstrap_eb444": 0x6E02D25,
    "bootstrap_fd53c": 0x6E02D26,
    "bootstrap_window_proc": 0x6E02D27,
    "bootstrap_a7387": 0x6E02D28,
    "bootstrap_e9865": 0x6E02D29,
    "bootstrap_on_application_quit": 0x6E02D2A,
    "bootstrap_on_application_focus": 0x6E02D2B,
    "bootstrap_ee33a": 0x6E02D2C,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--stop-after-app-callback", action="store_true")
    return parser.parse_args()


def game_assembly_base(pid: int) -> int:
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if line.rstrip().endswith("/GameAssembly.dll"):
            return int(line.split("-", 1)[0], 16)
    raise RuntimeError("GameAssembly.dll is not mapped")


def main() -> int:
    args = parse_args()
    base = game_assembly_base(args.pid)
    deadline = time.monotonic() + args.timeout
    started = time.monotonic()
    previous: dict[str, int] = {}

    try:
        memory = os.open(f"/proc/{args.pid}/mem", os.O_RDONLY)
    except OSError as error:
        raise SystemExit(f"Unable to open process memory: {error}") from error

    try:
        while time.monotonic() < deadline:
            if not Path(f"/proc/{args.pid}").exists():
                print("ngsx_markers process=exited", flush=True)
                return 1
            current = {
                name: os.pread(memory, 1, base + rva)[0]
                for name, rva in MARKERS.items()
            }
            for name, value in current.items():
                if previous.get(name) != value:
                    elapsed_ms = round((time.monotonic() - started) * 1000)
                    print(
                        f"ngsx_marker elapsed_ms={elapsed_ms} name={name} value={value}",
                        flush=True,
                    )
            previous = current
            if args.stop_after_app_callback and current["app_on_init"] != 0:
                print("ngsx_markers app_callback_observed=true", flush=True)
                return 0
            time.sleep(0.05)
    except (FileNotFoundError, ProcessLookupError, IndexError, OSError):
        print("ngsx_markers process=exited", flush=True)
        return 0
    finally:
        os.close(memory)

    print("ngsx_markers timeout=true", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

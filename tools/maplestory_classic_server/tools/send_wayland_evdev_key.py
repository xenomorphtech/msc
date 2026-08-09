#!/usr/bin/env python3
"""Send one physical evdev key through a selected Wayland compositor seat."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile


TOOLS_DIRECTORY = Path(__file__).resolve().parent
SOURCE = TOOLS_DIRECTORY / "wayland_evdev_key.c"
PROTOCOL = (
    TOOLS_DIRECTORY
    / "protocol"
    / "virtual-keyboard-unstable-v1.xml"
)
KEYCODES = {
    "escape": 1,
    "esc": 1,
    "digit1": 2,
    "digit2": 3,
    "digit3": 4,
    "digit4": 5,
    "digit5": 6,
    "digit6": 7,
    "digit7": 8,
    "digit8": 9,
    "digit9": 10,
    "digit0": 11,
    "q": 16,
    "w": 17,
    "e": 18,
    "r": 19,
    "t": 20,
    "y": 21,
    "u": 22,
    "i": 23,
    "o": 24,
    "p": 25,
    "enter": 28,
    "leftctrl": 29,
    "ctrl": 29,
    "a": 30,
    "s": 31,
    "d": 32,
    "f": 33,
    "g": 34,
    "h": 35,
    "j": 36,
    "k": 37,
    "l": 38,
    "leftshift": 42,
    "shift": 42,
    "z": 44,
    "x": 45,
    "c": 46,
    "v": 47,
    "b": 48,
    "n": 49,
    "m": 50,
    "space": 57,
    "f1": 59,
    "f2": 60,
    "f3": 61,
    "f4": 62,
    "f5": 63,
    "f6": 64,
    "f7": 65,
    "f8": 66,
    "f9": 67,
    "f10": 68,
    "f11": 87,
    "f12": 88,
    "up": 103,
    "left": 105,
    "right": 106,
    "down": 108,
    "insert": 110,
    "delete": 111,
}
MAX_EVDEV_KEYCODE = 0x2FF


def resolve_keycode(value: str) -> int:
    normalized = value.lower().removeprefix("key_").replace("_", "")
    if normalized in KEYCODES:
        return KEYCODES[normalized]
    try:
        keycode = int(value, 0)
    except ValueError as error:
        names = ", ".join(sorted(KEYCODES))
        raise argparse.ArgumentTypeError(
            f"unknown key {value!r}; use an evdev number or one of: {names}"
        ) from error
    if not 0 <= keycode <= MAX_EVDEV_KEYCODE:
        raise argparse.ArgumentTypeError(
            f"evdev keycode must be between 0 and {MAX_EVDEV_KEYCODE}"
        )
    return keycode


def cached_helper_path() -> Path:
    digest = hashlib.sha256(SOURCE.read_bytes() + PROTOCOL.read_bytes()).hexdigest()
    return Path(tempfile.gettempdir()) / (
        f"maple-wayland-evdev-key-{os.getuid()}-{digest[:16]}"
    )


def build_helper() -> Path:
    cached = cached_helper_path()
    if cached.is_file() and os.access(cached, os.X_OK):
        return cached

    scanner = shutil.which("wayland-scanner")
    pkg_config = shutil.which("pkg-config")
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if scanner is None or pkg_config is None or shutil.which(compiler[0]) is None:
        raise RuntimeError(
            "building the helper requires wayland-scanner, pkg-config, and a C compiler"
        )
    flags = shlex.split(
        subprocess.check_output(
            [pkg_config, "--cflags", "--libs", "wayland-client", "xkbcommon"],
            text=True,
        )
    )
    with tempfile.TemporaryDirectory(prefix="maple-wayland-evdev-build-") as raw:
        build = Path(raw)
        header = build / "virtual-keyboard-unstable-v1-client-protocol.h"
        protocol_code = build / "virtual-keyboard-unstable-v1-protocol.c"
        binary = build / "wayland-evdev-key"
        subprocess.run(
            [scanner, "client-header", str(PROTOCOL), str(header)], check=True
        )
        subprocess.run(
            [scanner, "private-code", str(PROTOCOL), str(protocol_code)], check=True
        )
        subprocess.run(
            compiler
            + [
                "-std=c17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O2",
                "-I",
                str(build),
                str(SOURCE),
                str(protocol_code),
                "-o",
                str(binary),
            ]
            + flags,
            check=True,
        )
        binary.chmod(0o700)
        os.replace(binary, cached)
    return cached


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "send a physical evdev key directly to a selected wlroots "
            "Wayland seat; this does not use X11 or move the host cursor"
        )
    )
    parser.add_argument("key", type=resolve_keycode)
    parser.add_argument(
        "--hold-ms", type=int, default=100, help="press duration, from 0 to 10000"
    )
    parser.add_argument(
        "--wayland-display",
        default=os.environ.get("WAYLAND_DISPLAY"),
        help="nested compositor socket name, for example wayland-2",
    )
    parser.add_argument(
        "--runtime-directory",
        type=Path,
        default=Path(
            os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
        ),
    )
    arguments = parser.parse_args()
    if not 0 <= arguments.hold_ms <= 10000:
        parser.error("--hold-ms must be between 0 and 10000")
    if not arguments.wayland_display:
        parser.error("set WAYLAND_DISPLAY or pass --wayland-display")
    return arguments


def main() -> None:
    arguments = parse_args()
    environment = os.environ | {
        "XDG_RUNTIME_DIR": str(arguments.runtime_directory),
        "WAYLAND_DISPLAY": arguments.wayland_display,
    }
    try:
        helper = build_helper()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"could not build Wayland key helper: {error}") from error
    result = subprocess.run(
        [str(helper), str(arguments.key), str(arguments.hold_ms)],
        check=False,
        env=environment,
    )
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()

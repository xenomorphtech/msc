#!/usr/bin/env python3
"""Launch MapleStory Classic directly into the local custom-server laboratory.

This path intentionally does not contact Chromium, CDP, NGM, or the Beanfun
website.  It uses the placeholder argument tuple accepted by the client for
local protocol work, so it is not an authenticated production-server launcher.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PREFIX = PROJECT_ROOT / "downloads/maplestory_classic_wine_prefix"
GAME_PROCESS_NAME = "Maplestory_Classic.exe"
GAME_WINDOW_CLASS = "maplestory_classic.exe"
LOCAL_GAME_ARGUMENTS = ("1", "dummy", "1", "1")
DISPLAY_PATTERN = re.compile(r"^:\d+(?:\.\d+)?$")
SWAY_SOCKET_PATTERN = re.compile(r"^sway-ipc\.\d+\.\d+\.sock$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "launch MapleStory directly under Wine for the local custom server; "
            "no browser, CDP, NGM, or website ticket is used"
        )
    )
    parser.add_argument("--network-namespace", default="mapleproxy")
    parser.add_argument("--login-port", type=int, default=12082)
    parser.add_argument("--world-port", type=int, default=12857)
    parser.add_argument(
        "--display",
        help="nested Sway Xwayland display; discovered automatically by default",
    )
    parser.add_argument(
        "--sway-socket",
        type=Path,
        help="nested Sway IPC socket; discovered automatically by default",
    )
    parser.add_argument(
        "--wine-prefix", type=Path, default=DEFAULT_PREFIX
    )
    parser.add_argument(
        "--wine-log", type=Path, default=Path("/tmp/maple-local-game.log")
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="seconds to wait for the window"
    )
    parser.add_argument(
        "--restart",
        action="store_true",
        help="cold-stop this Wine prefix before launching",
    )
    return parser.parse_args()


def command_output(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"command failed ({command[0]}): {detail}")
    return result.stdout


def nested_sway_socket(runtime_directory: Path) -> Path:
    candidates: list[Path] = []
    for socket in sorted(runtime_directory.glob("sway-ipc.*.sock")):
        if not SWAY_SOCKET_PATTERN.match(socket.name):
            continue
        try:
            outputs = json.loads(
                command_output(
                    ["swaymsg", "-s", str(socket), "-t", "get_outputs", "-r"]
                )
            )
        except (json.JSONDecodeError, RuntimeError):
            continue
        if any(
            output.get("active") and str(output.get("name", "")).startswith("X11-")
            for output in outputs
        ):
            candidates.append(socket)
    if len(candidates) != 1:
        raise RuntimeError(
            "could not select one nested Sway socket; pass --sway-socket "
            f"(candidates={len(candidates)})"
        )
    return candidates[0]


def xwayland_displays() -> tuple[str, ...]:
    displays: set[str] = set()
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            arguments = process.joinpath("cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if not arguments or Path(os.fsdecode(arguments[0])).name != "Xwayland":
            continue
        for raw_argument in arguments[1:]:
            argument = os.fsdecode(raw_argument)
            if DISPLAY_PATTERN.match(argument):
                displays.add(argument)
                break
    return tuple(sorted(displays))


def is_wlroots_display(display: str, xauthority: Path) -> bool:
    environment = os.environ | {"DISPLAY": display, "XAUTHORITY": str(xauthority)}
    root = subprocess.run(
        ["xprop", "-root", "_NET_SUPPORTING_WM_CHECK"],
        check=False,
        text=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if root.returncode != 0:
        return False
    match = re.search(r"0x[0-9a-fA-F]+", root.stdout)
    if match is None:
        return False
    window = subprocess.run(
        ["xprop", "-id", match.group(0), "_NET_WM_NAME"],
        check=False,
        text=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return window.returncode == 0 and '"wlroots wm"' in window.stdout


def nested_xwayland_display(xauthority: Path) -> str:
    candidates = tuple(
        display
        for display in xwayland_displays()
        if is_wlroots_display(display, xauthority)
    )
    if len(candidates) != 1:
        raise RuntimeError(
            "could not select one nested Sway Xwayland display; pass --display "
            f"(candidates={len(candidates)})"
        )
    return candidates[0]


def maple_processes() -> set[int]:
    matches: set[int] = set()
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            command = process.joinpath("cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if GAME_PROCESS_NAME.encode() in command:
            matches.add(int(process.name))
    return matches


def ensure_listener(namespace: str, port: int, label: str) -> None:
    if not 1 <= port <= 65535:
        raise RuntimeError("listener port must be between 1 and 65535")
    output = command_output(
        [
            "sudo",
            "-n",
            "ip",
            "netns",
            "exec",
            namespace,
            "ss",
            "-ltnH",
            f"sport = :{port}",
        ]
    )
    if not output.strip():
        raise RuntimeError(
            f"no local {label} listener is active in {namespace} on port {port}"
        )


def ensure_audio_mute_service() -> None:
    service = "maplestory-audio-mute.service"
    active = subprocess.run(
        ["systemctl", "--user", "is-active", "--quiet", service], check=False
    )
    if active.returncode != 0:
        subprocess.run(
            ["systemctl", "--user", "start", service], check=True
        )
    verified = subprocess.run(
        ["systemctl", "--user", "is-active", "--quiet", service], check=False
    )
    if verified.returncode != 0:
        raise RuntimeError("MapleStory audio mute service is not active")


def maple_window_id(
    sway_socket: Path, expected_processes: set[int] | None = None
) -> int | None:
    try:
        tree = json.loads(
            command_output(
                ["swaymsg", "-s", str(sway_socket), "-t", "get_tree", "-r"]
            )
        )
    except (json.JSONDecodeError, RuntimeError):
        return None
    pending = [tree]
    while pending:
        node = pending.pop()
        properties = node.get("window_properties") or {}
        if str(properties.get("class", "")).lower() == GAME_WINDOW_CLASS:
            process_id = node.get("pid")
            if (
                expected_processes is None
                or process_id in expected_processes
            ):
                window_id = node.get("id")
                if isinstance(window_id, int):
                    return window_id
        pending.extend(node.get("nodes") or ())
        pending.extend(node.get("floating_nodes") or ())
    return None


def window_is_ready(
    sway_socket: Path, expected_processes: set[int] | None = None
) -> bool:
    return maple_window_id(sway_socket, expected_processes) is not None


def launch_game(
    *,
    namespace: str,
    username: str,
    uid: int,
    display: str,
    xauthority: Path,
    prefix: Path,
    wine_log: Path,
) -> None:
    executable = (
        prefix / "drive_c/Program Files/Gamania/maplestory_classic/Maplestory_Classic.exe"
    )
    if not executable.is_file():
        raise RuntimeError(f"MapleStory executable does not exist: {executable}")
    wine_log.parent.mkdir(parents=True, exist_ok=True)
    with wine_log.open("ab") as log:
        result = subprocess.run(
            [
                "sudo",
                "-n",
                "ip",
                "netns",
                "exec",
                namespace,
                "sudo",
                "-n",
                "-u",
                username,
                "env",
                f"XDG_RUNTIME_DIR=/run/user/{uid}",
                f"DISPLAY={display}",
                "WAYLAND_DISPLAY=",
                f"XAUTHORITY={xauthority}",
                f"WINEPREFIX={prefix}",
                "WINEDEBUG=-all",
                "setsid",
                "-f",
                "wine",
                str(executable),
                *LOCAL_GAME_ARGUMENTS,
            ],
            check=False,
            cwd=executable.parent,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"Wine launcher exited with status {result.returncode}; see {wine_log}"
        )


def main() -> int:
    arguments = parse_args()
    if arguments.timeout <= 0:
        raise SystemExit("--timeout must be greater than zero")
    username = os.environ.get("SUDO_USER") or getpass.getuser()
    account = pwd.getpwnam(username)
    runtime_directory = Path(f"/run/user/{account.pw_uid}")
    xauthority = Path(account.pw_dir) / ".Xauthority"
    sway_socket = arguments.sway_socket or nested_sway_socket(runtime_directory)
    display = arguments.display or nested_xwayland_display(xauthority)

    ensure_listener(
        arguments.network_namespace, arguments.login_port, "login"
    )
    ensure_listener(
        arguments.network_namespace, arguments.world_port, "world"
    )
    ensure_audio_mute_service()

    existing = maple_processes()
    if existing and not arguments.restart:
        raise RuntimeError(
            "MapleStory is already running; pass --restart for a cold relaunch"
        )
    if arguments.restart:
        environment = os.environ | {"WINEPREFIX": str(arguments.wine_prefix)}
        subprocess.run(["wineserver", "-k"], check=False, env=environment)
        deadline = time.monotonic() + min(arguments.timeout, 10.0)
        while maple_processes() and time.monotonic() < deadline:
            time.sleep(0.05)
        if maple_processes():
            raise RuntimeError("MapleStory did not exit during the cold restart")

    launch_game(
        namespace=arguments.network_namespace,
        username=username,
        uid=account.pw_uid,
        display=display,
        xauthority=xauthority,
        prefix=arguments.wine_prefix.resolve(),
        wine_log=arguments.wine_log,
    )
    deadline = time.monotonic() + arguments.timeout
    while time.monotonic() < deadline:
        processes = maple_processes()
        window_id = (
            maple_window_id(sway_socket, processes) if processes else None
        )
        if window_id is not None:
            subprocess.run(
                [
                    "swaymsg",
                    "-s",
                    str(sway_socket),
                    f"[con_id={window_id}] focus",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(
                json.dumps(
                    {
                        "started": True,
                        "browser_used": False,
                        "display": display,
                        "sway_socket": str(sway_socket),
                        "audio_mute_active": True,
                        "window_ready": True,
                        "window_id": window_id,
                    },
                    sort_keys=True,
                )
            )
            return 0
        time.sleep(0.1)
    raise RuntimeError(f"MapleStory window did not appear within {arguments.timeout:g}s")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"launch failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

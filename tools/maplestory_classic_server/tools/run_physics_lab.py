#!/usr/bin/env python3
"""Run Wine against the local server in persistent visible Weston and hook physics.

The lab owns a loopback-only network namespace, capture-backed login/world
replay, an in-memory NGSX stub, and a Frida hook.  A nested Weston X11-backend
window stays visible on host ``:0`` and intentionally outlives Wine restarts.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import signal
import subprocess
import sys
import time
from typing import IO, Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SERVER_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PREFIX = PROJECT_ROOT / "downloads/maplestory_classic_wine_prefix"
DEFAULT_LOGIN_TRANSCRIPT = (
    PROJECT_ROOT
    / "downloads/maple_protocol_captures/"
    "1786118307321677094_13.115.120.13_10282.jsonl"
)
DEFAULT_PLAINTEXT_JSONL = (
    PROJECT_ROOT
    / "tools/il2cpp_packet_dump/target/private/111.streams-83-92-114.jsonl"
)
DEFAULT_REFERENCE_PCAP = PROJECT_ROOT / "111.pcapng"
DEFAULT_FRIDA = PROJECT_ROOT / ".codex_tmp/frida-venv/bin/python"
DEFAULT_FRIDA_SERVER = PROJECT_ROOT / ".codex_tmp/frida-windows/frida-server.exe"
DEFAULT_WORLD = Path("/home/sdancer/ms4/knowledge/world-v300.json")
GAME_PROCESS_NAME = "Maplestory_Classic.exe"
LOGIN_HOSTNAME = "tw-login.maplestoryclassic.games.gamania.com"
NETWORK_NAMESPACE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
DISPLAY_PATTERN = re.compile(r"^:(\d+)(?:\.\d+)?$")
REDIRECT_COMMENT = "msc-physics-lab-login"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network-namespace", default="maplephysics")
    parser.add_argument("--login-port", type=int, default=12082)
    parser.add_argument("--world-port", type=int, default=12857)
    parser.add_argument("--http-api-port", type=int, default=12858)
    parser.add_argument("--login-destination-port", type=int, default=10282)
    parser.add_argument("--wine-prefix", type=Path, default=DEFAULT_PREFIX)
    parser.add_argument("--login-transcript", type=Path, default=DEFAULT_LOGIN_TRANSCRIPT)
    parser.add_argument("--plaintext-jsonl", type=Path, default=DEFAULT_PLAINTEXT_JSONL)
    parser.add_argument("--reference-pcap", type=Path, default=DEFAULT_REFERENCE_PCAP)
    parser.add_argument("--login-tcp-stream", type=int, default=83)
    parser.add_argument("--world-tcp-stream", type=int, default=114)
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=PROJECT_ROOT / ".codex_tmp/physics-lab",
    )
    parser.add_argument("--pipe", type=Path, default=Path("/tmp/maple-physics.fifo"))
    parser.add_argument(
        "--physics-jsonl", type=Path, default=Path("/tmp/maple-physics.jsonl")
    )
    parser.add_argument(
        "--physics-latest",
        type=Path,
        default=Path("/tmp/maple-physics-latest.json"),
    )
    parser.add_argument(
        "--compositor",
        choices=("weston", "xvfb"),
        default="weston",
        help="persistent host-visible Weston by default; Xvfb is a headless fallback",
    )
    parser.add_argument("--parent-display", default=":0")
    parser.add_argument("--wayland-display", default="maple-physics-weston")
    parser.add_argument("--weston-state", type=Path)
    parser.add_argument("--display")
    parser.add_argument("--screen", default="1360x768x24")
    parser.add_argument("--world-file", type=Path, default=DEFAULT_WORLD)
    parser.add_argument("--map-id", type=int, default=101_000_000)
    parser.add_argument(
        "--agent-model",
        type=Path,
        default=PROJECT_ROOT / ".codex_tmp/physics-lab/rl-model.json",
    )
    parser.add_argument(
        "--agent-status", type=Path, default=Path("/tmp/maple-rl-agent.json")
    )
    parser.add_argument(
        "--launch-ui", action=argparse.BooleanOptionalAction, default=False
    )
    parser.add_argument(
        "--launch-agent", action=argparse.BooleanOptionalAction, default=False
    )
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument(
        "--security-patch",
        type=Path,
        default=Path(__file__).with_name("gdb_patch_ngsx_success.py"),
    )
    parser.add_argument("--hold-open-seconds", type=float, default=7200.0)
    parser.add_argument("--frida-python", type=Path, default=DEFAULT_FRIDA)
    parser.add_argument("--frida-server", type=Path, default=DEFAULT_FRIDA_SERVER)
    parser.add_argument(
        "--frida-transport",
        choices=("windows", "linux"),
        default="windows",
        help="Windows frida-server inside Wine avoids native Linux-agent crashes",
    )
    parser.add_argument("--frida-port", type=int, default=27042)
    parser.add_argument(
        "--hook",
        choices=("none", "frida", "gdb"),
        default="none",
        help=(
            "how to map IL2CPP after launch; default none because Frida "
            "injection and long GDB attaches crash or stall this Wine client"
        ),
    )
    parser.add_argument(
        "--restart-wine",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--attach-only",
        action="store_true",
        help="map and dump an already-running Maplestory_Classic.exe",
    )
    parser.add_argument(
        "--enter-field",
        action="store_true",
        help="best-effort Xvfb clicks through world/channel/character select",
    )
    parser.add_argument(
        "--detach",
        action="store_true",
        help="leave the lab running after the hook is attached",
    )
    return parser.parse_args(argv)


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


def owner_only_log(path: Path) -> IO[bytes]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "ab", buffering=0)


def namespace_listener_active(namespace: str, port: int) -> bool:
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
    return bool(output.strip())


def maple_processes(*, prefix: Path | None = None) -> set[int]:
    matches: set[int] = set()
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            command = process.joinpath("cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if GAME_PROCESS_NAME.encode() not in command:
            continue
        if prefix is not None:
            try:
                environ = process.joinpath("environ").read_bytes()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if f"WINEPREFIX={prefix}".encode() not in environ:
                continue
        matches.add(int(process.name))
    return matches


def allocated_displays() -> set[int]:
    displays: set[int] = set()
    for path in Path("/tmp/.X11-unix").glob("X*"):
        match = re.fullmatch(r"X(\d+)", path.name)
        if match:
            displays.add(int(match.group(1)))
    return displays


def display_is_xvfb(display: str) -> bool:
    number = display[1:].split(".", 1)[0]
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            command = process.joinpath("cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if not command or Path(os.fsdecode(command[0])).name != "Xvfb":
            continue
        if any(os.fsdecode(argument) == display or os.fsdecode(argument) == f":{number}" for argument in command[1:]):
            return True
    return False


def allocate_display(requested: str | None) -> str:
    if requested:
        match = DISPLAY_PATTERN.fullmatch(requested)
        if match is None:
            raise RuntimeError(f"invalid display: {requested}")
        number = int(match.group(1))
        if number in allocated_displays() and not display_is_xvfb(requested):
            raise RuntimeError(f"display {requested} is already in use")
        return f":{number}"
    used = allocated_displays()
    for number in range(10, 200):
        if number not in used:
            return f":{number}"
    raise RuntimeError("no free Xvfb display in :10..:199")


def ensure_network_namespace(
    name: str, *, login_destination_port: int, login_port: int
) -> None:
    if NETWORK_NAMESPACE_PATTERN.fullmatch(name) is None:
        raise RuntimeError(f"unsafe network namespace name: {name!r}")
    namespaces = {
        line.split(maxsplit=1)[0]
        for line in command_output(["sudo", "-n", "ip", "netns", "list"]).splitlines()
        if line.strip()
    }
    if name not in namespaces:
        command_output(["sudo", "-n", "ip", "netns", "add", name])
        hosts_directory = Path("/etc/netns") / name
        command_output(["sudo", "-n", "install", "-d", "-m", "0755", str(hosts_directory)])
        hosts = (
            "127.0.0.1 localhost\n"
            "::1 localhost ip6-localhost ip6-loopback\n"
            f"127.0.0.1 {LOGIN_HOSTNAME}\n"
        )
        installed = subprocess.run(
            ["sudo", "-n", "install", "-m", "0644", "/dev/stdin", str(hosts_directory / "hosts")],
            check=False,
            input=hosts,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode != 0:
            detail = installed.stderr.strip() or installed.stdout.strip()
            raise RuntimeError(f"could not install namespace hosts file: {detail}")
    command_output(["sudo", "-n", "ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"])
    iptables = ["sudo", "-n", "ip", "netns", "exec", name, "iptables", "-t", "nat"]
    rule = [
        "-p",
        "tcp",
        "--dport",
        str(login_destination_port),
        "-m",
        "comment",
        "--comment",
        REDIRECT_COMMENT,
        "-j",
        "REDIRECT",
        "--to-ports",
        str(login_port),
    ]
    for line in command_output([*iptables, "-S", "OUTPUT"]).splitlines():
        tokens = shlex.split(line)
        if "--comment" in tokens and tokens[tokens.index("--comment") + 1] == REDIRECT_COMMENT:
            tokens[0] = "-D"
            command_output([*iptables, *tokens])
    command_output([*iptables, "-I", "OUTPUT", "1", *rule])


def wait_for_listener(namespace: str, port: int, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"listener on port {port} exited with {process.returncode}")
        if namespace_listener_active(namespace, port):
            return
        time.sleep(0.1)
    raise RuntimeError(f"listener on port {port} did not start")


def login_reply_hex(
    plaintext_jsonl: Path, *, tcp_stream: int, world_port: int
) -> dict[int, list[str]]:
    sys.path.insert(0, str(SERVER_ROOT))
    from ipaddress import IPv4Address

    from maple_server.packets import CharacterListEnvelope, WorldHandoff
    from maple_server.plaintext_source import load_plaintext_packets, server_plaintexts

    server = list(
        server_plaintexts(
            load_plaintext_packets(plaintext_jsonl, tcp_stream=tcp_stream)
        )
    )
    account = (1).to_bytes(2, "little") + server[3][2:]
    handoff = WorldHandoff.parse(server[20])
    handoff_bytes = WorldHandoff(
        result=handoff.result,
        address=IPv4Address("127.0.0.1"),
        port=world_port,
        character_id=handoff.character_id,
        trailing=handoff.trailing,
        opcode=handoff.opcode,
    ).to_bytes()
    return {
        6: [server[13].hex()],
        13: [
            "0d0000",
            account.hex(),
            server[5].hex(),
            server[6].hex(),
            server[7].hex(),
            server[8].hex(),
            server[9].hex(),
            server[10].hex(),
        ],
        4: [server[15].hex(), server[16].hex()],
        5: [
            CharacterListEnvelope.parse(server[17]).to_bytes().hex(),
            server[18].hex(),
            server[19].hex(),
        ],
        7: [handoff_bytes.hex()],
    }


def login_replay_command(arguments: argparse.Namespace, username: str, work_dir: Path) -> list[str]:
    replies = login_reply_hex(
        arguments.plaintext_jsonl,
        tcp_stream=arguments.login_tcp_stream,
        world_port=arguments.world_port,
    )
    account_info = pwd.getpwnam(username)
    command = [
        "sudo",
        "-n",
        "ip",
        "netns",
        "exec",
        arguments.network_namespace,
        "sudo",
        "-n",
        "-u",
        username,
        "env",
        f"HOME={account_info.pw_dir}",
        f"PYTHONPATH={SERVER_ROOT}",
        sys.executable,
        "-m",
        "maple_server",
        "replay",
        "--listen-host",
        "0.0.0.0",
        "--listen-port",
        str(arguments.login_port),
        "--no-strict",
        "--transcript",
        str(arguments.login_transcript.resolve()),
        "--transcript-dir",
        str(work_dir / "login"),
        "--server-frame-patch",
        "0=000000010000000000000400740065007300740000000000000000000000000000000000",
        "--server-frame-patch",
        "3=0a00",
        "--drop-server-frame",
        "4",
    ]
    for opcode in (6, 13, 4, 5, 7):
        for payload in replies[opcode]:
            command.extend(["--reply-on-client-opcode", f"{opcode}={payload}"])
        if opcode == 4:
            command.extend(["--client-opcode-reply-delays", "4=0,2.5"])
            command.append("--rewrite-channel-transition-world")
        if opcode == 5:
            command.extend(["--client-opcode-reply-delays", "5=0,0,1.0"])
    command.extend(
        [
            "--validate-login-state",
            "--post-transcript-start-delay-seconds",
            "5",
            "--hold-open-seconds",
            str(arguments.hold_open_seconds),
        ]
    )
    return command


def world_replay_command(
    arguments: argparse.Namespace, username: str, work_dir: Path, world_transcript: Path
) -> list[str]:
    account = pwd.getpwnam(username)
    return [
        "sudo",
        "-n",
        "ip",
        "netns",
        "exec",
        arguments.network_namespace,
        "sudo",
        "-n",
        "-u",
        username,
        "env",
        f"HOME={account.pw_dir}",
        f"PYTHONPATH={SERVER_ROOT}",
        sys.executable,
        "-m",
        "maple_server",
        "replay",
        "--listen-host",
        "0.0.0.0",
        "--listen-port",
        str(arguments.world_port),
        "--http-api-host",
        "127.0.0.1",
        "--http-api-port",
        str(arguments.http_api_port),
        "--no-strict",
        "--transcript",
        str(world_transcript),
        "--transcript-dir",
        str(work_dir / "world"),
        "--keep-world-open",
        "--world-heartbeat-interval-seconds",
        "5",
        "--generate-initial-field-snapshot",
        "--generate-field-npc-spawns",
        "--generate-fixed-server-records",
        "--generate-variable-server-records",
        "--omit-mob-spawns",
        "--timing-scale",
        "1",
        "--hold-open-seconds",
        str(arguments.hold_open_seconds),
    ]


def start_xvfb(display: str, screen: str, log_path: Path) -> subprocess.Popen[bytes]:
    log = owner_only_log(log_path)
    process = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", screen, "-nolisten", "tcp", "-ac"],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    socket_path = Path("/tmp/.X11-unix") / f"X{display[1:].split('.', 1)[0]}"
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Xvfb exited with {process.returncode}")
        if socket_path.exists():
            return process
        time.sleep(0.05)
    raise RuntimeError(f"Xvfb {display} did not create its socket")


def launch_wine(
    *,
    namespace: str,
    username: str,
    uid: int,
    display: str,
    xauthority: Path | None,
    prefix: Path,
    wine_log: Path,
) -> None:
    executable = (
        prefix / "drive_c/Program Files/Gamania/maplestory_classic/Maplestory_Classic.exe"
    )
    if not executable.is_file():
        raise RuntimeError(f"MapleStory executable does not exist: {executable}")
    display_environment = [f"DISPLAY={display}", "WAYLAND_DISPLAY="]
    if xauthority is not None:
        display_environment.append(f"XAUTHORITY={xauthority}")
    with owner_only_log(wine_log) as log:
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
                *display_environment,
                f"WINEPREFIX={prefix}",
                "WINEDEBUG=-all",
                "WINEDLLOVERRIDES=httpapi=n,b",
                "setsid",
                "-f",
                "wine",
                str(executable),
                "1",
                "dummy",
                "1",
                "1",
            ],
            check=False,
            cwd=executable.parent,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    if result.returncode != 0:
        raise RuntimeError(f"Wine launcher exited with status {result.returncode}")


def game_assembly_mappings_ready(mappings: list[str]) -> bool:
    for index, mapping in enumerate(mappings):
        fields = mapping.split()
        if "/GameAssembly.dll" not in mapping or len(fields) < 2:
            continue
        if "x" in fields[1]:
            return True
        if index + 1 >= len(mappings):
            continue
        next_fields = mappings[index + 1].split()
        try:
            mapping_end = int(fields[0].split("-", 1)[1], 16)
            next_start = int(next_fields[0].split("-", 1)[0], 16)
        except (IndexError, ValueError):
            continue
        if mapping_end == next_start and len(next_fields) >= 2 and "x" in next_fields[1]:
            return True
    return False


def game_assembly_ready(pid: int) -> bool:
    try:
        mappings = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return False
    return game_assembly_mappings_ready(mappings)


def dump_physics_map_gdb(pid: int, map_path: Path) -> None:
    map_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "env",
            f"MAPLE_PHYSICS_MAP={map_path}",
            "gdb",
            "-nx",
            "-q",
            "-batch",
            "-ex",
            "set pagination off",
            "-ex",
            "set print thread-events off",
            "-ex",
            "set auto-solib-add off",
            "-ex",
            "set architecture i386:x86-64",
            "-ex",
            "handle SIGSEGV nostop noprint pass",
            "-ex",
            f"source {Path(__file__).with_name('gdb_dump_physics_map.py')}",
            "-ex",
            "detach",
            "-p",
            str(pid),
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    (map_path.parent / "gdb-map.log").write_text(result.stdout)
    if result.returncode != 0 or not map_path.is_file():
        raise RuntimeError(
            "GDB physics map failed; see "
            f"{map_path.parent / 'gdb-map.log'}"
        )


def attach_frida(
    pid: int,
    pipe_path: Path,
    map_path: Path,
    jsonl_path: Path,
    latest_path: Path,
    frida_python: Path,
    network_namespace: str | None = None,
    username: str | None = None,
    remote: str | None = None,
) -> subprocess.Popen[bytes]:
    helper = Path(__file__).with_name("_frida_physics_attach.py")
    attach_started_ns = time.time_ns()
    log = owner_only_log(map_path.parent / "frida.log")
    try:
        helper_arguments = [
            str(frida_python),
            str(helper),
        ]
        if remote is None:
            helper_arguments.extend(["--pid", str(pid)])
            command = ["sudo", "-n", *helper_arguments]
        else:
            if network_namespace is None or username is None:
                raise RuntimeError("remote Frida requires namespace and username")
            helper_arguments.extend(
                ["--process-name", GAME_PROCESS_NAME, "--remote", remote]
            )
            command = [
                "sudo",
                "-n",
                "ip",
                "netns",
                "exec",
                network_namespace,
                "sudo",
                "-n",
                "-u",
                username,
                "env",
                f"HOME={pwd.getpwnam(username).pw_dir}",
                *helper_arguments,
            ]
        process = subprocess.Popen(
            [
                *command,
                "--script",
                str(Path(__file__).with_name("frida_physics_frame.js")),
                "--pipe",
                str(pipe_path),
                "--map",
                str(map_path),
                "--jsonl",
                str(jsonl_path),
                "--latest",
                str(latest_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log.close()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"Frida hook exited with {process.returncode}; see {map_path.parent / 'frida.log'}"
            )
        try:
            if map_path.stat().st_mtime_ns >= attach_started_ns:
                return process
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    stop_process_group(process)
    raise RuntimeError(
        f"Frida did not publish its IL2CPP map; see {map_path.parent / 'frida.log'}"
    )


def start_windows_frida_server(
    *,
    namespace: str,
    username: str,
    uid: int,
    display: str,
    xauthority: Path | None,
    prefix: Path,
    executable: Path,
    port: int,
    log_path: Path,
) -> subprocess.Popen[bytes] | None:
    if namespace_listener_active(namespace, port):
        return None
    if not executable.is_file():
        raise RuntimeError(
            f"Windows Frida server is missing: {executable}; download the matching release"
        )
    environment = [
        f"HOME={pwd.getpwnam(username).pw_dir}",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DISPLAY={display}",
        "WAYLAND_DISPLAY=",
        f"WINEPREFIX={prefix}",
        "WINEDEBUG=-all",
    ]
    if xauthority is not None:
        environment.append(f"XAUTHORITY={xauthority}")
    log = owner_only_log(log_path)
    try:
        process = subprocess.Popen(
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
                *environment,
                "wine",
                str(executable),
                "-l",
                f"127.0.0.1:{port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log.close()
    wait_for_listener(namespace, port, process, 20.0)
    return process


def launch_ui(
    *,
    arguments: argparse.Namespace,
    parent_display: str,
    work_dir: Path,
) -> subprocess.Popen[bytes]:
    manifest = PROJECT_ROOT / "tools/maplestory_gamestate_ui/Cargo.toml"
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(manifest),
        "--",
        "--physics-file",
        str(arguments.physics_latest),
        "--agent-file",
        str(arguments.agent_status),
        "--world-file",
        str(arguments.world_file),
        "--map-id",
        str(arguments.map_id),
    ]
    environment = os.environ | {"DISPLAY": parent_display}
    log = owner_only_log(work_dir / "egui.log")
    try:
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
    finally:
        log.close()


def launch_agent(
    *,
    arguments: argparse.Namespace,
    display: str,
    xauthority: Path | None,
    work_dir: Path,
) -> subprocess.Popen[bytes]:
    command = [
        sys.executable,
        str(Path(__file__).with_name("run_rl_navigation.py")),
        "--telemetry",
        str(arguments.physics_latest),
        "--world",
        str(arguments.world_file),
        "--map-id",
        str(arguments.map_id),
        "--model",
        str(arguments.agent_model),
        "--status",
        str(arguments.agent_status),
        "--display",
        display,
        "--quiet",
    ]
    if xauthority is not None:
        command.extend(["--xauthority", str(xauthority)])
    log = owner_only_log(work_dir / "rl-agent.log")
    try:
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log.close()


def maybe_enter_field(display: str, xauthority: Path | None = None) -> None:
    environment = os.environ | {"DISPLAY": display}
    if xauthority is not None:
        environment["XAUTHORITY"] = str(xauthority)
    # Exact 1360x768 coordinates for world tab, channel 1, and Start in the
    # current classic-login layout hosted by the persistent Weston output.
    clicks = (
        (490, 220, 1, 4.0),
        (590, 448, 2, 8.0),
        (1055, 338, 1, 2.5),
    )
    # GameAssembly is available before the selector finishes its entrance
    # animation on software-rendered Wine. Wait for the actual controls.
    time.sleep(20.0)
    for x, y, repeat, delay in clicks:
        subprocess.run(
            [
                "xdotool",
                "mousemove",
                "--sync",
                str(x),
                str(y),
                "click",
                "--repeat",
                str(repeat),
                "--delay",
                "120",
                "1",
            ],
            check=False,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(delay)
    subprocess.run(
        ["xdotool", "key", "Return"],
        check=False,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def write_world_transcript(arguments: argparse.Namespace, work_dir: Path) -> Path:
    import base64

    sys.path.insert(0, str(SERVER_ROOT))
    from maple_server.plaintext_source import transcript_from_plaintext_jsonl

    decoded = transcript_from_plaintext_jsonl(
        arguments.plaintext_jsonl, tcp_stream=arguments.world_tcp_stream
    )
    destination = work_dir / f"world-stream-{arguments.world_tcp_stream}.jsonl"
    destination.write_text("", encoding="ascii")
    destination.chmod(0o600)
    with destination.open("w", encoding="ascii") as output:
        for event in decoded.events:
            record: dict[str, Any] = {
                "event": event.event,
                "timestamp_ns": event.timestamp_ns,
            }
            if event.direction is not None:
                record["direction"] = event.direction
            if event.data:
                record["data_base64"] = base64.b64encode(event.data).decode("ascii")
            if event.metadata:
                record.update(event.metadata)
            output.write(json.dumps(record, separators=(",", ":")) + "\n")
    return destination


def prepare_pipe(path: Path) -> None:
    if path.exists():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path, 0o600)


def stop_process_group(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def main() -> int:
    arguments = parse_args()
    username = os.environ.get("SUDO_USER") or getpass.getuser()
    account = pwd.getpwnam(username)
    work_dir = arguments.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    owned: list[subprocess.Popen[bytes]] = []
    if arguments.attach_only:
        processes = maple_processes(prefix=arguments.wine_prefix.resolve())
        if len(processes) != 1:
            raise RuntimeError(
                f"attach-only needs exactly one {GAME_PROCESS_NAME} in "
                f"{arguments.wine_prefix}, found {len(processes)}"
            )
        pid = min(processes)
        if arguments.hook == "none":
            arguments.hook = "gdb"
        prepare_pipe(arguments.pipe)
        if arguments.hook == "frida":
            remote = None
            if arguments.frida_transport == "windows":
                if not namespace_listener_active(
                    arguments.network_namespace, arguments.frida_port
                ):
                    raise RuntimeError(
                        "Windows Frida server is not listening; start a full lab launch first"
                    )
                remote = f"127.0.0.1:{arguments.frida_port}"
            attach_frida(
                pid,
                arguments.pipe,
                work_dir / "il2cpp-map.json",
                arguments.physics_jsonl,
                arguments.physics_latest,
                arguments.frida_python,
                network_namespace=arguments.network_namespace,
                username=username,
                remote=remote,
            )
        else:
            dump_physics_map_gdb(pid, work_dir / "il2cpp-map.json")
        print(
            json.dumps(
                {
                    "attached": True,
                    "pid": pid,
                    "hook": arguments.hook,
                    "pipe": str(arguments.pipe),
                    "map": str(work_dir / "il2cpp-map.json"),
                },
                sort_keys=True,
            )
        )
        return 0

    for required in (
        arguments.login_transcript,
        arguments.plaintext_jsonl,
        arguments.wine_prefix,
    ):
        if not Path(required).exists():
            raise RuntimeError(f"required path does not exist: {required}")
    if arguments.hook == "frida" and not arguments.frida_python.is_file():
        raise RuntimeError(f"Frida Python is missing: {arguments.frida_python}")
    if (
        arguments.hook == "frida"
        and arguments.frida_transport == "windows"
        and not arguments.frida_server.is_file()
    ):
        raise RuntimeError(f"Windows Frida server is missing: {arguments.frida_server}")

    ensure_network_namespace(
        arguments.network_namespace,
        login_destination_port=arguments.login_destination_port,
        login_port=arguments.login_port,
    )
    xauthority: Path | None = None
    weston = None
    if arguments.compositor == "weston":
        sys.path.insert(0, str(SERVER_ROOT))
        from maple_server.weston import ensure_session

        state_path = arguments.weston_state or (work_dir / "weston-session.json")
        weston, weston_started = ensure_session(
            state_path=state_path,
            log_path=work_dir / "weston.log",
            runtime_directory=Path(f"/run/user/{account.pw_uid}"),
            parent_display=arguments.parent_display,
            wayland_display=arguments.wayland_display,
            screen=arguments.screen,
        )
        display = weston.xwayland_display
        xauthority = Path(weston.xauthority) if weston.xauthority else None
        if arguments.display is not None and arguments.display != display:
            raise RuntimeError(
                f"persistent Weston selected {display}, not requested {arguments.display}"
            )
        xvfb = None
    else:
        display = allocate_display(arguments.display)
        if display_is_xvfb(display):
            xvfb = None
        else:
            xvfb = start_xvfb(display, arguments.screen, work_dir / "xvfb.log")
            owned.append(xvfb)

    world_transcript = write_world_transcript(arguments, work_dir)
    if namespace_listener_active(arguments.network_namespace, arguments.world_port):
        world = None
    else:
        world_log = owner_only_log(work_dir / "world-server.log")
        world = subprocess.Popen(
            world_replay_command(arguments, username, work_dir, world_transcript),
            stdin=subprocess.DEVNULL,
            stdout=world_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        owned.append(world)
        wait_for_listener(arguments.network_namespace, arguments.world_port, world, 20.0)

    if namespace_listener_active(arguments.network_namespace, arguments.login_port):
        login = None
    else:
        login_log = owner_only_log(work_dir / "login-server.log")
        login = subprocess.Popen(
            login_replay_command(arguments, username, work_dir),
            stdin=subprocess.DEVNULL,
            stdout=login_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        owned.append(login)
        wait_for_listener(arguments.network_namespace, arguments.login_port, login, 20.0)

    prefix = arguments.wine_prefix.resolve()
    if arguments.restart_wine:
        subprocess.run(
            ["env", f"WINEPREFIX={prefix}", "wineserver", "-k"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["env", f"WINEPREFIX={prefix}", "wineserver", "-w"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30.0,
        )
        deadline = time.monotonic() + 8.0
        while maple_processes(prefix=prefix) and time.monotonic() < deadline:
            time.sleep(0.05)
        stale_maple = maple_processes(prefix=prefix)
        if stale_maple:
            raise RuntimeError(
                f"Wine restart left MapleStory processes alive: {sorted(stale_maple)}"
            )
        if arguments.hook == "frida" and arguments.frida_transport == "windows":
            # wineserver can return before its Windows sockets have completely
            # disappeared.  Do not mistake that dying listener for a reusable
            # Frida server and then launch the client without one.
            listener_deadline = time.monotonic() + 8.0
            while (
                namespace_listener_active(
                    arguments.network_namespace, arguments.frida_port
                )
                and time.monotonic() < listener_deadline
            ):
                time.sleep(0.05)

    frida_server_process = None
    if arguments.hook == "frida" and arguments.frida_transport == "windows":
        frida_server_process = start_windows_frida_server(
            namespace=arguments.network_namespace,
            username=username,
            uid=account.pw_uid,
            display=display,
            xauthority=xauthority,
            prefix=prefix,
            executable=arguments.frida_server.resolve(),
            port=arguments.frida_port,
            log_path=work_dir / "frida-server.log",
        )
        if frida_server_process is not None:
            owned.append(frida_server_process)

    patch_log = owner_only_log(work_dir / "ngsx-patch.log")
    security_patch = arguments.security_patch.resolve()
    if not security_patch.is_file():
        raise RuntimeError(f"security patch does not exist: {security_patch}")
    patch = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("patch_new_game_process.py")),
            "--timeout",
            str(arguments.timeout),
            "--patch-script",
            str(security_patch),
        ],
        stdin=subprocess.DEVNULL,
        stdout=patch_log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    owned.append(patch)
    time.sleep(0.2)
    launch_wine(
        namespace=arguments.network_namespace,
        username=username,
        uid=account.pw_uid,
        display=display,
        xauthority=xauthority,
        prefix=prefix,
        wine_log=work_dir / "wine.log",
    )

    deadline = time.monotonic() + arguments.timeout
    pid: int | None = None
    while time.monotonic() < deadline:
        candidates = maple_processes(prefix=prefix)
        if candidates:
            pid = min(candidates)
            if game_assembly_ready(pid):
                break
        time.sleep(0.1)
    if pid is None:
        raise RuntimeError("MapleStory process did not start")

    try:
        patch_status = patch.wait(timeout=arguments.timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("security patch watcher did not finish") from error
    if patch_status != 0:
        raise RuntimeError(
            f"security patch watcher exited with {patch_status}; "
            f"see {work_dir / 'ngsx-patch.log'}"
        )

    if arguments.enter_field:
        maybe_enter_field(display, xauthority)
        time.sleep(5.0)
    hook_process = None
    if arguments.hook != "none":
        prepare_pipe(arguments.pipe)
        if arguments.hook == "frida":
            hook_process = attach_frida(
                pid,
                arguments.pipe,
                work_dir / "il2cpp-map.json",
                arguments.physics_jsonl,
                arguments.physics_latest,
                arguments.frida_python,
                network_namespace=arguments.network_namespace,
                username=username,
                remote=f"127.0.0.1:{arguments.frida_port}"
                if arguments.frida_transport == "windows"
                else None,
            )
            owned.append(hook_process)
        else:
            dump_physics_map_gdb(pid, work_dir / "il2cpp-map.json")
    if arguments.launch_agent:
        if arguments.hook != "frida":
            raise RuntimeError("--launch-agent requires --hook frida")
        agent_process = launch_agent(
            arguments=arguments,
            display=display,
            xauthority=xauthority,
            work_dir=work_dir,
        )
        owned.append(agent_process)
    else:
        agent_process = None
    if arguments.launch_ui:
        ui_process = launch_ui(
            arguments=arguments,
            parent_display=arguments.parent_display,
            work_dir=work_dir,
        )
        owned.append(ui_process)
    else:
        ui_process = None

    print(
        json.dumps(
            {
                "started": True,
                "namespace": arguments.network_namespace,
                "display": display,
                "parent_display": arguments.parent_display
                if arguments.compositor == "weston"
                else None,
                "compositor": arguments.compositor,
                "weston_pid": None if weston is None else weston.pid,
                "weston_started": weston_started
                if arguments.compositor == "weston"
                else False,
                "wayland_display": None
                if weston is None
                else weston.wayland_display,
                "xauthority": None if xauthority is None else str(xauthority),
                "login_port": arguments.login_port,
                "world_port": arguments.world_port,
                "pid": pid,
                "pipe": str(arguments.pipe),
                "physics_jsonl": str(arguments.physics_jsonl),
                "physics_latest": str(arguments.physics_latest),
                "map": str(work_dir / "il2cpp-map.json"),
                "work_dir": str(work_dir),
        "security_stub": security_patch.name,
                "hook": arguments.hook,
                "frida_transport": arguments.frida_transport,
                "frida_server_pid": None
                if frida_server_process is None
                else frida_server_process.pid,
                "world_source": str(world_transcript),
                "egui_pid": None if ui_process is None else ui_process.pid,
                "rl_agent_pid": None
                if agent_process is None
                else agent_process.pid,
                "rl_model": str(arguments.agent_model),
                "rl_status": str(arguments.agent_status),
            },
            sort_keys=True,
        )
    )
    if arguments.detach:
        return 0
    try:
        while True:
            time.sleep(1.0)
            if hook_process is not None and hook_process.poll() is not None:
                raise RuntimeError(f"hook exited with {hook_process.returncode}")
            if not Path(f"/proc/{pid}").exists():
                raise RuntimeError("MapleStory process exited")
    except KeyboardInterrupt:
        return 0
    finally:
        if not arguments.detach:
            for process in reversed(owned):
                stop_process_group(process)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"physics lab failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error

"""Persistent nested Weston session for the Wine movement laboratory.

Weston is deliberately not a child resource of a particular Wine launch.  It
runs with the X11 backend as one visible window on the host display and owns a
long-lived Xwayland display.  Wine may therefore be killed and relaunched
without destroying or replacing the host-visible compositor surface.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
from typing import IO, Mapping


DISPLAY_PATTERN = re.compile(r"^:\d+(?:\.\d+)?$")
SCREEN_PATTERN = re.compile(r"^(\d+)x(\d+)(?:x\d+)?$")
XSERVER_LOG_PATTERN = re.compile(r"xserver listening on display (:\d+(?:\.\d+)?)")


@dataclass(frozen=True)
class WestonSession:
    """Validated coordinates of one persistent Weston/Xwayland process tree."""

    pid: int
    process_start_ticks: int
    xwayland_keeper_pid: int
    xwayland_keeper_start_ticks: int
    parent_display: str
    wayland_display: str
    xwayland_display: str
    xauthority: str
    runtime_directory: str
    width: int
    height: int


def parse_screen(value: str) -> tuple[int, int]:
    match = SCREEN_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid screen geometry: {value!r}")
    width, height = (int(part) for part in match.groups())
    if width < 320 or height < 240:
        raise ValueError("Weston screen must be at least 320x240")
    return width, height


def _process_start_ticks(pid: int) -> int | None:
    try:
        # comm is parenthesized and may contain spaces, so split after its final ')'.
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        return None
    try:
        return int(fields[19])  # proc stat field 22; fields starts at field 3.
    except (IndexError, ValueError):
        return None


def _process_arguments(pid: int) -> tuple[str, ...]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return ()
    return tuple(os.fsdecode(item) for item in raw if item)


def _children(pid: int) -> tuple[int, ...]:
    path = Path(f"/proc/{pid}/task/{pid}/children")
    try:
        return tuple(int(item) for item in path.read_text(encoding="ascii").split())
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        return ()


def _descendants(pid: int) -> tuple[int, ...]:
    found: list[int] = []
    pending = list(_children(pid))
    while pending:
        child = pending.pop()
        found.append(child)
        pending.extend(_children(child))
    return tuple(found)


def _xwayland_details(weston_pid: int) -> tuple[str, str] | None:
    for pid in _descendants(weston_pid):
        arguments = _process_arguments(pid)
        if not arguments or Path(arguments[0]).name != "Xwayland":
            continue
        display = next((item for item in arguments[1:] if DISPLAY_PATTERN.fullmatch(item)), None)
        try:
            auth_index = arguments.index("-auth")
            authority = arguments[auth_index + 1]
        except (ValueError, IndexError):
            authority = ""
        if display is not None:
            return display, authority
    return None


def _xserver_display_from_log(path: Path) -> str | None:
    try:
        contents = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return None
    matches = XSERVER_LOG_PATTERN.findall(contents)
    return matches[-1] if matches else None


def _start_xwayland_keeper(
    display: str, environment: Mapping[str, str]
) -> subprocess.Popen[bytes]:
    """Keep one root-property client connected to Weston's lazy Xwayland."""

    child_environment = dict(environment)
    child_environment.pop("XAUTHORITY", None)
    return subprocess.Popen(
        ["xprop", "-display", display, "-root", "-spy", "_MAPLE_WESTON_KEEPALIVE"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=child_environment,
        start_new_session=True,
    )


def _session_is_live(session: WestonSession) -> bool:
    if _process_start_ticks(session.pid) != session.process_start_ticks:
        return False
    if (
        _process_start_ticks(session.xwayland_keeper_pid)
        != session.xwayland_keeper_start_ticks
    ):
        return False
    arguments = _process_arguments(session.pid)
    if not arguments or Path(arguments[0]).name != "weston":
        return False
    if not any(item == f"--socket={session.wayland_display}" for item in arguments):
        return False
    details = _xwayland_details(session.pid)
    if details != (session.xwayland_display, session.xauthority):
        return False
    runtime_socket = Path(session.runtime_directory) / session.wayland_display
    x_socket = Path("/tmp/.X11-unix") / f"X{session.xwayland_display[1:].split('.', 1)[0]}"
    authority_ok = not session.xauthority or Path(session.xauthority).exists()
    return runtime_socket.exists() and x_socket.exists() and authority_ok


def load_session(path: str | Path) -> WestonSession | None:
    state_path = Path(path)
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
        session = WestonSession(**raw)
    except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return session if _session_is_live(session) else None


def _write_session(path: Path, session: WestonSession) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(asdict(session), output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _owner_only_log(path: Path) -> IO[bytes]:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "ab", buffering=0)


def ensure_session(
    *,
    state_path: str | Path,
    log_path: str | Path,
    runtime_directory: str | Path,
    parent_display: str = ":0",
    wayland_display: str = "maple-physics-weston",
    screen: str = "1360x768x24",
    timeout: float = 12.0,
) -> tuple[WestonSession, bool]:
    """Return a live session, starting a detached Weston only when necessary.

    The boolean is true only when this call started Weston.  The returned
    compositor is intentionally not terminated by the Wine lab.
    """

    if DISPLAY_PATTERN.fullmatch(parent_display) is None:
        raise ValueError(f"invalid parent X11 display: {parent_display!r}")
    if not wayland_display or "/" in wayland_display or "\0" in wayland_display:
        raise ValueError(f"invalid Wayland socket name: {wayland_display!r}")
    width, height = parse_screen(screen)
    state_path = Path(state_path)
    log_path = Path(log_path)
    runtime_directory = Path(runtime_directory)
    runtime_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = state_path.with_suffix(state_path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("a+b") as lock:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        existing = load_session(state_path)
        if existing is not None:
            if existing.parent_display != parent_display:
                raise RuntimeError(
                    f"persistent Weston is on {existing.parent_display}, not {parent_display}"
                )
            return existing, False

        stale_socket = runtime_directory / wayland_display
        if stale_socket.exists():
            stale_socket.unlink()
        environment = os.environ | {
            "DISPLAY": parent_display,
            "XDG_RUNTIME_DIR": str(runtime_directory),
        }
        log = _owner_only_log(log_path)
        try:
            process = subprocess.Popen(
                [
                    "weston",
                    "--backend=x11",
                    "--xwayland",
                    f"--socket={wayland_display}",
                    f"--width={width}",
                    f"--height={height}",
                    "--renderer=pixman",
                    "--idle-time=0",
                    "--no-config",
                ],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=environment,
                start_new_session=True,
            )
        finally:
            log.close()
        deadline = time.monotonic() + timeout
        keeper: subprocess.Popen[bytes] | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"Weston exited with {process.returncode}; see {log_path}"
                )
            details = _xwayland_details(process.pid)
            if details is None:
                if keeper is not None and keeper.poll() is not None:
                    keeper = None
                advertised = _xserver_display_from_log(log_path)
                if advertised is not None and keeper is None:
                    keeper = _start_xwayland_keeper(advertised, environment)
            start_ticks = _process_start_ticks(process.pid)
            keeper_ticks = (
                None if keeper is None else _process_start_ticks(keeper.pid)
            )
            if (
                details is not None
                and start_ticks is not None
                and keeper is not None
                and keeper.poll() is None
                and keeper_ticks is not None
            ):
                display, authority = details
                session = WestonSession(
                    pid=process.pid,
                    process_start_ticks=start_ticks,
                    xwayland_keeper_pid=keeper.pid,
                    xwayland_keeper_start_ticks=keeper_ticks,
                    parent_display=parent_display,
                    wayland_display=wayland_display,
                    xwayland_display=display,
                    xauthority=authority,
                    runtime_directory=str(runtime_directory),
                    width=width,
                    height=height,
                )
                if _session_is_live(session):
                    _write_session(state_path, session)
                    return session, True
            time.sleep(0.05)
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        if keeper is not None:
            try:
                os.killpg(keeper.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        raise RuntimeError(f"Weston did not expose Xwayland; see {log_path}")


def stop_session(path: str | Path, *, timeout: float = 5.0) -> bool:
    session = load_session(path)
    if session is None:
        return False
    try:
        os.killpg(session.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return False
    try:
        os.killpg(session.xwayland_keeper_pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and _process_start_ticks(session.pid) is not None:
        time.sleep(0.05)
    return _process_start_ticks(session.pid) is None

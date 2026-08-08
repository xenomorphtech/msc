#!/usr/bin/env python3
"""Patch the next MapleStory Classic process before managed startup runs.

The watcher is intended to be started before NGM launches the game.  It waits
for a new Wine process whose comm name matches MapleStory Classic, waits only
until GameAssembly.dll is mapped, then uses a short-lived GDB attachment to
apply a validated in-memory patch.  No executable files are modified.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import time


PROCESS_NAME_PREFIX = "maplestory_clas"
DEFAULT_PATCH = Path(__file__).with_name("gdb_patch_ngsx_success.py")


def maple_processes() -> set[int]:
    matches: set[int] = set()
    for status_path in Path("/proc").glob("[0-9]*/comm"):
        try:
            name = status_path.read_text().strip().casefold()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if name.startswith(PROCESS_NAME_PREFIX):
            matches.add(int(status_path.parent.name))
    return matches


def game_assembly_is_ready(pid: int) -> bool:
    try:
        mappings = Path(f"/proc/{pid}/maps").read_text().splitlines()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return False
    # Wine first exposes the PE header mapping while its executable sections
    # are still zero-filled.  Attaching in that interval makes an otherwise
    # successful GDB source command report a misleading prologue mismatch.
    return any(
        "/GameAssembly.dll" in mapping
        and len(fields := mapping.split()) >= 2
        and "x" in fields[1]
        for mapping in mappings
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--patch-script", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--trace-script", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    patch_script = args.patch_script.resolve()
    if not patch_script.is_file():
        raise SystemExit(f"Patch script does not exist: {patch_script}")
    trace_script = args.trace_script.resolve() if args.trace_script else None
    if trace_script is not None and not trace_script.is_file():
        raise SystemExit(f"Trace script does not exist: {trace_script}")

    existing = maple_processes()
    deadline = time.monotonic() + args.timeout
    pid: int | None = None

    while time.monotonic() < deadline:
        candidates = maple_processes() - existing
        if candidates:
            pid = min(candidates)
            break
        time.sleep(0.001)

    if pid is None:
        print("patch_watcher patched=false reason=process_timeout", flush=True)
        return 2

    while time.monotonic() < deadline:
        if game_assembly_is_ready(pid):
            break
        if not Path(f"/proc/{pid}").exists():
            print("patch_watcher patched=false reason=process_exited", flush=True)
            return 3
        time.sleep(0.0005)
    else:
        print("patch_watcher patched=false reason=module_timeout", flush=True)
        return 4

    try:
        os.kill(pid, signal.SIGSTOP)
    except (ProcessLookupError, PermissionError) as error:
        print(f"patch_watcher patched=false reason=stop_failed error={error}", flush=True)
        return 5

    debugger = ["gdb"] if os.geteuid() == 0 else ["sudo", "-n", "gdb"]
    debugger_commands = [
        "-ex",
        "set pagination off",
        "-ex",
        "set print thread-events off",
        "-ex",
        "set auto-solib-add off",
        "-ex",
        f"source {patch_script}",
    ]
    if trace_script is not None:
        debugger_commands.extend(["-ex", f"source {trace_script}", "-ex", "continue"])
    debugger_commands.extend(["-ex", "detach"])
    attach_deadline = min(deadline, time.monotonic() + 2.0)
    transient_attach_failures = 0
    try:
        while True:
            result = subprocess.run(
                [
                    *debugger,
                    "-nx",
                    "-q",
                    "-batch",
                    "-p",
                    str(pid),
                    *debugger_commands,
                ],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if result.returncode == 0:
                break
            transient_attach = (
                "Operation not permitted" in result.stdout
                or "already traced by process" in result.stdout
            )
            if (
                not transient_attach
                or time.monotonic() >= attach_deadline
                or not Path(f"/proc/{pid}").exists()
            ):
                break
            transient_attach_failures += 1
            time.sleep(0.025)
    finally:
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            pass

    source_failed = any(
        marker in result.stdout
        for marker in (
            " mismatch:",
            "Error while executing Python code",
            "Python Exception",
            "Traceback (most recent call last)",
        )
    )
    returncode = result.returncode or (1 if source_failed else 0)
    output = result.stdout.replace(str(pid), "[pid]")
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    print(
        f"patch_watcher patched={'true' if returncode == 0 else 'false'} "
        f"attach_retries={transient_attach_failures}",
        flush=True,
    )
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())

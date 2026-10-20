#!/usr/bin/env python3
"""Expose the dedicated Wine display through a local noVNC viewer."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

STATE = Path(__file__).resolve().parents[2] / "downloads/cw_wine"


def alive(pidfile, marker):
    if not pidfile.exists():
        return False
    process = Path("/proc") / pidfile.read_text().strip() / "cmdline"
    return process.exists() and marker in process.read_bytes()


def start():
    web = Path("/usr/share/novnc")
    if not shutil.which("x11vnc") or not shutil.which("websockify") or not (web / "vnc.html").exists():
        raise RuntimeError("viewer needs x11vnc, novnc and websockify packages")
    if not Path("/tmp/.X11-unix/X97").exists():
        raise RuntimeError("launch the dedicated headless Wine display first")
    (STATE / "logs").mkdir(parents=True, exist_ok=True)
    commands = [("vnc", b"x11vnc", ["x11vnc", "-display", ":97", "-localhost", "-rfbport", "5907", "-shared", "-forever", "-nopw", "-noxdamage", "-quiet"]),
                ("novnc", b"websockify", ["websockify", "--web", str(web), "127.0.0.1:6080", "127.0.0.1:5907"])]
    for name, marker, command in commands:
        pidfile = STATE / (name + ".pid")
        if alive(pidfile, marker):
            continue
        with (STATE / "logs" / (name + ".log")).open("ab") as log:
            process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        pidfile.write_text(str(process.pid) + "\n")
        time.sleep(.2)
        if process.poll() is not None:
            raise RuntimeError(f"{name} exited; see {STATE / 'logs' / (name + '.log')}")
    return "http://127.0.0.1:6080/vnc.html?autoconnect=true&resize=scale"


def stop():
    for name, marker in [("novnc", b"websockify"), ("vnc", b"x11vnc")]:
        pidfile = STATE / (name + ".pid")
        if alive(pidfile, marker):
            subprocess.run(["kill", "-TERM", pidfile.read_text().strip()], check=False)
        pidfile.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()
    if args.stop:
        stop()
    else:
        print(json.dumps({"viewer_url": start()}))

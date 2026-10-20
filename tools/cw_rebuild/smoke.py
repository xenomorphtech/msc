#!/usr/bin/env python3
"""Launch and exercise the current hybrid client in the dedicated Wine display."""
import json
import argparse
import os
import pwd
from pathlib import Path
import re
import subprocess
import sys
import time

from PIL import ImageGrab

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
STATE = REPO / "downloads/cw_wine"


def wait_for(path, text, timeout=150, retry=None):
    end = time.monotonic() + timeout
    next_retry = time.monotonic() + 2
    while time.monotonic() < end:
        if path.exists() and text in path.read_text():
            return
        if retry and time.monotonic() >= next_retry:
            retry()
            next_retry = time.monotonic() + 2
        time.sleep(.25)
    raise RuntimeError(f"timeout waiting for {text}; see {path}")


def x(*args):
    return subprocess.check_output(["xdotool", *map(str, args)], env={**os.environ, "DISPLAY": ":97"}, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--combat", action="store_true", help="also exercise tutorial melee, EXP and respawn")
    args = parser.parse_args()
    executable = REPO / "downloads/cw_graph/validation/client-transport/input.exe"
    subprocess.run(["x86_64-w64-mingw32-gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                    str(HERE / "input.c"), "-o", str(executable), "-luser32"], check=True)
    launch = json.loads(subprocess.check_output([sys.executable, str(HERE.parent / "cw_wine/launch.py"),
                                                "--headless", "--restart", "--rebuilt"], text=True))
    log = Path(launch["server_log"])
    (STATE / "logs/hybrid-latest-launch.json").write_text(json.dumps(launch, indent=2) + "\n")
    wait_for(log, "waiting role=login request_opcode=118")
    def choose_channel():
        x("mousemove", 450, 422); x("click", "--repeat", 2, "--delay", 150, 1)
    wait_for(log, "waiting role=login request_opcode=121", retry=choose_channel)
    def choose_character():
        x("mousemove", 975, 225); x("click", 1)
    wait_for(log, "sandbox_ready role=world", retry=choose_character)
    # Wait for rendering and the spawn movement packet before testing fresh input.
    wait_for(log, "recv role=world opcode=33041")
    window = x("search", "--onlyvisible", "--name", "^MapleStory$").splitlines()[0]
    x("windowfocus", window)
    x("mousemove", 390, 550); x("click", 1)
    def save(name):
        path = STATE / "logs" / ("hybrid-" + name + ".png")
        ImageGrab.grab(xdisplay=":97").save(path)
        return path
    field = save("field")
    def key(keycode, duration):
        command = ["sudo", "-n", "ip", "netns", "exec", "maple-cw-local", "runuser", "-u", pwd.getpwuid(os.getuid()).pw_name,
                   "--", "env", "DISPLAY=:97", "WINEPREFIX=" + str(STATE / "prefix"), "WINEDEBUG=-all",
                   "wine", str(executable), str(keycode), str(duration)]
        subprocess.run(command, check=True, capture_output=True)
    key(0x44, 1200)
    moved = save("moved")
    key(0x20, 120)
    time.sleep(.1)
    jumped = save("jumped")
    time.sleep(.6)
    key(0x41, 1200)
    key(0x49, 80)
    inventory = save("inventory")
    key(0x49, 80)
    # NPC conversation is client-side; quest acceptance is handled by sandbox.py.
    x("mousemove", 280, 541); x("click", "--repeat", 2, "--delay", 150, 1)
    time.sleep(.6)
    npc = save("npc")
    extra_screenshots = []
    if args.combat:
        x("mousemove", 466, 467); x("click", 1)
        time.sleep(.2)
        x("keydown", "d")
        for _ in range(5):
            x("keydown", "space"); time.sleep(.12); x("keyup", "space"); time.sleep(.68)
        x("keyup", "d")
        time.sleep(.7)
        extra_screenshots.append(save("combat-position"))
        for _ in range(6):
            x("keydown", "Control_L"); time.sleep(.12); x("keyup", "Control_L"); time.sleep(.68)
        extra_screenshots.append(save("combat-kill"))
        time.sleep(6.5)
        extra_screenshots.append(save("combat-respawn"))
    wait_for(log, "recv role=world opcode=17373", timeout=20)
    sessions = dict(re.findall(r"connected role=(login|world) session=(\d+)", log.read_text()))
    trace = max(STATE.glob("client/cw-rebuilt-[0-9]*.jsonl"), key=lambda p: p.stat().st_mtime_ns)
    command = [sys.executable, str(HERE / "verify_runtime.py"), "--trace", str(trace),
               "--login", str(STATE / "transcripts" / (sessions["login"] + "-login.jsonl")),
               "--world", str(STATE / "transcripts" / (sessions["world"] + "-world.jsonl"))]
    for path in [field, moved, jumped, inventory, npc, *extra_screenshots]:
        command += ["--screenshot", str(path)]
    if (STATE / "client/cw-leaf-build.json").exists():
        leaf_trace = max(STATE.glob("client/cw-leaf-[0-9]*.jsonl"), key=lambda p: p.stat().st_mtime_ns)
        command += ["--leaf-trace", str(leaf_trace)]
    if args.combat:
        command += ["--combat", "--quest-state", str(STATE / "transcripts/sandbox/character-188753.json")]
    subprocess.run(command, check=True)
    print(json.dumps({"launch": launch, "sessions": sessions, "npc_screenshot": str(npc)}, indent=2))


if __name__ == "__main__":
    main()

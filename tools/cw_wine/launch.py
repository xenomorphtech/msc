#!/usr/bin/env python3
"""Run the patched native client and capture replay in a local-only Wine setup."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

from patch import digest, patch


REPO = Path(__file__).resolve().parents[2]
WORKSPACE = REPO.parent
STATE = REPO / "downloads/cw_wine"
NAMESPACE = "maple-cw-local"
WINE_SERVER = "/usr/lib/x86_64-linux-gnu/wine/wineserver"


def namespace_command(command):
    user = pwd.getpwuid(os.getuid()).pw_name
    return ["sudo", "-n", "ip", "netns", "exec", NAMESPACE,
            "runuser", "-u", user, "--", *command]


def stop():
    if (STATE / "prefix").exists():
        subprocess.run(namespace_command(["env", "WINEPREFIX=" + str(STATE / "prefix"),
                                          WINE_SERVER, "-k"]), check=False)
        subprocess.run(namespace_command(["env", "WINEPREFIX=" + str(STATE / "prefix"),
                                          WINE_SERVER, "-w"]), check=False)
    pidfile = STATE / "server.pid"
    if pidfile.exists():
        pid = int(pidfile.read_text())
        proc = Path(f"/proc/{pid}/cmdline")
        if proc.exists() and b"cw_wine/replay.py" in proc.read_bytes():
            subprocess.run(["sudo", "-n", "kill", "-TERM", "--", f"-{pid}"], check=False)
        pidfile.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restart", action="store_true", help="restart only this dedicated Wine prefix")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--headless", action="store_true", help="use the dedicated Xvfb display :97")
    parser.add_argument("--display", help="X11 display; default: current DISPLAY, or :97")
    parser.add_argument("--debug", default="-all", help="Wine debug channels")
    parser.add_argument("--renderer", choices=["auto", "wined3d", "dxvk"], default="auto")
    parser.add_argument("--speed", type=float, default=1, help="recording playback speed")
    args = parser.parse_args()
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    (STATE / "logs").mkdir(exist_ok=True)
    if args.stop:
        stop()
        return
    if not shutil.which("wine"):
        parser.error("Wine is not installed; see README.md")
    namespaces = subprocess.check_output(["sudo", "-n", "ip", "netns", "list"], text=True)
    if not any(line.split()[0] == NAMESPACE for line in namespaces.splitlines() if line.split()):
        subprocess.run(["sudo", "-n", "ip", "netns", "add", NAMESPACE], check=True)
    subprocess.run(["sudo", "-n", "ip", "-n", NAMESPACE, "link", "set", "lo", "up"], check=True)
    links = json.loads(subprocess.check_output(
        ["sudo", "-n", "ip", "-n", NAMESPACE, "-j", "link", "show"], text=True))
    if any(link["ifname"] != "lo" for link in links):
        parser.error("the dedicated namespace has an external interface; expected loopback only")
    if args.restart:
        stop()
    processes = []
    for entry in Path("/proc").glob("[0-9]*/environ"):
        try:
            if b"WINEPREFIX=" + str(STATE / "prefix").encode() + b"\0" in entry.read_bytes():
                cmd = entry.with_name("comm").read_text().strip()
                if cmd == "MapleStory.exe":
                    processes.append(entry.parent.name)
        except (OSError, PermissionError):
            pass
    if processes:
        parser.error("the local client is already running; use --restart")
    display = args.display or (":97" if args.headless else os.environ.get("DISPLAY", ":97"))
    if display == ":97" and not Path("/tmp/.X11-unix/X97").exists():
        with (STATE / "logs/xvfb.log").open("ab") as log:
            p = subprocess.Popen(["Xvfb", ":97", "-screen", "0", "1366x768x24",
                                  "-nolisten", "tcp", "-ac"], stdout=log, stderr=log,
                                 start_new_session=True)
        (STATE / "xvfb.pid").write_text(str(p.pid) + "\n")
        for _ in range(50):
            if Path("/tmp/.X11-unix/X97").exists():
                break
            time.sleep(.1)
    if not (STATE / "client").exists():
        subprocess.run(["cp", "-a", "--reflink=auto", str(WORKSPACE / "maplestorycw/appdata"),
                        str(STATE / "client")], check=True)
    source = (WORKSPACE / "maplestorycw/appdata/MapleStory.exe").read_bytes()
    modified, changes = patch(source, ["loopback-login", "early-log-null-guard", "local-ngsx-run-failure"])
    (STATE / "client/MapleStory.exe").write_bytes(modified)
    manifest = {"original_sha256": digest(source), "patched_sha256": digest(modified), "patches": changes}
    (STATE / "client/MapleStory.patches.json").write_text(json.dumps(manifest, indent=2) + "\n")
    renderer = args.renderer if args.renderer != "auto" else ("wined3d" if display == ":97" else "dxvk")
    if renderer == "dxvk":
        for name in ["d3d11", "dxgi"]:
            dll = Path(f"/usr/lib/dxvk/wine64/{name}.dll.so")
            if not dll.is_file():
                parser.error("DXVK x64 is absent; install dxvk-wine64 or use --renderer wined3d")
            shutil.copyfile(dll, STATE / f"client/{name}.dll")
    overrides = ("d3d11,dxgi=n;" if renderer == "dxvk" else "d3d11,dxgi=b;") + "mscoree,mshtml="
    env = ["env", "DISPLAY=" + display, "WINEPREFIX=" + str(STATE / "prefix"),
           "WINEARCH=win64", "WINEDLLOVERRIDES=" + overrides, "WINEDEBUG=" + args.debug,
           "DXVK_LOG_PATH=" + str(STATE / "logs")]
    for name in ["XAUTHORITY", "XDG_RUNTIME_DIR"]:
        if name in os.environ:
            env.append(name + "=" + os.environ[name])
    if not (STATE / "prefix/user.reg").exists():
        subprocess.run(namespace_command([*env, "wineboot", "-u"]), check=True)
    subprocess.run(namespace_command([*env, "wine", "reg", "add", "HKCU\\Software\\Wine\\Drivers",
                                      "/v", "Audio", "/d", "", "/f"]), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stamp = time.time_ns()
    server_log = STATE / f"logs/server-{stamp}.log"
    with server_log.open("wb") as log:
        command = [sys.executable, str(Path(__file__).with_name("replay.py")),
                   "--capture-dir", str(REPO / "downloads/cw_decode/export"),
                   "--logs", str(STATE / "transcripts"), "--speed", str(args.speed)]
        server = subprocess.Popen(namespace_command(command), stdout=log, stderr=log,
                                  start_new_session=True)
    (STATE / "server.pid").write_text(str(server.pid) + "\n")
    for _ in range(50):
        if "listening role=world" in server_log.read_text():
            break
        if server.poll() is not None:
            raise RuntimeError(server_log.read_text())
        time.sleep(.1)
    client_log = STATE / f"logs/client-{stamp}.log"
    # Explorer's shell launch can change the working directory. Keep native
    # resource/DLL lookup rooted at the working client for virtual desktops.
    (STATE / "client/run-local.cmd").write_text(
        '@echo off\r\ncd /d "%~dp0"\r\nMapleStory.exe GameLaunching 127.0.0.1 8484\r\n')
    with client_log.open("wb") as log:
        if display != ":97":
            batch = "Z:" + str(STATE / "client/run-local.cmd").replace("/", "\\")
            command = [*env, "wine", "explorer", "/desktop=MapleCW,1366x768", "cmd", "/c", batch]
        else:
            command = [*env, "wine", str(STATE / "client/MapleStory.exe"),
                       "GameLaunching", "127.0.0.1", "8484"]
        client = subprocess.Popen(namespace_command(command), cwd=STATE / "client",
                                  stdout=log, stderr=log, start_new_session=True)
    (STATE / "launch.pid").write_text(str(client.pid) + "\n")
    print(json.dumps({"display": display, "renderer": renderer, "namespace": NAMESPACE,
                      "client_pid": client.pid, "server_pid": server.pid,
                      "client_log": str(client_log), "server_log": str(server_log)}))


if __name__ == "__main__":
    main()

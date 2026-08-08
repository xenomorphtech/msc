# Running the client

## Installed paths

```text
WINEPREFIX=/home/sdancer/ms/downloads/maplestory_classic_wine_prefix
EXE=/home/sdancer/ms/downloads/maplestory_classic_wine_prefix/drive_c/Program Files/Gamania/maplestory_classic/Maplestory_Classic.exe
NGM=/home/sdancer/ms/downloads/maplestory_classic_wine_prefix/drive_c/ProgramData/Nexon/NGM/NGM64.exe
```

The client runs under Wine. Wine may log .NET/Mono warnings, but those warnings
were not the cause of the final in-client policy dialog. The prefix also
contains the installed NGM helper and Wine Mono.

## Contained desktop

The host uses XMonad. A nested Sway compositor keeps Chromium and the game in
one host window instead of spilling across host workspaces and monitors. Its
configuration is:

```text
/home/sdancer/ms/.codex_tmp/maple_sway.conf
```

A suitable nested launch pattern from the host X session is:

```sh
XDG_RUNTIME_DIR=/run/user/1000 \
WLR_BACKENDS=x11 \
WLR_X11_OUTPUTS=1 \
sway -c /home/sdancer/ms/.codex_tmp/maple_sway.conf
```

The known working instance used Wayland socket `wayland-2` and Xwayland display
`:1`. Those numbers are allocated dynamically and must be rediscovered after a
restart. Useful checks are:

```sh
find /run/user/1000 -maxdepth 1 -type s -name 'wayland-*' -print
ps -ef | rg 'Xwayland.*:[0-9]+'
```

The Sway rules float the MapleStory window at 1360x762 and keep Chromium and
the game on workspace 1.

## Direct client launch for local-server testing

Use the repository launcher for custom-server work. It does not contact the
browser, CDP, NGM, or the Beanfun website:

```sh
cd /home/sdancer/ms
python tools/maplestory_classic_server/tools/launch_local_game.py --restart
```

The launcher discovers the active nested Sway socket and its wlroots Xwayland
display, verifies that login port `12082` and world port `12857` are listening
inside `mapleproxy`, starts/verifies `maplestory-audio-mute.service`,
cold-restarts only this Wine prefix when `--restart` is requested, and focuses
the new window through Sway.
It uses the four local placeholder arguments and never reads or prints an
authenticated launch ticket. Run without `--restart` to make an existing game
process a hard error instead of stopping it.

The equivalent manual command is:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  XDG_RUNTIME_DIR=/run/user/1000 \
  DISPLAY=:1 \
  WAYLAND_DISPLAY= \
  WINEPREFIX=/home/sdancer/ms/downloads/maplestory_classic_wine_prefix \
  WINEDEBUG=-all \
  setsid -f wine \
  '/home/sdancer/ms/downloads/maplestory_classic_wine_prefix/drive_c/Program Files/Gamania/maplestory_classic/Maplestory_Classic.exe' \
  1 dummy 1 1
```

This uses X11 through the nested Sway instance's Xwayland server. Change
`DISPLAY=:1` if the new Xwayland display differs. Prefer the launcher so these
runtime endpoints and the audio invariant are checked automatically.

The client also rendered through Wine's native Wayland driver inside Sway:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  XDG_RUNTIME_DIR=/run/user/1000 \
  WAYLAND_DISPLAY=wayland-2 \
  DISPLAY= \
  WINEPREFIX=/home/sdancer/ms/downloads/maplestory_classic_wine_prefix \
  WINEDEBUG=-all \
  setsid -f wine \
  '/home/sdancer/ms/downloads/maplestory_classic_wine_prefix/drive_c/Program Files/Gamania/maplestory_classic/Maplestory_Classic.exe' \
  1 dummy 1 1
```

Use Xwayland by default because that was the selected setup. The placeholder
arguments are sufficient for local custom-server iterations, but they are not
a substitute for an official authenticated launch ticket. The browser/CDP
procedure below is retained only for official-server capture work.

## Official authenticated NGM launch

For an official session:

1. Run Chromium inside the same `mapleproxy` namespace and nested Sway desktop.
2. Use the persistent profile `/tmp/maple-proxied-login` and remote debugging
   port `9229`, and pass `--disable-quic`. The transparent relay handles TCP;
   QUIC otherwise bypasses it over UDP and can expose the host region.
3. Log in manually and reach/click **Launch Software** on the MapleStory site.
4. Run the helper below while the authenticated tab and CDP endpoint remain
   open:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  XDG_RUNTIME_DIR=/run/user/1000 \
  DISPLAY=:1 \
  MAPLE_TARGET_DISPLAY=:1 \
  node /home/sdancer/ms/.codex_tmp/maple_launch_ngm_from_cdp.mjs
```

The helper reads `NgmLayerHelper.argument` from the authenticated page and
preserves literal quotes in the NGM argument string. It does not store the
website password. NGM is only necessary when a fresh official ticket is
required.

For repeatable automation, load `.env` and run
`tools/maplestory_classic_server/tools/refresh_hk_ticket_from_cdp.mjs` first.
It prints only `ticketReady` and whether the new argument differs from the
previous one; it never prints the argument or credentials. The helper now uses
a cache-busted, URL-encoded Galaxy login transaction, hard-reloads the
authenticated main page, and waits before both authorization clicks so a fresh
flow can establish its cookies. It also handles the second Beanfun login iframe
that may appear after the Game Start click. It reuses an already-authenticated
main page without requiring account variables; credentials are required only
if the ID and password form actually appears. Then launch with:

```sh
MAPLE_NETWORK_NAMESPACE=mapleproxy \
MAPLE_PATCH_HTTPAPI=1 \
MAPLE_TARGET_DISPLAY=:1 \
node /home/sdancer/ms/.codex_tmp/maple_launch_ngm_from_cdp.mjs
```

The fully HK-routed browser and game reach the local login server when that
server is also listening inside `mapleproxy`. The prior all-HK failure was a
host-versus-namespace listener mistake, not a route limitation. Keep browser
and game on the same exit during a ticketed launch and verify the relay and
local listener from inside the namespace:

```sh
sudo ip netns exec mapleproxy ss -ltnp | rg ':12345'
sudo ip netns exec mapleproxy ss -ltnp | rg ':12082'
```

If the dedicated profile's cookies are cleared, Beanfun may temporarily return
login-flow timeout `01004`. A forced fresh login followed by the helper's
cache-busting, main-page reload, and delayed clicks restored repeatable ticket
issuance. Region switching alone did not resolve the timeout.

An early GDB attach can be observed by the startup/NGS path, and a persistent
attach stalls Wine rendering. For protocol probes, use brief validated patches
only; the transparent opcode-`2` controller probe is documented in
`REVERSE_ENGINEERING.md`.

## Stop or cold-restart Wine

This stops every process in this MapleStory Wine prefix:

```sh
WINEPREFIX=/home/sdancer/ms/downloads/maplestory_classic_wine_prefix wineserver -k
```

Use this before a cold launch if stale NGM, Unity, or wineserver processes are
interfering.

## Keep only MapleStory muted

Do not rely on the changing PipeWire node number. The repository includes a
user service that continuously matches output nodes whose application or node
name is exactly `Maplestory_Classic.exe` and mutes them within a 250 ms poll:

```sh
systemctl --user link \
  /home/sdancer/ms/tools/maplestory_classic_server/maplestory-audio-mute.service
systemctl --user enable --now maplestory-audio-mute.service
systemctl --user is-active maplestory-audio-mute.service
```

The service is currently linked and enabled. Verify the live stream with
`wpctl status --name`, then run `wpctl get-volume NODE_ID`; it must end in
`[MUTED]`. The helper intentionally ignores other output applications and all
input streams. Its implementation is `maple_server/audio_mute.py` and it can
also be run once for diagnostics:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server
python -m maple_server.audio_mute --once --verbose
```

## Interact inside the nested Wayland desktop

The current game surface is inside the nested Sway compositor on
`wayland-2`, not on the host desktop. Do not use `xdotool` to move the host
cursor. Resolve the nested compositor socket and operate on its own seat:

```sh
nested_sway_socket=/run/user/1000/sway-ipc.1000.195243.sock
SWAYSOCK=$nested_sway_socket swaymsg -t get_tree
SWAYSOCK=$nested_sway_socket swaymsg '[class="maplestory_classic.exe"] focus'
SWAYSOCK=$nested_sway_socket swaymsg 'seat seat0 cursor set X Y'
SWAYSOCK=$nested_sway_socket swaymsg 'seat seat0 cursor press button1'
SWAYSOCK=$nested_sway_socket swaymsg 'seat seat0 cursor release button1'
```

The Sway PID/socket is not stable across compositor restarts; list
`/run/user/1000/sway-ipc.*.sock` and identify the one whose output is
`X11-1`. Coordinates above are in that nested output's coordinate space.

## Wine graphics selection

The prefix was configured with both drivers available:

```text
HKCU\Software\Wine\Drivers Graphics=x11,wayland
```

Set only `DISPLAY` for Xwayland or only `WAYLAND_DISPLAY` for native Wayland to
make the intended path unambiguous.

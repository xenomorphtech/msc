# Native CW client under Wine

The patched working client is in `downloads/cw_wine/client/`. The reference
`../maplestorycw/appdata/` is preserved. This is the native 0.9.0 client from
the supplied capture, not the older Unity/IL2CPP client.

## Launch

From the workspace containing `msc/`, `maplestorycw/` and `.venv/`:

```sh
.venv/bin/python msc/tools/cw_wine/launch.py --restart
```

The launcher uses the terminal's `DISPLAY` and requests a 1366x768 Wine
desktop window; the game can change its size. It selects DXVK for desktop
launches and WineD3D for the private headless desktop:

```sh
.venv/bin/python msc/tools/cw_wine/launch.py --headless --restart
```

The headless display is `:97`, at 1366x768. Mouse/keyboard tools used for this
display must explicitly set `DISPLAY=:97` so they do not affect the host
desktop. Normal desktop launches require the terminal's valid `XAUTHORITY`
when the X server uses authentication. `--display` overrides the display.

To stop only this client/prefix and its replay server:

```sh
.venv/bin/python msc/tools/cw_wine/launch.py --stop
```

Wine 10.0 x64, `iproute2`, passwordless `sudo`, and Python with `pycryptodome`
are required. Headless operation additionally needs `Xvfb`. The supplied
environment was prepared with Ubuntu's `wine64`, `wine`, `xdotool`,
`mesa-utils`, and `dxvk-wine64` packages. Desktop launches use the package's
DXVK 2.6 x64 `d3d11` and `dxgi` DLLs, copied into the working client directory.
See the [DXVK project instructions](https://github.com/doitsujin/dxvk#how-to-use).
`--renderer wined3d` or `--renderer dxvk` overrides the automatic choice.
Screenshot inspection used optional Pillow/python-xlib.
The launcher creates its own prefix, mutes its audio driver, and uses a
loopback-only network namespace named `maple-cw-local`. Neither the client nor
its security/overlay subprocesses have a route to official servers.

## Executable changes

The patcher accepts only this original SHA-256:

```text
4384087a6df1991cb59fea6d1ef086dbe746c7a5af0705bfc39769f4cc56e276
```

1. **Local login address**, RVA `0x349aba8`, file offset `0x34999a8`:
   replace the address-list entry `44.234.162.36` with padded `127.0.0.1`.
   The native `GameLaunching` and `IPPORT` argument parser checks this list.
2. **Early logging null guard**, RVA `0x2ca2050`, file offset `0x2ca1650`:
   preserve the original `mov eax,[rcx+0x60]; ret` getter for valid objects and
   return zero when `rcx` is null. The unmodified executable crashes here
   while logging an early startup error; this was reproduced under GDB.
3. **Offline NGSX run failure**, RVA `0xcf6268`, file offset `0xcf5868`:
   the failure callback still clears its ready flag, then jumps to its normal
   epilogue instead of throwing `CSecurityNGSXRunFailed`. This exact exception
   was identified from Wine's exception trace and the executable's native
   throw metadata. The patch does not set a successful security result or
   generate a server attestation. It permits the local offline client to keep
   running when the security module cannot run under Wine.

The resulting executable SHA-256 is:

```text
251741fe1899326599a5937fe49bea1e7d73e610384a1202a551c5295b9b122a
```

`MapleStory.patches.json` beside the working executable records every changed
byte and its original value. These patches preserve file size and the layout
of other functions. No DLL is patched. The launcher stops and waits for its
Wine prefix before replacing the executable when `--restart` is used.

To regenerate the patched executable separately:

```sh
.venv/bin/python msc/tools/cw_wine/patch.py \
  maplestorycw/appdata/MapleStory.exe \
  msc/downloads/cw_wine/client/MapleStory.exe --guard-early-logging --local-ngsx
```

The client command inside the local namespace is:

```text
wine MapleStory.exe GameLaunching 127.0.0.1 8484
```

Using `GameLaunching` without its address and port triggers the launcher's
`0x22000009` rejection path. This is separate from a Wine loader failure.

## Local replay and verification

`replay.py` reads the private plaintext exports from
`downloads/cw_decode/export/`, validates their hashes, and serves login on
`127.0.0.1:8484` and world handoff on `127.0.0.1:8541`. The handoff's IP/port
are rewritten to loopback. Login uses the captured account/character template;
it is a local playback experiment, not an account authentication service.

The client renders the login, world/channel selection, character-selection,
and in-field gameplay under Wine. The replay waits for real channel and character selections
before sending the corresponding replies. Independent ten-second heartbeat
probes keep an idle selection screen connected. Original frame timing alone
is insufficient: sending the handoff before character selection exits the
client.
After the captured account template loads, choose Windia / CH.1, then select
the existing character. No live account credentials are required.

The field was verified at **Maple Road / East Entrance to Mushroom Town**,
with the local character, NPCs, remote players, UI and map assets rendered.
The earlier field-entry exit was traced to the NGSX run-failure exception and
resolved by the third patch above.
The headless WineD3D run also emitted movement packets after right-arrow input
and completed four matching world heartbeat exchanges. Its screenshot is
`downloads/cw_wine/logs/field.png`. The desktop DXVK run initialized the NVIDIA
GPU and reached the channel-selection protocol barrier. Visual verification
on the host desktop was unavailable because its Xwayland screen reported
zero dimensions and no connected outputs; use `--headless` in that situation.

**This is capture playback, not a complete authoritative game server.** The
recorded timeline supplies server updates, including later field transitions;
it does not implement fresh combat, inventory or quest decisions for arbitrary
new actions. It is suitable for running and inspecting the client locally.

Private screenshots, Wine logs, and live plaintext transcripts are under
`downloads/cw_wine/`. All are ignored by Git. The supplied reference executable
is unchanged. Regression checks:

```sh
.venv/bin/python -m unittest discover -s msc/tools/cw_wine -v
```

The tests reject a mismatched original executable and prove that restoring
only the manifest-declared bytes reconstructs the original file exactly.

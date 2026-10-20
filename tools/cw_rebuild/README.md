# Incremental native client rebuild

The playable checkpoint installs 369 function replacements rebuilt from Ghidra
C into the existing native client, using the original assets. It runs in the
dedicated local Wine setup. The remaining engine functions still come from the
original binary. Runtime traces distinguish installed functions from executed
functions; the first complete checkpoint exercised 63 replacements.

From the workspace containing `msc/`, `maplestorycw/` and `.venv/`:

```sh
# Build and validate recovered transport against the entire capture.
.venv/bin/python msc/tools/cw_rebuild/build.py

# Start the hybrid client and stable local field.
.venv/bin/python msc/tools/cw_wine/launch.py --restart --rebuilt --view

# Automated login, field, movement, jump, inventory and NPC checkpoint.
.venv/bin/python msc/tools/cw_rebuild/smoke.py --combat

# Rebuild and test the bounded integer leaf-function batch.
.venv/bin/python msc/tools/cw_rebuild/leaf.py
```

The graph export and local Wine environment must already exist; see
[the graph workflow](../cw_graph/README.md) and [Wine setup](../cw_wine/README.md).
Python dependencies include those workflows' requirements, Capstone and Pillow.
The build uses GCC and `x86_64-w64-mingw32-gcc`. Generated code, DLLs, test logs,
screenshots and validation records stay under the ignored `downloads/` tree.

## Current local gameplay

Select Windia, channel 1, then the existing character. The captured bindings use
**A/D** to walk and **Space** to jump. **I** opens inventory; double-click Todd
to talk. Accepting Todd's How-to-Hunt starts quest 1005 in response to the new
request, updates the quest helper and saves that quest state across reconnects.
Basic single-target melee against the initial tutorial mobs has local HP,
death, respawns, EXP and tutorial kill progress. It currently accepts the client's reported
basic damage, rather than recalculating attack damage on the server.

`--view` starts the dedicated display and a local noVNC viewer at
<http://127.0.0.1:6080/vnc.html?autoconnect=true&resize=scale>.
Install `x11vnc`, `novnc` and `websockify` for this option. For an already running
headless client, `.venv/bin/python msc/tools/cw_wine/view.py` starts the viewer
without restarting the game. The viewer listens on loopback. `launch.py --stop`
stops this client's Wine prefix, server and viewer.

With `--rebuilt`, the launcher defaults to `--world-mode sandbox`. It sends the
initial field snapshot, keeps independent heartbeat/IV state, and records new
commands. It does not play later recorded quest dialogs, player decisions or
map changes. `--world-mode replay` retains the complete recording for comparison.

Other combat forms, player damage, level-up, quest completion/rewards, loot, inventory persistence,
portals/map transitions and multiplayer still need server implementations.
Movement uses native client physics; saved movement origins are observations,
not server-approved end positions. The original capture supplies account and
field initialization. The server is specific to that local fixture.

## Replacement and verification boundary

| Original executable RVA | Rebuilt function |
| --- | --- |
| `0xcc12a0` | AES table initialization |
| `0xcc1970` | AES-256 key expansion |
| `0xcc1af0` | AES-256 block encryption |
| `0xcc3f30` | IV shuffling |
| `0x7475e0` | Inbound additive decoding |

The generator copies these five bodies unchanged from the pinned graph export.
Global references use shared backing tables in tests and the client's real
global addresses in the DLL. Keeping aliases and initialization flags together
is necessary for callers that still use original code.

Build validation compiles objects and links executables separately. Both Linux
ASan and Windows/Wine run 60,749 cases: AES known/random vectors, in-place and
separate-buffer decoding, chunk boundaries, and transport operations for all
30,184 captured packets. The DLL remains pending for runtime verification until
the gameplay checkpoint exercises every replacement function.

The installer adds a PE import for `cw_rebuilt.dll` to the disposable client
copy. The DLL verifies 32-byte function preimages and replaces their entries
with jumps into rebuilt implementations. Runtime traces count completed calls.
The launcher pins reference, source and artifact hashes and requires successful
standalone tests. The reference installation is unchanged.

`verify_runtime.py` requires channel/character selection, field entry, live
heartbeat replies, at least three movement packets with changing origins, and
completed calls through all five replacements. It preserves immutable evidence
snapshots. Kùzu marks these five functions integrated only while those evidence
hashes remain valid. Screenshots are reviewed separately; protocol checks do
not determine whether rendered content looks correct.

With `--combat`, the checkpoint also requires a matching fresh attack, HP
update, mob death, tutorial counter, EXP award, saved state and live respawn.
The automated check walks and jumps onto the first platform and attacks through
the same keyboard path used by the viewer.

## Integer leaf batch

The leaf batch has 364 functions at the current export snapshot. They compile
into a Windows DLL and a Linux test executable. The Wine oracle maps the
unchanged reference executable without running its startup and calls the
original functions directly, comparing results with the rebuilt DLL. The Linux
ASan build then replays the original results. All 364 pass 820,080 cases covering
small values, integer boundaries, constants and neighbors, and seeded random
arguments. Their DLL is also installed by `--rebuilt` after its build succeeds.
Only functions with completed runtime calls during the gameplay checkpoint are
marked integrated in the graph; the other installed functions remain pending
for integration coverage.

Candidate selection requires primitive integer arguments/returns, bounded
forward control flow, no function calls, no global/pointer memory access and
an allowed integer instruction set. This restricts direct oracle execution
to a small, inspectable group. It is not a proof for all possible inputs.

[leaf-abi.json](leaf-abi.json) records native call-site hashes for six Boolean
predicates whose decompiled `undefined8` return width was too broad. Every
recorded caller consumes `AL`; the verifier independently checks those
instructions before comparing the defined low byte. Other functions retain
their recovered return widths. The initial failed wide-return run is retained
in `downloads/cw_graph/attempts/`. A separate function with an unresolved incoming
RAX dependency remains a recorded compile failure until its ABI is recovered.

The next integration groups are packet readers/writers and movement/combat
code. Each group must compile, match original behavior on meaningful cases, and
pass the playable checkpoint before being counted as integrated. The graph's
discovery, decompilation, compilation, tests and live integration remain separate.

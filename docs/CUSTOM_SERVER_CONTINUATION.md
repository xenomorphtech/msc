# MapleStory Classic custom-server continuation

Last updated: 2026-08-13 UTC

Branch: `agent/maple-login-gamestate`

Pushed HEAD when this note was written: `e3d6993` (`Promote bounded initial field snapshots`)

## Objective and working rules

Continue the capture-backed custom server against both repository-root reference
captures:

- `111.pcapng`, especially gameplay streams `92` and `114`;
- `1-10FS.pcapng`, gameplay stream `126` (levels 1 through 10).

Keep the browser-free local Wine client able to traverse login, world, channel,
character selection, and the world handoff. Model packet bytes only as far as
the captures, pinned native client, or a controlled live experiment establish
them. Keep protocol, status, custom-server, reverse-engineering, README, and
HTTP API documentation synchronized with implementation checkpoints. Run all
gates, commit intentional changes, push the branch, fetch it again, and verify
the remote head after each useful increment.

This worktree is shared and intentionally dirty. Existing changes and untracked
files are not all part of this task. Never stage the whole tree.

## Current repository checkpoint

The most recent pushed sequence is:

```text
e3d6993 Promote bounded initial field snapshots
2567355 Type remote player appearance-adjacent fields
8716833 Bound world entry tickets
7e2bfdb Model remote player stat resets
df00beb Model remote player instructions
fcdbd18 Type terminal endpoint handoff
```

Checkpoint `e3d6993` established that all three captured opcode-`157` initial
field snapshots are already exactly materialized by the typed snapshot parser.
Typed initial snapshots and compact transitions now have full structural
coverage and zero unparsed bytes; only the explicit opaque fallback remains
partial. Reference coverage after that checkpoint was:

```text
111.pcapng stream 92:       34574 full /  633 partial / 0 unknown / 0 invalid
111.pcapng stream 114:         69 full /    7 partial / 0 unknown / 0 invalid
1-10FS.pcapng stream 126:   70077 full / 1023 partial / 0 unknown / 0 invalid
```

All tracked Python tests and all Rust gates passed before `e3d6993` was pushed.
The tracked Python suite then contained 330 tests.

## Dirty-worktree boundary

At the time of this note, these pre-existing paths were modified or untracked
and must not be swept into a protocol checkpoint without reviewing ownership:

```text
 M docs/CLIENT.md
 M docs/PROTOCOL.md
 M docs/STATUS.md
 M tools/maplestory_classic_server/README.md
 M tools/maplestory_classic_server/requirements.txt
?? 1-10FS.pcapng
?? 111.pcapng
?? docs/VAST_WINE_DEPLOYMENT.md
?? tools/maplestory_classic_server/maple_server/security_type1.py
?? tools/maplestory_classic_server/maple_server/wzjson.py
?? tools/maplestory_classic_server/tests/test_draw_map_navigation.py
?? tools/maplestory_classic_server/tests/test_dump_gametables.py
?? tools/maplestory_classic_server/tests/test_dump_quests.py
?? tools/maplestory_classic_server/tests/test_security_type1.py
?? tools/maplestory_classic_server/tools/deploy_vast_wine_client.sh
?? tools/maplestory_classic_server/tools/draw_map_navigation.py
?? tools/maplestory_classic_server/tools/dump_gametables.py
?? tools/maplestory_classic_server/tools/dump_quests.py
?? tools/maplestory_classic_server/tools/maple_xinput_click.c
?? tools/maplestory_classic_server/tools/security_type1_unicorn.py
```

The modified documentation contains unrelated GameTables, quest, navigation,
NGSX/opcode-`13`, and test-count work. If opcode-`189` documentation must share
one of those files, stage only the intended hunk (for example with a generated
patch plus `git apply --cached`) and inspect `git diff --cached` before the
commit. Do not use `git add docs/PROTOCOL.md docs/STATUS.md` wholesale.

## Strongest remaining bounded family: server opcode 189

Opcode `189` is a remote-player field entry. Opcode `190` is its exact `u32`
object-id removal. Across streams `92`, `114`, and `126`, the corpus contains
114 entries and 39 leaves. The current model parses and round-trips:

- object id, level, and counted UTF-16 name;
- a secondary counted UTF-16 value and the following `u16/u8/u16/u8` fields;
- a `u16` immediately before a complete `CharacterListAppearance`;
- after appearance: `i32`, `u32`, four `i32`s, two `i16`s, `u8`, and `u16`;
- the exact opcode-`190` leave record and remote-player lifecycle fold.

The remaining opaque portions are a pre-appearance bridge and a post-appearance
tail. Across all entries, existing accounting measured 13,663 typed body bytes
and 22,673 opaque body bytes. The bridge is 128 bytes in 112 entries and 129
bytes in two entries. Observed tail lengths range from 32 through 120 bytes.
Stream `92` alone has bridge lengths `128 x 56` and `129 x 2`, with tail
families led by `95 x 28`, `68 x 16`, `76 x 6`, `120 x 3`, `80 x 3`, `81 x 1`,
and `103 x 1`. Recompute these counts from source before putting them in a
permanent protocol claim; they are investigative notes, not a checked-in test.

The first stream-`114` entry is a useful controlled packet:

```text
server frame index: 17
plaintext length:   333 bytes
opcode:             189 (0x00bd)
bridge length:      128 bytes
tail length:        68 bytes
```

Its bridge is highly regular but must not be assigned semantics from repeated
zeros. Its tail visibly contains a counted UTF-16 resource-like name ending in
`.pt` plus fixed-width values, but the string and surrounding values should
remain redacted/neutral until the native read sequence proves their boundaries.

### Pinned native evidence

The pinned client binary is:

```text
/home/sdancer/ms/downloads/maplestory_classic_wine_prefix/drive_c/Program Files/Gamania/maplestory_classic/GameAssembly.dll
image base: 0x180000000
```

The opcode-`189` body delegate is RVA `0x11819e0`. Native disassembly established
this sequence without guessing:

1. The delegate reads the secondary UTF-16 value and known scalar prefix.
2. At delegate RVA approximately `0x1182751`, it dispatches a separate record.
3. It calls the pre-appearance bridge parser at RVA `0xd5c740`.
4. It then reads the known pre-appearance `u16` and calls the appearance parser
   at RVA `0x1246ca0`.
5. It consumes the known post-appearance scalars and continues through the
   remaining tail readers in the same delegate.

Temporary disassemblies from the investigation may still exist as:

```text
/tmp/op189.objdump
/tmp/op189_bridge.objdump
```

The bridge parser is flattened and includes a virtual nested-parser call, so a
static list of its direct primitive-reader calls is not an execution grammar.
Static disassembly alone is insufficient to type the bridge. A live primitive
read trace is the next authoritative step.

## Live custom-server state and lessons from the trace attempt

The long-running capture-backed services were still listening in network
namespace `mapleproxy`:

```text
login: 0.0.0.0:12082
world: 0.0.0.0:12857
HTTP:  127.0.0.1:12858
```

The world server was started from `111.pcapng` stream `114` with generated
initial snapshot, fixed records, variable records, NPC spawns, reactive typed
responses, heartbeat probes, and opt-in HTTP packet injection. Query it inside
the namespace:

```sh
sudo -n ip netns exec mapleproxy \
  curl -fsS http://127.0.0.1:12858/api/v1/status | jq .
```

The top-level status key for injection is `server_packet_injection` (not under
`protocol`). When a client is in-world, require both:

```text
.connections.active == 1
.server_packet_injection.ready == true
```

A fresh browser-free run successfully traversed world/channel/character and
entered map `101000000`. At the proof sample the server had one active
connection, heartbeat `last_round_trip_ms=2.431`, and no pending probe. The
client later exited before the intended non-stop attach. Final server status
showed five accepted/five completed connections, zero failures, no active
connection, and 4,808 probes matched by 4,808 responses with none pending.
The Wine log ended with:

```text
wine: Call from ... to unimplemented function
httpapi.dll.HttpCancelHttpRequest, aborting
```

Do not retain the earlier transient theory that the new connection simply hit
the replay hold-open timeout; the timing did not prove that. The authoritative
facts are only that the process disappeared before attach, the server recorded
a normal completed socket, and Wine logged the unimplemented HTTP API abort.

### All-stop GDB failure and why it matters

One attempted trace attached GDB first and tried to enable non-stop mode
afterward. GDB correctly refused to change the setting while the inferior was
running. Continuing in all-stop mode caused Wine to open a hidden
`Fatal error in GC` window containing `SuspendThread loop failed`. The visible
game screen then ignored navigation input. No opcode-`189` trace was captured.
GDB was detached cleanly, but this experiment is negative operational evidence:
do not attach this Wine client in all-stop mode.

Enable non-stop before `attach`, ignore Wine's `SIGUSR1/SIGUSR2`, then use
`continue -a`. Use a command sequence whose ordering is explicit rather than
`gdb -p PID` followed by `set non-stop on`:

```sh
sudo -n ip netns exec mapleproxy env \
  MAPLE_TRACE_OPCODE=189 \
  MAPLE_TRACE_DUMP_BYTES=0 \
  gdb -q -nx \
    -ex 'set pagination off' \
    -ex 'set non-stop on' \
    -ex 'handle SIGUSR1 nostop noprint pass' \
    -ex 'handle SIGUSR2 nostop noprint pass'

# At the GDB prompt, after resolving the fresh live PID:
attach PID
source /home/sdancer/ms/tools/maplestory_classic_server/tools/gdb_trace_packet_reads.py
set logging file /tmp/op189-reader-trace.log
set logging overwrite on
set logging enabled on
continue -a
```

After the packet is captured, interrupt GDB, disable logging, `detach`, and
`quit`. Check for a `Fatal error in GC` window before trusting the result.

## Exact browser-free relaunch and navigation

The nested compositor used for the successful run was:

```text
display:     :1
sway socket: /run/user/1000/sway-ipc.1000.195243.sock
Wayland:     wayland-2
```

These identifiers can change after a compositor restart. Rediscover them
rather than assuming they remain valid. With the listeners already up, the
working cold launch was:

```sh
cd /home/sdancer/ms
PYTHONPATH=tools/maplestory_classic_server \
python tools/maplestory_classic_server/tools/launch_local_game.py \
  --restart \
  --display :1 \
  --sway-socket /run/user/1000/sway-ipc.1000.195243.sock \
  --timeout 45
```

There is a stale zombie client/window (`PID 902196`, historically Sway
container `451`) which can overlap the fresh window. Select the Sway container
whose PID matches the new `Maplestory_Classic.exe`; do not use hard-coded
container or X11 window ids.

The Unity raw-input path ignores ordinary `xdotool` synthetic clicks. Direct
nested-Sway seat input worked. In the current 1918x1078 nested output, this
sequence navigated from world/channel selection to character selection:

```text
(736,347) -> (836,544) -> (1114,492)
```

Each click used a 300 ms press and roughly a 1.2 second inter-click delay. The
character screen's Start Game button was at approximately `(1300,431)`. Verify
each screen visually or through a fresh screenshot; coordinates are evidence
for this layout, not a general UI API.

One click helper pattern is:

```sh
maple_sway_socket=/run/user/1000/sway-ipc.1000.195243.sock
SWAYSOCK=$maple_sway_socket swaymsg '[pid=FRESH_PID] focus'
SWAYSOCK=$maple_sway_socket swaymsg 'seat seat0 cursor set X Y'
SWAYSOCK=$maple_sway_socket swaymsg 'seat seat0 cursor press button1'
sleep 0.30
SWAYSOCK=$maple_sway_socket swaymsg 'seat seat0 cursor release button1'
```

The focus selector may need to be resolved from `swaymsg -t get_tree` if the
installed Sway does not accept a PID criterion directly.

## Controlled opcode-189 trace recipe

1. Confirm login/world/API listeners without restarting the long-running
   servers.
2. Cold-launch only the Wine client and enter the field with nested-Sway input.
3. Confirm one active world connection, injection ready, and increasing matched
   heartbeats.
4. Resolve the fresh `Maplestory_Classic.exe` PID.
5. Start GDB in non-stop mode before attaching, source
   `tools/gdb_trace_packet_reads.py`, enable logging, and `continue -a`.
6. Extract the first stream-`114` opcode-`189` plaintext directly from the PCAP
   and inject it through the loopback API.
7. Wait only long enough to see the full reader sequence, then detach GDB.
8. Verify the client still answers heartbeats. Preserve the trace-derived field
   table in repository documentation; do not commit raw packet bytes or private
   runtime artifacts unnecessarily.

Extraction can be performed without hard-coding the 333-byte payload:

```sh
cd /home/sdancer/ms
PYTHONPATH=tools/maplestory_classic_server python - <<'PY'
from pathlib import Path
from maple_server.gamestate import decode_transcript
from maple_server.pcap import load_pcap_tcp_stream

decoded = decode_transcript(load_pcap_tcp_stream(Path("111.pcapng"), 114))
for frame in decoded.frames:
    if (
        frame.direction == "server_to_client"
        and int.from_bytes(frame.plaintext[:2], "little") == 189
    ):
        print(frame.plaintext.hex())
        break
else:
    raise SystemExit("stream 114 has no server opcode 189")
PY
```

Post it only while the API reports a single injection-ready connection:

```sh
sudo -n ip netns exec mapleproxy curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"plaintext_hex":"HEX_FROM_THE_EXTRACTION_COMMAND"}' \
  http://127.0.0.1:12858/api/v1/server-packets | jq .
```

Expected API response properties are `accepted=true`, `opcode=189`, and
`plaintext_length=333`. A 409 means there is not exactly one active replay
connection. The endpoint is intentionally loopback-only and injection is
explicitly opt-in.

### How to interpret the read trace

`gdb_trace_packet_reads.py` logs the primitive name, reader RVA, caller RVA,
packet cursor, managed buffer length, cached opcode, and opcode decoded from
the framed buffer. The trace logs the cursor on entry to each primitive reader.
Use the ordered cursor deltas and the primitive labels to reconstruct the
executed grammar. Preserve caller RVAs because the same primitive sequence can
be split between the outer delegate, bridge parser, and nested virtual parser.

The managed incoming buffer retains a four-byte encrypted-frame header before
the plaintext. Confirm this for the live record (`length` should be plaintext
length plus four and `frame_opcode` should be `0xbd`) before translating cursor
positions into plaintext offsets. Do not silently subtract four if the live
trace contradicts that invariant.

Useful primitive-reader RVAs are already encoded in the tracing script:

```text
u16      0x1cd0300     u8       0x1cd0530
bool     0x1cd0560     i8       0x1cd0700
i16      0x1cd0730     i32      0x1cd0760
i64      0x1cd0790     u64      0x1cd07c0
datetime 0x1cd09d0     u32      0x1cd0b00
utf16    0x1cd0ca0     string   0x1cd0ce0
```

## Implementation plan after the trace

### 1. Derive the executed grammar

Create a table for every reader call in the exact injected packet:

```text
sequence | cursor | plaintext offset | primitive | caller RVA | consumed bytes
```

Partition it into existing prefix, bridge parser, appearance parser, known
post-appearance fields, and remaining tail. Repeat with at least one independent
variant if a conditional field controls the 128/129-byte bridge or the major
tail-length families. One 128-byte/68-byte sample is enough to type that exact
variant, not all 114 packets.

### 2. Add neutral typed packet structures

Implement the proven bridge/tail records in
`tools/maplestory_classic_server/maple_server/packets.py`. Use neutral names for
unknown-purpose scalars and redact values in `safe_dict()`. Name only structural
roles established by the reader grammar (flag, count, timestamp wire type,
counted string, repeated record, etc.). Keep an explicit opaque fallback for
unproven variants.

Do not promote opcode `189` to full coverage merely because a fixed number of
bytes can be sliced. Full coverage requires that every byte in a supported
variant be consumed by a structural codec and exactly round-trip.

### 3. Fold only evidence-backed state

Update `gameplay.py` only where typed fields establish safe aggregates or real
remote-player state. Identity-bearing strings and capture-specific scalar
values must remain absent or redacted from safe JSON. Preserve the current
remote-player lifecycle semantics unless the new native/capture evidence proves
an additional state transition.

### 4. Test every supported boundary

Extend `tests/test_gameplay.py` with:

- exact parse/serialize round trips for the captured bridge/tail variant;
- conditional/count and truncation failures at every new variable boundary;
- safe-dictionary redaction checks;
- full coverage and zero unparsed bytes only for proven variants;
- partial coverage and correct unparsed accounting for opaque fallbacks;
- fold assertions for any newly exposed safe aggregate.

Run both reference analyses and the latest local transcript. The long corpus is
the independent variant check; do not validate only stream `114`.

### 5. Update documentation selectively

Update the opcode-`189` sections in:

- `docs/PROTOCOL.md`;
- `docs/STATUS.md`;
- `docs/CUSTOM_SERVER.md`;
- `docs/REVERSE_ENGINEERING.md` when the live trace changes the method;
- `tools/maplestory_classic_server/README.md`.

Document the live API preconditions and response without exposing raw packet
contents. Include exact capture counts, supported variants, fallback behavior,
coverage totals, native RVAs, and live proof. Clearly separate observed facts,
native evidence, and inference.

### 6. Run gates, stage narrowly, commit, push, continue

From the repository root:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server
test_files=($(git ls-files 'tests/test_*.py'))
PYTHONPATH=. python -m unittest ${test_files[@]}

cd /home/sdancer/ms
cargo test --manifest-path tools/il2cpp_packet_dump/Cargo.toml
cargo test --manifest-path tools/il2cpp_packet_dump/Cargo.toml \
  --test current_version -- --ignored
MAPLE_PACKET_JSONL=/home/sdancer/ms/tools/il2cpp_packet_dump/target/private/111.streams-83-92-114.jsonl \
  cargo test --manifest-path tools/il2cpp_packet_dump/Cargo.toml \
  --test capture_jsonl -- --ignored
```

Before committing, call codebase-memory graph discovery first and
`check_index_coverage` for every operated-on file. Inspect both working and
staged diffs. Stage only the intended files/hunks. Then:

```sh
git commit -m '...'
git push origin agent/maple-login-gamestate
git fetch origin agent/maple-login-gamestate
maple_local_head=$(git rev-parse HEAD)
maple_remote_head=$(git rev-parse origin/agent/maple-login-gamestate)
test "$maple_local_head" = "$maple_remote_head"
git status --short --branch
```

After the opcode-`189` checkpoint, recompute the partial/unknown inventory and
continue from the strongest capture-bounded family. Do not stop merely because
the checkpoint is pushed.

## Files to read first when resuming

Use the codebase-memory graph before filesystem search for structural code
discovery, then read the exact relevant sources:

```text
docs/CUSTOM_SERVER.md
docs/PROTOCOL.md
docs/REVERSE_ENGINEERING.md
docs/STATUS.md
tools/maplestory_classic_server/README.md
tools/maplestory_classic_server/maple_server/packets.py
tools/maplestory_classic_server/maple_server/gameplay.py
tools/maplestory_classic_server/tests/test_gameplay.py
tools/maplestory_classic_server/tools/gdb_trace_packet_reads.py
```

The index was last known healthy for the code/test/tracer files. Documentation
scope coverage was best-effort and not tracked as fresh metadata, so read the
source directly before editing it.

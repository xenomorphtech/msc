# MapleStory Classic custom-server continuation

Last updated: 2026-08-13 UTC

Branch: `agent/maple-login-gamestate`

Baseline HEAD for this continuation: `02f194c` (`Document custom server continuation plan`)

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

The pushed sequence immediately preceding this opcode-`189` increment was:

```text
4b48e6f Anchor opcode 189 delegated tail at packet end
1c248f5 Type opcode 189 delegated tail
1ae38d5 Read opcode 189 follow-up on both branches
c5dfb17 Restore opcode 189 runtime tail boundary
3251036 Type opcode 189 direct residual text
3492af3 Fully type opcode 189 bridge
a18b72e Type opcode 189 bridge records
7f18779 Type opcode 189 bridge mask
bdf05fe Type current opcode 148 records
c583c23 Correlate opcode 13 world exchange
3e1a613 Type opcode 189 conditional tail
683cedf Type opcode 189 tail prefix
d17a077 Type opcode 13 IV security envelopes
02f194c Document custom server continuation plan
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

Checkpoint `d17a077` types client opcode `13`, subtype `1` as a
`uint32` IV-derived security value followed by a reserved-zero `uint32`.
Native producer evidence and an independent cipher-IV replay reproduce all
`446/446` stream-`92` and `970/970` stream-`126` records with zero mismatches.
The tracked parser exactly re-emits all 1,416 records, redacts the value from
safe output, and promotes only this subtype to full structural coverage. The
remaining subtype-`6` and subtype-`13` bodies stay opaque and partial. Resulting
reference coverage is:

```text
111.pcapng stream 92:       35020 full /  187 partial / 0 unknown / 0 invalid
111.pcapng stream 114:         69 full /    7 partial / 0 unknown / 0 invalid
1-10FS.pcapng stream 126:   71047 full /   53 partial / 0 unknown / 0 invalid
```

The checkpoint gate reran all 330 tracked Python tests, 17 Rust unit tests, the
pinned-client ignored test, and the private capture-JSONL ignored test. All
passed. The three gameplay analyses are valid with zero issues; stream `126`
retains its one previously known warning.

Checkpoint `c583c23` correlates the remaining opcode-`13` world security
exchange without exposing its bodies. Server opcode `12` is paired FIFO with
server opcode `14`, and each server opcode `14` is paired FIFO with the next
client opcode `13`; safe state reports body-length agreement, pending/unmatched
counts, and timing only. Streams `92` and `114` contain six opcode-`14`/`13`
pairs, all with matching 392-byte bodies but no byte-identical pair. Reference
coverage remains `35020/187`, `69/7`, and `71047/53` full/partial for streams
`92`, `114`, and `126`. The checkpoint passed 332 tracked Python tests, all 17
Rust tests, and both ignored pinned/private gates, then was pushed and fetched
back at the same commit.

## Current bounded family: server opcode 148

The last non-opcode-`13`/`189` partial packet is one server opcode-`148`
variant-`9` frame in `1-10FS.pcapng` stream `126`. It declares 12 records and
has a 1,632-byte body. Static native recovery now pins the full current-build
path: opcode handler `acda742a...::c430c9bc...` resolves the `c5b43350...`
manager, whose variant-`9` branch reads a signed record count and invokes the
`f818561e...` deserializer with mask `0x9`. That mask reads, per record:

- two signed `i32` values;
- two DateTime values, each carried as eight raw bytes;
- one counted UTF-16 string followed by a required zero byte.

The current grammar does not consume the capture. At record zero, its first
string has a plausible count but the required following byte is nonzero. A
full mask sweep confirms no string-bearing mask from `0x0` through `0xf`
consumes even the first record. Although `1,632 / 12 = 136`, all positions in
the candidate 136-byte slices vary and there is no cross-record fixed-zero or
UTF-16-like region, so that quotient is not sufficient evidence for a record
boundary. Keep this body as the existing lossless legacy opaque fallback and
exact 1,639-byte native-manifest pin.

The tracked parser and native manifest now model current-layout nonempty
variant `9` independently: repeated records parse and re-emit exactly, safe
output exposes only record count, layout status, typed count, and text
code-unit lengths, and any incompatible body falls back losslessly to opaque
bytes. The existing captured packet must remain partial until another capture
or native version identifies its legacy grammar.

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
NGSX, and test-count work. The opcode-`13` native-evidence hunk is intentionally
relevant to the typed subtype-`1` checkpoint, but the untracked helper, Unicorn
harness, and tests remain outside this commit. Stage only the intended hunks
(for example with a generated patch plus `git apply --cached`) and inspect
`git diff --cached` before the commit. Do not use `git add docs/PROTOCOL.md
docs/STATUS.md` wholesale.

## Current bounded family: server opcode 189

Opcode `189` is a remote-player field entry. Opcode `190` is its exact `u32`
object-id removal. Across streams `92`, `114`, and `126`, the corpus contains
114 entries and 39 leaves. The current model parses and round-trips:

- object id, level, and counted UTF-16 name;
- a secondary counted UTF-16 value and the following `u16/u8/u16/u8` fields;
- four consecutive `u32` mask words at the start of the pre-appearance bridge;
- after that mask: the optional direct `u8`, two fixed `u8`s, and all seven
  virtual records with exact widths `15/15/15/13/20/17/15`;
- a `u16` immediately before the opcode-specific three-style-word appearance;
- after appearance: `i32`, `u32`, four `i32`s, two `i16`s, `u8`, and `u16`;
- in every entry: a bool-terminated loop; each executed record contains a
  selector `i32`, nested `i32`, packet string, `i64`, a two-short vector,
  `u8`, and `i16`, followed after the loop by three `i32`s and one variant
  `u8`;
- for each nonzero variant: one `u32`, a packet string, bool, three `u8`s, and
  bool, followed by the conditional prefix shared with the zero variant;
- at packet end in every entry: five packet UTF-16 values, one further `u8`,
  one `i32`, and one eight-byte DateTime wire value;
- the exact opcode-`190` leave record and remote-player lifecycle fold.

There is no remaining opaque portion in the supported opcode-`189` bodies.
Across all entries, current accounting measures 36,336 typed body bytes and
zero opaque body bytes. Per stream, the typed/opaque counts are `19,730/0`,
`1,326/0`, and `15,280/0` for
streams `92`, `114`, and `126`. The full bridge is 128 bytes in 112 entries and
129 bytes in two entries. Its 16-byte mask is followed by 112 typed bytes, or
113 typed bytes when the direct `u8` is present.
The masks have one nonzero word and seven enabled bits in 112 entries, and two
nonzero words and eight enabled bits in two entries. Raw words are retained
only for re-emission and never reported. The corrected appearance boundary
types the tail prefix in all 114 entries: 44 have no loop records, 63 have one,
and seven have two. All 77 executed nested records take the extended reader
path. Fifty-one nonzero variants type the unequal-branch group, and the
following conditional prefix is typed in all 114 entries. Both runtime-state
arms converge at
RVA `0x1183720` before the follow-up read. At RVA
`0x118381e`, a null runtime parser field leads to a throw, while the successful
non-null path calls the downstream parser at `0x1183857`. Constructor and
callee recovery establish five required packet strings, one `u8`, one `i32`,
and one DateTime. The handler performs no later packet read and returns at
`0x1183892`. Requiring that grammar to consume exactly to packet end yields one
unique record in every entry. Streams `92/114` use code-unit shapes
`(0,1,1,9|15|16|20,0)` and stream `126` uses `(0,0,0,0,0)`. These are checked
corpus results; text and scalar roles remain redacted and neutral.

This nested-loop-reader increment keeps semantic coverage at
`35020/187`, `69/7`, and `71047/53` full/partial for streams `92`, `114`, and
`126`; opcode `189` remains partial despite exact byte coverage. All 336
tracked Python tests, 17 Rust tests, the pinned-build ignored test, and the
private capture-JSONL ignored
test pass. All three gameplay analyses remain valid; stream `126` retains only
its known one-HP warning. Focused native-manifest validation consumes all 52
stream-`126` opcode-`189` packets with zero unsupported or failed shapes.

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
3. It calls the pre-appearance bridge parser
   `fda0a837...::d8fe2358...` at RVA `0xd5c740`. That method
   invokes `cd0d0bca...::a910877d...`, which performs four consecutive
   packet-`UInt32` reads before conditional dispatch.
4. It then reads the known pre-appearance `u16` and calls the appearance parser
   at RVA `0x1246ca0`.
5. It consumes the known post-appearance scalars and continues through the
   remaining tail readers in the same delegate.

Temporary disassemblies from the investigation may still exist as:

```text
/tmp/op189.objdump
/tmp/op189_bridge.objdump
```

The native reader stores the four wire words in reverse logical field order.
After recovering that order, all 114 masks enable the seven virtual-array
slots at logical indices `82..88`; the two 129-byte stream-`92` bridges also
enable direct logical bit `7`, whose branch reads one `u8`. The reader then
consumes two unconditional `u8`s and iterates an instance array of exactly
seven virtual records. Constructor/factory control flow and offline LibCpp2IL
metadata resolution map logical slots `82..88` to exact widths
`15/15/15/13/20/17/15`. Every record starts with two `i32`s and a DateTime
helper's `u8 + i32`; the 15-byte form adds `u16`, the 13-byte form stops at the
base, the 20-byte form adds a second DateTime and `u16`, and the 17-byte form
adds `i32`. The DateTime helper always consumes both the flag and `i32`. This
types the complete 112/113 bytes after the mask. GDB and Frida are not safe on
this Wine build, so continue from offline/native evidence or a new capture
rather than retrying runtime attachment.

This completed-bridge increment keeps structural coverage at `35020/187`,
`69/7`, and `71047/53` full/partial for streams `92`, `114`, and `126`; opcode
`189` stays partial. All 333 tracked Python tests, 17 Rust tests, the
pinned-build ignored test, and the private capture-JSONL ignored test pass. All
three gameplay analyses remain valid; stream `126` retains only its known
one-HP warning. A
focused native-manifest validation consumes all 52 stream-`126` opcode-`189`
packets with zero unsupported or failed shapes. The broad stream-`126`
validator still reports 139 unrelated supported-shape failures, so it must not
be described as globally clean.

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

A fresh 2026-08-13 browser-free run again traversed world/channel/character and
entered through the transformed handoff. The client emitted character opcode
`7` after Start and opened one local world connection. Before instrumentation,
the world HTTP status reported injection ready, five of five heartbeat probes
matched, `last_round_trip_ms=3.367`, and none pending. This is the current
end-to-end login proof.

### Runtime instrumentation failures and why they matter

One attempted trace attached GDB first and tried to enable non-stop mode
afterward. GDB correctly refused to change the setting while the inferior was
running. Continuing in all-stop mode caused Wine to open a hidden
`Fatal error in GC` window containing `SuspendThread loop failed`. The visible
game screen then ignored navigation input. No opcode-`189` trace was captured.
GDB was detached cleanly, but this experiment is negative operational evidence:
do not attach this Wine client in all-stop mode.

The corrected experiment enabled non-stop before `attach`, ignored
`SIGUSR1/SIGUSR2`, and used `continue -a`. Attach still left worker threads
stopped until a second `continue -a`; heartbeat traffic then resumed. The HTTP
endpoint accepted and wrote the 333-byte stream-`114` opcode-`189` record, but
the tracer logged no primitive reads, heartbeats stopped, and Wine opened the
same `Fatal error in GC` / `SuspendThread loop failed` window. GDB detached
cleanly. This proves only the serialized server write, not client parsing or
acceptance. Do not retry opcode-`189` with GDB on this build; the next attempt
must use lower-intrusion instrumentation or additional offline/native evidence.

A fresh client then proved that Frida is not a safe lower-intrusion substitute
on this build. After world handoff and verified heartbeat progression, a bare
`frida.attach` with no hooks returned `ProcessNotRespondingError` because the
process refused the agent load or terminated during injection. The client and
world connection disappeared. No opcode-`189` packet was injected in this
attempt. Do not retry Frida; continue from offline/native evidence.

Offline recovery then corrected the upstream boundary. The outer method calls
the appearance parser at RVA `0x1246ca0`; its delegated record reader at
`0x12cca10` ends its direct fields with an `i32` at `0x12cd447`, then calls the
array helper at `0x1cd0d60` with a statically computed count of three. The
shared character-list appearance shape has seven trailing style words, so
using it for opcode `189` had consumed four post-appearance words. The opcode
now selects the three-word shape explicitly while character lists retain the
seven-word default.

With that alignment, the pinned delegate's RVA
`0x1182ba8` reads a bool; true enters the repeated `i32` read at `0x1182be7`
and calls the selected record's nested parser at `0x1182d3e` before the next
bool at `0x1182d48`. The nested method at `0xf96e00` reads `i32` and packet
string, then the captured extended variants read `i64`, a `Vector2` encoded as
two protected shorts, `u8`, and `i16`. The false loop exit reaches three `i32`
reads at `0x1182e42/0x1182e52/0x1182e62`, then a `u8` read at `0x1182e89`.
The implemented codec round-trips all 114 reference entries and publishes only
safe counts/length/presence summaries. The executed loop has no records in 44
entries, one in 63, and two in seven.

Static byte `0x15 + 0xeb` wraps to zero, so variant zero selects the equality
path at RVA `0x118313f`. The 51 nonzero variants take the unequal branch at
`0x1182eba`, which reads `u32`, a packet UTF-16 string (including its
unconstrained trailing `u8`), bool, three `u8`s, and bool. Six captured strings
have nonzero trailing bytes; safe output exposes only lengths and nonzero
summaries. Both paths reach the subsequent reader calls: bool at
`0x1183144`, conditional packet UTF-16 at `0x1183174`, bool at `0x1183252`,
conditional `i64` pairs at `0x1183272/0x118327c` and
`0x11832aa/0x11832b4`, a bool and conditional `u32/u32/i32` group at
`0x11832c4` and `0x11832e2/0x11832f2/0x1183302`, then continuation bool at
`0x11833a8`. Its false path jumps to `0x1183720`; the true path first performs
runtime-state-dependent work, then every arm reconverges at `0x1183720` and
reads the follow-up bool at `0x1183725`. Deeper control flow consults runtime
object state before a delegated parser at `0x16ca1d0`. RVA `0x118381e` loads
the player object's parser field; the null path throws, while the non-null path
calls the parser at `0x1183857`. The callee begins with a packet-string helper
at `0x16ca271`. Its two later subrecords are required: the first reads four
more packet strings and one `u8`, and the second reads `i32` plus DateTime.
The outer player constructor creates the delegated record and its constructor
creates both nested records, although Unity prefab serialization can replace
constructor defaults. After the parser call, the handler invokes one player
virtual method without the packet reader and returns at `0x1183892`. The unique
packet-terminal parse types this reader in all 114 entries. The conditional
prefix is typed in all 114 entries. Parsing the per-loop nested reader at its
actual call site removes the former gap families, so every supported body now
has zero opaque bytes.

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

## Controlled opcode-189 experiment result

The planned GDB trace was executed with the required live preconditions and
failed safely enough to detach, but not safely enough to produce a read ledger.
Do not repeat it, and do not substitute Frida on this Wine build. The extraction
and injection commands below remain useful for a future independently safe
probe, but an `accepted=true` HTTP response establishes
only that the server serialized the write. Require continuing heartbeats and
independent instrumentation before claiming that the client parsed a packet.

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

### How to interpret a future lower-intrusion read trace

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

## Next implementation plan

### 1. Preserve the closed opcode-189 boundary

All supported opcode-`189` bodies now exact-consume with zero opaque bytes.
Keep the six observed nested-`i32` variants capture-bounded until offline
metadata or an independent capture proves how an unobserved value selects the
base versus extended nested-reader path. Do not retry GDB or Frida on this Wine
build.

### 2. Inventory the next material opaque family

The two long server opcode-`77` variant-`8` wrappers still retain 75-byte
metadata regions around an otherwise typed opcode-`39` equipment-item record.
Use native code, metadata, and the two independent item observations to locate
another executed reader boundary without assigning gameplay meaning from byte
frequency.

### 3. Promote only another executed boundary

Use neutral structural names, preserve arbitrary packet-string trailing bytes,
redact all strings and scalar values from `safe_dict()`, and retain opaque
fallbacks for unproven opcode-`77` layouts. Opcode `189` has exact byte coverage
but remains partial semantic coverage because the neutral field roles are not
claimed.

### 4. Re-run all independent checks

For the next boundary, add exact round trips, truncation checks at every
variable-width read, redaction assertions, typed/gap accounting, and any
justified fold assertions. Run streams `92`, `114`, and `126`, plus the
saved active transcript; the short stream alone is not an independent variant
check.

### 5. Keep all user-facing protocol surfaces synchronized

Update `docs/PROTOCOL.md`, `docs/STATUS.md`, `docs/CUSTOM_SERVER.md`, this file,
`docs/REVERSE_ENGINEERING.md`, and the custom-server README with exact counts,
gap behavior, native RVAs, and the distinction between observed bytes,
native evidence, and inference. Preserve the HTTP injection preconditions and
do not expose raw identity-bearing payloads.

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

This opcode-`13` increment keeps all non-type-`1` bodies opaque but records
the cross-session exchange evidence. Streams `92` and `114` each contain one
server type `12`, a server type `14` `4934.955..4945.945` ms later, and a
same-length client type `13` another `27.305..30.942` ms later. Stream `92`
adds four type-`14`/type-`13` pairs at `180.722..184.383` second server
intervals; all six client messages follow in `27.305..77.244` ms and match the
392-byte server body length. The fold publishes redacted FIFO correlation,
length-match, pending/unmatched, and latency state/events. Structural coverage
does not change (`35020/187`, `69/7`, and `71047/53` full/partial for streams
`92`, `114`, and `126`), and no replay policy is enabled.

The correlation checkpoint reran all 332 tracked Python tests, 17 Rust unit
tests, the pinned-client ignored integration test, and the private capture-JSONL
ignored test. All passed. The three gameplay analyses remain valid with zero
issues; stream `126` retains only its previously known one-HP warning.

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

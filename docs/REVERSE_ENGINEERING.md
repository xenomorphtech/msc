# Reverse-engineering notes

## Artifacts

```text
/home/sdancer/ms/downloads/maplestory_classic_il2cpp/
/home/sdancer/ms/.codex_tmp/Cpp2IL/
/home/sdancer/ms/.codex_tmp/maple_framework_isil/
/home/sdancer/ms/.codex_tmp/maple_framework_dummy_cs/
/home/sdancer/ms/.codex_tmp/maple_dummy_dlls/
/home/sdancer/ms/.codex_tmp/maple_isil_focus/
```

The `.codex_tmp/Cpp2IL` directory is a nested Git checkout. Its
`Cpp2IL.Core/OutputFormats/IsilDumpOutputFormat.cs` was locally patched to
honor `CPP2IL_ASSEMBLY_FILTER`, allowing focused Framework output. Do not reset
that checkout casually.

## Reproducible packet-shape dump

`tools/il2cpp_packet_dump` is the version-pinned structural source of truth for
opcodes, attributed handlers, and ordered direct packet-reader calls. Its
manifest binds protocol `300` to the current `GameAssembly.dll`, metadata,
generated C#/ISIL trees, and the SHA-256 identities of `111.pcapng` and
`1-10FS.pcapng`. Regenerate and validate it with:

```sh
cd /home/sdancer/ms/tools/il2cpp_packet_dump
cargo run --release -- verify \
  --manifest versions/maple-classic-300-2026-08-08.json
cargo run --release -- dump \
  --manifest versions/maple-classic-300-2026-08-08.json \
  --output target/current-il2cpp-packets.json
```

The gameplay model uses these generated reads only where they exactly consume
the observed payload. The current increment proves server opcode `60` as one
signed `i32`, opcode `94` as `bool + i32 + i32`, and opcode `379` as a `u8`
branch with four `datetime/i64` reads on variant `36`. Fourteen reference
packets consume exactly under those shapes. The Rust validator has a native
boolean primitive matching the pinned reader's `BitConverter.ToBoolean` call:
zero is false and every nonzero byte is true. The validator normalizes that
truth value for branch/constant checks while typed Python codecs retain a
noncanonical raw byte for lossless re-emission. Captured opcode `276` provides
the concrete cross-corpus case: wire byte `0x05` is accepted as true.
Opcode `137` is the complementary partial case: the dump proves direct
`i16/i32/i32` reads, while capture comparison leaves the following 72 bytes
opaque until delegated-reader evidence is available.
Opcode `169` demonstrates why the flattened direct-read list must be paired
with native control flow. Its handler's first `u8` selects one of eight jump
table arms; selector `3` lands at `0x180BC3281`, calls the pinned UTF-16 reader
once, and exits through the common return. That executed arm consumes the sole
54-byte gameplay packet exactly, while the other reads in the generated list
belong to mutually exclusive selector branches.
Opcode `29` demonstrates the complementary delegated-reader case. The
automatic dump correctly identifies handler `b7bc850c...` but reports no
direct reads because the handler passes its reader into ledger constructor
`0x180CB4390`. Native tracing shows a `u8` count there and a loop over record
constructor `0x180CB3F20`, whose ordered calls are
`i32/i32/UTF-16/i32/i16`. That call graph exactly consumes both byte-identical
327-byte `111.pcapng` packets as four records. The checked-in semantic manifest
records the proven delegated grammar while the generated handler entry remains
the authoritative evidence that the top-level handler itself has no direct
reader calls.

Opcode `135` adds an executed-loop case. Generated handler `aecdc2fe...`
contains flattened `u8/bool/i16/i32` call sites across several nested branches.
The IL2CPP code is copied into an anonymous executable mapping under Wine, so
file-backed perf uprobes correctly produced no samples; a long-lived GDB attach
also blocked Unity scheduling. A version-bound shared-object hook was instead
loaded in one brief attach, patched four candidate primitive readers, and
detached before replay. It logged packet pointer, pre-read cursor, opcode, and
caller without payload values. One local-client replay produced 1,305 ordered
`u8/bool/i32` records on a single opcode-`135` packet object. The sequence is
strictly monotonic from framed cursor `6` through `3729`; its 45 gaps are all
two bytes, the generated `u16` reader never executes, and the generated `i16`
reader supplies exactly those 45 reads. Replaying the reconstructed 1,350-read
grammar against the private plaintext consumes all 3,725 bytes and re-emits it
byte-for-byte. The checked-in manifest records only this structural grammar and
redacted count evidence; the private trace and plaintext remain ignored.

Exported plaintext JSONL under `target/private/` is evidence, not source: it
contains private captured bytes, remains ignored, and must not be committed or
pasted into reports. The checked-in manifest and deterministic dump describe
structure without carrying those payloads.

## Identified IL2CPP types

Original metadata/source-path strings established these names:

```text
Framework.Network.AESCipher
Framework.Network.AESCipher|AES_ALG_INFO
Framework.Network.AESCipher|RIJNDAEL_CIPHER_KEY
Framework.Network.InnoGuardCipher
Framework.Network.Packet
Framework.Network.Session
Framework.Network.WxStreamHash
```

The obfuscated class corresponding to `AESCipher` is:

```text
b9e4d430c4a28790f54a8a9fe532d8350c30e9e1a98f418c9035a0543963dbd
```

Probable `InnoGuardCipher` class:

```text
dfd720eb92098e5f57828e9d010d1e6027d22c2abfde17f67508206f70c6c2c
```

The standard public MapleStory AES key and standard IV-shuffle table were not
present as literal byte sequences in `GameAssembly.dll`, so do not assume a
stock cipher implementation.

## GDB static-array dumper

The current script is:

```text
/home/sdancer/ms/tools/maplestory_classic_server/tools/gdb_dump_cipher_arrays.py
```

It attaches to the Wine-hosted Windows x64 process and manually builds Windows
x64 ABI calls using `RCX`, `RDX`, `R8`, `R9`, and shadow-stack space. Normal
GDB inferior calls use the wrong ABI in this situation.

Launch the client first, then attach:

```sh
CLIENT_PID=$(pgrep -n -f 'Maplestory_Classic.exe')

sudo gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'set print thread-events off' \
  -ex 'set architecture i386:x86-64' \
  -ex 'handle SIGSEGV nostop noprint pass' \
  -ex 'set scheduler-locking on' \
  -ex 'source /home/sdancer/ms/tools/maplestory_classic_server/tools/gdb_dump_cipher_arrays.py' \
  -p "$CLIENT_PID"
```

This is invasive debugging against a disposable client run. Restart the Wine
prefix afterward if the inferior becomes unstable.

## Relevant IL2CPP export RVAs

These RVAs were resolved for the current `GameAssembly.dll` build:

```text
il2cpp_alloc                     0x425dc0
il2cpp_domain_get                0x426f00
il2cpp_domain_assembly_open      0x426f10
il2cpp_assembly_get_image        0x3fd740
il2cpp_class_from_name           0x425ec0
il2cpp_class_get_field_from_name 0x425f40
il2cpp_field_static_get_value    0x427250
il2cpp_runtime_class_init        0x38e700
il2cpp_class_get_name            0x425f70
il2cpp_class_get_namespace       0x425f80
```

Re-resolve these after any game update; they are build-specific.

## Current reverse-engineering result

The cipher is no longer the blocker. Runtime probes and focused Cpp2IL output
were sufficient to implement AES payload processing and IV shuffling with
observed-vector tests.

The active work is now in the login controller and world parser. Build-specific
RVAs for the current client are:

```text
login opcode-1 handler       0x00c0e5c0
login transition helper     0x00c08230
world opcode-2 handler       0x00c10630
world record parser          0x012cb2e0
UTF-16 packet string reader  0x01cd0ca0
```

The string reader consumes a `uint16` character count, UTF-16LE code units,
and a trailing byte. That final byte was the source of the earlier malformed
world records.

Focused output for the opcode-`1` handler also shows that it reads a result
byte followed by account identifiers/flags, strings, and fixed-width values
before initializing global login state. Replacing the handler with a direct
transition therefore skips essential setup. A bounded 128-byte zero-filled
payload is currently used to exercise the original parser safely while the
full account schema is recovered.

The successful stream-`83` reference now closes that structural gap. Its
63-byte account response parses exactly through result, account ID, three
flags/booleans, three UTF-16 strings, a `uint16`, three additional flag bytes,
an `int64` timestamp, and two trailing bytes. Account strings do not consume
the world parser's extra trailing byte. The reference opcode is `0`, while the
local build reaches this handler with opcode `1`; replay rewrites only those
two opcode bytes.

The same reference validates the world parser without GDB: all five
2,183-byte records consume exactly, including 60 channels apiece. Flags `1`
and `2` render named/online tabs live. Client opcode `4` selects a world,
server opcode `402` performs a two-packet timed transition, client opcode `5`
selects a channel, server opcode `4` carries the character list, client opcode
`7` selects a character, and server opcode `5` performs the handoff.

The opcode-`4` handler's indirect character-data constructor matches the
world-entry stat prefix followed by its appearance parser. Capture evidence
then fixes the remaining control flow: two reserved `uint32` values and a byte
count precede the records; each record has two sentinel-terminated appearance
slot maps, seven neutral `uint32` style values, an entry byte, a ranking flag,
and optionally four signed ranking values; a six-byte trailer follows the
record loop. This consumes both the one-record 170-byte stream-`83` response
and the empty 18-byte `1-10FS.pcapng` stream-`116` response exactly. Neutral
names are retained where the handler establishes width/control flow but not
game meaning.

Focused Cpp2IL output for the world parser is stored under:

```text
/home/sdancer/ms/.codex_tmp/maple_world_type_isil/IsilDump/Assembly-CSharp/
```

The current GDB probes live in
`tools/maplestory_classic_server/tools/`:

```text
gdb_force_login_transition.py
gdb_redirect_login_opcode1.py
gdb_patch_login_opcode1_transition.py
gdb_patch_login_opcode2_transition.py
gdb_dump_world_parser.py
gdb_stage_opcode2_controller_capture.py
gdb_trace_packet_reads.py
```

`gdb_dump_world_parser.py` reports only structural fields and handler branches;
it does not dump credentials or ticket data. In practice, leaving GDB attached
stalls Wine/Unity rendering even when the probe is armed after startup, so it is
not suitable for timing-sensitive validation.

`gdb_stage_opcode2_controller_capture.py` is the current non-stalling probe. It
validates the opcode-`2` and world-parser prologues, redirects both through
separate verified zero-filled executable padding regions at RVAs `0x52de900`
and `0x52de940`, stores controller/stream/world arguments in writable padding at
RVA `0x6be5b80`, executes the exact displaced prologues, and returns to the
original functions. Its `arm`, `status`, `restore`, and `dump` actions each
attach only briefly. The transparent run confirmed that the handler and parser
both execute and that the parsed object contains world `test` with channel
`test-1`.

Focused Cpp2IL output for controller field `+0xc8` is stored under:

```text
/home/sdancer/ms/.codex_tmp/maple_world_event_isil/IsilDump/Assembly-CSharp/
```

That field is wrapper type
`b7915082055ad4e85ef9b377003089ac7f24de4489704b7129555d1243d4684`.
Its `List<World>` backing field is wrapper `+0x50`, and its add method is the
handler's call at RVA `0xa9a540`. Reading wrapper `+0x18` as a list count caused
the earlier false zero-world result. The corrected dump reports `worlds=1`.

Attaching before NGS finishes startup can still invalidate the run. Do not
leave a breakpoint probe attached, and always restore process-local patches.

`gdb_trace_packet_reads.py` traces the build's packet primitive readers by RVA.
Its manifest-backed labels now cover all 12 readers used by this build:
`u16=0x1cd0300`, `u8=0x1cd0530`, `bool=0x1cd0560`, `i8=0x1cd0700`,
`i16=0x1cd0730`, `i32=0x1cd0760`, `i64=0x1cd0790`, `u64=0x1cd07c0`,
`datetime=0x1cd09d0`, `u32=0x1cd0b00`, `utf16=0x1cd0ca0`, and
`string=0x1cd0ce0`. Opcode filtering accepts either the cached plaintext opcode
or the opcode at the framed buffer cursor, which avoids silently dropping the
first targeted read.

Set `MAPLE_TRACE_OPCODE` to restrict output to one plaintext opcode,
`MAPLE_TRACE_DUMP_BYTES=0` to omit repeated packet-buffer hex, and
`MAPLE_TRACE_STOP_CURSOR` to disable all reader breakpoints at a known final
cursor. The compact opcode-`157` run used:

```sh
MAPLE_TRACE_OPCODE=157 \
MAPLE_TRACE_DUMP_BYTES=0 \
MAPLE_TRACE_STOP_CURSOR=4506
```

The stream-`114` initial field packet produced 734 reader calls and reached the
configured final cursor, which made the trace useful as a complete structural
read ledger rather than a truncated console dump. Use GDB non-stop mode and
`continue -a`; set non-stop before `attach`, pass `SIGSEGV`, `SIGUSR1`, and
`SIGUSR2` without stopping/printing, and issue `continue -a` again if attach
left other threads stopped. Detach immediately after the targeted packet; an
all-stop or lingering attach stalls Wine's worker/GC threads. Even the
non-stop trace can destabilize the instrumented client after hundreds of
breakpoints, so treat that client process as sacrificial and validate the
recovered layout offline against the PCAP. The decoded 112-byte prefix now
round-trips both stream `92` and stream `114`. The trace's repeated item-reader
callers also bound five equipment groups and the use/setup/etc/cash lists; the
two extracted inventory regions round-trip independently. The remaining
1,422 bytes decode into counted skill, string-property, timestamp, saved-map,
and extended-property collections plus a fixed trailer. The complete initial
packet is now structurally bounded; semantic identification of neutral fields
is the next boundary.

The same short-lived method closed both expanded variable-server records. For
opcode `385`, the trace read the discriminator bool at framed cursor `6`, then
89 repetitions of `u8` and `i32`, ending exactly at framed cursor `452` for the
448-byte plaintext. For opcode `156`, it read `u8` at cursor `6`, a five-byte
packet UTF-16 string at cursor `7`, bool at `12`, and three `i32` values at
`13`, `17`, and `21`, ending exactly at cursor `25` for the 21-byte plaintext.
Offline capture decoding and exact re-emission confirm both ledgers. The live
client then accepted exact post-bootstrap replays of both packets without a
map/player-state change and continued pairing heartbeats. These traces prove
field widths, repetition counts, and complete consumption only; names remain
neutral and no security interpretation is attached.

The next generated-shape pass closed two more finite field-bootstrap records.
Opcode `147` needs no live trace: its generated handler performs eight direct
signed-`i32` reads for two rectangles, then an `i32` count and that many
signed-`i32` values. Its exact 94-byte packet is byte-identical in streams
`92`, `114`, and `126`. Opcode `272` delegates immediately, so the generated
top-level dump supplied the handler boundary and a focused live
primitive-reader trace supplied the body. Starting at framed cursor `6`, the
trace consumed one `i32`, two `i64`, five `i32`, an entry count, then 11
entries. Each entry reads an `i32` selector, two booleans, and two independently
counted lists of three-`i32` records. One final `i32` ended exactly at framed
cursor `1,060`, the end of the 1,056-byte plaintext plus framing cursor bias.
Offline parse/re-emission and the native manifest consume all six cross-corpus
packets exactly. The active client accepted the same opcode-`272` plaintext
twice after bootstrap and continued heartbeats; the GDB pause, not packet
processing, explains the observed 36.6-second round-trip outlier. This evidence
establishes widths and repetition only, so selectors and values stay redacted
and semantically neutral.

The automatic `tools/il2cpp_packet_dump` output now also drives opcode `148`
instead of leaving every occurrence as a hex prefix. Its top-level handler
delegates to a manager parser and exposes variants `9`, `10`, `12`, and `13`.
The current GameAssembly data value resolves the delegated record mask to
`0x9`; the same value was confirmed in a short live process read. That evidence
bounds count-zero variant `9`, empty variant `10`, and the two signed-`i32`
variants `12`/`13`. One 1,639-byte legacy variant-`9` packet with 12 records
does not consume under the current parser, so the generated manifest keeps its
1,632-byte record region as an explicit capture-pinned opaque shape rather than
claiming a false decode. All other 22 cross-corpus packets use the semantic
switch shape. A live replay of variant `10` matched the predicted neutral fold,
left core state unchanged, and kept the client and heartbeats active.

Cross-corpus validation also corrected the automatic manifest's manual client
opcode-`43` layer. Stream `92` alone made values `4`, `8`, and `12` look like
compact discriminators, but stream `126` uses those same leading bytes in the
counted UTF-16 form and continues through `35`. The byte is therefore retained
as a neutral sequence. Two candidate shapes now share the opcode: a variable
`u8, u32, counted UTF-16, zero, byte[6]` form and a fixed
`u8, byte[9]` form. Total packet length distinguishes them without ambiguity.
Native validation consumes all 45 client packets, and the existing fixed
server shape consumes its three `u8, byte[16]` responses. The model does not
name the redacted identifier, string, or opaque bytes as security state.

Client opcode `114` is bounded directly from all 44 long-corpus packets rather
than from a server handler. Offsets `3..4` are a little-endian UTF-16 code-unit
count, followed by exactly that many code units, a required zero byte, and one
final u32. Counts `8/9/11` explain all observed lengths `26/28/32` under the
same grammar. The leading u8 is nondecreasing, but the trailing u32 decreases
22 times and cannot be retained as a client-tick interpretation. The manifest
therefore uses neutral names and the gameplay fold redacts both text and final
value. Timing near tutorial/UI packets remains hypothesis-only evidence.

Client opcode `66` closes the adjacent server opcode-`348` envelope at the
capture level. Selector counts match exactly (`0:20, 3:2, 6:7, 17:2`), and a
chronological per-selector FIFO leaves all 31 transactions matched with no
orphan on either side. Twenty-five client packets are only `u16 opcode, u8
selector, u8 status`; six selector-`6`/status-`1` packets add one u32. The
automatic manifest represents the observed selector/status branches as one
nested switch, and native validation consumes all 31 without ambiguity. The
u32 remains redacted because correlation proves the response boundary, not its
meaning. Round trips span `728.174..10,436.006` ms (median `1,561.373` ms).

Live replay also found a necessary state boundary. Sending one exact
selector-`0` opcode-`348` packet from the level-1-to-10 session to the active
level-12 short-stream client produced no opcode `66`; the client answered one
more heartbeat and then closed the world connection. Recovery through the
browser-free launcher and direct nested-Wayland seat returned it to the field
with 719/719 matched heartbeats. This negative cross-state result prevents the
offline adjacency from being generalized into a state-independent injection
recipe.

The final stream-`92` opaque pair demonstrates the same evidence discipline.
The automatic `tools/il2cpp_packet_dump` artifact contains the opcode-`394`
enum member but no attributed managed handler, so it cannot supply a reader
grammar. Exact capture accounting instead closes the 119-byte server payload
as a 57-code-unit trailing-zero UTF-16 envelope and the client opcode-`279`
payload 57.92 ms later as one neutral byte plus the same envelope width. A
private code-unit comparison finds one changed span, indices `10..14`, with all
52 other units equal. That is strong temporal and structural correlation, but
an exact injection into the live local-Wine field session produced no opcode
`279` while leaving the client responsive. The checked-in model therefore
records redacted envelopes, correlation, and gap timing without calling the
pair security state or treating opcode `279` as a guaranteed response.

The remaining short-stream client exit cluster is capture-driven because the
automatic dump describes incoming server handlers, not these outgoing client
writes. Two independent world sessions provide the same ordering: empty opcode
`241`, a six-byte client status packet after roughly 65 ms, and terminal server
opcode `9` after roughly 166 ms. The status opcode differs (`46` in stream `92`,
`45` in stream `114`), but both bodies are exactly one redacted `u32`. That
repetition supports an `exit_requested` gamestate transition and temporal
pairing while leaving the value and reason semantics unnamed. Empty opcode `75`
is separately repeated at the same initial field-loading boundary in streams
`92` and `126`, and the local-Wine replay independently emitted it. A local UI
exit attempt did not emit opcode `241`; no server terminal packet was forced,
so the live effect remains explicitly unproven.

The remaining fixed-width outgoing records use the same capture-bounded rule.
Opcode `307` no longer retains an opaque body: two references and 28 live
records all split as redacted `u32`, redacted `u32`, zero `u32`. Its second
value is zero 26 times and page-aligned in all four nonzero samples, but both
values and the record purpose stay neutral. Opcode `100` similarly no longer
does: both 26-byte samples decode as client tick, count `2`, then LUK/INT
stat-mask and increment pairs. The following opcode-`41` responses apply the
requested `1/4` and `9/29` gains exactly while consuming the summed `5/38` AP,
after 107.555/406.248 ms. Opcodes `308` and `311` also have stronger
cross-capture boundaries. The 74-byte opcode-`308`
record is two redacted doubles, two redacted `u64`s, a `u32` mirrored by two
doubles, and fixed controls; all 24 reference/latest-live mirrors agree. The
22-byte opcode-`311` record is zero `u64`, redacted `u32`, zero `u64` in all 13
samples. Timing still supplies only a cadence observation: opcode `308` repeats
near five minutes and opcode `311` near ten minutes after its first
bootstrap-skewed interval. Longer paused-live gaps keep that cadence
observational rather than mandatory. Three controlled nested-Wayland menu
confirmations in the local Wine session each emitted a 41-byte opcode-`310`
record with counted 16-unit UTF-16 and a zero-u32/zero-u8 suffix, but no opcode
`241` or phase change. The automatic manifest therefore adds typed neutral
`307/308/310/311` shapes. The gameplay fold redacts neutral values and exposes
only structural aggregates,
phase/epoch, and intervals. It does not promote timing or UI adjacency into a
semantic or replay claim.

The independent `1-10FS.pcapng` stream-`126` packet then exposed the compact
marker-`26` branch without another debugger trace. Exact offline cursor
accounting splits its 823 bytes into the shared character prefix, a 537-byte
nine-group inventory with five items, and a 172-byte progression. That final
region uses the common counted skills/properties/saved-map prefix, then a
seven-byte neutral variant header and compact trailer. Parsing and re-emitting
that variant byte-for-byte guards against treating a shorter valid branch as
an opaque exception or forcing the marker-`23` grammar onto it.

Client opcode `80` no longer needs a debugger trace for its primitive shape.
All 17 stream-`92` instances are exactly `u16 opcode, u32 tick, i16 Use slot,
u32 item template` and round-trip. Their typed state correlations establish
same-slot quantity `-1`, red-potion HP `+50`, and blue-potion MP `+80` with
maximum capping. The live reactive test reproduced the predicted red-potion
`2 -> 1` and HP `50 -> 100` effects. Keep the tick role and last-item
remove-versus-zero behavior unnamed until independent evidence resolves them.

Client opcode `185` also no longer needs a primitive-reader trace for its
captured boundary. Its 23-byte base and 35-byte extended forms, the three short
opcode-`49` result variants, and all three opcode-`312` removal widths
round-trip across stream `92`. FIFO inventory/mesos effect correlation plus
exact drop-id removal correlation matches all 54 local pickup chains. The
opcode-`311` drop spawn is already fully typed across its animated item/mesos
and field-load item/mesos variants; no additional primitive trace is required
for its captured boundary. Keep the opcode `185` validation token, optional
proof, opcode-`49` flags, and opcode-`312` reason/actor roles neutral.

## Next debugger work

1. Locate the inner character-record parser reached from the 170-byte server
   opcode-`4` response and name its exact fields.
2. Trace the two opcode-`402` branches only if the capture-faithful 2.5-second
   sequence still fails to produce client opcode `5`.
3. Trace the remaining finite field-bootstrap opcodes `27`, `28`, `142`, and
   `425`, preferring a generated direct-read ledger where available. Trace the
   bounded five-byte player-movement type-`3` command only if a controlled
   effect requires its semantics. The opcode-`41` stat-delta, opcode-`39`
   inventory-effect, opcode-`80` consumable-use, opcode-`185` pickup-request,
   and opcode-`311` drop-spawn grammars are complete at their evidenced
   boundaries.
4. Keep all patches process-local and validate prologue bytes before writing.

## Managed array layout confirmed in memory

For the arrays inspected in this Unity/IL2CPP build:

```text
array length: object + 0x18
array data:   object + 0x20
```

The dumper treats byte arrays as one-byte elements and one table as 32-bit
unsigned elements. It reports lengths, SHA-256 digests, and short previews
rather than indiscriminately dumping large tables.

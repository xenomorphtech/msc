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

Offline ordering comparison is the safe boundary for the remaining world
opcode-`13` bodies. Streams `92` and `114` each contain one server type `12`, a
server type `14` after `4934.955..4945.945` ms, and a client type `13` after a
further `27.305..30.942` ms. Four later stream-`92` type-`14` messages recur
`180.722..184.383` seconds apart and receive a client type `13` within the
combined `27.305..77.244` ms range. All six correlated bodies are 392 bytes on
both directions, but they are not byte-equal and offline comparison does not
establish a capture-stable inner primitive boundary. Model only FIFO timing and
equal-length evidence; do not
trace, label, synthesize, or replay the opaque body.

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

A 2026-08-13 opcode-`189` attempt showed that pre-enabling non-stop mode is not
sufficiently safe for this Wine build. Attach initially left worker threads
stopped; a second `continue -a` restored heartbeat traffic, but injecting the
333-byte stream-`114` record produced no primitive-reader log and opened
Wine's `Fatal error in GC` / `SuspendThread loop failed` window. GDB detached
cleanly, and the injection endpoint had accepted and written the frame, but
there is no client-parse or acceptance evidence. Do not repeat the opcode-`189`
GDB trace on this build; use lower-intrusion instrumentation or additional
offline/native analysis instead.

A fresh-process control showed that Frida is not a safe lower-intrusion option
for this Wine build either. The client had completed world handoff and was
pairing generated heartbeats before a bare Frida attach with no script or
hooks. `frida.attach` returned `ProcessNotRespondingError` because the process
refused the agent load or terminated during injection; the client process and
world connection then disappeared. No packet was injected in this attempt, so
it is attach-safety evidence only. Do not retry Frida against this build.

Offline method recovery subsequently closed the first 16 bytes of opcode
`189`'s pre-appearance bridge without runtime attachment. Bridge parser RVA
`0xd5c740` maps to `fda0a837...::d8fe2358...`; before its conditional
dispatch, it invokes `cd0d0bca...::a910877d...`. That method performs four
consecutive packet `UInt32` reads into the four-field `cd0d0bca...` value
type. Decoding all 114 entries confirms a 16-byte four-word mask prefix in
every 128/129-byte bridge. The masks have one nonzero word and seven enabled
bits in 112 entries, and two nonzero words and eight enabled bits in two; raw
words remain redacted. The codec re-emits all four words exactly.

Further offline recovery established that `a910877d...` stores those wire
words in reverse logical field order. Every captured mask enables the seven
virtual-array slots at logical indices `82..88`; the two 129-byte stream-`92`
bridges additionally enable direct bit `7`, whose `d8fe2358...` branch reads
one `u8`. Two unconditional `u8` reads follow. The `fda0a837...` instance
constructor creates exactly seven virtual records, and its factory reduces the
slot indices to `82..88`. Offline LibCpp2IL metadata resolution maps the
factory globals to their exact classes, establishing logical-slot widths
`15/15/15/13/20/17/15`. Every record starts with two `i32`s and the DateTime
helper's `u8 + i32`; the 15-byte form adds `u16`, the 13-byte form stops at the
base, the 20-byte form adds a second DateTime and `u16`, and the 17-byte form
adds `i32`. The helper consumes each `i32` regardless of its flag value. All
114 bridges are therefore completely typed after the mask without attaching
to Wine.

Static control-flow recovery closed the first residual opcode-`189` tail
boundary without runtime attachment. The outer delegate calls the bool reader
at RVA `0x1182ba8`; a true result enters an `i32` read at `0x1182be7` and the
loop repeats through the bool read at `0x1182d48`. The false exit reaches three
consecutive `i32` reads at `0x1182e42`, `0x1182e52`, and `0x1182e62`, then a
`u8` at `0x1182e89`. Offline decoding and exact re-emission validate that
grammar across all 114 opcode-`189` records. Every initial/terminating bool and
final `u8` is zero, while the three-`i32` zero masks are `000 x 74`, `011 x
24`, and `111 x 16` (`1` means zero). The codec preserves generic nonzero loop
flags and values but exposes only counts/nonzero summaries in safe output.

The variant byte is zero in all captures. The delegate computes its comparison
constant from static byte `0x15 + 0xeb`, which wraps to zero; equality selects
RVA `0x1183116`. That path reads another bool at `0x1183144`. True selects the
packet UTF-16 reader at `0x1183174`, preserving its otherwise discarded
trailing byte. Both branches join at the bool read at `0x1183252`. A true value
there gates the `i64` pair at `0x1183272/0x118327c`; the next bool at
`0x118328c` similarly gates `0x11832aa/0x11832b4`. The bool at `0x11832c4`
gates `u32/u32/i32` reads at `0x11832e2/0x11832f2/0x1183302`, and a final bool
at `0x11833a8` selects the next branch. Its false path jumps directly to RVA
`0x1183720`. The true path first performs runtime-state-dependent work, then
every arm reconverges at `0x1183720` and reads another bool at `0x1183725`.

Exact offline execution of that grammar consumes all 114 records without
overrun and re-emits them byte-for-byte. Encoded prefix lengths are `6 x 83`,
`25 x 24`, and `34 x 7`. All 24 optional strings are empty; the raw trailing
byte is `16 x 18` or `20 x 6`. The first `i64` pair is absent, the second occurs
31 times, the numeric group seven times, and the continuation branch 24 times.
All 114 records execute the follow-up bool after reconvergence: 111 values are
zero and three stream-`92` values are one; every true-continuation record has a
zero follow-up. The call site loads the player object's parser field at RVA
`0x118381e`; its null path throws, while the successful non-null path calls
`e3ad4d05...::ef3213da...` at `0x1183857`. That callee begins with a
packet-string helper at `0x16ca271`. Both later subobject checks are generated
null guards, not optional wire branches: null reaches
`il2cpp_codegen_raise_null_reference_exception`. The first required subrecord
at `+0x18` calls its parser at `0x16c9ea0`, which invokes the same packet-string
helper four times and then reads one `u8`. The required `+0x20` subrecord then
reads one `i32` at `0x1cd0760` and one DateTime at `0x1cd09d0`. The player base
constructor creates the outer `+0x380` object, and that object's constructor
creates both nested records. The opcode factory clones a Unity prefab, however,
so serialized state can still replace constructor defaults.

The helper at `0x1cd0ca0` calls the base packet-string reader at `0x1ccffc0`
and then the `u8` reader at `0x1cca780`. The base reader consumes `u16` code
units followed by twice that many UTF-16LE bytes; the trailing `u8` is consumed
without a zero check. The whole delegated record is therefore five packet
strings, one further `u8`, one `i32`, and one eight-byte DateTime, with a
28-byte all-empty minimum. Offline execution succeeds without underflow for
`30/2/32` records in streams `92/114/126`. Those 64 records re-emit exactly;
the other 50 keep the entire suffix opaque. All five compatible strings are
empty. Safe output exposes only lengths and nonzero summaries. The remaining
opaque suffixes still end in the shared 12-byte sequence, but that shape does
not establish another reader boundary. Values and text remain redacted and
semantically neutral.

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
is `acda742a...::c430c9bc...`; it resolves the `c5b43350...` singleton and
tail-calls that manager's packet parser, which exposes variants `9`, `10`, `12`,
and `13`. The current GameAssembly data value resolves the delegated record
mask to `0x9`; the same value was confirmed in a short live process read. The
record deserializer proves mask `0x9` means two signed `i32` values, two
DateTime/`i64` values, and one counted UTF-16 value with a required trailing
zero byte. The tracked parser and generated manifest now encode that complete
repeat grammar and redact every record value except text code-unit counts.

The one 1,639-byte capture packet still fails the exact current grammar at its
first record because the required string terminator is nonzero. Its 12-record,
1,632-byte body is divisible into 136-byte slices, but all byte positions vary
across those slices and no fixed zero or UTF-16-like region independently
supports that boundary. It therefore remains a lossless legacy opaque fallback
and an exact capture-pinned manifest shape rather than a guessed decode. The
other 22 cross-corpus packets use the semantic switch shape. A live replay of
variant `10` matched the predicted neutral fold, left core state unchanged, and
kept the client and heartbeats active.

Cross-corpus validation first corrected the automatic manifest's manual client
opcode-`43` switch, then chronological correlation supplied the missing
semantics. The leading byte equals the active field epoch in all 45 packets,
and every request is followed by the next opcode-`157` field snapshot without
an intervening transfer. The variable form is `u8 epoch, i32 -1, counted
UTF-16 portal name, zero, i16 x, i16 y, u16 zero`: its 42 names are conventional
portal identifiers such as `west00`, `east00`, `out00`, and `in01`. The three
fixed forms are `u8 epoch + nine zero bytes`; each follows a same-epoch HP-zero
stat update, bounding them as death respawns. Total length distinguishes the
forms without ambiguity, and sentinel/zero guards reject shapes outside the
corpus. Portal text stays redacted even though the field roles are now typed.

The response boundary is server opcode `157`, not server opcode `43`: all 45
transactions match, with `28.125..940.035` ms latency and no pending request.
The fixed server opcode-`43` family remains separately neutral.

Cross-corpus chronology also resolves the earlier neutral positioned-effect
family as the field-reactor lifecycle. The pinned handler grouping and client
strings (`Reactor/{0:D7}`, `reactorState`) identify the subsystem; the exact
server shapes make opcode `322` spawn, `320` state update, and `323` removal.
All 82 stream-`126` lifecycle records round-trip, and every update/removal
references an active same-field object.

Client opcode `225` closes the transaction. All 15 exact 16-byte requests
reference an active reactor immediately after opcode-`50` attack, then
FIFO-match the next same-object state update (12) or removal (3). The 12
updates echo the request stance, every response arrives within
`388.463..1,102.698` ms, and no request is left pending. This correlation
supports typed reactor roles while keeping runtime object ids aliased and the
character-position value build-specific.

The same cross-version grammar check corrects client opcode `158` mode `0`.
Its former nine-byte opaque tail is exactly one `u32 key, u8 binding type,
i32 action` record after a count of one. Eleven stream-`126` packets exercise
empty, skill, item, and action bindings across evdev Left Ctrl, Left Shift,
Home, and keypad zero. Modes `1` and `2` remain the count-zero field-load
sequence; one counted manifest shape consumes both branches exactly.

Use independent client enums as semantic corroboration only after the local
wire shape is exact. Here the legacy-client `KeyType` values `4`/`6` name the
already captured opcode-`385` selector families as menu/face, and `KeyAction`
keeps pickup/sit/attack/jump/interact consecutive at `50..54`. The current
snapshot's seven selector-`6` values `100..106` and focused `M` menu control
agree. This is enough to name safe state fields, but not to widen opcode-`158`
mode-`0` beyond binding types `0/1/2/5` actually observed on the wire.

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
`2 -> 1` and HP `50 -> 100` effects. The last-item remove-versus-zero behavior
remains unnamed because the capture does not exercise it.
Independent v79 handler source resolves the shared leading u32 by passing it
to `updateTick` for both item movement and Use-item requests; the same item-
move handler names the final signed short quantity. That source-level role
confirmation promotes the already fully correlated opcode-`79` and opcode-
`80` reference requests without expanding their responder policies.

Client opcode `185` also no longer needs a primitive-reader trace for its
captured boundary. Its 23-byte base and 35-byte extended forms, the three short
opcode-`49` result variants, and all three opcode-`312` removal widths
round-trip across stream `92`. FIFO inventory/mesos effect correlation plus
exact drop-id removal correlation matches all 54 local pickup chains. The
opcode-`311` drop spawn is already fully typed across its animated item/mesos
and field-load item/mesos variants; no additional primitive trace is required
for its captured boundary. Keep the opcode `185` validation token, optional
proof, opcode-`49` flags, and opcode-`312` reason/actor roles neutral.

Client opcode `207` now applies the same source-and-capture boundary to its
high-volume control prefix. The original v83 writer emits six one-byte action
arguments followed by a reserved 13-byte region. Two independent server
handlers support option/activity and skill-id/level placement, while differing
on whether the final two bytes form one option or separate values. The codec
therefore exposes option flags, signed activity code, skill id/level, and two
neutral auxiliary bytes. Guida83 reads the remaining 13 bytes as `u8` plus
three `u32` values, closing the source-backed structural boundary while leaving
their behavior neutral. Across both captures, the marker is zero, the first
u32 is `0/1`, and the final pair is `0x00ffddcc`. Stream `92` validates that
split across 12,100 paths and stream `126` across another 22,855, all at full
coverage; captured option flags are `0`, `1`, and `17`, while signed activities
are mainly `-1` with `12`, `13`, and `24` also observed. Acknowledgement flag
prediction now names the typed option field instead of indexing an opaque byte.

## Next debugger work

1. Locate the inner character-record parser reached from the 170-byte server
   opcode-`4` response and name its exact fields.
2. Trace the two opcode-`402` branches only if the capture-faithful 2.5-second
   sequence still fails to produce client opcode `5`.
3. Trace the remaining finite field-bootstrap opcodes `27`, `28`, `142`, and
   `425`, preferring a generated direct-read ledger where available. Trace the
   bounded five-byte player-movement type-`3` command only if a controlled
   effect requires its semantics. For life movement, the independently sourced
   v83 parsers now cover captured command tags through `17`; keep unobserved
   tags `18..22` neutral until a reference packet exercises them. The
   opcode-`41` stat-delta, opcode-`39`
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

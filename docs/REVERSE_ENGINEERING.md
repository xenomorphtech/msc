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
`continue -a`; an all-stop attach stalls Wine's worker/GC threads. Even the
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
remaining useful trace target is opcode `311`, which must establish a typed
field-drop spawn before a safe live pickup can be generated. Keep the opcode
`185` validation token, optional proof, opcode-`49` flags, and opcode-`312`
reason/actor roles neutral.

## Next debugger work

1. Locate the inner character-record parser reached from the 170-byte server
   opcode-`4` response and name its exact fields.
2. Trace the two opcode-`402` branches only if the capture-faithful 2.5-second
   sequence still fails to produce client opcode `5`.
3. Trace opcode-`311` field-drop spawn to enable a controlled live pickup;
   trace the bounded five-byte player-movement type-`3` command only if a
   controlled effect requires its semantics. The opcode-`41` stat-delta,
   opcode-`39` inventory-effect, opcode-`80` consumable-use, and opcode-`185`
   pickup-request grammars are complete at their evidenced boundaries.
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

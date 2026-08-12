# Maple IL2CPP packet dump

This Rust CLI creates a reproducible, version-locked view of MapleStory
Classic's IL2CPP packet surface. It has three deliberately separate layers:

- the complete `ushort` opcode enum and every method carrying the packet
  handler attribute;
- ordered *direct* calls from each handler to known packet-reader RVAs, taken
  from ISIL (these are evidence, not a claim that branches or helper parsers
  were flattened);
- manually analyzed packet shapes, plus explicitly labeled observed-opaque
  variants whose opcode/direction/total width is pinned without claiming
  unproven internal field semantics.

The current manifest pins protocol 300, the 2026-08-08 client binaries, the
obfuscated enum/attribute identities, reader method RVAs, and the SHA-256 of
both reference captures, `111.pcapng` and `1-10FS.pcapng`. A mismatched binary,
metadata file, enum file, or capture is rejected.

## Build and dump

Run from this directory:

```sh
cargo run --release -- verify \
  --manifest versions/maple-classic-300-2026-08-08.json

cargo run --release -- dump \
  --manifest versions/maple-classic-300-2026-08-08.json \
  --output target/current-il2cpp-packets.json
```

The dump is stable JSON: no timestamps or absolute source paths, and opcodes,
handlers, files, and reads have deterministic ordering.

## Capture JSONL and exact-consumption validation

The exporter asks `tshark` only for TCP segments. Rust performs endpoint
identification, overlap-checked TCP reassembly, handshake parsing, Maple
AES-OFB decryption, IV advancement, frame-header validation, and JSONL
serialization itself. It also locates a valid Maple greeting within the first
4,096 reassembled bytes and removes the corresponding per-direction transport
preludes. This is required for `1-10FS.pcapng` stream `126`, whose measured
preludes are 28 client bytes and 14 server bytes.

```sh
cargo run --release -- export-pcap \
  --manifest versions/maple-classic-300-2026-08-08.json \
  --pcap /home/sdancer/Downloads/111.pcapng \
  --stream 83 --stream 92 --stream 114 \
  --output tests/private/111.streams-83-92-114.jsonl \
  --summary target/111.streams-83-92-114.summary.json

cargo run --release -- validate \
  --manifest versions/maple-classic-300-2026-08-08.json \
  --input tests/private/111.streams-83-92-114.jsonl \
  --output target/111.shape-report.json \
  --require-all-supported

cargo run --release -- export-pcap \
  --manifest versions/maple-classic-300-2026-08-08.json \
  --pcap ../../1-10FS.pcapng \
  --stream 126 \
  --output target/private/1-10FS.stream-126.jsonl \
  --summary target/1-10FS.stream-126.summary.json
```

Each JSONL row includes plaintext hex and therefore can contain private
account, character, or network data. `tests/private/*.jsonl` is intentionally
ignored; do not commit or paste it into logs. Rows also carry the capture hash,
stream, direction/index, opcode, byte length, and plaintext hash.

The validator fails on a short read, trailing/extra bytes, a wrong expected
constant, a non-`0`/`1` generated `bool`, payload hash mismatch, ambiguous
shape, or (with
`--require-all-supported`) any absent opcode/length variant. Semantic shapes
and observed-opaque width pins are distinct in the manifest: an opaque variant
proves framing and exact total consumption, but does not pretend that its body
fields have been decoded. Run the pinned regression with:

```sh
cargo test --release --test current_version -- --ignored
cargo test --release --test capture_jsonl -- --ignored
```

For capture 111 streams 83, 92, and 114 the pinned regression contains 35,316
packets. All 35,316 are covered and exactly consumed: zero unsupported variants
and zero short-read, over-read, constant, ambiguity, or hash failures. The
manifest currently declares 135 semantic/manual shapes and 88 explicitly
observed-opaque exact-width variants. Eleven exact-width opaque pins overlap
semantic shapes and are retained as raw capture evidence but suppressed from
the effective shape set. Opcodes `276`, `137`, and `29` add the twelfth through
fourteenth overlaps; opcode `135` adds the fifteenth. Opcode `169` adds a
non-overlapping shape found only in `1-10FS`; server opcode `394` and client
opcode `279` add the sixteenth and seventeenth overlaps. Client opcodes `46`,
`75`, and `241` add overlaps 18 through 20; opcode `115` adds the twenty-first.
The live-only, non-overlapping opcode-`310` width, local opcode-`0` probe, and
capture-backed client
opcode-`64`/`79`/`111`/`222`/`225`/`276`/`298` layouts add ten active shapes.
Five non-overlapping legacy-login layouts add the next five active shapes.
The final four stream-`116` login layouts add four more. Typed opcode-`307`,
opcode-`308`, opcode-`311`, and ability-point opcode-`100` layouts suppress four
opaque pins without increasing the effective shape count. Live selector-`5`
action-`51` controls add non-overlapping client chair sit/recovery/stand shapes
for opcodes `49`, `82`, and `48`. This leaves 198 active shapes and 63 active
opaque pins.
Opcode `135` combines handler `aecdc2fe...` with a detached local-Wine
primitive-reader trace. Its 1,350-read nested count grammar consumes and
re-emits the sole 3,725-byte stream-`114` packet exactly; the checked-in shape
contains no captured numeric values.
The opcode-`394`/`279` shapes are explicitly capture/correlation-backed. The
automatic dump proves that server enum member `394` exists but attributes no
managed handler. Exact framing supplies the server's trailing-zero UTF-16
envelope and the client's neutral-byte-plus-UTF-16 envelope; both contain 57
code units and suppress their matching opaque pins. A live local-Wine injection
did not elicit opcode `279`, so the manifest source and higher-level model do
not claim causal response or security semantics.
Client opcodes `75` and `241` add exact opcode-only shapes from repeated
cross-capture positions. Client opcode `46` adds the same redacted-u32 boundary
already declared for opcode `45`; both occur between opcode `241` and final
server opcode `9` in their respective world streams. These three shapes
suppress matching opaque pins without using the incoming-handler dump to claim
outgoing-client semantics it cannot provide.
Client opcode `307` now suppresses its opaque pin with the cross-capture shape
`redacted u32 + redacted u32 + zero u32`. Across two references and 28 live
records, the second value is zero 26 times and every nonzero value is page-
aligned; purpose and both values remain neutral/redacted. Opcode `100` also
suppresses its opaque pin with a counted ability-point allocation shape: client
tick, allocation count, and repeated stat-mask/increment pairs. Stream `92`
requests LUK/INT `+1/+4`, then opcode `41` applies those exact gains and spends
all five AP after 107.555 ms. Stream `126` independently requests `+9/+29` and
applies those gains while spending 38 AP after 406.248 ms. Opcodes `308` and
`311` also suppress their opaque pins with cross-capture typed shapes. Across 11
reference and 13 active-live opcode-`308` records, the layout is two redacted
`f64`s, two redacted `u64`s, one `u32` mirrored by two `f64`s, and fixed control
values. All 24 mirrors agree. All six reference and seven live opcode-`311`
records are `zero u64 + redacted u32 + zero u64`. Purpose remains neutral;
cadence is observational. Opcode `310` is separately typed from three
controlled local-Wine menu confirmations as counted 16-unit UTF-16 plus a
zero-u32/zero-u8 suffix. Its text, purpose, and UI role remain redacted/neutral,
and the manifest does not equate it with the captured opcode-`241` exit request.
Client opcode `79` adds a 13-byte semantic shape from two stream-`126`
transactions: `u32 client tick + u8 inventory type + i16 source + i16
destination + i16 trailing count`. Each request is followed by a server
opcode-`39` move with the exact same inventory/source/destination tuple. Native
validation consumes both records; the trailing signed-count role remains
neutral rather than being inferred from its captured value `-1`.
Client opcode `158` now uses one variable-length counted shape across all three
reference streams. Modes `1` and `2` have zero changes and encode the field-
load sequence. Mode `0` repeats `u32 key code + u8 binding type + i32 action`;
all 11 stream-`126` packets carry one change and match the independent v83
keymap-change grammar. Native validation consumes both 10-byte and 19-byte
variants through the same manifest shape.
Client opcode `225` adds one exact 16-byte reactor-hit shape for 15 stream-`126`
records: signed/redacted reactor object id, signed character-position value,
u16 stance, and a zero u32. Every request targets an active reactor introduced
by server opcode `322`, immediately follows client opcode `50`, and matches the
next same-reactor opcode-`320` state update or opcode-`323` removal. Native
validation consumes all 15 requests and all 12 updates echo the request stance.
Client opcode `298` adds one exact 76-byte shape for 12 stream-`126` item-
acquisition requests. The manifest consumes the selection, kind, item,
quantity, neutral duration, expiration, redacted serial, five reserved zeros,
two `-99` sentinels, two trailing zeros, and `0/1` flags. All 12 records match
the next same-epoch server opcode-`39` additions by kind-derived inventory and
item template; native validation consumes the isolated 12-packet corpus with
zero failures.
Client opcode `276` adds two capture-bounded selector shapes. The active local-
Wine transcript supplies selector `17` followed by three zero bytes; the sole
stream-`126` selector-`24` packet supplies two redacted header values, five
counted groups, and 19 redacted u32 pairs. Both shapes consume exactly without
assigning roles to the selector, group, header, or pair values.
Client opcode `222` adds the exact 19-byte compact branch of
`ItemPickupRequest`: epoch, tick, signed position, drop id, and neutral token,
without opcode `185`'s control word or optional proof. All six stream-`126`
records resolve to known same-epoch drops and complete the matching inventory
or mesos effect, gain notice, and removal chain. Isolated native validation
consumes all six packets with zero failures.
Client opcode `64` adds the exact 10-byte NPC-interaction request:
`uint16 opcode, uint32 npc_object_id, int16 player_x, int16 player_y`. Both
stream-`126` object ids resolve to active NPCs and both positions equal the last
same-epoch client opcode-`47` movement endpoint; the next same-epoch server
opcode `348` follows after `396.405..439.289` ms. Independent live
action-`54`/Space input emitted three more requests for active NPC template
`1032005`. Client opcode `111`
adds an exact eight-byte record containing a neutral u32 and signed slot; its
sole slot `3` matches the next opcode-`39` Cash remove/add after `486.349` ms.
The opcode-`111` u32, its higher-level action role, and causality remain
neutral. Isolated native validation consumes all three reference packets with
zero failures.
Client opcode `101` replaces its earlier five-neutral-value shape with the
exact recovery request boundary: reserved zero, type `20`, reserved u16, HP
recovery u16, MP recovery u16, and final zero. Stream `126` supplies 33 HP-`10`
and 113 MP-`3` packets; stream `92` supplies seven HP-`10` and 66 MP-`5`
packets. Python correlation matches all 219 to authoritative opcode-`41` stat
updates, while isolated native validation consumes all 219 with zero failures.
Client opcode `115` replaces its observed-opaque pin with the exact 22-byte
inner-portal request shape: active field epoch, redacted four-code-unit UTF-16
portal name with zero terminator, and signed source/destination positions. The
two stream-`92` paths chain within one pixel and remain in the same field epoch.
The native shape intentionally accepts only the captured four-code-unit width;
isolated validation consumes both records with zero failures.
Login client opcode `6` replaces its 1,836-byte observed-opaque pin with a
variable shape containing nine neutral `u32` header fields, a `u32` record
count, and repeated `(u16 index, u32 opaque value)` pairs. Stream `83` carries
299 records while stream `116` and the current live login each carry 152; all
three lengths satisfy `42 + 6*count`, and every Python-decoded sample has the
complete unique `0..count-1` index set. Isolated native validation exactly
consumes both capture records. Header and record values remain redacted and no
higher-level role is assigned.
Login client opcode `31` replaces its 183-byte observed-opaque pin with one
variable redacted shape shared by stream `83`, stream `116`, and the current
live login transcript. All three records have a 20-byte zero prefix, variant
`2`, three trailing-zero UTF-16 fields, a `uint32` blob length fixed at `48`,
the opaque blob, and a three-byte zero suffix. Their distinct total lengths
`183/275/201` and text code-unit patterns `10/0/38`, `7/51/36`, and `1/51/5`
exact-consume under the same grammar without assigning semantics or publishing
the retained contents.
Login client opcode `274` replaces its 1,698-byte observed-opaque pin with the
sole captured fixed variant: redacted 768/74-code-unit text regions around
captured constants `u32 2, u8 1, u8 1`, with both counted-text trailing bytes
fixed to zero. The isolated stream-`83` record exact-consumes natively; its text
contents and higher-level role remain neutral.
The live-only 36-byte server opcode-`0` shape records the documented local
account-bootstrap frame patch: result zero, one redacted `u32` id, three zero
flags, a redacted four-code-unit UTF-16 region, and a 16-byte zero suffix. It is
kept distinct from a complete account result and exact-consumes in isolated
native validation.
Legacy login server opcodes `3`, `390`, and `6` add generated-read-backed
layouts of `u8 + i32 + bool`, `u8`, and trailing-zero counted UTF-16 plus `u8`.
Client opcodes `255` and `9` add capture-bounded redacted `u32` and
trailing-zero counted UTF-16 layouts. All five stream-`116` packets
exact-consume in isolated native validation. The opcode-`6` text exactly echoes
the preceding opcode-`9` text after 235.214 ms; the opcode-`255`/`390` adjacency
at 238.384 ms remains evidence only, not a causal or semantic claim.
The remaining stream-`116` shapes exact-consume server opcode `35`, client
opcode `10`, server opcode `7`, and client opcode `16`. Opcode `35` is a neutral
redacted counted-text prelude. Opcode `10` is counted name plus eight redacted
`u32` values. Generated opcode-`7` handler `f2861e8a...` supplies the result
byte; the captured success body exact-consumes as the existing character
snapshot fields plus a fixed 49-byte compact-appearance variant. Its name and
seven-field appearance fingerprint match opcode `10`. Opcode `16` repeats the
created id and the next handoff repeats it again. All four isolated packets
validate natively, leaving zero unknown observations in both login references.
Login server opcodes `20`, `21`, `23`, and `161` replace four observed-opaque
pins with exact fixed-record shapes. Both reference login streams contain all
four: opcode `20` carries one neutral `uint32`, opcodes `21` and `161` carry a
zero `uint8`, and opcode `23` carries a zero `uint32`. The live login supplies
an independent opcode-`23` observation. Isolated native validation consumes
all eight reference packets; safe Python state reports only widths, opcode
counts, and zero status while the varying opcode-`20` value remains redacted.
Login server opcode `22` replaces its 34,447-byte observed-opaque pin with one
variable shape: `u32` entry count plus repeated trailing-zero counted UTF-16
text and `u16` index. The 299-entry stream-`83` packet and 152-entry
stream-`116` packet both exact-consume in isolated native validation; live is
byte-identical to the latter. All three index sets are complete and match the
later client opcode-`6` sets. Text and higher-level roles remain redacted.
Opcode `94` is no longer an
opaque width pin: its generated handler reads `bool + i32 + i32`, while opcode
`60` reads one signed `i32` and opcode `379` selects between a one-byte short
form and four `datetime/i64` values. Opcode `148` is represented by one
semantic switch shape: variant `9` with count zero, empty variant `10`, and
variants `12`/`13` with two signed `i32` values. The legacy nonempty variant-`9`
capture remains an explicit 1,639-byte opaque pin because its body does not
consume under the current build's delegated record mask `0x9`. The gameplay
transaction shapes cover
client opcode `103`, server opcode `46`, and client opcode `293`; all 26
occurrences of that family in `1-10FS.pcapng` stream `126` are exactly consumed.
Opcodes `60`, `94`, and `379` contribute 14 exact reference frames: ten in
stream `126` and four across `111.pcapng` streams `92`/`114`.
Targeted native validation also consumes all 23 opcode-`148` frames: 22 through
the semantic shape and the one legacy body through its exact opaque pin.
The client opcode-`43` shape is a field-transfer request, not a stream-`92`
switch keyed by its leading byte. Two unambiguous candidates describe the
cross-corpus boundary: a portal form with active `u8` field epoch, signed map
sentinel `-1`, counted UTF-16 portal name, signed position, and zero `u16`; or a
12-byte death-respawn form with the epoch plus nine zeros. All 45 client
packets validate natively and correlate to the next opcode-`157` snapshot. The
existing 19-byte server opcode-`43` shape remains a separate neutral family.
Client opcode `114` adds one variable-width redacted shape: a neutral `u8`, a
counted UTF-16 field with required zero terminator, and a trailing `u32`. It
consumes all 44 stream-`126` packets at lengths `26`, `28`, and `32`; text and
the final value remain omitted from safe gameplay analysis.
Client opcode `66` adds one selector/status switch shape correlated with server
opcode `348`. The five captured four-byte forms are selector/status `0/1`,
`0/255`, `3/1`, `6/0`, and `17/1`; selector/status `6/1` adds one redacted
`u32`. Native validation exactly consumes all 31 packets, and the manifest
rejects unobserved selector/status/length combinations.
Server opcode `147` adds the generated handler's two four-`i32` rectangles and
counted `i32` vector. Server opcode `272` adds the delegated handler's
live-traced header, counted nested ledgers, two validated booleans per entry,
and terminal `i32`. The semantic shapes replace only the matching 94- and
1,056-byte opaque pins in the effective set. Targeted native validation
consumes and re-emits all six cross-corpus packets (three identical packets per
opcode) without an
unsupported, short-read, trailing-byte, constant, boolean, or ambiguity
failure.
Server opcodes `27` and `28` add the generated handlers' signed record counts
and exact repeated integer/text grammars. Opcode `142` adds its generated
boolean gate and the exact delegated header plus counted text/control records.
Each has separate fixed-width declarations for the `111` and `1-10FS`
variants. Opcode `425` adds a 68-byte `u16`-counted signed-value ledger with a
four-word trailer; the three gameplay packets are identical, and a live trace
independently observed all 12 repeated `i32` reads. Targeted native validation
consumes all 13 selected packets without unsupported, short-read, trailing-byte,
constant, boolean, or ambiguity failures.
Server opcodes `228`, `230`, `231`, `232`, `234`, and `235` share generated
handlers that directly read exactly one `u32`. Seven fixed-width shapes retain
their remaining capture-bounded bytes as explicit opaque tails: five replace
matching `111` pins and two add widths seen only in `1-10FS`. Targeted native
validation consumes all 12 packets with zero unsupported or consumption
failures; higher-level analysis keeps them partial because the client handler
does not assign readable roles to the tails.
Server opcode `276` adds one direct generated `bool` read. Both gameplay
captures encode true as byte `0x05`; the pinned reader's ISIL calls
`BitConverter.ToBoolean`, so native boolean validation normalizes zero to false
and every nonzero byte to true before constant/branch checks. The semantic
three-byte shape suppresses the matching opaque pin, and targeted validation
consumes both cross-corpus packets without failure.
Server opcode `137` adds the generated handler's direct `i16/i32/i32` prefix
and a 72-byte capture-bounded tail. The semantic 84-byte shape suppresses the
matching opaque pin and validates both stream-`92` packets plus the one
stream-`126` packet; safe gameplay analysis keeps these observations partial
and redacts the prefix and tail.
Server opcode `169` adds the generated handler's selector-`3` arm rather than
its flattened branch superset. The first `u8` indexes an eight-way native jump
table; arm `3` calls the UTF-16 reader once and reaches the common return. The
semantic `u16 opcode + u8 selector + trailing-zero UTF-16` shape consumes the
sole 54-byte stream-`126` packet exactly. The payload text remains private and
only its 24-code-unit length is exposed by higher-level analysis.
Server opcode `29` adds the delegated grammar missing from its top-level
handler's empty direct-read list. Handler `b7bc850c...` constructs the ledger
through `0x180CB4390`, which reads a `u8` count and loops over record
constructor `0x180CB3F20`; each record reads
`i32/i32/trailing-zero UTF-16/i32/i16`. The semantic 327-byte shape suppresses
the matching opaque pin and exactly consumes both byte-identical four-record
packets from streams `92` and `114`. Text and numeric fields remain private;
higher-level analysis publishes only record and code-unit counts.
The complete 71,100-frame stream intentionally remains a broader modeling
corpus rather than an all-opcode manifest regression.

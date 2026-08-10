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
manifest currently declares 100 semantic/manual shapes and 96 explicitly
observed-opaque exact-width variants. Eleven exact-width opaque pins overlap
semantic shapes and are retained as raw capture evidence but suppressed from
the effective shape set. Opcodes `276`, `137`, and `29` add the twelfth through
fourteenth overlaps; opcode `135` adds the fifteenth. Opcode `169` adds a
non-overlapping shape found only in `1-10FS`; server opcode `394` and client
opcode `279` add the sixteenth and seventeenth overlaps. Client opcodes `46`,
`75`, and `241` add overlaps 18 through 20. This leaves 176 active shapes and
76 active opaque pins.
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
The client opcode-`43` shape is no longer a stream-`92` switch keyed by its
leading byte. Two unambiguous candidates now describe the real cross-corpus
boundary: `u8 + u32 + counted UTF-16 + zero + six bytes`, or the 12-byte
compact `u8 + nine bytes` envelope. All 45 client packets validate natively,
including sequences `13..35` from stream `126`; the existing 19-byte server
shape covers the other three opcode-`43` packets.
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

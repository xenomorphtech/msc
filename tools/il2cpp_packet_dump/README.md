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
manifest currently contains 71 semantic/manual shapes and 96 explicitly
observed-opaque exact-width variants, 167 total. Opcode `94` is no longer an
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
The complete 71,100-frame stream intentionally remains a broader modeling
corpus rather than an all-opcode manifest regression.

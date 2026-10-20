# Native MapleStory CW capture decoder

Exports **complete decrypted transport packets**, with original capture frame
numbers, timestamps, directions, opcodes, plaintext hex and SHA-256 hashes.
This targets the native `maplestorycw/appdata` client, not the protocol-300
Unity/IL2CPP client supported by the other tools in this repository. Its opcode
numbers and string encodings must not be passed to the older semantic parsers.

## Run

From the workspace containing `gameplay.pcapng`, `maplestorycw/` and `msc/`:

```sh
python3 -m venv .venv
.venv/bin/pip install -r msc/tools/cw_packet_decode/requirements.txt
# tshark must also be installed.
.venv/bin/python msc/tools/cw_packet_decode/decode.py gameplay.pcapng \
  --output msc/downloads/cw_decode/export \
  --binary-dir maplestorycw/appdata
.venv/bin/python msc/tools/cw_packet_decode/analyze.py \
  msc/downloads/cw_decode/export/stream-91.jsonl \
  --output msc/downloads/cw_decode/export
.venv/bin/python -m unittest discover -s msc/tools/cw_packet_decode -v
```

Discovery finds TCP streams 61 and 91. Explicit selection is available through
repeated `--stream` arguments. `tshark` reads the capture through stdin so the
exporter works with Ubuntu's restrictive AppArmor profile. All work is offline.

## Verified capture result

Capture SHA-256:
`0338c81f704e9d90c0a237a2e96e2a039c18819e86f3cae249d0d839ced93823`

| TCP stream | Role | Client packets | Server packets | Total |
| --- | --- | ---: | ---: | ---: |
| 61, port 8484 | Login/selection/handoff | 50 | 30 | 80 |
| 91, port 8541 | Gameplay | 11,672 | 18,432 | 30,104 |
| Both | | 11,722 | 18,462 | 30,184 |

Every encrypted byte is consumed. All 30,184 frame headers agree with their
direction's advancing IV, and all ciphertexts round-trip exactly. There are no
TCP gaps, conflicting overlaps, partial headers, or partial bodies. The clear
greetings occupy 54 and 21 bytes respectively, outside those packet counts.

These checks establish transport integrity and plaintext recovery. They do not
establish a complete interpretation of each packet's fields.

## Cipher evidence

The existing decoder supplied the AES chunking and Maple IV-shuffle algorithm.
The native binaries supplied the changed key and the second payload mode:

- Both directions of stream 61 and the client direction of stream 91 use
  AES-256 OFB, restarting at each Maple chunk: first `0x5b0` bytes, then chunks
  of `0x5b4` bytes, seeded by four repetitions of the current four-byte IV.
- The server direction of stream 91 encodes each plaintext byte as
  `(plain_byte + IV[0]) & 255`. Decode by subtraction, **not XOR**. The native
  executable's receive branch is at RVA `0x741677` (helper `0x7475e0`); the
  corresponding send addition branch is at `0x746442`.
- `ZLZ64.dll` initializes 32 DWORDs at RVA `0x83030` in function `0x3a60`.
  Key expansion at RVA `0x4250` reads DWORDs at byte offsets
  `0,16,32,48,64,80,96,112`. The executable's equivalent expansion is at
  RVA `0xcc1970`. Treating the DWORDs as a contiguous byte key gives the wrong
  result. The resulting AES key is:
  `0f0000001b000000c500000046000000f3000000be000000ff00000075000000`.
- The standard shuffle table appears in the executable at RVA `0x3b17840`
  and the DLL at `0x830b0`; the executable shuffle routine is around `0xcc3f30`.
- Encrypted payload length is the XOR of the two little-endian header words.
  The first word equals `u16le(IV[2:4]) XOR mask`; observed masks are `0x00df`
  client-to-server and `0xfffe` server-to-client. Each direction advances its
  IV once per complete encrypted packet.

The first seven-byte server ciphertext `5447f32f442643`, using IV `7156bc60`,
decrypts to `20000000000000`. This account-free captured vector is included in
the tests, alongside a captured IV/header transition.

Reference binary SHA-256 pins:

```text
MapleStory.exe 4384087a6df1991cb59fea6d1ef086dbe746c7a5af0705bfc39769f4cc56e276
ZLZ64.dll     2db9ec805a0cfab78dabd8978f42af2129cb91e9939fbd06f8992f80b4a192e9
```

## Outputs and interpretation limits

- `stream-61.jsonl`, `stream-91.jsonl`: lossless plaintext and wire provenance.
  `opcode` is the decrypted on-wire little-endian u16, not a guessed name.
  Six records also have exact `decoded_fields`: the two counted file lists
  (251 and 178 ASCII paths) and the two neutral text-ledger families (server
  opcodes 57 and 58, each observed in both streams). Parsing reaches the exact
  end of both multi-chunk AES file-list packets, independently checking payload
  structure beyond the first cipher chunk.
- `summary.json`: capture and binary hashes, greeting variants, frame/byte
  totals, integrity checks, and complete opcode/length distributions.
- `gameplay-events.jsonl`: bounded candidate events with raw tails retained.
- `correlations.json`: aggregate evidence for those candidates.

The optional analyzer is specific to this capture. It identifies nine server
opcode-422 snapshot candidates, matches all 9,159 server opcode-996 replies to
the preceding client `0xb226` packet with the same `u32/u16` prefix, and matches
81 empty server-opcode-1579/client-`0x43dd` periodic probe/response pairs. These
are evidence-backed relationships. They are not a claim that all movement,
entity status, inventory, combat, or field data has been semantically decoded.
The matching algorithm uses the most recent identical prefix within each
snapshot epoch: one key repeats, 60 outstanding requests cross snapshot
boundaries, and one remains at capture end. This avoids misreporting a reused
key as a five-minute response latency.

Gameplay contains 115 distinct server opcodes and 46 distinct client opcodes.
Many client opcode values are obfuscated (`0xb226`, `0x8111`, etc.). Server
opcode 50 carries a length-delimited 5,192-byte opaque blob just before those
values appear; whether/how it configures the opcode mapping remains unproven.
The exporter preserves the blob and every on-wire opcode. It does not substitute
old-version opcode names or claim the mapping is recovered.

This implementation supports the two observed greeting/cipher profiles.
Unknown cipher selections, split greetings during automatic discovery, capture
beginnings after the greeting, transport preludes, IPv6, and extended-length
Maple frames need further work. Explicit stream selection supports a greeting
split across TCP segments. Selected malformed streams fail instead of skipping
bytes or inventing plaintext.

Plaintext includes private account/character/session data. Generated files stay
in the repository's ignored `downloads/` directory, with a private output
directory and mode-0600 JSONL files. Do not commit these artifacts.

## Security and anti-tamper packet evidence

The following are native-build findings. Attribution specifically to NGS/grap
is not yet established; security-related behavior and a vendor-specific
anti-cheat protocol are different claims.

| Direction and opcode | Observed evidence | Confidence / limits |
| --- | --- | --- |
| Server `32 / 0x20`, client `112 / 0x70` | Multiplexed client security/integrity messages. Client subtype 2 is constructed at executable RVA `0x16387a0`; it calls helpers `0xcc6b30`/`0xcc6e60`, which sample executable memory and collect integrity/environment values. | Strong anti-tamper evidence for subtype 2; other subtypes retain opaque fields. Gameplay has 398 client packets, login 5. |
| Server `27 / 0x1b`, client `156 / 0x9c` | 83 pairs, server width 48 and client width 149, at roughly ten-second intervals. Client construction at `0x16399d0` writes diagnostic sentinels, invokes `0x163d4f0` to validate protected local data, and handles pointer/length challenge fields. | Strong integrity-check evidence; not identified as an NGS/grap wire protocol. All replies pair in order; median capture delay 3.947 ms. |
| Server `43 / 0x2b` and `44 / 0x2c` in login | Exact counted file/resource lists, including native DLLs and WZ assets. Client `119 / 0x77` is constructed at `0xce971e` and its leading constants match the captured 7,751-byte response. | File/resource verification candidate; lists alone do not prove anti-cheat purpose or map every response field. |
| Server `79 / 0x4f`, client `195 / 0xc3` | 84 gameplay and 6 login pairs. Client handler `0x163e000` echoes a request byte and appends a computed local status boolean. | Check/status traffic; no direct anti-cheat attribution established. |

For client opcode 112, gameplay subtype/width counts are `1/48:389`, `2/47:1`,
`4/7:1`, `5/11:5`, and `13/42:2`. Login adds `1/48:2`, `2/47:1`, and
`13/42:2`. All five gameplay server-subtype-5 messages are followed by a
client-subtype-5 reply within 0.469–30.324 ms. Server subtype 12 precedes a
client subtype 13 in both streams; that adjacency is not yet a proven causal
mapping. The dominant subtype-1 body remains opaque.

Example original capture frames for inspection: opcode `27 -> 156` at
`107680 -> 107682`, opcode `79 -> 195` at `109311 -> 109314`, and the login
file lists at `6789` and `105412`. These are frame numbers in the original
capture, not JSONL line numbers. The empty `1579 -> 0x43dd` periodic pair has
only keepalive-like evidence and is not classified as anti-cheat.

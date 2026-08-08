# Confirmed protocol facts

## Login greeting

Login begins with a 33-byte cleartext greeting. One captured greeting was:

```text
1f00 2c01 0300 330030003000 6e3c795a 885db958 04
2c010000 2c010000 00000000
```

Parsed fields:

```text
packet payload length: 31
protocol version:      300
subversion:            UTF-16LE "300"
IV 1:                  6e 3c 79 5a
IV 2:                  88 5d b9 58
locale:                4
trailing build words:  300, 300, 0
```

The IV values are session material; do not assume this example applies to a
new connection.

## Encrypted-frame header

Each encrypted login frame starts with four bytes. Its payload length is:

```text
uint16_le(header[0:2]) XOR uint16_le(header[2:4])
```

This framing is implemented in:

```text
/home/sdancer/ms/tools/maplestory_classic_server/maple_server/protocol.py
```

Known packet payload lengths from the first complete official session:

```text
client -> server: 275, 954, then seven packets of 10 bytes
server -> client: 27, 164, 21770, 12, 6, then seven packets of 2 bytes
```

The second session had the same core sequence and continued producing
heartbeat-sized packets until capture stopped.

## Payload cipher

The protocol-300 payload cipher is implemented in
`tools/maplestory_classic_server/maple_server/protocol.py`. Each direction has
its own four-byte IV. A frame is decrypted with the current IV, then that IV is
advanced with the recovered Maple shuffle routine. Appended synthetic server
frames must continue from the IV after the last replayed server frame; reactive
client reads must advance the client IV in the same way.

This implementation is validated by observed ciphertext/header vectors and by
round-trip tests. The former assumption that the cipher constants were still
the main blocker is obsolete.

## Login opcodes recovered so far

```text
server 0   bootstrap/login prelude
client 13  typed opcode-13 envelope or status message
server 13  typed opcode-13 envelope or three-byte acknowledgment
server 1   account/login result
server 2   one world record, or a signed world-id -1 sentinel
client 4   select world (`uint32 world_id`)
server 402 channel transition (12-byte then 8-byte response)
client 5   select channel (`uint8 world`, `uint16 channel`, IPv4)
server 4   character-list response
client 7   select character (`uint32 character_id`)
server 5   world-server handoff
```

The custom replay acknowledges the client's type-`15` opcode-`13` status with
plaintext `0d0000`. That is enough for the client to continue into the login
controller. It is a local-server behavior, not a claim that the official NGS
proof has been reproduced.

Opcode `13` has three bounded envelopes in the observed sessions:

```text
acknowledgment (3 bytes)
uint16 opcode = 13
uint8  result

opaque envelope (7 + payload_length bytes)
uint16 opcode = 13
uint8  message_type
uint32 payload_length
byte[payload_length] opaque body

client status message
uint16 opcode = 13
uint8  message_type = 15
uint16 UTF-16 code-unit count
char16[code-unit count] message
uint8  zero trailing byte
```

The successful reference sends server message type `7` with 27 opaque bytes
after the character list and time. It is followed by three client type-`6`
messages whose opaque bodies are 176, 184, and 137 bytes, then character
selection opcode `7`. A live official-ticket A/B replay reached the same
character-controller loading overlay with or without type `7`; neither run
emitted type `6` or opcode `7`. The temporal ordering therefore does not prove
that type `7` is a security request or that type `6` is its response. The app
handler path for type `7` also terminates in its UI-dialog utility, so the
decoder deliberately uses the neutral `opcode_13_envelope` name. Length
prefixes and exact packet boundaries remain validated. Direct placeholder
launches also emit a fully decoded type-`15` status message containing “Please
check the network connection status.”

The captured server frame at index `3` is a second opcode-`0` message with
plaintext result byte `2`. It is the direct source of the replayed
account-policy dialog: replacing only this frame with heartbeat `0a00` removes
the dialog. Changing result `2` to `0` instead displays “Logging in, please
wait,” so zero is not yet proven to mean unconditional success for this
message.

The earlier two-byte opcode-`1` probe could trigger a controller transition but
bypassed required account state. A bounded 128-byte zero-filled opcode-`1`
payload lets the original handler run, creates its empty world staging list,
and reaches world selection after an informational modal is dismissed. This is
still a structural probe, not a decoded production account response. Direct
transition probes separately established state `1` as world selection and
state `2` as character selection.

## Successful login reference (`111.pcapng`, stream 83)

The successful reference uses the same 33-byte version-`300`, subversion-`300`,
locale-`4` handshake and the same directional cipher masks (`3` client,
`~300` server). Validate and fold it into typed game state with:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server
python -m maple_server analyze-login \
  --pcap /home/sdancer/Downloads/111.pcapng \
  --tcp-stream 83 \
  --packets \
  --fail-on-invalid
```

The final state is `handoff_ready`: five worlds, selected world `4`, selected
channel `23`, a received character list, a character selection, and a matching
handoff. Numeric account and character identifiers are redacted by default.
The validated server sequence is:

```text
frame 3       opcode 0, 63-byte successful account result
frames 5-9   opcode 2, five 2,183-byte world records
frame 10     opcode 2, signed world-id -1 sentinel
frames 15-16 opcode 402, 12-byte then 8-byte transition results
frame 17     opcode 4, 170-byte character-list response
frame 18     opcode 134, 10-byte server time
frame 19     opcode 13, type-7 envelope with 27 opaque bytes
frame 20     opcode 5, 19-byte world handoff
```

All world packets parse to their exact ends. Worlds `1` through `4` use
visible/online flag `1`; world `5` uses flag `2`. Each has 60 channels,
event EXP/drop values `100`, channel unknown value `200`, and no balloons.
This explains why flag-`0` test worlds were retained in memory but rendered
with blank labels.

The client selects a world with six-byte opcode `4`, then a channel with
nine-byte opcode `5`, and finally a character with six-byte opcode `7`. The
opcode-`5` fields are one world byte, a little-endian channel `uint16`, and four
IPv4 octets.

Timing is part of the channel transition. The first opcode-`402` response
arrives about 28 ms after client opcode `4`; the second arrives about 2.54 s
later, and client opcode `5` follows immediately. Sending both `402` packets
back-to-back reproduces a live stall after the channel button is clicked.

Both opcode-`402` variants are now structurally bounded:

```text
stage 0 (12 bytes)
uint16 opcode = 402
uint16 stage = 0
uint32 transition_value_0
uint32 transition_value_1

stage 1 (8 bytes)
uint16 opcode = 402
uint16 stage = 1
uint32 selected_world_id
```

The reference stage-0 values are `267748` and `267744`; their higher-level
meaning remains unnamed, but no bytes are opaque. The stage-1 world id must
match the triggering client opcode-`4` selection. Replaying the captured world
`4` after a live world-`1` selection is now rejected by the game-state fold and
reproduces the channel-button stall even with correct timing.

The login state machine cannot skip directly from character-list/time to the
handoff. A live bypass sent the valid endpoint-rewritten frame `20` without
frame `19` or the client type-`6`/opcode-`7` sequence. The client accepted the
handoff far enough to blank the scene, but never connected to the local world
port and then exited after the login socket closed. The A/B replay above also
shows that frame `19` alone does not unlock selection. Therefore the real
ordering gate is a client-side completion and character-selection transition;
the available evidence does not make it a server-side security-validation
requirement.

Replaying the successful stream's six-byte server opcode `23` at this point is
also insufficient. In the live synthetic-callback probe it produced only a
fully decoded client opcode-`13` type-`15` status with an empty message. The
client stayed in `character_selection` and sent no opcode `7`. Because that
session had already produced a native opcode-`6` packet during startup, opcode
`23` is best classified as an NGSX initialization/status trigger, not the
missing post-selection security completion packet.

The successful 63-byte account packet is fully bounded as follows. Its three
strings use a `uint16` UTF-16 code-unit count without the extra world-string
trailing byte:

```text
uint16 opcode (0 in reference; rewritten to 1 for the local handler)
uint8  result = 0
uint32 account_id
uint8  gender
uint8  administrator
bool8  restricted
string account_name
uint16 unknown
uint8[3] account_flags
int64  created_at_ticks
string secondary_name
string tertiary_name
byte[2] trailing
```

## World-list packet (`server opcode 2`)

The current parser model is:

```text
uint16 opcode = 2
int8   world_id
string world_name
uint8  world_flag
string event_description
uint16 event_exp_rate
uint16 event_drop_rate
uint8  channel_count
repeat channel_count:
  string channel_name
  int32  population
  uint8  world_id
  uint8  channel_id
  uint8  adult_channel
  int32  unknown
uint16 balloon_count
repeat balloon_count:
  uint16 x
  uint16 y
  string message
```

Every `string` above is encoded as a little-endian `uint16` UTF-16 character
count, followed by that many UTF-16LE code units, followed by one additional
byte consumed by the client string reader. Omitting that byte shifts every
subsequent field. A separate three-byte packet `02 00 ff` ends the world list.

The current 51-byte test packet describes world `0` named `test`, with one
channel named `test-1`, zero population, and no balloons. Do not place the raw
hex in general logs; the replay command in `CUSTOM_SERVER.md` is the canonical
lab recipe.

Dual transparent process-local trampolines confirm that opcode `2` reaches the
build-specific handler and the world parser without leaving GDB attached. The
51-byte test record decodes exactly as world id `0`, name `test`, one channel
named `test-1`, and zero-valued remaining fields. Focused Cpp2IL established
that controller field `+0xc8` is a wrapper whose `List<World>` backing field is
at wrapper `+0x50`; the corrected live dump shows one retained world both
before and after the signed-id `-1` sentinel. The former `worlds=0` observation
read wrapper `+0x18` and was not a list count.

## World handoff packet (`server opcode 5`)

The successful 19-byte shape is fully consumed as:

```text
uint16 opcode = 5
uint16 result = 0
byte[4] IPv4 address (network octet order)
uint16 port (little-endian)
uint32 character_id
byte[5] trailing zeros
```

The selected character ID must equal the handoff character ID. The replay's
`?handoff=127.0.0.1:PORT` PCAP-frame transform changes only address and port
after validating this shape.

## `58880` exchange

The client sent a stable HTTP/1.1 request:

```http
GET / HTTP/1.1
Host: 54.238.121.146:58880
Cache-Control: no-cache
```

The response was 218 bytes and had the fixed body:

```text
aewwawuiaryatp
```

Date and cache/entity metadata varied. The role appears to be a probe or
handoff rather than the encrypted login channel.

This is the complete observed HTTP surface; there is no JSON management API.
Custom-server control is CLI-based and observations are mode-`0600` JSONL. In
the successful `111.pcapng` flow, the actual encrypted world handoff is instead
`43.142.194.150:8587`.

## Bootstrap connection

An additional TLS connection was captured at `54.65.46.47:5050`, with roughly
842 client bytes and 4,544 server bytes in the first observed exchange. It has
not yet been decoded.

## Capture inventory

Primary captures live in:

```text
/home/sdancer/ms/downloads/maple_protocol_captures/
```

Important files:

```text
1786118307321677094_13.115.120.13_10282.jsonl
1786118506764535468_52.193.141.80_10282.jsonl
1786118312530175497_54.238.121.146_58880.jsonl
1786118511968891795_54.238.121.146_58880.jsonl
1786118473811233268_54.65.46.47_5050.jsonl
```

The fresh HK SOCKS5 official reference is:

```text
hk_official_reference_20260808/1786166652482700663_35.73.142.21_10282.jsonl
hk_official_reference_20260808/1786166661254491571_54.238.121.146_58880.jsonl
```

It contains 1,377 client bytes and 22,092 server bytes on `10282`. Decryption
produces server opcodes `27, 28, 22, 0, 23`, followed by ten opcode-`10`
heartbeats; the client produces opcodes `31, 6`, followed by ten opcode-`23`
frames. The `58880` exchange contains 77 client bytes and 221 server bytes.

## Current unknowns

- The successful account shape is decoded, but the regional opcode mapping
  differs (`0` in the successful capture, `1` for the local handler), and
  several fields still have unknown semantics.
- The character-list opcode/result envelope is validated, but its inner 167
  bytes remain intentionally opaque/partial.
- The 19-byte handoff shape is validated; the initial stream-`92` world/map
  state still needs semantic decoding beyond encrypted-frame replay.
- The purpose and required state for the TLS `5050` connection remain unknown.
- The exact semantics of captured opcode-`0` result values other than the
  observed policy result `2` remain unknown.

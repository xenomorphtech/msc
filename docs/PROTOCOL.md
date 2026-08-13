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
server 0   local 36-byte diagnostic account-prefix probe
server 3   redacted u8/i32/bool record
server 6   redacted trailing-zero UTF-16 plus uint8 record
server 7   successful character-creation snapshot and compact appearance
server 35  redacted login-prelude text record
server 390 redacted uint8 record
client 9   redacted trailing-zero UTF-16 record
client 10  character-creation name plus eight redacted uint32 values
client 16  select the newly created character
client 255 redacted uint32 record
server 10  empty heartbeat probe
client 6   redacted indexed record set
client 274 fixed 768/74-code-unit redacted text record
client 23  neutral uint64 heartbeat response value
client 31  three redacted UTF-16 fields and a 48-byte opaque blob
client 13  typed opcode-13 envelope or status message
server 13  typed opcode-13 envelope or three-byte acknowledgment
server 27  counted redacted integer/text ledger
server 28  counted redacted paired-text ledger
server 22  counted redacted indexed-text ledger
server 20  redacted neutral uint32 record
server 21  zero uint8 record
server 23  zero uint32 record
server 161 zero uint8 record
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

The current local replay also begins with an explicitly patched 36-byte server
opcode-`0` diagnostic. It is not a complete `AccountLoginResponse`: it contains
result `0`, a redacted `uint32` account id, three zero account flags, one
redacted four-code-unit UTF-16 name, and a 16-byte zero suffix. The fold records
it as a partial local bootstrap probe and does not authenticate the account from
it; the later full opcode-`1` account result performs that transition. This
exact live-only shape consumes natively without publishing the id or name.

Five legacy stream-`116` records now have neutral, exact boundaries. Generated
server handlers read opcode `3` as `uint8 + int32 + bool`, opcode `390` as one
`uint8`, and opcode `6` as trailing-zero counted UTF-16 plus `uint8`; the
captured records consume exactly under those layouts. Capture-bounded client
opcode `255` is one redacted `uint32`, while client opcode `9` is one redacted
trailing-zero counted UTF-16 field. The opcode-`6` text exactly echoes the
preceding opcode-`9` text after 235.214 ms. Opcode `390` follows client opcode
`255` after 238.384 ms, but that adjacency is not treated as causal. Safe output
publishes only widths, text length, boolean state, and echo/timing evidence.

Legacy stream `116` then exercises a complete empty-list character-creation
path. Client opcode `10` contains one redacted counted name and eight redacted
`uint32` values. After 271.948 ms, generated server opcode `7` reads result zero
and delegates to a body that exactly reuses `InitialCharacterSnapshot` followed
by the captured compact appearance. The response name and its
gender/face/hair/equipment fingerprint exactly match the request. Client opcode
`16` repeats the new character id 3,994.739 ms later, and the existing opcode-`5`
world handoff repeats it again after 597.284 ms. The request's first `uint32`,
the response's three style values, and opcode-`16`'s zero-byte role remain
neutral. The separate server opcode-`35` prelude is capture-bounded as constants
`0/1`, one redacted seven-code-unit text field, and a three-byte zero suffix.
Together these records reduce successful stream `116` to zero unknown packets.

The login fold now reuses the world transport heartbeat shapes: server opcode
`10` is exactly two bytes and client opcode `23` is exactly ten bytes, carrying
one little-endian `uint64` response value whose higher-level meaning remains
unknown. Every observed response
immediately follows a probe. Successful stream `83` has one matched pair at
14.107 ms. Stream `116` has four probes, three matched responses at 10.006,
0.349, and 14.445 ms, and one final pending probe. The current local login has
eight matched pairs, zero unmatched/pending responses, and a maximum 2,594.990
ms round trip caused by replay pacing. Safe output exposes only response-value
presence, pair counters, and round-trip timing; the value itself is redacted.

Client opcode `6` is a variable indexed record set with an exact shared
boundary across stream `83`, stream `116`, and the current live login:

```text
uint16 opcode = 6
uint32 neutral_header[9]            # redacted; zero-based fields 1 and 5 = 0
uint32 record_count
repeat record_count:
    uint16 record_index             # complete unique set 0..count-1
    uint32 opaque_value             # redacted
```

The total width is therefore `42 + 6 * record_count`. Stream `83` carries 299
records in 1,836 bytes; stream `116` and the current live login each carry 152
records in 954 bytes. All three contain every index exactly once, although
their wire order is not sequential. Safe output exposes only the fixed header
width, common zero-field indices, record count, complete-index check, and
aggregate counts. Header and record values—and the higher-level role of the
set—remain neutral.

The sole captured client opcode-`274` packet is a fixed 1,698-byte redacted
variant at the start of stream `83`: a 768-code-unit trailing-zero UTF-16
field, `uint32 2`, two `uint8 1` flags, and a 74-code-unit trailing-zero UTF-16
field. Both fields contain hex-like text, but the codec deliberately exposes
only their widths and the intervening constants. The contents and higher-level
role remain neutral. Python round-trips the full packet and the native manifest
exact-consumes the isolated record.

Login also reuses the exact server opcode-`27` and opcode-`28` ledger codecs
already validated in gameplay. Opcode `27` is an `i32` count followed by three
redacted `i32` values and one trailing-zero UTF-16 field per entry. Opcode `28`
is an `i32` count followed by two redacted `i32` values and two trailing-zero
UTF-16 fields per entry. Stream `83` carries `18/5` entries at `1,056/260`
bytes; stream `116` carries `1/4` at `27/164` bytes. The live login independently
replays the same four-entry, 164-byte opcode-`28` variant. Every record consumes
and round-trips exactly at full shape coverage. Safe login state exposes only
packet/entry counts and text code-unit totals; all text and numeric values stay
redacted and their higher-level roles remain neutral.

Server opcode `22` carries a `uint32` entry count followed by repeated
`(trailing-zero counted UTF-16 text, uint16 index)` entries. Stream `83` has
299 entries and 16,473 text code units in 34,447 bytes; stream `116` and the
live login share the same 152-entry, 10,502-code-unit, 21,770-byte record.
Every sample exact-consumes, all text trailing bytes are zero, and each index
set is the complete unique range `0..count-1`. The later client opcode-`6`
record uses the same index set in all three sessions, although ordering differs.
The fold reports only counts, code-unit totals, and that correlation; text and
the family's higher-level role stay redacted and neutral.

Four small login-server records also share exact boundaries across stream `83`
and stream `116`. Opcodes `21` and `161` are each a two-byte opcode followed by
a zero `uint8`; opcode `23` is followed by a zero `uint32`; opcode `20` is
followed by a varying neutral `uint32`. The live login independently contains
the same zero-valued opcode-`23` record. Login-specific codecs keep this family
separate from gameplay's fixed-record path, redact the opcode-`20` value, and
expose only opcode counts, widths, and zero/nonzero status. All eight reference
records exact-consume natively and round-trip in Python.

Client opcode `31` is a capture-bounded variable record rather than an opaque
width pin. Stream `83`, stream `116`, and the current live login independently
establish this grammar:

```text
uint16 opcode = 31
byte[20] reserved_prefix = zero
uint8  variant = 2
utf16  opaque_text_1 + trailing zero byte
utf16  opaque_text_2 + trailing zero byte
utf16  opaque_text_3 + trailing zero byte
uint32 opaque_blob_length = 48
byte[48] opaque_blob
byte[3] reserved_suffix = zero
```

The three packet lengths are `183`, `275`, and `201` bytes, with text
code-unit patterns `10/0/38`, `7/51/36`, and `1/51/5`. The codec round-trips
the contents but safe packet/state output exposes only the variant, zero-field
checks, text lengths, blob length, and aggregate pattern/count telemetry. The
text, blob contents, and higher-level role remain deliberately neutral.

Opcode `13` has four bounded envelopes in the observed sessions:

```text
acknowledgment (3 bytes)
uint16 opcode = 13
uint8  result

fixed client type-1 envelope (11 bytes)
uint16 opcode = 13
uint8  message_type = 1
uint32 security_value = crc32_non_reflected_le16(outbound_iv)
uint32 reserved = 0

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

The world-session gameplay fold uses the same neutral family. Stream `92`
contains 446 fixed client type-`1` envelopes, 104 client type-`6` envelopes,
and five client type-`13` envelopes. Stream `126` contains 970 fixed client
type-`1` envelopes. On the server direction, stream `92` contains 14 type-`7`,
one type-`12`, and five type-`14` envelopes; stream `114` contains one each of
types `12` and `14`. Across login and gameplay, all 23 captured server packets
have a body length that reaches the exact packet end; the automatic dump's
handler confirms the leading discriminator read. The fold emits
direction-specific type/body-length distributions and redaction flags without
exposing any body. Server packets fold as partial
`server_opcode_13_envelope` observations and
`server_opcode_13_message_received` events. The payload meanings remain
partial rather than being labeled as security traffic.

The two independent `111.pcapng` world sessions also establish a redacted
ordering/cadence relationship without identifying those bodies. Each begins
with one server type `12`; its first server type `14` follows after
`4934.955..4945.945` ms, and a client type `13` follows after another
`27.305..30.942` ms. Stream `92` contains four later type-`14`/type-`13` pairs:
the server messages recur `180.722..184.383` seconds apart and all five client
messages follow within `27.305..77.244` ms. Every one of the six cross-stream
type-`14`/type-`13` pairs has equal 392-byte body lengths, but none of the bodies
is byte-equal and their content remains redacted and opaque. The gameplay fold
publishes FIFO correlation counts, length-match counts, pending/unmatched
counts, and correlation timing through safe analysis while retaining partial
coverage and leaving replay disabled.

## Client opcode `43` field-transfer requests

Client opcode `43` requests a field transfer. Its leading byte is the active
field epoch: all 45 packets match the folded epoch, and every packet is followed
by the next server opcode-`157` field snapshot with no intervening opcode-`43`.
The two layouts are portal transfer and death respawn:

```text
portal transfer:
  uint16 opcode = 43
  uint8 field_epoch
  int32 destination_map_id = -1     # destination resolved by server/portal
  uint16 portal_name_code_units
  utf16le[portal_name_code_units] portal_name
  uint8 zero_terminator = 0
  int16 position_x
  int16 position_y
  uint16 reserved_value = 0

death respawn:
  uint16 opcode = 43
  uint8 field_epoch
  byte[9] zero_body

server opcode-43 neutral envelope:
  uint16 opcode = 43
  uint8 message_type = 0
  byte[16] captured_body = 00000000000000000002000000000002
```

Stream `92` contributes nine portal transfers, three death respawns, and three
neutral server packets. The server packets are byte-identical: message type
zero followed by the fixed 16-byte signature above. Each immediately follows
an HP-zero/experience stat update, but its higher-level purpose remains
unresolved. The three respawns each follow a same-epoch HP-zero stat update by
`2.271..2.918` seconds and use an all-zero body. Stream `126` contributes 33
portal transfers. Portal-name lengths are `4:5`, `5:9`, `6:27`, and `8:1`
code units across both captures;
all portal requests use map sentinel `-1`, a zero reserved value, and signed
positions. Safe state/events redact the portal name but expose epoch matching,
variant, position, pending/matched transitions, and latency.

All 45 client requests round-trip as full observations and match their next
field snapshot. Response latency is `28.125..940.035` ms (combined median
`399.027` ms). Promoting this family changes stream `92` to
`13,505/21,702/0/0` and stream `126` to `27,188/43,912/0/0`; stream `114`
remains `54/22/0/0`, with no warnings beyond stream `126`'s known six one-HP
combat-model disagreements.

The automatic manifest uses portal and death-respawn candidates rather than the
earlier sequence-keyed switch. Exact packet length makes the candidates
unambiguous, while equality guards enforce map sentinel `-1`, the zero portal
reserved value, the death-respawn zero body, and the capture-bounded server
signature. The three server observations now fold at full structural coverage,
moving current stream-`92` coverage from `34,544/663/0/0` to
`34,547/660/0/0`; native validation consumes all 35,207 decrypted packets.

An exact captured 19-byte server envelope was injected into an already active
browser-free custom-server session. The fold added one opcode-`43`
event, core phase/map/player/inventory/progression state stayed unchanged,
matched heartbeats advanced from 173 to 176, and the connection remained
active with zero failures. No client opcode-`43` response appeared because
server opcode `43` is not the field-transfer response; the capture-backed
response boundary is the following opcode-`157` snapshot. The injection still
proves bounded non-stalling acceptance for the separately neutral server
family only. Reanalysis now classifies that exact signature as structurally
full; it does not retroactively assign a gameplay meaning.

## Client opcode `114` redacted text envelope

All 44 stream-`126` packets use one exact variable-width grammar:

```text
uint16 opcode = 114
uint8 control_value
uint16 text_code_units
utf16le[text_code_units] opaque_text
uint8 zero_terminator = 0
uint32 opaque_value
```

Text lengths `8`, `9`, and `11` produce total packet lengths `26`, `28`, and
`32`; their counts are `2`, `8`, and `34`. The control values span `1..34`
across 26 observed values and are nondecreasing in capture order, but that alone
does not establish a sequence or tutorial-step role. There are 13 distinct
redacted strings and 43 distinct trailing values; the trailing values decrease
22 times, so they are not modeled as a monotonic client tick.
Because the counted text and required terminator delimit the record exactly,
redaction and neutral roles do not imply structural opacity. All 44 records now
report full structural coverage and pass the independent manifest validator
with exact consumption; text, trailing-value meaning, and higher-level purpose
remain deliberately unresolved.

Forty-three packets have prior opcode-`244`/`247` tutorial/UI traffic, with 29
within 30 seconds and a median gap of 15.285 seconds. That supports a possible
UI relationship but is too indirect to call the packet an acknowledgement.
The fold therefore emits neutral `client_opcode_114_submitted` events and
publishes only control and text-length distributions plus a redacted-value
count. Python and native manifest validators consume and re-emit all 44 packets
without ambiguity or failure. Because the family is client-originated and the
active idle level-12 client emits none, no server-to-client live replay or
client-visible effect is claimed.

## Inner-portal traversal (`client opcode 115`)

The final two unknown stream-`92` packets are exact same-field portal requests:

```text
uint16 opcode = 115
uint8  field_epoch
uint16 portal_name_code_units
utf16le[portal_name_code_units] portal_name
uint8  zero_terminator = 0
int16  source_x
int16  source_y
int16  destination_x
int16  destination_y
```

Both requests carry the active field epoch `7` and a four-code-unit portal
name, retained only for exact re-emission and redacted from safe output. Their
source/destination paths are `(1050,234) -> (1099,410)` and
`(1099,411) -> (1040,1007)`: the second source is within one pixel of the first
destination. The first request is followed by same-epoch mob visibility
removals and entries; the second is followed by remote-player, mob, and drop
visibility removals. No field snapshot or epoch transition occurs.

This structure and role also agree with the older open-source
`UseInnerPortalHandler`/`InnerPortalHandler` family, which reads an inner-portal
name plus start/final positions and updates the character within the current
map. Capture-local position chaining and visibility changes remain the primary
version-300 evidence; older layouts are not used to widen the accepted modern
shape. The Python codec accepts the typed variable-name grammar, while the
native manifest deliberately pins the only observed 22-byte/four-code-unit
variant. Both captured records consume and re-emit exactly at full coverage.
Safe state exposes only counts, name length, epoch matches, coordinates,
deltas, and the one-pixel chain result. Stream `92` advances from
`13,417/21,788/2/0` to `13,419/21,788/0/0` with no warnings.

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
  --pcap /home/sdancer/ms/111.pcapng \
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
frame 17     opcode 4, 170-byte typed character-list response
frame 18     opcode 134, 10-byte server time
frame 19     opcode 13, type-7 envelope with 27 opaque bytes
frame 20     opcode 5, 19-byte world handoff
```

All world packets parse to their exact ends. Worlds `1` through `4` use
visible/online flag `1`; world `5` uses flag `2`. Each has 60 channels,
event EXP/drop values `100`, channel unknown value `200`, and no balloons.
This explains why flag-`0` test worlds were retained in memory but rendered
with blank labels.

### Character-list success shape

Two independent login captures bound successful server opcode `4`: stream
`83` in `111.pcapng` has one character and a total length of 170 bytes, while
stream `116` in `1-10FS.pcapng` has zero characters and a total length of 18
bytes. Both parse and re-emit byte-for-byte as:

```text
uint16 opcode = 4
int8   result = 0
uint32 reserved_1
uint32 reserved_2
uint8  character_count
repeat character_count:
  character stat snapshot
  uint8 gender
  uint8 skin
  uint32 face_id
  repeated uint8 slot + uint32 item_id, terminated by slot 0xff
  repeated masked slot + item_id, terminated by slot 0xff
  uint32 cash_weapon_id
  uint32 opaque_style_values[7]
  uint8 entry_code
  bool ranking_present
  if ranking_present: int32 ranking_values[4]
uint8  trailer_1
uint8  trailer_2
uint32 trailer_3
```

The stat snapshot reuses the typed world-entry prefix: character id, data
flags, UTF-16 name, gender/skin/face/hair, companion id, level/job, four base
stats, HP/MP, AP/SP, EXP, fame, map/portal, and two neutral state fields. The
record validates that its repeated appearance identity matches the stat
snapshot. Slot `0` in the first appearance list carries the hair template in
both the parser and emitter. The seven style values and final trailer retain
neutral names because only their widths and positions are independently
established.

The login JSON state reports character count plus level/job/stats, HP/MP,
map, equipment counts, and ranking presence. Character id and name are
`"present"` unless `--show-identifiers` is explicitly enabled. A subsequent
client opcode `7` is invalid if its character id was not advertised by this
list. Replay references can append `?character-list` to require a full typed
parse and state-driven re-encode before encryption.

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
shows that frame `19` alone does not unlock selection.

Replaying the successful stream's six-byte server opcode `23` late is also
insufficient. In the live synthetic-callback probe it produced only a fully
decoded client opcode-`13` type-`15` status with an empty message; the client
stayed in `character_selection` and sent no opcode `7`. The missing variable
was ordering: non-strict replay consumed fresh-client extra frames as captured
events and emitted captured server frame `4` before the actual opcode `6`.

With frame `4` omitted and its plaintext sent reactively after the observed
client opcode `6`, a clean unpatched client returned a non-empty type-`15`
status, completed world/channel/character selection, emitted opcode `7`,
accepted the transformed handoff, and opened the local world connection. Thus
the bounded rule is:

```text
client opcode 6 (variable opaque security payload)
server opcode 23 (six-byte captured response)
client opcode 13, type 15 (non-empty completion/status message)
```

The server response is necessary in this position, while a late duplicate is
not a substitute. The type-`7` envelope still is not independently sufficient;
it participates after the ordered NGSX completion rather than causing that
completion itself.

This ordered NGSX exchange is the only security/anti-cheat packet sequence so
far demonstrated by a clean-client A/B run to gate entry into the game. If the
opcode-`23` response is absent or sent before the real client opcode `6`, the
completion is missing or the subtype-`15` status is empty; the client then
sends no opcode `7` and opens no world connection. That establishes an
admission boundary for the observed Taiwan build, but it is not proof that the
production service has no additional server-side policy checks.

### Client opcode 13, subtype 1 (outbound-IV companion)

Subtype `1` is not the server challenge or completion packet in the admission
sequence above. The native pre-send producer emits it immediately before an
ordinary outbound client frame whenever the low 16 bits of the current
outbound Maple cipher IV are divisible by `31`:

```text
uint16 opcode = 13
uint8  subtype = 1
uint32 value = crc32_non_reflected_le16(outbound_iv)
uint32 reserved = 0
```

`value` is CRC-32 with polynomial `0x04C11DB7`, initial value `0`, no input or
output reflection, and final XOR `0`, evaluated over the two little-endian
bytes of `uint16(outbound_iv)`. It is therefore deterministic cipher-state
traffic rather than a reply derived from any inbound server packet.

The result is pinned to `GameAssembly.dll` SHA-256
`6f2a93efc0f16f30685c902134ecc79ad67fe384f345f503fa688658acbddeea`.
The original producer is VA `0x181CD62A0` / RVA `0x1CD62A0`; the emulated CRC
helper is VA `0x181C96BF0` / RVA `0x1C96BF0`; and its table-installing static
constructor is VA `0x181C98C50` / RVA `0x1C98C50`.

Capture verification reproduced all observed subtype-`1` frames with zero
mismatches: `446/446` in `111.pcapng` stream `92` and `970/970` in
`1-10FS.pcapng` stream `126` (`1,416/1,416` total). Nothing in those captures
or the producer data flow indicates that subtype `1` independently grants or
denies world entry.

The tracked `Opcode13Type1Envelope` now parses and exactly re-emits both
`uint32` fields. Safe reports expose only that the security value was present
and that the reserved word was zero; they never expose the value itself.
Accordingly, all 1,416 subtype-`1` observations now have full structural
coverage. The length-prefixed subtype-`6` and subtype-`13` bodies remain
partial and opaque.

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

## World entry (`client opcode 8`)

All three world references use the same exact 66-byte request boundary:

```text
uint16 opcode = 8
uint32 entry_value                     # neutral; non-identity role
uint32 character_id
uint8  ticket_prefix = 0
uint32 ticket_length = 48
byte[48] ticket                         # redacted
byte[3] reserved_zero = 0
```

The first `uint32` after the opcode was previously mislabeled as the character
id. Cross-checking it against the large opcode-`157` snapshot in `111.pcapng`
streams `92` and `114`, and against `1-10FS.pcapng` stream `126`, proves that
the second word is the character id. The 56-byte suffix also has an exact
capture-bounded frame in every stream: a zero prefix, declared length `48`,
48 redacted bytes, and three reserved zeros. The fold validates that equality
and framing while redacting both the identifier and ticket bytes from normal
reports. All three observations now have full structural coverage; current
strict totals are `70,076/1,024/0/0`, `34,573/634/0/0`, and `68/8/0/0` for
streams `126`, `92`, and `114` respectively. The latest saved world transcript
independently folds its request at full coverage and reaches `766/16/0/0`.

## Initial field snapshot (`server opcode 157`, large variant)

The first opcode-`157` packet on each validated world connection contains a
typed character/stat prefix followed by a much larger nested state tail. The
stream-`92` plaintext is 4,464 bytes and the independent stream-`114`
plaintext is 4,506 bytes. Both consume the same 112-byte prefix exactly and
round-trip byte-for-byte through `InitialFieldSnapshot`:

```text
uint16 opcode = 157
uint32 marker = 23
uint8  reserved_flag = 0
uint8  contains_character_data = 1
uint8  character_data_mode = 1
uint16 reserved = 0
uint32 opaque_session_value[3]
int64  sentinel = -1
uint8  character_record_prefix = 0
uint32 character_id
uint32 character_data_flags
string character_name                 # uint16 count + UTF-16LE + zero byte
uint8  gender
uint8  skin
uint32 face_id
uint32 hair_id
uint64 companion_id
uint8  level
uint16 job_id
uint16 strength
uint16 dexterity
uint16 intelligence
uint16 luck
uint16 current_hp
uint16 max_hp
uint16 current_mp
uint16 max_mp
uint16 ability_points
uint16 skill_points
uint32 experience
int16  fame
uint32 map_id
uint8  portal_index
uint8  opaque_state_flag
uint64 opaque_state_value
byte[] inventory_and_post_inventory_tail
```

The tail begins with a 30-byte preamble ending in the `1900-01-01` FILETIME
sentinel. It then contains five zero-terminated equipment groups followed by
zero-terminated use, setup, etc, and cash groups. Each item begins with a slot,
record type, template id, cash flag, optional cash id, and expiration. Stack
records additionally expose a `uint16` quantity. Equipment records materialize
upgrade slots/level, 15 signed stat values, owner text, flags, two metadata
values, two extension flags, five extension values, conditional identity, and
both sentinel-framed timestamp/value groups. Stack records retain a fixed
ten-byte reserved region; it is zero in every reference item.

Stream `92` contains group counts `4/1/4/0/0/24/2/17/1`; stream `114`
contains `4/1/4/0/0/24/2/18/1`. The inventory regions are 2,930 and 2,972
bytes respectively, and both are followed by the same 1,422-byte progression
region. Each inventory region and complete initial packet round-trips
byte-for-byte. Reports expose item slot/template/quantity data and the
character-name code-unit count, but not the name text or raw character id. The
gameplay fold checks the embedded character id against client opcode `8`, then
seeds player, field, and inventory state and emits a `field_snapshot_received`
event with variant `initial_character_snapshot`.

The level-1 capture uses marker `26` rather than marker `23` but retains the
same typed character and inventory grammar. Its 823-byte initial packet seeds
character level `1`, job `0`, HP/MP maxima, and nine inventory groups. The
537-byte inventory region contains five items and round-trips. Its following
172-byte compact progression is also typed:

```text
uint8  reserved_flag = 0
uint16 skill_count = 1
repeat skill_count: uint32 skill_id, uint32 level   # captured (12, 0)
uint16 reserved = 0
uint16 string_property_count = 0
uint16 timestamp_property_count = 0
int64  reserved = 0
uint32 saved_map_id[16]
byte[7] neutral_variant_header
byte[] compact_trailer
```

The compact trailer reuses the two validated 17-byte blocks, followed by five
empty UTF-16 strings, a zero variant constant, reserved data, the FILETIME
sentinel, server-local FILETIME, and final `uint32`. The 172-byte region and
complete 823-byte packet round-trip exactly. Reports now expose
`snapshot_marker: 26`, `progression_typed: true`, and
`progression_shape: compact`, and the gamestate fold retains the skill, saved
maps, and server clock.

The 1,422-byte continuation is also structurally complete:

```text
uint8  reserved_flag = 0
uint16 skill_count
repeat skill_count: uint32 skill_id, uint32 level
uint16 reserved = 0
uint16 string_property_count
repeat string_property_count: uint32 key, string value
uint16 timestamp_property_count
repeat timestamp_property_count: uint32 key, int64 ticks
int64  reserved = 0
uint32 saved_map_id[16]
uint8  reserved_flag = 0
uint32 constant = 1
uint8  variant                         # 1 in stream 92; 2 in stream 114
uint16 extended_property_count
repeat extended_property_count: uint32 key, string value
uint16 reserved = 0
byte[112] fixed_trailer
```

Both captures contain six skill entries, seven string properties, 35 timestamp
properties, and 12 extended properties. The fixed trailer contains two
validated 17-byte blocks, five UTF-16 strings with code-unit counts
`0/1/1/16/0`, constant/reserved fields, the `1900-01-01` sentinel, a
server-local FILETIME, and one final `uint32`. Values of keyed strings and
trailer strings are retained for exact re-encoding but omitted from normal
reports.

The layout is supported by a complete live primitive-reader trace of the
stream-`114` packet: 734 observed calls consumed the body through the final
field. The trace also showed that RVA `0x1cd0560` is a direct one-byte reader,
while RVAs `0x1cd0730` and `0x1cd0790` account for the two- and eight-byte gaps
in the typed prefix. The entire packet is now structurally bounded. Semantic
names remain neutral for the five equipment groups, keyed property roles, and
parts of the fixed trailer until independent effects identify them.

The gameplay fold therefore reports both marker-`23` keyed-property snapshots
and marker-`26` compact snapshots at full structural coverage. Neutral field
names do not represent unparsed bytes: all three reference packets re-emit
exactly, their observations report `opaque_snapshot_bytes: 0` and
`unparsed_snapshot_bytes: 0`, and the genuinely unparsed short-envelope
fallback remains partial. Current strict totals are `35,020/187/0/0`,
`69/7/0/0`, and `71,047/53/0/0` for streams `92`, `114`, and `126`.
The latest saved world transcript independently improves to `767/15/0/0`.

The first controlled typed mutation targets `current_hp`. Replay analyzes the
entire normalized world transcript, requires exactly one valid initial
snapshot, checks `0 <= current_hp <= max_hp`, replaces only the nested HP
field, requires an unchanged packet length, and parses the generated bytes back
to the same typed value before patching/re-encrypting the frame. A stream-`114`
real-client run changed captured HP `50/222` to `1/222`. The client HUD showed
`HP 1 / 222`; the independently captured replay transcript folded to
`phase=active`, map `101000000`, HP `1/222`, unchanged inventory/progression,
nine active NPCs, and matched heartbeat traffic. This confirms the field
offset and width as a live effect, not only an offline round trip.

`TypedInitialFieldSnapshot` is the reusable generator boundary for both large
variants. `--generate-initial-field-snapshot` materializes the envelope,
character, inventory groups/items, marker-specific progression, and trailer,
then requires byte-identical same-length output when no mutation is requested.
`GET /api/v1/status` exposes that plan under
`protocol.initial_field_snapshot_emitter` with frame index, emitter name,
inventory group/item counts, skill count, progression shape/variant,
original/emitted/max HP, prediction, and `frames_patched`. The existing HP
option performs its bounded mutation through the same generator and exposes
the fields under `protocol.initial_player_hp_rewrite`.

The baseline generator has also crossed the real-client boundary. In the
2026-08-09 stream-`114` run, runtime status reported server frame `3`, one
patch, nine inventory groups/54 items, six skills, keyed-property variant `2`,
and unchanged HP `50/222`. The client rendered level `12`, HP `50/222`, MP
`97/342`, and EXP `1464`. Its simultaneously captured transcript folds validly
to `active` with those values, the same inventory/progression state, and 7/7
matched generated heartbeats. Therefore the exact re-emission is accepted by
the live encrypted client path as well as by the offline round-trip checks.

The later 59- and 95-byte opcode-`157` variants are
`CompactFieldTransition`. Both share transition sequence, map, portal, HP,
reserved fields, the `1900-01-01` FILETIME sentinel, server clock, and a final
neutral `u32`. The 95-byte marker-`23` branch carries UTF-16 character counts
`1/1/16` and constant `2`; the 59-byte marker-`26` branch carries three empty
counted strings and constant `0`. All 12 marker-`23` records in stream `92` and
all 35 marker-`26` records in stream `126` round-trip exactly and update the
same field-transition state without replacing the initial player-stat model.
The marker-`26` sequences span `2..36`; its observed final neutral values are
`0/1/2/7`.

## Remote-player field lifecycle (`189`, `190`)

The pinned version-300 IL2CPP opcode-`189` handler reads a u32 object id, a u8
level, and a terminated counted UTF-16 name before delegating the remaining
player body. Native control flow in the delegate then reads a second terminated
counted UTF-16 string, a fixed `u16/u8/u16/u8` header, and a separately
delegated appearance record. The bridge delegate first reads four consecutive
`u32` mask words before entering its conditional body. In all 114 entries the
logical mask enables seven virtual-record slots. The two longer stream-`92`
bridges also enable one direct `u8` branch. Next come two fixed `u8`s and seven
virtual records with exact widths `15/15/15/13/20/17/15`. The outer delegate
reads one `u16` immediately before the appearance
and, immediately afterward, an `i32`, a `u32`, four `i32`s, a two-`i16`
vector, a `u8`, and a `u16`. The adjacent opcode-`190` handler reads exactly
one u32 object id and removes that player:

```text
opcode 189:
    uint16 opcode
    uint32 object_id                 # redacted
    uint8 level
    uint16 name_code_units
    utf16le[name_code_units] name    # retained only for re-emission
    uint8 zero_name_terminator
    uint16 secondary_text_code_units
    utf16le[secondary_text_code_units] secondary_text  # redacted
    uint8 zero_secondary_text_terminator
    uint16 header_value_1
    uint8 header_value_2
    uint16 header_value_3
    uint8 header_value_4
    uint32[4] pre_appearance_mask_words  # values redacted
    if logical_mask_bit_7:
        uint8 pre_appearance_direct_value
    uint8[2] pre_appearance_fixed_values
    PreAppearanceRecord15[3] pre_appearance_leading_records
    PreAppearanceRecord13 pre_appearance_record_4
    PreAppearanceRecord20 pre_appearance_record_5
    PreAppearanceRecord17 pre_appearance_record_6
    PreAppearanceRecord15 pre_appearance_trailing_record
    uint16 appearance_prefix_value
    CharacterListAppearance appearance
    int32 post_appearance_value_1
    uint32 post_appearance_value_2
    int32[4] post_appearance_values
    int16[2] post_appearance_vector
    uint8 post_appearance_value_3
    uint16 post_appearance_value_4
    if nonoverlapping_tail_prefix_partition:
        bool tail_has_repeated_value
        while tail_has_repeated_value:
            int32 tail_repeated_value
            bool tail_has_repeated_value
        int32[3] tail_post_loop_values
        uint8 tail_variant
        if nonoverlapping_conditional_prefix_partition:
            bool conditional_optional_text_present
            if conditional_optional_text_present:
                PacketUtf16 conditional_optional_text  # redacted
            bool conditional_first_i64_pair_present
            if conditional_first_i64_pair_present:
                int64[2] conditional_first_i64_pair
            bool conditional_second_i64_pair_present
            if conditional_second_i64_pair_present:
                int64[2] conditional_second_i64_pair
            bool conditional_numeric_group_present
            if conditional_numeric_group_present:
                uint32 conditional_numeric_value_1
                uint32 conditional_numeric_value_2
                int32 conditional_numeric_value_3
            bool conditional_continuation
            bool conditional_followup
    byte[] opaque_pre_delegated_gap     # 2, 4, 10, 11, or 23 bytes
    PacketUtf16 delegated_primary_text       # redacted
    PacketUtf16[4] delegated_nested_texts    # redacted
    uint8 delegated_nested_value
    int32 delegated_comparison_value
    uint64 delegated_datetime_wire_value     # terminal field

opcode 190:
    uint16 opcode
    uint32 object_id                 # redacted
```

Each virtual record starts with the same 13-byte native base reader:

```text
PreAppearanceRecord13:
    int32 value_1
    int32 value_2
    uint8 time_present
    int32 time_value

PreAppearanceRecord15 extends PreAppearanceRecord13:
    uint16 trailing_value

PreAppearanceRecord20 extends PreAppearanceRecord13:
    uint8 second_time_present
    int32 second_time_value
    uint16 trailing_value

PreAppearanceRecord17 extends PreAppearanceRecord13:
    int32 trailing_value
```

Each time helper consumes its flag and following `i32` unconditionally; the
flag changes interpretation, not width. Offline metadata resolution maps these
forms to logical mask slots `82..88` in the order shown above. Field roles
beyond those native type boundaries remain deliberately neutral.

Streams `92/114/126` contain `58/4/52` entries and `29/0/10` leaves. All 153
packets round-trip exactly. Across all 114 entries, the body grammar types
35,369 bytes and leaves 967 bytes explicit. The full bridge is 128 bytes in
112 records and 129 bytes in two stream-`92` records; after its typed 16-byte
mask, all 112/113 bytes are typed before the appearance.
The masks contain one nonzero word and seven enabled bits in 112 entries, or
two nonzero words and eight enabled bits in two entries. Raw words remain
redacted. At RVA `0x1183720`, both runtime-state arms reconverge before the
follow-up bool read. At RVA `0x118381e`, the call site loads the player
object's parser field. The null path throws; the successful non-null path calls
RVA `0x16ca1d0` at `0x1183857`. The player base constructor allocates this
outer object, and its constructor allocates both nested records. The callee
unconditionally reads one packet UTF-16 string, dispatches a required nested
reader for four more packet strings and one `u8`, then requires the second
nested record and reads one `i32` plus an eight-byte DateTime wire value. Each
packet-string helper is `u16 code units + UTF-16LE + u8`; the helper preserves
the final byte but does not require it to be zero. Null at the outer field or
either nested record reaches a generated null-reference throw. After the call,
the handler invokes one player virtual method without passing the packet reader
and returns at `0x1183892`; it performs no later packet read.

The downstream grammar has a 28-byte all-empty minimum. Searching only for a
record that consumes exactly to packet end yields one and only one candidate in
every entry across all three corpora. This corrects the earlier false-positive
front-of-suffix alignment produced by long zero runs. Streams `92/114` have
terminal text-code-unit shapes `(0,1,1,9|15|16|20,0)`; all 52 stream-`126`
records are `(0,0,0,0,0)`. Text and scalar values remain redacted. The terminal
record is 28 bytes 52 times, 50 bytes once, 62 bytes three times, 64 bytes 51
times, and 72 bytes seven times.

Seventy entries retain both earlier typed prefixes without overlap, four retain
only the 14-byte loop/scalar prefix, and 40 conservatively demote both earlier
prefixes. The exact opaque gap before the terminal record is 2 bytes four
times, 4 bytes 40 times, 10 bytes seven times, 11 bytes 60 times, and 23 bytes
three times. There are no bytes after the terminal record. Per-stream
typed/opaque body accounting is `19,276/454`, `1,296/30`, and `14,797/483`.
The
appearance-prefix value is nonzero in 78 entries, and
the ten post-appearance fields are nonzero 545 times in aggregate. Exactly
three records exercise a five-code-unit secondary text,
and one of those independently exercises all four nonzero header fields
(`1002/11/4018/1`); the other 113 headers are zero. Appearance records contain
473 visible and 35 masked slot/template pairs in stream `92`, 32 visible and
zero masked pairs in stream `114`, and 298 visible and 19 masked pairs in
stream `126`. Identifiers, strings, face/style values, and item templates
remain redacted from safe output.

The appearance boundary is capture-bounded rather than inferred from byte
frequency: parsing after the native-delegate-relative 128/129-byte bridge and
two-byte prefix, then requiring the appearance's leading hair slot, yields
exactly one valid record in every entry across all three streams. The residual
regions keep entries at partial coverage; the 39 exact removals are full. Every
removal references a player introduced in the same field epoch. More
importantly, all 563 opcode-
`202` player-movement broadcasts and all 652 server opcode-`217` life-movement
broadcasts now correlate with a prior entry instead of creating players from
movement alone.

The fold emits `remote_player_entered_field` and
`remote_player_left_field`, clears active players at field transitions, and
preserves entry metadata when later movement supplies a position. Safe state
exposes only an alias, level, both string-code-unit counts, appearance entry
counts, typed/opaque byte counts, mask nonzero-word/enabled-bit counts,
header/prefix-presence counts,
post-appearance nonzero-field counts, tail-prefix counts/nonzero summaries,
conditional-prefix presence/count summaries, terminal delegated-reader
length/nonzero summaries, and position when known. It never
emits a captured object id, string, or appearance identifier. The saved active
custom-server transcript remains valid with six terminal delegated records,
1,974 typed body bytes, and 52 opaque body bytes. Four entries retain both
earlier prefixes; two conservatively retain neither.

A browser-free live A/B/A then composed the restored player's captured
entry/control values with the local player's validated movement path. Opcode
`202` moved the white-haired remote sprite to the predicted `(629,-2691)`.
Injecting its typed six-byte opcode-`190` removed the sprite and changed folded
active-player state `4 -> 3`; replaying the exact opcode-`189` plus the composed
movement made it visible again and restored `3 -> 4`. The final transcript is
valid with zero unknown leaves. The client remained active on map `101000000`
with no connection failures and 209/209 paired heartbeat probes.

## Remote-player/mob-template value record (`224`)

The pinned opcode-`224` handler reads the remote-player object id directly and
delegates the remaining body. The two sustained gameplay references establish
the complete 22-byte packet:

```text
uint16 opcode = 224
uint32 object_id                    # active remote player; redacted/aliased
uint8  marker = 0xff
uint32 value                        # neutral role
uint32 mob_template_id
uint8  flag                         # observed 0 or 1
uint16 reserved = 0
uint32 repeated_value               # must equal value
```

Stream `126` contains 20 records and stream `92` contains nine; stream `114`
contains none. All 29 consume and re-encode byte-for-byte. At each frame the
object id names a remote player introduced by opcode `189`, and at least one
currently active mob has the encoded template. The long stream uses player
aliases for two ids and templates `130100`, `210100`, and `1110100`; stream
`92` uses four player ids and templates `130100`/`210100`.

The fold emits `remote_player_mob_value_received` with a session-local player
alias, known-player boolean, active-template count, mob template, neutral
value, and flag. It records unknown-player/inactive-template counters for
future captures but both remain zero in the references. Safe output never
contains the player id. The repeated value and remote-player/mob correlations
are exact; they do not by themselves prove that the value is damage or justify
a live visual/state effect claim.

## Capture-bounded selector envelope (`239`)

The pinned version-300 opcode-`239` handler reads one selector byte and
dispatches through a larger branch table. The reference captures exercise four
selectors with these exact bodies:

```text
uint16 opcode = 239
uint8  selector

selector 3:
    uint8 record_count
    repeat record_count:
        uint32 key                 # retained for re-emission; redacted
        int32  value

selector 9 or 13:
    # no body

selector 21:
    uint16 text_code_units
    utf16le[text_code_units] text  # retained for re-emission; redacted
    uint8 text_terminator = 0
    uint32 trailing_value
```

Stream `126` contains 59 packets: 29 selector-`3` lists with 38 total records,
27 selector-`9` packets, two selector-`13` packets, and one selector-`21`
packet. That string has 14 UTF-16 code units and its trailing value is `1`.
Stream `92` contributes one more empty selector-`13` packet; stream `114`
contains none. All 60 packets consume and re-encode exactly at full coverage.

The fold emits `server_opcode_239_received` and records selector/count, signed
record-value, text-length, and trailing-value distributions. Safe state,
events, reports, JSON, and HTTP-derived analysis omit all record keys and text.
The fields remain neutral: packet shape and handler dispatch do not establish
whether a branch represents UI, inventory, progression, or another subsystem.
Selectors not observed in the two captures remain unknown rather than being
accepted by one of these codecs.

## Tutorial UI instruction (`247`)

The pinned version-300 opcode-`247` handler reads a terminated counted UTF-16
string, two signed 16-bit values, and a control byte. One control branch reads
two additional signed 32-bit values:

```text
uint16 opcode = 247
uint16 text_code_units
utf16le[text_code_units] text        # retained only for re-emission
uint8 text_terminator = 0
int16 value_1
int16 value_2
uint8 control_value
optional int32 extended_value_1
optional int32 extended_value_2
```

Only stream `126` contains this family: 33 packets of 60 or 62 bytes, with 17
distinct tutorial localization keys. Six strings contain 25 UTF-16 code units
and 27 contain 26. `value_1` has distribution `100:7, 110:2, 150:23, 200:1`;
`value_2` is always `5`, the control byte is always `1`, and none uses the
extended branch. All 33 parse at full coverage and round-trip exactly. The fold
emits `tutorial_ui_instruction_received` and exposes only code-unit and numeric
distributions; text never appears in safe state, events, reports, or JSON.

Two exact compact packets were injected into the live level-12 client. Both
were accepted, independently folded at full coverage, and left the client
active on map `101000000` with four remote players and no connection failure.
Framebuffers sampled at 100 ms, 400 ms, and one second showed no new overlay,
so rendering is state-gated in this client state and is not claimed. The live
test validates packet shape, encryption/order, and non-blocking handling only.

## Instructional dialogue request (`244`, selector `8`)

The pinned version-300 opcode-`244` handler first reads a selector byte. Its
selector-`8` branch performs three signed 32-bit reads, exactly matching the
only branch present in the reference captures:

```text
uint16 opcode = 244
uint8 selector = 8
int32 value_1
int32 value_2
int32 value_3
```

Stream `126` contains 54 such packets, all exactly 15 bytes. They consume and
round-trip exactly at full coverage. `value_1`, `value_2`, and `value_3` have
28, 19, and 13 distinct values respectively; `value_3` is zero in 42 packets.
Those roles remain neutral because width and UI effect do not establish their
higher-level identifiers. Other selector or length branches stay unknown
rather than being forced through the selector-`8` codec.

An exact captured packet with values `1036, 2003, 0` was injected into a fresh
level-12 live client. It immediately opened an instructional NPC dialogue:
the 100 ms framebuffer showed partially rendered text and the one-second frame
showed the complete message. The injected packet reappeared in the transcript
as one exact full-coverage `instructional_dialogue_requested` event. The fold
remained valid and active on map `101000000`, all 11 observed heartbeat pairs
matched, and runtime reported no connection failure. This validates the
dialogue-request effect while deliberately leaving its numeric value roles
unnamed.

## Field reactors (`225`, `320`, `322`, `323`)

Server opcodes `322`, `320`, and `323` are the reactor spawn, state-update, and
removal lifecycle. This is supported by the pinned handler grouping, the exact
wire shapes, the `Reactor/{0:D7}` and `reactorState` strings in the build, and
the matching roles in the independent Cosmic
[reactor-hit handler](https://github.com/P0nk/Cosmic/blob/master/src/main/java/net/server/channel/handlers/ReactorHitHandler.java)
and [reactor packet builders](https://github.com/P0nk/Cosmic/blob/master/src/main/java/tools/PacketCreator.java).
The version-300 layouts are:

```text
opcode 320:
    uint16 opcode
    int32 reactor_object_id          # aliased/redacted
    uint8 state
    int16 x
    int16 y
    uint16 stance
    uint8 reserved_value = 0
    uint8 frame_delay

opcode 322:
    uint16 opcode
    int32 reactor_object_id          # aliased/redacted
    int32 reactor_id
    uint8 state
    int16 x
    int16 y
    uint8 spawn_flag

opcode 323:
    uint16 opcode
    int32 reactor_object_id          # aliased/redacted
    uint8 state
    int16 x
    int16 y
```

Stream `126` contains 12/50/20 packets respectively, all exactly 15/16/11
bytes and all exact full-coverage round trips. Every state update/removal
references an active same-field reactor; removals delete the entity and field
snapshots clear the active reactor map. State/events expose only `reactor:N`
aliases, reactor template, coordinates, state/flag distributions, and the
request/response correlation. Raw runtime object ids are omitted.

A live exact opcode-`322` record at captured coordinates `(2609,-372)` was
accepted without a visible in-view change. A second typed record changed only
the i16 coordinates to the folded local-player position `(633,-2677)`. At 100
ms the client showed a transient blue `10` directly above the player; it was
gone at one second, HP remained `50/222`, and the connection stayed active.
The transcript folds the pair exactly as `reactor:1` creation then update,
ending at `(633,-2677)` with zero unknown updates and 131/131 matched heartbeat
pairs. The blue `10` is consistent with reactor template `2000`; the live check
validates placement/acceptance, not gameplay policy for that reactor.

Client opcode `225` is the corresponding reactor-hit request:

```text
uint16 opcode = 225
int32  reactor_object_id             # aliased/redacted
int32  character_position            # observed 2 or 3
uint16 stance                        # observed 305 or 393
uint32 reserved_value = 0
```

All 15 stream-`126` requests are 16 bytes. Their five object ids resolve to
active same-epoch reactors and every request follows targetless opcode `50`.
FIFO correlation by reactor id matches every request to the next opcode-`320`
state update (12) or opcode-`323` removal (3) in `388.463..1,102.698` ms
(median `406.749` ms). All 12 updates echo the request stance exactly; no
request remains pending. The `character_position` label is supported by the
independent reactor-hit handler but remains build-specific telemetry here.
Python and native codecs consume/re-emit every request exactly. Promoting the
15 requests while reclassifying the already-full 82 lifecycle packets moves
stream `126` from `27,188/43,912/0/0` to `27,203/43,897/0/0`.

## Redacted selector envelope (`276`)

Two independently observed selector branches share client opcode `276`.
Stream `126` contributes one 210-byte selector-`24` packet:

```text
uint16 opcode = 276
uint32 selector = 24
uint32 header_value_1                 # retained; redacted
uint32 header_value_2                 # retained; redacted
uint32 group_count
repeat group_count:
    uint32 group_selector             # retained; redacted
    uint32 pair_count
    repeat pair_count:
        uint32 value_1                # retained; redacted
        uint32 value_2                # retained; redacted
```

Its `group_count` is `5`; per-group pair counts are `3,5,5,3,3`, totaling 19.
The active local-Wine transcript independently contributes the compact branch:

```text
uint16 opcode = 276
uint32 selector = 17
uint8  reserved[3] = 0
```

The fold publishes only selector, `compact`/`grouped` shape, group count, pair
count, and field epoch. Header, group-selector, and pair values remain present
for exact re-emission but are omitted from safe state and events. Both Python
branches round-trip exactly, the native manifest keeps distinct nine- and
210-byte shapes, and isolated native validation exact-consumes both packets.
The reference grouped record and independently observed compact record now have
full structural coverage; redacted headers, group selectors, pair values, and
higher-level purpose remain neutral.
No request/response, UI, or gameplay meaning is assigned from the shared opcode
alone. The long corpus moves from the opcode-`298` checkpoint
`26,661/44,429/10/0` to `26,661/44,430/9/0`; the held-open live transcript
moves from one unknown packet to zero and closes warning-free after the
configured two-hour hold with all `1,440/1,440` heartbeats matched. Its final
gameplay phase remains map `101000000` at HP `50/222`.

## Item-acquisition transaction (`298` -> `39`)

All 12 client opcode-`298` packets in stream `126` have one exact 76-byte
shape:

```text
uint16 opcode = 298
uint32 control_value = 0
uint32 selection_index
uint32 request_kind                  # observed 1 -> Use, 2 -> Cash
uint32 item_id
uint32 quantity
uint32 duration_value                # observed 0, 10080, or 20160
uint64 expires_at_ticks = 150842304000000000
uint32 serial_value                  # retained for exact re-emission; redacted
uint32 reserved_values[5] = 0
int32  signed_sentinel_values[2] = -99
uint32 trailing_values[2] = 0
uint8  flag_1 = 0
uint8  flag_2 = 1
```

The selection indices are `25,24,23,22,10,9,8,7,6,5,3,4`; request kinds are
`{1:9,2:3}`, duration values are `{0:8,10080:1,20160:3}`, and only the three
kind-`2` records carry nonzero serials. The serial field is excluded from safe
packet state, events, and text reports.

Every request is followed in the same field epoch by a server opcode-`39`
addition with the request-kind inventory and exact item template. The bounded
latencies are `388.332..711.700` ms. All nine Use requests match aggregate
response quantity, including quantity `2` split into two quantity-`1` slots.
Two Cash stack additions have response quantity `3` for request quantity `1`,
and the Cash equipment-style addition has no quantity. The fold therefore
records 12 item/inventory matches, nine quantity matches, two quantity
mismatches, one quantity-unavailable response, and zero pending requests; it
does not reject the three Cash distinctions or infer what authorizes the
acquisition. Empty opcode-`39` change sets immediately before some additions
do not prematurely close a request.

The Python codec, fold, and native manifest consume and re-emit all 12 records
exactly. All 12 now report full structural coverage while neutral control,
selection, duration, serial, sentinel, and flag roles remain neutrally named or
redacted. Safe analysis adds request counts by inventory/kind, neutral duration
distributions, nonzero-serial counts, match/quantity/pending counters, and
last/maximum response latency. Coverage advances from
`26,661/44,417/22/0` to `26,661/44,429/10/0`.

`--reactive-item-acquisition-responses` serves only the five permanent Use
transactions for which the capture proves an exact construction rule:
`(selection,item,quantity)` values `(5,2000016,100)`, `(6,2000018,100)`,
`(9,2000079,100)`, `(10,2030059,10)`, and `(22,2000031,300)`. An admitted
request must retain kind `1`, duration `0`, serial `0`, all fixed fields, and
an item template absent from the modeled Use inventory. The response is one
opcode-`39` add with update flag `0`, inventory type `2`, the lowest positive
free slot, record type `2`, requested quantity, zero-length owner, captured
zero metadata, and both permanent/sentinel timestamps. Timed Use and all Cash
requests remain unserved because their expirations, serials, quantities, and
record variants require additional policy evidence.

The encrypted replay integration test drives opcode `298` through the actual
hold-open reader and validates the generated opcode `39`, mutable policy state,
runtime events, and immutable transcript fold. The reference account already
owns four of the five permanent templates, leaving only item `2000079`
currently eligible. Its ordinary UI did not expose the captured acquisition
action, so the real-client check independently validates the response side:
after a typed removal cleared an earlier permanent-stack probe, the exact
eligible item-`2000079`, quantity-`100`, slot-`25` addition appeared in the
open Use inventory without disconnecting. The clean transcript
`downloads/maple_custom_server_observed/item_acquisition_live_20260812_clean/world/1786499171269565791_replay_12857.jsonl`
remained valid and warning-free at `156/133/0/0`, folded 25 Use items including
the exact slot/template/quantity, and matched `60/60` heartbeats with none
pending. This proves client acceptance of the response shape, not a genuine
live opcode-`298` request; the encrypted integration test is the handler proof.

## Redacted text envelope (`348`)

The pinned version-300 opcode-`348` handler performs four common primitive
reads before selector dispatch. The observed branches have this exact grammar:

```text
uint16 opcode = 348
uint8  category
int32  primary_value                 # retained for re-emission; redacted
uint8  selector
int32  value
uint16 text_code_units
utf16le[text_code_units] text        # retained for re-emission; redacted
uint8  text_terminator = 0
if selector == 0:
    uint8 control_1
    uint8 control_2
```

Only stream `126` contains opcode `348`: 31 packets, 30 distinct payloads, and
six distinct primary values. Category is `4` and value is zero in every packet.
Selectors occur as `0:20, 3:2, 6:7, 17:2`. Selector `0` control pairs are
`0:0` once, `0:1` nine times, and `1:1` ten times; selectors `3`, `6`, and `17`
end immediately after the string terminator. Packet lengths range from 59 to
391 bytes. Every packet consumes and re-encodes exactly at full coverage.

The fold emits `server_opcode_348_received` and exposes category, selector,
value, text-code-unit, and control-pair distributions. Safe state, events,
reports, JSON, and HTTP-derived analysis omit the primary value and text.
Their higher-level roles remain neutral, and handler selectors absent from the
captures stay unknown.

Every one of those 31 server packets is followed by exactly one same-selector
client opcode `66` packet, with no pending or unmatched transaction when
processed chronologically. Its capture-bounded grammar is:

```text
uint16 opcode = 66
uint8  selector
uint8  status
if selector == 6 and status == 1:
    uint32 optional_value            # retained for re-emission; redacted
```

The four-byte selector/status forms are `0/1` (19), `0/255` (1), `3/1` (2),
`6/0` (1), and `17/1` (2). Six `6/1` packets use the eight-byte form; their
optional value is `5` five times and `1` once. Same-selector FIFO round trips
range from `728.174` to `10,436.006` ms with a `1,561.373` ms median. The fold
emits `server_opcode_348_acknowledged`, exposes only selector/status/shape,
redacted-value presence, pending counts, and timing, and warns on unmatched or
unfinished transactions. All 31 packets parse, re-encode, and validate through
the generated native shape without exposing the text or optional value.

A cross-state live replay does not establish that arbitrary opcode-`348`
packets are safe. The custom server wrote one exact 63-byte selector-`0` packet
from the level-1-to-10 stream to an active level-12 client bootstrapped from
short stream `114`. The client emitted no opcode `66`; after one more heartbeat
it closed the world connection and displayed a black framebuffer. The launcher
and direct nested-Wayland seat restored the same client to an active field with
719/719 heartbeats. This is negative state/build-gating evidence, not a
contradiction of the capture-local one-to-one transaction correlation.

## Client opcode `64` NPC interaction request

Stream `126` contains two exact 10-byte requests with this grammar:

```text
uint16 opcode = 64
uint32 npc_object_id                 # observed 170389 and 11827
int16  player_x
int16  player_y
```

The two object ids resolve in folded field state to active NPC templates `2003`
and `22000`. Their player positions `(198,275)` and `(3331,-219)` exactly match
the endpoint of the last same-epoch client opcode-`47` life-movement path. The
next same-epoch server opcode `348` follows after `439.289` and `396.405` ms,
respectively.

An independent live input control establishes the semantic boundary. The
expanded opcode-`385` keyboard map binds action `54` to evdev Space (`57`). A
physical Space press emitted three repeated opcode-`64` requests while held;
all carried object `3294`, which was the active field NPC template `1032005`,
and player position `(677,-2695)`. The folded NPC position was `(740,-2693)`.
The automatic dump establishes only the opcode enum; the object-id role comes
from this input effect plus the independent active-NPC correlations.

The fold emits `npc_interaction_requested`, aliases the runtime NPC id, reports
active/unknown target counts and template distributions, validates the player
position against same-epoch movement, and FIFO-correlates the following opcode
`348`. It warns on an inactive target, position mismatch, or unfinished
request. Both reference requests resolve, match position, receive opcode `348`,
and leave nothing pending. The live custom server does not implement that
response, so its three otherwise valid requests remain pending with one
explicit warning. Python and the native manifest consume and re-emit every
record exactly. Stream `126` currently measures `26,664/44,436/0/0`
full/partial/unknown/invalid observations.

## Fixed-width neutral server records

Three independent gameplay streams share a small fixed-width server-record
family. Their complete grammars, including the two-byte opcode, are:

```text
opcode 24, 45, 178:                 uint16 opcode
opcode 58, 71, 89, 105, 121:        uint16 opcode; uint8 value
opcode 56, 72, 74:                  uint16 opcode; uint16 value
opcode 60:                          uint16 opcode; int32 value
opcode 112, 131, 301,
       386, 388, 389:               uint16 opcode; uint32 value
opcode 96:                          uint16 opcode; uint16 value_1;
                                    uint16 value_2
opcode 76:                          uint16 opcode; uint32 value_1;
                                    uint32 value_2
opcode 398:                         uint16 opcode; uint64 value
opcode 11:                          uint16 opcode; uint32 reserved=0;
                                    uint8 reserved=0
opcode 59:                          uint16 opcode; uint32 character_id;
                                    uint8 flag=1; uint32 reserved_1=0;
                                    uint32 reserved_2=0;
                                    uint32 reserved_3=0
```

Opcode `59` is the only member with an established state relationship: its
character id equals the preceding world-entry character id in streams `92`,
`114`, and `126`. Normal reports retain only the match boolean. The remaining
values stay semantically neutral. The generated IL2CPP dump proves that opcode
`60` performs one direct signed-`i32` read; its six stream-`126` values are
`1037, 1039, 1042, 1043, 1044, 2132`. Each appears in a mob-reward packet batch,
but adjacency does not establish the field's meaning. Stream `126` also proves
opcode `388` is not a reserved-zero record (`value=0xfde04000`). Variable-width
opcodes `156` and `385` are bounded separately below and are not included in
this family.

Short stream `114` contains 21 records: one of every supported opcode except
the sustained-session opcodes `60` and `301`. Streams `92` and `126` contain
69 and 94 records respectively, including a second opcode-`96`, repeated empty
opcode `45`, and repeated opcode-`301` values later in gameplay. Opcode `190` is now
the remote-player removal described above rather than a neutral numeric
record. All 184 remaining fixed-record observations parse at full
coverage, round-trip exactly, update opcode counters, and emit
`fixed_server_record_received` or `initial_character_context_received` events
with the current field epoch.

`--generate-fixed-server-records` materializes every typed observation,
reparses it, preserves its original length and server-frame index, and rejects
duplicates or explicit-patch conflicts. `GET /api/v1/status` exposes the safe
plan under `protocol.fixed_server_record_emitter`; it includes neutral values,
frame indices, field epochs, patch count, and an unchanged player/phase
prediction, but no character id. A browser-free live stream-`114` run first
composed the original 11 generated records with the typed initial snapshot and
nine generated NPC spawns; the other ten now-typed records traveled as
unchanged capture bytes in that connection. A fresh run of the expanded
emitter then patched all 21 fixed records. The client reached and rendered map
`101000000` with one active connection, no failures, and 13/13 paired heartbeat
probes. The status API reported `frames_patched:21` and the exact 21-opcode
plan. The expanded emitter also has exhaustive byte-for-byte PCAP round-trip
coverage.

## Neutral server records (`69`, `93`, `94`, `137`, `148`, `205`, `276`, `379`)

These eight opcodes recur with capture-bounded layouts in the gameplay
streams. Their semantic roles remain neutral, and fields that may carry a
character/session value are redacted from safe output:

```text
opcode 69:
    uint16 opcode
    uint8 record_count = 7
    repeat record_count:
        byte[38] reserved_zero = 0

opcode 93:
    uint16 opcode
    uint8 value_count
    repeat value_count: uint32 value

opcode 94:
    uint16 opcode
    bool flag
    int32 primary_value
    int32 secondary_value

opcode 137:
    uint16 opcode
    int16 record_count              # observed 10
    repeat record_count:
        int32 first_value           # redacted
        int32 second_value          # redacted

opcode 148:
    uint16 opcode
    uint8 variant
    variant 9:
        int32 record_count
        repeat record_count under current IL2CPP mask 0x9:
            int32 primary_value       # redacted
            int32 secondary_value     # redacted
            int64 start_time          # DateTime bits, redacted
            int64 end_time            # DateTime bits, redacted
            utf16 text + uint8 zero   # redacted
        byte[] legacy_records_blob    # lossless fallback on grammar mismatch
    variant 10: no body
    variant 12 or 13: int32 primary_value; int32 secondary_value

opcode 205:
    uint16 opcode
    uint32 primary_value             # redacted
    uint32 secondary_value
    uint64 numeric_value
    uint8 trailing_value

opcode 276:
    uint16 opcode
    bool8 enabled                    # captured raw byte 0x05 => true

opcode 379, variant 35:
    uint16 opcode
    uint8 variant

opcode 379, variant 36:
    uint16 opcode
    uint8 variant
    int64 time_1
    int64 time_2
    int64 time_3
    int64 time_4
```

Streams `92/114/126` contribute `37/5/93` records respectively. By opcode,
the combined counts are `69:50`, `93:7`, `94:3`, `137:3`, `148:23`,
`205:42`, `276:2`, and `379:5`. Every
opcode-`69` count is `7` and all seven 38-byte records are zero in these
captures. The generated handler independently proves the initial `u8` read;
the repeated-record boundary is deliberately limited to the only observed
count and width. Every opcode-`93` packet counts four u32 values. Opcode `205` is
fully bounded, as is the counted opcode-`93` vector. The generated handler dump
independently supplies the exact direct-read sequences for opcodes `94`, `137`,
`276`, and `379`. Opcode `137` reads an `i16` count and loops over two `i32`
reads. All three packets use count `10`, consume as ten exact pairs, and have
ten distinct pairs within each packet; the two stream-`92` packets are exact
duplicates, while stream `126` contains the same ten pairs in a different
order. The numeric values stay redacted and neutral. This promotes one/two
observations in streams `126`/`92` to full coverage, advancing them to
`69,934/1,166/0/0` and `34,540/667/0/0`; stream `114` remains
`64/12/0/0`. Both opcode-`276` packets are the
three-byte `0x05` true form, both opcode-`379` short packets use variant `35`,
and its three
four-datetime packets use variant `36`. Opcode `148` contributes one empty
variant-`9`, nine empty variant-`10`, nine variant-`12`, three variant-`13`, and
one nonempty variant-`9` packet. The current delegated IL2CPP record mask is
`0x9`, which reads two `i32` values, two DateTime/`i64` values, and one
trailing-zero counted UTF-16 value per record. The legacy nonempty body fails
that grammar at record zero's required string terminator and therefore retains
1,632 record bytes as one explicit partial observation.
Together the family provides 131 full and four partial observations with 1,848
opaque bytes rather than inventing suffix or record semantics. All 50 opcode-
`69` packets (36/13/1 in streams `126`/`92`/`114`) independently validate and
round-trip exactly.

The gamestate fold emits `neutral_server_record_received`, tracks packets by
opcode, typed-value counts, reserved-zero byte counts, and opaque-byte totals,
and exposes only redacted safe details. The HTTP-derived analysis publishes
opcode `69`'s count, record width, and zero-byte total, but no record contents.
All 135 packets reparse and round-trip byte-for-byte.

## Pet activation (`server 201`)

The 46 formerly neutral opcode-`201` records are exact pet-activation
envelopes. The generated current-client handler proves dispatch through the
shared delegated parser; independent TMS pet packet writers name the ordered
body, and every Protocol-300 packet consumes this grammar exactly:

```text
uint16 opcode = 201
uint32 character_id                  # redacted; owner alias in safe output
uint32 pet_slot
uint8  activation_flag = 1
uint8  activation_type
uint32 pet_item_id
uint16 name_code_units = 0
uint8  name_trailing_zero = 0
uint64 pet_serial_id                 # redacted
int16  x
int16  y
uint8  stance
uint16 foothold_id
```

Streams `126`/`92`/`114` contain 30/15/1 packets. All 42 local-owner records
match the world-entry character id; the other four match active remote players,
leaving zero unknown owners. The fold emits `pet_activated`, reports item,
slot, activation type, position, stance, foothold, and owner alias, and keeps
the character id, pet serial, and empty name out of ordinary JSON, events, and
HTTP-derived analysis. Native validation and Python round trips consume all 46
packets exactly. Coverage advances to `69,719/1,381/0/0`,
`34,494/713/0/0`, and `64/12/0/0` for streams `126`/`92`/`114`.

A typed live replay of captured opcode-`94` values (`flag=true`, primary
`2380000`, secondary `2`) added exactly one neutral event while phase, field
epoch, map, player, inventory, progression, skills, and fixed-record state
remained unchanged. The browser-free client answered the next generated
heartbeat and remained on map `101000000`; this proves non-stalling acceptance,
not a higher-level meaning for either integer.

A fresh browser-free direct-Wayland run also accepted a generated three-byte
opcode-`148` variant-`10` packet. Its transcript added one full
`neutral_server_record_received` event, left the folded core state unchanged,
advanced matched heartbeat probes from 11 to 18, and retained one active world
connection with zero injection failures. This validates the bounded empty
branch and predicted neutral fold only.

Opcode `276` also exposes why IL2CPP `bool` cannot be constrained to wire bytes
`0` and `1`. The generated handler directly calls the pinned boolean reader,
whose ISIL calls `BitConverter.ToBoolean`; both reference packets carry
`0x05`, which therefore means true. Native validation now normalizes every
nonzero byte to true for comparisons, while the Python record keeps the raw
byte for exact re-emission. A loopback replay of exact packet `140105` added a
second full opcode-`276` event. The core-state digest was unchanged, phase/map
remained `active`/`101000000`, the next three heartbeats matched with no pending
probe, and packet injection retained zero failures.

Opcode `137` remains deliberately partial. Its three generated prefix values
and 72-byte tail are retained for exact re-emission but redacted from safe
analysis; only typed-value and tail-length counts are published. All three
packets validate natively and in the state fold. Live replay is deferred because
the generated handler does not name the values or consume the delegated tail,
so cross-session injection would not be a bounded semantic test.

## Server opcode `169` text instruction

The automatic dump identifies an eight-way selector handler. Native jump-table
inspection is required because its direct-read list is the union of mutually
exclusive branches. Selector `3` lands at `0x180BC3281`, calls the pinned
UTF-16 reader once, then exits through the common return:

```text
uint16 opcode = 169
uint8  selector = 3
uint16 text_code_units
utf16  text[text_code_units]        # redacted
uint8  trailing_zero = 0
```

The sole reference occurrence is a 54-byte server packet in
`1-10FS.pcapng` stream `126`; its string has 24 code units and the shape
consumes the frame exactly. `ServerOpcode169TextInstruction` preserves the
text for exact re-emission but omits it from safe dictionaries, events, JSON,
and text reports. The gamestate fold increments selector/text-length counters
and emits `server_opcode_169_text_instruction_received` with selector, length,
and field epoch only. The observed event occurs at epoch `31` and moves the
packet from unknown to full coverage. No cross-session replay is claimed until
the client resource effect is independently bounded.

## Server opcode `29` delegated text ledger

The generated opcode table identifies handler `b7bc850c...`, but its direct
packet-read list is empty because it constructs a separate ledger object. The
handler passes the `PacketReader` to constructor `0x180CB4390`; native control
flow proves that constructor reads a `u8` count and invokes record constructor
`0x180CB3F20` once per entry. The record constructor performs the exact ordered
reads below:

```text
uint16 opcode = 29
uint8  entry_count
repeat entry_count:
    int32  key                       # redacted, role unproven
    int32  value_1                   # redacted, role unproven
    uint16 text_code_units
    utf16  text[text_code_units]     # redacted
    uint8  trailing_zero = 0
    int32  value_2                   # redacted, role unproven
    int16  short_value               # redacted, role unproven
```

`111.pcapng` contains one 327-byte server packet in stream `92` and one in
stream `114`. They are byte-identical, have `entry_count = 4`, and contain
text lengths `30`, `36`, `31`, and `31` code units. The grammar consumes all
327 bytes, both native manifest validations pass, and
`ServerOpcode29TextLedger` parses and re-emits both payloads byte-for-byte.

Safe state publishes only packet count, entry-count distribution, total and
per-entry text lengths, redaction flags, and field epoch. The fold emits
`server_opcode_29_ledger_received` and a full
`server_opcode_29_text_ledger` observation. At that decoder checkpoint, stream
`92` coverage changed to `13,412/21,762/33/0` and stream `114` to
`51/20/5/0`; the level-1-to-10
stream remains `26,660/44,381/59/0`. No live replay is claimed because the
obfuscated numeric fields and captured text have not yet been shown safe across
sessions.

## Server opcode `135` bootstrap ledger

The generated opcode table maps server opcode `135` to handler
`aecdc2fee9fbe41bb513947bf2cc9b43154d7eb6d73fbc67a79d1f3b2aa4810`.
Its flattened read list contains `u8`, IL2CPP `bool`, `i16`, and `i32` calls
from mutually nested loops. A non-stalling in-process trace on the local Wine
client recorded every executed non-`i16` primitive for the exact captured
packet: 1,305 calls on one packet object, monotonically advancing from framed
cursor `6` to `3729`. The only 45 unhooked spans are two bytes each; inserting
the generated `i16` primitive at those spans produces this exact grammar:

```text
uint16 opcode = 135
uint8  section_a_entry_count
repeat section_a_entry_count:
    bool    enabled
    int32   value                         # redacted, role unproven
    int32   value_count
    repeat value_count:
        int32 value                       # redacted

uint8  section_b_entry_count
repeat section_b_entry_count:
    bool    enabled
    int32   value_1                       # redacted, role unproven
    uint8   value_2                       # redacted, role unproven
    int16   pair_count
    repeat pair_count:
        int32 value_1                     # redacted
        int32 value_2                     # redacted

uint8  section_c_value                    # redacted, role unproven
int16  section_c_pair_count
repeat section_c_pair_count:
    int32 value_1                         # redacted
    int32 value_2                         # redacted

int32  section_d_entry_count
repeat section_d_entry_count:
    int32 value                           # redacted, role unproven
    int16 group_1_count
    repeat group_1_count:
        int32 value_1                     # redacted
        uint8 value_2                     # redacted
    int16 group_2_count
    repeat group_2_count:
        int32 value_1                     # redacted
        uint8 value_2                     # redacted
```

The sole `111.pcapng` stream-`114` packet is 3,725 plaintext bytes. Section A
contains two entries and 166 repeated values; section B contains two entries
and 21 pairs; section C contains ten pairs; section D contains 21 entries with
260 members in each nested group. The Python codec consumes all bytes and
re-emits the original packet exactly, while the generated manifest independently
validates the same count grammar. Safe analysis omits every numeric value and
exposes only entry/group counts, enabled counts, redaction flags, and field
epoch.

The fold emits `server_opcode_135_ledger_received` and a full
`server_opcode_135_bootstrap_ledger` observation, moving stream `114` to
`52/20/4/0`. The exact captured plaintext was also sent through loopback-only
`POST /api/v1/server-packets` while the local Wine client was the sole replay
peer. The client processed the ledger and retained its field connection and
heartbeat exchange. This proves packet shape and non-blocking handling, not the
meaning or cross-session safety of the redacted values.

## Correlated opcode `394` / client opcode `279` text envelopes

The automatic packet dump contains the server opcode-`394` enum member but no
attributed managed handler, so the shape below comes from exact capture
consumption rather than a flattened read list:

```text
uint16 opcode = 394
uint16 text_code_units = 57
utf16  text[text_code_units]          # redacted
uint8  trailing_zero = 0
```

The sole server packet is 119 bytes. The next client packet, 57.92 ms later,
has this exact 120-byte boundary:

```text
uint16 opcode = 279
uint8  control_value                  # observed 1; neutral role
uint16 text_code_units = 57
utf16  text[text_code_units]          # redacted
uint8  trailing_zero = 0
```

The two strings have equal lengths and 52 of 57 code units are identical; the
only changed span is indices `10..14`. Both codecs preserve the text privately
for exact re-emission while safe state, events, and packet observations expose
only lengths, the control byte, changed count/span, temporal correlation, and
the observed gap. FIFO pairing is an analysis correlation, not a causal claim:
injecting the exact server packet through the local replay's loopback HTTP API
did not produce client opcode `279` within seven seconds, and the local Wine
client remained connected and responsive in-field. The model therefore uses
neutral envelope/event names and does not require opcode `394` for login or
gameplay. The two full observations move stream `92` to
`13,414/21,782/11/0`; stream `114` remains `52/22/2/0` and stream `126` remains
`26,660/44,381/59/0`.

## Client field bootstrap and world exit

Client opcode `158` is a shared mode/count envelope, not one uniform field-load
stage packet:

```text
uint16 opcode = 158
uint32 mode
uint32 change_count

repeat change_count:
    uint32 key_code
    uint8  binding_type
    int32  action_id
```

Modes `1` and `2` carry count zero and remain the repeated field-load
`1 -> 2` sequence in streams `92` and `114`. Mode `0` carries keymap changes.
All 11 stream-`126` mode-`0` packets have count one and match the independent
v83 keymap-change grammar. The key codes are Linux evdev values: `29` Left
Ctrl, `42` Left Shift, `71` Home, and `82` keypad zero. Binding types are
`0` empty/removal, `1` skill, `2` item, and `5` action. Observed binding values
include learned skills `2001005`, item templates `2000013`/`2000014`, and
action `52`, while the first packet assigns type `1` value `1000` at key `42`.
The fold applies changes to the opcode-`385` keyboard snapshot state, emits
`keyboard_bindings_changed`, and exposes key/type/action values. The exact
counted grammar supports arbitrary multi-change packets even though the
reference corpus contains only count one.

Client opcode `75` is an exact opcode-only marker:

```text
uint16 opcode = 75
```

It occurs once during the initial `field_loading` phase in `111.pcapng` stream
`92` and `1-10FS.pcapng` stream `126`. The browser-free local-Wine transcript
independently emits the same marker at field epoch `1`. No stronger semantic
role is assigned.

Client opcode `301` is the first client gameplay packet in each of streams
`92`, `114`, and `126`, and independently in the active custom-server login:

```text
uint16 opcode = 301
uint32 reserved_zero = 0
```

All four packets are the identical six bytes `2d0100000000`. They follow the
immediately preceding server bootstrap record by `7.109`, `8.105`, `0.533`,
and `10.121` ms respectively. The exact constant is now enforced, every byte
round-trips, and the fold reports the acknowledgement at full coverage without
publishing an opaque value. The bootstrap role comes from its invariant
position; no narrower subsystem purpose is assigned.

Both terminating `111.pcapng` world sessions share this client/server sequence:

```text
uint16 opcode = 241                    # empty world-exit request

uint16 opcode = 45 or 46               # stream 114 or 92
uint32 value                            # redacted status value

uint16 opcode = 9
uint8  endpoint_flag = 1                # observed control; narrower role neutral
byte[4] destination_ipv4                # network-order address; redacted
uint16 destination_port                 # little-endian; redacted
```

The request is emitted from `active`. Status opcode `46` follows by 64.396 ms
in stream `92`; status opcode `45` follows by 66.699 ms in stream `114`. The
final server packet follows the request by 165.073 and 167.004 ms respectively.
The fold enters `exit_requested`, reports the status value only as redacted,
then enters `terminated` and records FIFO correlation plus round-trip timing on
opcode `9`. The endpoint fields are not an inference from byte appearance:
stream `92` advertises `43.142.194.134:10283`, and the client begins TCP stream
`113` to that exact endpoint `1.757` ms after opcode `9`; stream `114`
advertises `43.142.194.127:10284`, followed by TCP stream `115` to that exact
endpoint after `16.125` ms. Safe analysis reports only that a destination is
present and redacted. Exact packet observations promote all three client boundaries to
full coverage. Stream `92` reaches `13,417/21,782/8/0`, stream `114` reaches
`54/22/0/0`, and stream `126` reaches `26,661/44,381/58/0`.

With the endpoint handoff itself promoted from partial to full, current strict
totals become `34,571/636/0/0` for stream `92` and `67/9/0/0` for stream
`114`. Stream `126` contains no opcode `9` and remains
`70,074/1,026/0/0`; the active saved transcript likewise contains no terminal
handoff and remains `2,982/52/0/0`.

The current local client's game-menu confirmation did not emit opcode `241`,
so a terminal injection was intentionally not attempted. Three controlled
direct-Wayland confirmations instead emitted one client opcode-`310` packet
each, with no phase transition or later opcode `241`. This leaves the captured
transaction exact and independently repeated, but its live UI trigger unproven
in the current replay state.

## Fixed-width and typed client reports

Four additional outgoing-client families repeat at exact widths in the two
sustained gameplay captures. A fifth width is independently bounded by the
three controlled local-Wine menu confirmations:

| opcode | packet/body bytes | stream `92` | stream `126` | local Wine | bounded observation |
| --- | ---: | ---: | ---: | ---: | --- |
| `100` | `26/24` | 1 | 1 | 1 | counted ability-point allocation request |
| `307` | `14/12` | 1 | 1 | 28 | two redacted words plus zero trailer near bootstrap |
| `308` | `74/72` | 2 | 11 | 13 | typed mirrored-value record; approximately 300-second cadence while continuously running |
| `310` | `41/39` | 0 | 0 | 3 | counted redacted UTF-16 plus zero suffix |
| `311` | `22/20` | 2 | 6 | 7 | zero-bounded `u32`; bootstrap-skewed first gap, then approximately 600 seconds |

Opcode `100` is fully modeled as:

```text
uint16 opcode = 100
uint32 client_tick
uint32 allocation_count
repeat allocation_count:
  uint32 stat_mask
  uint32 increment
```

Both captures use count `2` and the existing opcode-`41` masks for LUK and INT.
Stream `92` requests increments `1/4`; 107.555 ms later opcode `41` raises the
two stats by exactly `1/4` and lowers AP from `5` to `0`. Stream `126` requests
`9/29`; 406.248 ms later the response raises the stats by exactly `9/29` and
lowers AP from `38` to `0`. The fold correlates both responses with zero
pending, mismatched, or unverified requests and exposes safe per-stat totals and
latency.

The local client's auto-allocation control adds a bounded request variant: it
keeps the same count-`2` LUK/INT layout but may encode zero for the unchanged
stat. An exact live request used `LUK +0, INT +1`. Individual increments are
therefore unsigned `u32` values that may be zero, while the request total must
remain positive.

`--reactive-ability-point-allocation-responses` turns the correlation into an
opt-in hold-open handler. It derives mutable STR/DEX/INT/LUK/AP state from the
validated replay, rejects requests that exceed available AP or overflow a
`u16` result, and emits one opcode-`41` record with request flag `1`, the
requested stat bits plus AP, updated stat/AP values, and the captured zero
tail. Configured opcode-`100` replies are mutually exclusive. HTTP telemetry
is published at `protocol.ability_point_allocation_responses`.

For the live control, one typed opcode-`41` injection made AP `1` visible in
the client, and direct nested-Wayland auto-allocation produced `LUK +0,
INT +1`. The responder returned mask `0x00004300`, kept LUK at `15`, raised INT
`57 -> 58`, and lowered AP `1 -> 0`. The client remained active on map
`101000000`; runtime recorded `1/1` requests, zero rejection, one response
packet, and `54/54` heartbeat pairs at the proof sample. Independent analysis
of
`downloads/maple_custom_server_observed/ability_point_live_20260811/world/1786491988812896059_replay_12857.jsonl`
is warning-free at `159/133/0/0`, matches the allocation exactly in `0.213` ms,
and leaves none pending.

Opcode `307` decodes as `redacted u32 + redacted u32 + zero u32` in two
references and 28 live records. The middle value is zero in 26 samples and all
four nonzero values are page-aligned; that distribution does not establish a
role, so both values remain redacted. Opcode `310` decodes as one counted
redacted UTF-16 value plus `zero u32 + zero u8`; all three controlled records
use 16 code units and the same text, but neither text nor UI role is exposed or
named. Opcode `308` decodes two redacted `f64`s, two redacted `u64`s,
one `u32` mirrored by two `f64`s, controls `50/1`, a `0/1` variant, and terminal
controls `1/0`. The mirror holds for all 11 stream-`126` and 13 latest-live
records; observed `(mirror, variant)` pairs are reference `59/60,0` and live
`3/56/59/60,0/1`. Opcode `311` is exactly
`zero u64 + redacted u32 + zero u64` for all six reference and seven live
samples. State exposes typed/redacted aggregates without raw values.
Events add opcode, field epoch, phase, and the observed interval after the first
record. Stream `92` observes a
301.474-second opcode-`308` gap and a 584.534-second opcode-`311` gap. Stream
`126` keeps opcode `308` within `299.995..310.551` seconds and opcode `311`
within `557.141..610.544` seconds. In the first local run, the first nine
opcode-`308` gaps stay within `299.992..300.017` seconds before one later
592.004-second gap; opcode `311` has one bootstrap-skewed 346.476-second gap
followed by approximately 600-second gaps. Cadence is therefore descriptive,
not a guarantee that every interval produces a packet.

Opcodes `307/308/310/311` remain partial observations: numeric structure,
cadence, and controlled UI correlation do not establish field semantics or
replay safety. Opcode `100` is full because the repeated masks and increments
match the authoritative stat/AP deltas in both captures. The automatic packet
manifest replaces the `100/307/308/311` opaque pins with typed shapes and adds
an explicit typed/redacted live-only opcode-`310` shape; it does not invent outgoing-client
semantics from incoming handler reads. Current coverage is
`13,420/21,787/0/0` for stream `92`, remains `54/22/0/0` for stream `114`, and
is `26,662/44,438/0/0` for stream `126`. The first local transcript folds
all three opcode-`310` records with zero unknown packets and an `active` final
packet state; its socket later timed out without opcode `241`. A fresh
browser-free relaunch then traversed world/channel/character selection through
the nested Wayland seat and re-entered map `101000000`. Its transcript
`positioned_effect_actions_live_20260811/world/1786445521564813241_replay_12857.jsonl`
is valid and warning-free at the post-entry `62/41/0/0` sample, remains
`active` at HP `50/222`, and matches all 10 sampled heartbeat probes with none
pending. Runtime status reports one active local world connection, injection
ready, and zero injection failures while the typed initial snapshot,
fixed/variable records, and NPC spawns are generated.

## Field-bootstrap ledgers (`147`, `272`)

Each opcode occurs once and byte-identically across gameplay streams `92`,
`114`, and `126`, immediately after the initial field snapshot and the earlier
fixed/variable bootstrap records. The generated opcode-`147` handler directly
reads two rectangles followed by a counted integer vector:

```text
uint16 opcode = 147
int32 rectangle_1[4]
int32 rectangle_2[4]
int32 value_count
repeat value_count:
    int32 value
```

The captured packet is exactly 94 bytes. Its rectangles are
`(-300,-370,300,220)` and `(-300,-405,300,290)`, and `value_count` is `14`.
The vector values remain neutrally named and are omitted from safe output.

Opcode `272` delegates from its generated top-level handler. A focused live
primitive-reader trace over the exact 1,056-byte captured plaintext supplies
the complete nested grammar:

```text
uint16 opcode = 272
int32 header_value
int64 start_ticks
int64 end_ticks
int32 header_values[5]
int32 entry_count
repeat entry_count:
    int32 selector
    bool8 flag_1
    bool8 flag_2
    int32 group_1_count
    repeat group_1_count:
        int32 values[3]
    int32 group_2_count
    repeat group_2_count:
        int32 values[3]
int32 trailer_value
```

The reference has 11 entries, both flags false in every entry, 28 total
group-1 triples, 43 total group-2 triples, and trailer zero. Selectors and all
header/triple values are retained only for exact re-emission and redacted from
safe state and events. Counts are bounded before allocation, booleans accept
only wire values `0` and `1`, and the decoder requires exact final-cursor
consumption.

The fold emits `field_bounds_ledger_received` and
`field_configuration_ledger_received`, records rectangle/count/group/flag and
trailer distributions, and marks both observations full. The native manifest
keeps the original opaque width pins as raw evidence but suppresses them when
the matching semantic opcode/length shape is active, avoiding ambiguity. All
six cross-corpus packets parse and re-emit exactly through both implementations.

Two exact post-bootstrap opcode-`272` writes through the opt-in loopback packet
API were accepted by the active browser-free client. The resulting transcript
folds the original plus both injections as three full ledger events, remains
`active` on map `101000000`, and leaves player, inventory, progression, skills,
NPCs, and phase unchanged. Heartbeat responses continued after detach; the
focused debugger pause accounts for the 36.6-second maximum round trip. This
validates packet acceptance and the predicted neutral fold, not a semantic name
for the ledger fields.

## Counted bootstrap ledgers (`27`, `28`, `142`, `425`)

These shapes are driven by the current automatic
`tools/il2cpp_packet_dump` handler output and exact parsing of both gameplay
corpora. The opcode-`27` and opcode-`28` top-level handlers each read one
signed record count before delegating their entries:

```text
uint16 opcode = 27
int32 entry_count
repeat entry_count:
    int32 key
    int32 value
    int32 control
    utf16z text                 # uint16 code-unit count + UTF-16LE + zero byte

uint16 opcode = 28
int32 entry_count
repeat entry_count:
    int32 key
    int32 value
    utf16z text_1
    utf16z text_2
```

The 1,056-byte opcode-`27` form in `111` has 18 records and 390 total text
code units; the 27-byte stream-`126` form has one record and three code units.
The 260-byte opcode-`28` form has five records and `56/36` code units in its
two text columns; stream `126` uses a 164-byte, four-record form with `18/33`
code units. Keys, values, controls, and text are retained only for exact
round-trip encoding and omitted from safe output.

Opcode `142` reads one boolean directly and delegates only when it is true:

```text
uint16 opcode = 142
bool8 enabled
if enabled:
    utf16z header_text
    int32 entry_count
    repeat entry_count:
        int32 key
        int32 control
        utf16z text_1
        utf16z text_2
        bool8 flag_1
        bool8 flag_2
        int32 value_1
        int32 value_2
```

The disabled branch ends after three bytes. Both captured packets use the
enabled branch: stream `92` is 254 bytes with four records, nine header code
units, and 65 entry-text code units; stream `126` is 190 bytes with three
records, nine header units, and 45 entry-text units. Every captured `flag_1` is
true and every `flag_2` is false. The typed decoder preserves each raw byte and
applies the same zero/nonzero truth rule as the IL2CPP reader; the current
ledger captures happen to use canonical `0` and `1`. The count remains bounded
before parsing.

Opcode `425` has the following capture-complete neutral shape:

```text
uint16 opcode = 425
uint16 value_count
repeat value_count:
    int32 value
int32 trailer[4]
```

The packets in streams `92`, `114`, and `126` are byte-identical, 68 bytes
long, have count `12`, and end with trailer `(0,0,1,1)`. A focused live trace
independently entered the delegated handler at reader cursor 6, observed its
internally consumed count, and recorded exactly 12 repeated `i32` reader calls
at cursors `8,12,...,52`. The four trailer words are also identical across all
three captures and required for exact final-cursor consumption. Repeated values
remain redacted; safe analysis publishes only the count and neutral trailer.

The native manifest uses seven fixed-width semantic declarations so each
captured width replaces only its matching opaque pin. All 13 selected
private-regression packets validate natively (`9` from the selected `111`
streams, including the login duplicates, plus `4` from `1-10FS`) and every one
round-trips through the Python codecs. The state fold emits one full ledger
observation/event per packet and reports only record counts, text lengths,
boolean counts, and trailer shapes. That batch raised coverage to
`26,659/44,373/68/0` on stream `126`, `13,410/21,755/42/0` on stream `92`,
and `49/20/7/0` on stream `114`.

The loopback-only `POST /api/v1/server-packets` route accepted one exact
opcode-`425` packet while the real client was in the field. The resulting
transcript folds the captured packet and injected copy as two full
`server_opcode_425_ledger_received` events and keeps phase, map `101000000`,
player, inventory, and progression state unchanged. The later process exit
followed the debugger session rather than a synchronous packet rejection; a
fresh browser-free direct-Wayland launch returned to the field with sound
muted and a ready world connection.

## Generated `u32` envelopes (`228`, `231`, `234`, `235`)

These four opcodes are registered on the same generated handler class. Each
handler makes exactly one direct `PacketReader` call, a `u32`, then invokes its
local state method without another reader call. The captures contain additional
bytes after that value, so the shared boundary starts as a typed leading value
plus a capture-bounded suffix:

```text
uint16 opcode
uint32 primary_value
bytes  suffix
```

Only these observed opcode/tail-length combinations are accepted:

| Opcode | Tail bytes | Packet bytes | Occurrences |
| ---: | ---: | ---: | ---: |
| `228` | `4` reserved zero | `10` | `1` in stream `92` |
| `231` | `20` reserved zero | `26` | `1` in stream `126` |
| `234` | `3` reserved zero | `9` | `1` in stream `92`, `2` in stream `126` |
| `235` | `6` reserved zero | `12` | `1` in stream `92`, `2` in stream `126` |

The shared Python envelope consumes and re-emits the eight packets exactly.
Safe state and `neutral_server_record_received` events publish only opcode,
typed-value count, reserved-zero length, and opaque-tail length; the `u32` and
non-reserved tail bytes are redacted. Across both captures, all three opcode-
`234` suffixes are three zero bytes and all three opcode-`235` suffixes are six
zero bytes. Opcode `228` likewise ends in four zero bytes and opcode `231` in
20 zero bytes. All eight observations are full and contain no opaque bytes.

Opcode `230` is a separate remote-player instruction family. Native handler
`e49edb9d...` reads the leading `u32` as a remote-player object lookup key and
delegates the remainder to object method `ee73017d...`. That method reads a
`u8` selector. Capture-observed selector `9` ends immediately; selector `1`
jumps to native arm `0x180FF62BA`, which reads `i32`, `u8`, `u8`:

```text
uint16 opcode = 230
uint32 remote_player_object_id
uint8 selector

selector 9:
    end
selector 1:
    int32 value
    uint8 value_1
    uint8 value_2
```

The stream-`92` and stream-`126` compact records both use selector `9`. The
one long stream-`126` record uses selector `1` and values
`(4101003, 54, 6)`. All three object ids match active remote players already
introduced by opcode `189`. The dedicated codec consumes and re-emits all
three packets exactly; safe folds expose only the aliased player, selector,
and extended-value presence/count while redacting the object id and extended
values. All three observations are full.

Opcode `232` is a separate remote-player temporary-stat reset. Generated
handler `a73a2819...` reads a `u32` remote-player object lookup key and
delegates the reader to object method `abda8547...`. Native helper
`0x181CDC300` then fills a 128-bit mask struct by reading four `u32` words. The
object method intersects that mask with the player's current temporary-stat
mask and runs reset-side effects when the intersection is nonempty:

```text
uint16 opcode = 232
uint32 remote_player_object_id
uint32 temporary_stat_mask[4]
```

The sole stream-`92` packet targets object `335173`, which opcode `189`
introduced in the same field epoch and opcode `190` removed later. Its mask is
`(0, 0, 0, 0x80)`, enabling bit index `103`. The dedicated codec consumes and
re-emits the packet exactly; safe folds expose only the player alias and mask
structure while redacting the raw object id. The observation is full.

At the later opcode-`8` world-entry checkpoint, strict totals were
`70,076/1,024/0/0` for stream `126`, `34,573/634/0/0` for stream `92`, and
`68/8/0/0` for stream `114`.
The active saved transcript contains no opcode-`230` or opcode-`232` record.

At its original introduction, the family moved seven long-stream and five
stream-`92` observations from unknown to partial; the refined checkpoint values
are above. Live replay remains deferred because opcodes `230` and
`232` demonstrably target session-local remote-player object ids.

## Variable server records (`156`, `385`)

Both opcodes select between a compact and expanded capture variant with the
first byte after the opcode. Short-lived GDB primitive-reader traces now bound
both expanded branches completely:

```text
uint16 opcode
uint8  variant

opcode 156, variant 0:
    end
opcode 156, variant 1:
    utf16_packet_string text    # u16 units, UTF-16LE units, zero byte
    bool8 flag
    int32 values[3]

opcode 385, variant 0:
    repeat 89:
        uint8 selector
        int32 value
opcode 385, variant 1:
    end
```

Streams `92` and `114` contain the expanded pair `385:0`/`156:1`, byte-for-byte
identical between the two sessions. Stream `126` contains the compact pair
`385:1`/`156:0`. No other variants occur. The captured opcode-`385` expanded
packet is 448 bytes: its 89 selectors have counts
`0:45, 1:2, 2:3, 4:26, 5:6, 6:7`; the signed values range from `0` to
`2001005` with 43 distinct values. The captured 21-byte opcode-`156` expanded
packet has one text code unit, a false flag, and values `(2001004, 0, 0)`.
The opcode-`385` tuple index is a keyboard key code: index `29` is the Linux
evdev Left Ctrl code. Selector `1` is a skill binding and its value is the
skill id. The capture binds key `29` to learned skill `2001005` and key `71`
to learned skill `2001002`. Selector `0` is an empty binding, opcode-`158`
changes identify selector `2` as an item binding, and selector `5` is an action
binding. Live controls identify actions `50`, `51`, `53`, and `54` as pickup,
chair sit, jump, and NPC interaction respectively.

An independent legacy-client implementation names the remaining type ids
`4`/`6` as menu/face and action ids `50..54` as pickup, sit, attack, jump, and
interact/harvest in exactly the observed numeric order. Its default map also
places faces `100..106` on F1..F8 and menu actions on ordinary keyboard keys:
[KeyType.h](https://github.com/ryantpayton/MapleStory-Client/blob/4712e2233836fd265fc9ece7e40179ab76704da2/IO/KeyType.h#L24-L47),
[KeyAction.h](https://github.com/ryantpayton/MapleStory-Client/blob/4712e2233836fd265fc9ece7e40179ab76704da2/IO/KeyAction.h#L27-L108),
and [UIKeyConfig.h](https://github.com/ryantpayton/MapleStory-Client/blob/4712e2233836fd265fc9ece7e40179ab76704da2/IO/UITypes/UIKeyConfig.h#L134-L178).
The exact Protocol-300 snapshot agrees: selector `4` has 26 menu entries,
selector `6` has seven face-expression entries `100..106`, and action `52` is
bound to keypad zero. A focused `M` input opened the current client's local
`GAME MENU` without emitting an action packet. A controlled keypad-zero press
likewise emitted no dedicated packet in the empty-platform state; that negative
result limits network claims but does not contradict the source-backed attack
identity. Opcode-`156` field meanings remain neutral, and no security meaning
is inferred.

All four forms now have full shape coverage and exact typed round trips. The
fold records opcode/variant counts, 89 selector/value entries per expanded
opcode `385`, three typed int32 values per expanded opcode `156`, zero opaque
bytes, field epoch, and `variable_server_record_received` events. Safe output
retains only text length, flag, value/entry counts, and never the opcode-`156`
text or raw values. Expanded opcode `385` additionally updates the current
keyboard selector distribution plus skill, item, menu, action, and
face-expression maps, validates bound skill ids against initial progression,
exposes the named pickup/sit/attack/jump/NPC-interaction key sets, and emits a
`keyboard_bindings_loaded` event.

The empty-binding role comes from a one-byte live A/B/A, not the zero value.
The typed `keyboard-selector-zero=71` transform changed only key `71`'s
selector from captured `1` to `0` while preserving value `2001002` and all
other 88 entries. Physical key `71` first emitted opcode `104`; under selector
`0` it emitted no skill request while an ordinary client opcode-`13` packet
followed the input; restoring the exact original record restored opcode
`104`. Folded selector counts changed `45 -> 46 -> 45`, skill-binding counts
`2 -> 1 -> 2`, and the warning-free active snapshot retained 437/437 matched
heartbeats with none pending. Safe state/events expose `empty_binding_count`,
the six selector ids, and the five binding maps. Opcode-`156` text and raw
int32 values remain suppressed.

Selector `5` has a separate one-entry causal control. The expanded official map
contains six selector-`5` entries with values `50,51,53,54,50,52`; value `50`
is present at evdev key codes `44` and `78`. Physical Z at key `44` emitted no
skill request under captured `5/50`. Replacing only that entry with selector
`1` and learned skill `2001002` produced an authentic opcode-`104` request.
Restoring the exact `5/50` entry and presenting an admitted nearby drop
produced authentic pickup opcode `185`. Folded snapshots show action-binding
counts `6 -> 5 -> 6`, skill-binding counts `2 -> 3 -> 2`, and pickup keys
`(44,78) -> (78) -> (44,78)`. This identifies selector `5` as an action binding
and value `50` as pickup. The later controls below assign `51`, `53`, and `54`;
the independent enum assigns the remaining action `52` as attack.

`--generate-variable-server-records` re-emits every bounded observation at its
original frame index after length/reparse/uniqueness/conflict validation.
`protocol.variable_server_record_emitter` exposes only frame index, opcode,
variant, text length, flag, value/entry counts, per-family binding counts,
named action key sets, field epoch, patch count, and the predicted unchanged
player/phase state.

A browser-free stream-`114` proof regenerated frames `9` and `11`, composed
with the initial, fixed, and NPC emitters. A later opt-in HTTP experiment sent
those same two expanded plaintexts through the active cipher state. The real
client remained active on map `101000000` with HP `50/222`, MP `97/342`, and
110/110 paired generated heartbeats. Its transcript folds validly to four
variable events, 178 typed entries, six typed int32 values, and zero opaque
bytes. This establishes exact generation and post-bootstrap replay acceptance,
not the higher-level purpose of either packet.

A fresh browser-free A/B/A run established the keyboard meaning. Physical
evdev Left Ctrl (`29`) under the captured value `2001005` emitted a targeted
opcode-`52` variant-`18` two-hit action with damage `[27,32]`. One typed packet
changed only that entry's value to another learned skill, `2001004`; the next
Left Ctrl emitted variant `17`, one hit, damage `[65]`. Restoring the original
packet restored variant `18`, two hits, damage `[29,25]`. The immutable fold is
valid and warning-free, ends active on map `101000000` at HP `50`, records the
binding sequence `2001005 -> 2001004 -> 2001005`, and matches 91/91 heartbeats
with no pending or unmatched response. This proves the key/value relationship
without assigning meanings to the other selector families.

## Chair action requests (`client 49`, `client 82`, `client 48`)

Selector-`5` action `51`, bound to evdev X at key `45`, produced a complete
live chair lifecycle boundary without a modeled server response:

```text
client opcode 49 (6 bytes):
    uint16 opcode = 49
    uint32 item_id

client opcode 82 (2 bytes):
    uint16 opcode = 82

client opcode 48 (4 bytes):
    uint16 opcode = 48
    int16  marker = -1
```

Physical X rendered Setup-slot-`1` item `3010370`; the opcode-`49` body was the
same `3010370` value. Empty opcode `82` followed 20,006 ms later while the sit
intent remained open. Pressing X again sent opcode `48/-1`; a later Right
attempt repeated that exact stand request because the custom server had not
acknowledged the state. Neither reference PCAP contains opcodes `48`, `49`, or
`82` in the client direction, so these shapes are live-bounded rather than
capture-bounded.

The fold exposes full typed observations/events, correlates the requested item
with Setup inventory, and counts recovery/stand requests with or without an
open sit intent. It clears only the modeled client intent on the first stand
request or a field snapshot, and does not claim the server or client has
completed a state change.
Safe state therefore carries `server_acknowledgement_modeled: false`. The live
transcript is valid, warning-free, and back to zero unknown packets after these
three codecs.

## Jump, attack, and NPC-interaction keyboard actions

The same unchanged opcode-`385` map binds action `53` to evdev Left Alt (`56`)
and action `54` to Space (`57`). After restoring real host pointer focus to the
nested client, physical Left Alt produced a visually decisive jump with no
dedicated request packet. Physical Space emitted client opcode `64`; its object
id resolved to the active NPC and establishes the request grammar documented
above. Holding Space produced three repeats, so the fold counts raw requests
rather than coalescing input repetition.

The independent `KeyAction` enum above identifies action `52` as attack. Evdev
keypad zero (`82`) is the captured binding. Its controlled input did not emit a
dedicated packet in the empty-platform state; the nearby blue `10` recovery
display and alternating client opcode-`101` HP/MP recovery requests were
already occurring automatically and are not attributed to that input. Safe
keyboard state publishes sit/attack/jump/NPC-interaction action ids and key
sets while preserving this no-packet observation as a runtime boundary.

## Skill-record change transaction (`client 103`, `server 46`, `client 293`)

The level-1-through-10 capture contains a complete request/update/acknowledgement
transaction distinct from skill use:

```text
client opcode 103 (10 bytes):
  uint16 opcode = 103
  uint32 client_tick
  uint32 skill_id

server opcode 46:
  uint16 opcode = 46
  uint8  flag_a                 # boolean; semantic role remains neutral
  uint8  flag_b                 # boolean; semantic role remains neutral
  int16  record_count           # non-negative
  repeat record_count:
    int32 skill_id
    int32 level
    int32 auxiliary_value       # semantic role remains neutral
  uint8  trailing_value         # semantic role remains neutral

client opcode 293 (12 bytes):
  uint16 opcode = 293
  uint32 control_value          # 346 in all captured acknowledgements
  uint32 client_tick
  uint16 trailing_value         # zero in all captured acknowledgements
```

Stream `126` contains eight opcode-`103` requests, eight matching one-record
opcode-`46` updates, one additional zero-record update, and nine opcode-`293`
acknowledgements. Every request is followed by an update for the same skill id;
every update is acknowledged. The maximum observed request-to-update interval
is `691.152` ms and the maximum update-to-acknowledgement interval is `16.933`
ms. Folding the records yields skill levels `{12:0, 1000:1, 2001004:1,
2001005:6}` with no pending requests or acknowledgements.

Seven ordinary allocations are preceded by opcode-`41` skill-point changes
`7 -> 6` through `1 -> 0`; each opcode-`46` record raises only the requested
skill by one, uses flags `1:0` and auxiliary value `0`, and carries trailing
values `4,6,8,10,12,14,16`. The earlier beginner request for skill `1000` is
the bounded exception: opcode `41` reasserts `0`, yet opcode `46` still creates
level `1` with trailing value `2`. Across all eight responses, including that
exception, the trailing byte equals twice the folded sum of skill levels. This
is used only as a capture-bounded construction rule; the field's higher-level
role remains neutral and it is not labeled as skill points.

The fold gives all three packets full structural coverage, emits
`skill_level_change_requested`, `skill_records_updated`, and
`skill_record_update_acknowledged`, and reports request/ack correlations and
timing. Surrounding opcode-`41` stat updates independently change skill points;
the opcode-`46` trailing byte remains a separate field.

A browser-free real-client stream-`114` replay then tested the server packet in
both captured forms. Two zero-record packets and two one-record packets that
reasserted existing skill `2001005` at level `6` all produced client opcode
`293` with control `346` and trailing value `0`. The four acknowledgements took
`11.297` to `864.607` ms; none remained pending or unmatched. The immutable
fold stayed valid and warning-free on map `101000000`, with HP `50`, skill
levels, player state, inventory, and all other progression unchanged, while
61/61 generated heartbeats were paired. `inject-skill-record` now automates
typed construction, API submission, acknowledgement correlation, and these
invariant checks for either the empty form or one existing skill.

`--reactive-skill-level-change-responses` serves the ordinary positive-SP
branch during hold-open. It requires one modeled skill point, a non-negative
`int32` skill id and level result, and a twice-level-sum trailing value that fits
`uint8`; it deliberately rejects the captured zero-SP beginner exception.
An admitted opcode `103` emits opcode `41` first (request flag `0`, mask
`0x00008000`, SP minus one, one-zero tail), then opcode `46` (flags `1:0`, one
requested-skill record at level plus one, auxiliary `0`, captured trailing
rule). The option cannot share opcode `103` with a configured captured reply,
and telemetry is published at `protocol.skill_level_change_responses`.

The browser-free real client supplied an independent live proof after a typed
one-point injection. Clicking a skill sent opcode `103` for skill `1001`; the
handler moved raw SP `1 -> 0`, level `0 -> 1`, and emitted trailing value `30`.
The visible skill counter changed `5 -> 4`, and the client acknowledged opcode
`46` with opcode `293`, control `346`, and tail `0`. Independent analysis of
`downloads/maple_custom_server_observed/skill_level_live_20260812/world/1786494416311300328_replay_12857.jsonl`
is warning-free, matches the response in `0.383` ms and the acknowledgement in
`2.762` ms, leaves no request or acknowledgement pending, remains active on map
`101000000`, and paired `53/53` heartbeats at the proof sample.

## Client skill-use request (`104`)

The key-`71` live control produced a complete fixed-width client request:

```text
uint16 opcode = 104
uint32 client_tick
uint32 skill_id
uint8  skill_level
uint16 trailing_value    # observed 0; role remains neutral
```

The captured and restored `71 -> 2001002` binding each emitted an exact
13-byte opcode-`104` packet. Both requests carried skill id `2001002`, level
`1`, and trailing value `0`; the level agrees with the initial progression
snapshot. Their client ticks were `393636` and `623660`, a delta of `230024`
ms. The corresponding transcript timestamps differ by `230039.792` ms, only
`15.792` ms more, which supports interpreting the uint32 as a client
millisecond tick.

This result is causal rather than a shape-only label. With the captured
binding, physical evdev key code `71` emitted opcode `104`. Changing only the
opcode-`385` entry value to learned skill `2001004` made the same key emit the
already-modeled opcode-`52` variant-`17` attack instead. Restoring the exact
captured binding restored opcode `104` with skill id `2001002`. The two
opcode-`104` samples are from the controlled live transcript; streams `92`,
`114`, and `126` in the two reference PCAPs contain none.

The gameplay fold gives this packet full structural coverage, correlates the
skill id with both current keyboard bindings and learned skill levels, checks
the submitted level, tracks tick deltas/decreases and neutral trailing values,
and emits `client_skill_use_submitted`. It does not assign any server packet as
the request's semantic response or name `trailing_value` beyond the observed
zero.

A later live response-free control provides a narrower server invariant. Two
physical key-`71` presses produced same-skill requests 10,684.712 ms apart.
Exactly two periodic server opcode-`10` probes occurred between the requests;
no non-heartbeat server packet did. The second request and subsequent matched
heartbeats prove that an immediate gameplay response is not required for repeat
dispatch or connection liveness. They do not prove the skill's client-visible
or authoritative state effect. Each request event now reports its previous
request frame/elapsed time, same-skill relation, and intervening non-heartbeat
server opcode counts. Safe state separately counts same-skill repeats and the
subset with no intervening non-heartbeat packet.

## Local temporary-stat set prefix (`server 42`, partial)

Static client inspection and a bounded live parser trace establish only this
prefix:

```text
uint16 opcode = 42
uint32 mask_words[4]
if all mask words are zero:
    uint8 zero_mask_flag_a       # semantic role unknown
    uint8 zero_mask_flag_b       # semantic role unknown
    int16 zero_mask_trailing     # semantic role unknown
bytes opaque_tail                # any unmodeled remainder
```

The opcode-`42` client handler at RVA `0xe54150` calls the four-word mask
decoder before processing temporary-stat records. During a live all-zero probe,
the traced reads after that mask were two `uint8` values at packet cursors `22`
and `23`, followed by one `int16` ending at cursor `24`. Accounting for the
two-byte transport length header outside the plaintext gives an exact 22-byte
minimal plaintext. The analyzer therefore decodes the mask and zero-mask suffix
while preserving every remaining byte; nonzero-mask records remain entirely
opaque after the mask.

This is structural evidence, not a valid skill response. Neither gameplay
stream `92` nor `114` in `111.pcapng`, nor level-1-through-10 stream `126` in
`1-10FS.pcapng`, contains opcode `42`. The controlled live run sent a padded
160-byte all-zero probe and then the 22-byte minimal form. Both reached the
socket writer, but heartbeat replies stopped after the padded probe; the later
minimal form was therefore tested only on an already-stalled connection. The
fold emits partial `local_temporary_stat_set_header` observations and
`local_temporary_stat_set_received` events, preserves 138 opaque bytes on the
padded form, leaves HP/MP and other modeled state unchanged for a zero mask,
and sets `network_progression_proven: false`. A preceding opcode-`104` request
is exposed only as a non-causal candidate.

A clean browser-free control session subsequently reached map `101000000`,
produced one fully decoded opcode-`104` request from direct Wayland key `71`,
and matched all 16 heartbeat probes/responses with none pending. This separates
normal client progression from the unsafe opcode-`42` experiment. Do not replay
opcode `42` as a response until a capture-backed nonzero record grammar and a
fresh-client minimal-packet acceptance test exist.

## Non-pickup server opcode-`49` envelope

Server opcode `49` is overloaded. A byte discriminator of `0` selects the
separately modeled pickup-gain notice. Every other observed discriminator uses
the following neutral envelope and is excluded from pickup request/effect
correlation regardless of packet length:

```text
uint16 opcode = 49
uint8 variant

variant 1:
    uint32 key
    uint8 value_kind
    if value_kind == 1:
        utf16 text_value
        uint8 zero_terminator
    if value_kind == 2:
        uint64 numeric_value

variant 3:
    uint8 record_marker             # observed 1
    uint32 record_value
    bytes reserved_constant         # observed lengths 28, 29, or 36

variant 4:
    uint16 reserved_zero
    uint8 neutral_value             # observed 1 and 6

variant 6:
    uint64 numeric_value

variant 10:
    uint8 reserved_zero
    utf16 text_value
    uint8 zero_terminator

variant 12:
    uint32 key
    utf16 text_value
    uint8 zero_terminator
```

Stream `92` contributes variants `3/10/12 = 44/101/7`. Level-1-through-10
stream `126` contributes variants `1/3/4/6/10/12 = 128/214/2/1/1/5`; variant
`1` divides into 98 terminated strings and 30 u64 values. Thus all 503
non-pickup packets parse to their exact ends and round-trip byte-for-byte. The
258 variant-`3` packets further divide into exact total widths `36/37/44` with
counts `189/25/44`: all use marker `1`; widths `36` and `44` end in 28 and 36
zero bytes, while width `37` ends in constant byte `1` plus 28 zero bytes.
These capture-bounded constants promote all variant-`3` observations from
partial to full coverage. The two variant-`4` records are exact six-byte forms:
both carry a zero word and one neutral byte (`1` or `6`) in the same stat/job-
script update burst. No higher-level meaning is assigned to that byte. The
family now provides 503 full observations and zero opaque bytes. Current
reference coverage is `69,942/1,158/0/0` and `34,547/660/0/0` in streams
`126` and `92`; stream `114` remains `64/12/0/0`. The fold emits
`server_opcode_49_received` and tracks variant, neutral shape, text-code-unit,
reserved-constant-length, and opaque-byte distributions. Text is retained only
in the typed object for exact re-emission and is omitted from safe JSON,
events, text reports, and HTTP-derived analysis. The 258 exact-width records
also pass the independent native manifest validator while the record value
retains a deliberately neutral name. The two variant-`4` records separately
pass their exact native shape.

## Redacted server opcode-`77` envelope

All 515 opcode-`77` samples in the sustained gameplay references share a
one-byte variant discriminator. The text-bearing branches use the standard
`uint16` UTF-16LE code-unit count, but reports never expose the decoded text:

```text
uint16 opcode = 77
uint8 variant

variant 3:
    utf16 primary_text
    uint8 control[3]

variant 4:
    bool text_present
    if text_present:
        utf16 primary_text
        uint8 zero_terminator

variant 5:
    utf16 primary_text
    uint8 prefix_a = 3
    uint8 prefix_b = 10
    utf16 secondary_text
    uint8 zero_terminator
    uint8 separator = 10
    utf16 tertiary_text
    uint8 zero_terminator
    uint8 terminal_tag = 2
    uint32 terminal_value              # role remains neutral

variant 8:
    utf16 primary_text
    if exactly 4 bytes remain:
        uint8 reserved_zero = 0
        uint8 control                  # observed 0, 1, 4, or 7
        uint16 terminal_value          # observed 0 or 1; role neutral
    if exactly 117 bytes remain:
        uint8 reserved_zero = 0
        uint16 slot                     # observed 1 or 22
        uint8 inventory_type = 1       # Equip
        equipment_item_record          # shared opcode-39 item grammar
```

Variant `3` always has its exact three-byte suffix. Variant `4` has 41 short
false forms and ten true forms with a terminated string. All 22 variant-`5`
packets use control pattern `03 0a 0a 02` and consume exactly. Eleven of the 13
variant-`8` packets independently agree on the four-byte short suffix above:
controls `0/1/4/7` and terminal values `0/1`. Those short records now have full
coverage. The two remaining variant-`8` records are distinct 117-byte wrappers
around the existing equipment-item grammar. They expose slots `1`/`22`, item
templates `1372012`/`1050018`, non-cash permanent expiration, and both validated
filetime sentinels. The delegated native item reader additionally fixes two
upgrade bytes, 15 `i16` stat values, a terminated owner string, an `i16` flag,
two neutral bytes, two neutral `i32` values, a 12-byte extension block, an
optional non-Cash `i64`, and both timestamp/value tails. Both wrappers are now
full with zero opaque item-metadata bytes.

Stream `92` contributes variants `3/4/5/8 = 152/13/9/6`, stream `114`
contributes `1/1/0/0`, and level-1-through-10 stream `126` contributes
`276/37/13/7`. Every packet reparses and round-trips exactly: all 515
observations are full. At this checkpoint the strict stream totals move to
`34,553/654/0/0`, `64/12/0/0`, and `69,949/1,151/0/0`, respectively. Isolated
native validation consumes all 11 promoted short records without a failure or
unsupported shape; a separate two-record native corpus consumes both long item
wrappers exactly. The active saved transcript contains no variant-`8` record;
its two opcode-`77` observations remain full and the transcript stays valid at
`763/19/0/0`. The fold emits
`server_opcode_77_received`, tracks variant/control/value and text-length
distributions plus opaque-byte totals, and never copies any of the three text
fields into safe JSON, text reports, events, or HTTP status. The family keeps a
neutral name because the four variants span multiple visible-message forms;
frequency and readable strings alone do not establish one gameplay role.

## Inventory moves (`client 79` -> `server 39`)

The level-1-to-10 capture contains two exact 13-byte requests:

```text
uint16 opcode = 79
uint32 client_tick
uint8  inventory_type                 # 1 equip in both observations
int16  source_slot                    # observed 2 and 3
int16  destination_slot               # observed -11 in both
int16  quantity                       # observed -1 for both equip moves
```

The first request is followed 13 combined gameplay frames/1,040.241 ms later
by a single server opcode-`39` move for the same inventory and slots. The
second is followed in the next frame/402.275 ms by the same exact transaction
shape. This repeated
field equality is the semantic evidence for the inventory-move name; the
layout alone is not used to infer it. An independent v79
[inventory handler](https://github.com/mrzhqiang/ms079/blob/963e06e4cbc13a591d6d7a293b23dc05e69d60ab/src/main/java/handling/channel/handler/InventoryHandler.java#L75-L104)
names the leading value as the client tick and the final signed short as
quantity. No unobserved opcode-`79` length is accepted by the native manifest.

The state fold queues requests FIFO, correlates only an opcode-`39` operation
`2` with matching inventory/source/destination, and updates inventory from the
authoritative server packet rather than the request. It emits
`inventory_move_requested` and `inventory_move_confirmed`. Safe analysis JSON
reports request counts by inventory, matches, server moves without a request,
pending requests, and last/maximum response milliseconds; plaintext bytes are
never copied into those fields. Both native-manifest records and Python codecs
consume/re-emit exactly. The two requests now have full semantic coverage.

The opt-in `--reactive-inventory-move-responses` policy turns this correlated
pair into a bounded hold-open handler. It projects initial equipment group `1`
onto negative equipped slots, group `3` onto positive Equip-inventory slots,
and overlays later authoritative opcode-`39` changes. It admits only opcode
`79` inventory type `1`, captured quantity `-1`, and a source slot that
exists in that mutable model. The reply is one exact opcode-`39` operation-`2`
record with captured `update_flag=1`, request source/destination slots, and
captured `move_flag=2`; occupied destinations are swapped in policy state.
The handler requires `--keep-world-open`, cannot share opcode `79` with a
configured captured reply, and publishes observed/served/rejected counts plus
identifier-free item/slot state under `protocol.inventory_move_responses`.

A fresh local-Wine control supplied an independent destination variant. A UI
move from occupied Equip slot `3` to occupied slot `1` emitted one exact
opcode-`79` request with quantity `-1`; the handler returned one opcode
`39` and swapped item templates `1302000`/`1002053`. The live transcript folds
warning-free at `342/323/0/0`, matches the request and response with none
pending, remains `active` on map `101000000`, and had `222/222` matched
heartbeat probes at the proof sample. This validates general same-inventory
move/swap handling beyond the two captured moves to equipped slot `-11`.

## Inventory change sets (`server 39`)

The capture-validated packet grammar is:

```text
uint16 opcode = 39
uint8  update_flag                    # observed 0; role remains neutral
uint8  modification_count
repeat modification_count:
    uint8 operation
    uint8 inventory_type              # 1 equip, 2 use, 3 setup, 4 etc, 5 cash
    int16 slot
    if operation == 0: complete item_record
    if operation == 1: uint16 quantity
    if operation == 2: int16 destination_slot; uint8 move_flag
    if operation == 3: no operation-specific body
```

Operation `0` is add, `1` is stack-quantity replacement, `2` is a slot
move/swap, and `3` is remove. The captured add records reuse the
initial-inventory grammar: type `1` carries the equipment record bounded by
its two sentinel timestamps; types `2/3/4` carry a stack item record with
template, cash flag/optional cash id, expiration, quantity, owner string,
bounded metadata, sentinel timestamp, and tail; type `5` carries either the
same stack shape or the complete cash-item variant. Reports retain only
non-sensitive common fields and record length while re-encoding the entire
record. The observed operation-`2` records move equipped items from positive
bag slots to negative equipped slots with move flag `2`; the fold swaps an
occupied destination and otherwise moves the source item.

Coverage is assigned per change set rather than per opcode. Empty packets and
packets containing only quantity updates, moves, or removals are structurally
complete. Across both sustained captures, all 39 record-type-`2` stack
additions carry a ten-byte reserved-zero metadata field. All 66 record-type-`3`
Cash additions instead carry a neutral `u32` at their former four-byte metadata
boundary. Those branches now have zero opaque metadata bytes. The delegated
native equipment-item override fixes the remaining suffix fields and its
optional non-Cash identity; all 18 initial-snapshot equipment records and all
four stream-`126` equipment additions independently match and round-trip.
Across streams `126`, `92`, and `114`, all 327 captured change sets are
therefore full. Exact native validation consumes all 327 sustained-capture
opcode-`39` packets. The active saved transcript independently keeps its Cash
add full at `764/18/0/0`.

Stream `92` contains 69 packets and 71 modifications: `add:16`,
`update_quantity:40`, and `remove:15`, all under update flag zero. Thirteen
packets have an empty change list. Inventory types are `use:20`, `etc:21`, and
`cash:30`. Fifteen cash remove/add pairs refresh slot `4`; the remaining add
creates Etc slot `18`, item template `4010003`, quantity `1`. Every packet
round-trips byte-for-byte, all quantity/removal operations resolve an existing
slot, and the fold ends with Use slot `15` at `27`, 24 Use items, 18 Etc, two
Setup, and one Cash item. Stream `114` independently validates one empty packet
and one cash refresh pair with no unknown slots.

Stream `126` expands the grammar to 256 packets and 232 modifications:
`add:93`, `update_quantity:79`, `move:2`, and `remove:58`. It contains four
equipment adds, two cash-inventory stack adds, and two equip moves. Every
change set round-trips and the fold reports zero unknown-slot modifications.
The resulting stream totals are `67,290` full, `3,810` partial, and zero
unknown or invalid observations; stream `92` reaches `33,573/1,634/0/0` and
stream `114` reaches `61/15/0/0`.

The state-driven quantity emitter requires an existing stack item and sends a
single operation-`1` change. A real stream-`114` client accepted generated
plaintext `2700000101020f000100`, changing Use slot `15`, item template
`2000000`, from `27` to `1`. The inventory UI displayed quantity `1`; the
recorded transcript emitted the same previous/current event, preserved all
item counts and player state, remained active, and matched all 18 generated
heartbeats. The neutral update flag is deliberately not assigned a role.

## Client opcode `111` Cash-slot action

Stream `126` contains one exact eight-byte record with this capture-bounded
grammar:

```text
uint16 opcode = 111
uint32 neutral_value                 # observed 425341
int16  slot                          # observed 3
```

The next same-epoch server opcode-`39` change set arrives after `486.349` ms
and removes then re-adds Cash inventory slot `3`. The fold queues the action
and correlates only an opcode-`39` modification with inventory type Cash and
the exact signed slot. It reports one match, no pending action, and no warning.
The Python codec and native manifest consume and re-emit the record exactly.
The record now reports full structural coverage without assigning a role to its
neutral u32 or to the higher-level Cash-slot action.
The automatic dump proves only that the opcode enum exists; it supplies no
outgoing client handler or shape. The u32 value, action purpose, and causal
relationship to the authoritative inventory change therefore remain neutral.
With opcode `64` promoted to full coverage, the current stream-`126` total is
`26,664/44,436/0/0`.

## Consumable use (`client 80` -> `server 39`, `server 41`)

The capture-validated request is exactly 12 bytes:

```text
uint16 opcode = 80
uint32 client_tick
int16  use_slot
uint32 item_template_id
```

Stream `92` contains 17 requests and every packet round-trips byte-for-byte.
Thirteen name Use slot `21`, blue potion template `2000014`; four name Use slot
`15`, red potion template `2000000`. Each request agrees with the current typed
inventory slot/template. Each is followed by an opcode-`39` quantity update for
the same slot and template, and all 17 quantities decrease by exactly one.

Each request is also followed by the captured potion stat effect in opcode
`41`: red potion increases current HP by 50, while blue potion increases current
MP by 80 with max-MP capping (one observed delta is 79 because MP reaches its
modeled maximum `342`). All 17 quantity correlations and all 17 stat-effect
correlations match, with no unknown slots, template mismatches, or pending
requests at capture end. The same independent v79
[Use-item handler](https://github.com/mrzhqiang/ms079/blob/963e06e4cbc13a591d6d7a293b23dc05e69d60ab/src/main/java/handling/channel/handler/InventoryHandler.java#L298-L314)
passes the leading u32 to the character's tick updater.
Effects for item templates outside the two captured potions remain unknown.

The reactive policy derives mutable inventory and HP/MP state from a validated
world transcript. It accepts only the two evidenced potion templates, checks
slot/template/quantity and maximum-stat bounds, and sends opcode `39` before
opcode `41`. It conservatively rejects consuming the final item because the
capture does not establish whether that boundary uses quantity zero or an
operation-`3` remove.

A real stream-`114` client first accepted a typed red-potion update from
quantity `27` to `2`, then emitted opcode `80` for Use slot `15`. The generated
responses changed the visible inventory from `2` to `1` and the HUD from HP
`50/222` to `100/222`. The completed transcript independently folded one
request, one matching inventory response, one matching stat effect, zero
mismatches/pending requests, and 20 matched heartbeat pairs.

The current responder records `item_use_request_observed`,
`item_use_response_completed`, and `item_use_request_rejected` runtime events.
Its fresh browser-free proof used direct Wayland PageUp twice: frames
`232`/`234` applied quantity `2 -> 1` and HP `50 -> 100` with opcodes `[39,41]`,
then frame `250` rejected the second request because the last-item removal
shape remains unvalidated. That rejection emitted no packet and did not close
the client. The folded transcript is valid and warning-free with two requests,
one inventory/effect match, one explicit policy rejection, zero pending item
uses, and 90/90 matched heartbeats.

## Field-drop spawn (`server 311`)

Server opcode `311` creates or refreshes one field drop. Stream `92` contains
125 packets and 66 unique `(field_epoch, drop_object_id)` pairs. Fifty-nine
drops appear as an otherwise byte-identical mode-`1` then mode-`0` pair; seven
item drops use the shorter mode-`2` field-load form. All 125 packets parse and
re-encode byte-for-byte. The independent level-1-to-10 corpus adds four exact
mode-`2` field-load mesos records.

The shared prefix is:

```text
uint16 opcode = 311
uint8  spawn_mode                     # observed 0, 1, or 2
uint32 drop_object_id
uint8  drop_kind                      # 0 item, 1 mesos
uint32 value                          # item template or mesos amount
uint32 owner_value_1                  # role remains neutral
uint32 owner_value_2                  # equal to owner_value_1 in all 125
uint8  ownership_flag                 # zero in all 125
int16  position_x
int16  position_y
uint32 source_mob_object_id
```

Modes `0` and `1` then carry the animation source and duration:

```text
int16  source_x
int16  source_y
uint16 animation_duration_ms          # 450 in all 118 animated records
if drop_kind == 0: int64 expiration_ticks
uint8  final_flag                     # one in all animated records
```

That produces 44-byte item records and 36-byte mesos records. Every nonzero
source mob resolves to a field-local mob template retained after that mob's
leave/death packet; none is an unmodeled object. Mode `2` omits the animation
fields:

```text
if drop_kind == 0: int64 expiration_ticks
uint8 final_flag                      # zero in all seven field-load records
```

The resulting field-load item record is 38 bytes; a field-load mesos record is
30 bytes. Every captured item expiration is `150842304000000000`. The fold
assigns `drop:N` aliases, treats mode `0` as a refresh of its matching mode-`1`
record, retains active drops by field epoch, removes them on opcode `312`, and
clears them on a field reset.
Spawn mode, owner values/flag, expiration, and final-flag semantics remain
neutral even though their packet boundaries are exact.
The pinned opcode-`311` handler independently confirms every direct read and
both conditionals. The analyzer therefore reports full structural coverage for
all four capture-modeled mode/kind branches while retaining those neutral field
names. Across the two reference gameplay streams plus terminal stream `114`,
all 562 server opcode-`311` packets also pass the independent manifest validator
with exact byte consumption.

All 54 stream-`92` opcode-`185` requests reference a currently active modeled
drop. The following opcode-`49` value matches the spawn value in all 54 cases:
24 item results, 29 mesos results, and the one special result whose value is
the spawning item template. All 54 local reason-`5` removals also name that
same active drop; their actor equals both captured owner values and their tail
is zero. This establishes the complete spawn/request/effect/result/removal
chain without assigning a security meaning to the client validation token.

Stream `114` ends with one active mode-`2` item drop: template `4000004` at
`(-863,-1742)`. The final folded local-player position is `(633,-2677)`, and
the Etc inventory contains the same template in slot `7`, quantity `74`.

The owner fields are not a sufficient pickup switch. A typed live replay
rewrote both final mode-`2` owner words to the initial player id, and later
controls sent captured-shaped mode-`1`/mode-`0` pairs at the player. The fresh
source-mob controls preserved a known typed mob in field history, tested a
pair less than a millisecond after enter/leave, and repeated it with an
explicit controller-level-`0` release before leave. The client stayed healthy
and physical pickup input was verified, but no variant emitted opcode `185` or
compact opcode `222`. The bounded transcript snapshot was valid and
warning-free with 141/141 matched heartbeats and zero pickup requests. Runtime
status therefore reports only the modeled owner/source relations: owner
equality, proximity, source-mob presence/history, immediate lifecycle timing,
and controller release are not independently sufficient.

The first capture-timed combat/reward control placed a typed template-`210100`
mob at the player, observed a real opcode-`52` attack, and sent the matching
current-MP update, health `20 -> 0`, reason-`1` leave, opcode-`49` variant-`3`
record, EXP `+10`, redacted variant-`10` text, and source-matched `4000004`
mode-`1`/mode-`0` pair. Its first health response was 92.526 ms after the
attack versus 102.326 ms in that reference family, but pickup input emitted no
request. The exact capture drop in that control was later audited and found to
have no pickup request in its own field epoch. That run therefore bounds only
one capture-authentic packet family; it is not evidence that an officially
admitted drop family failed.

The corrected control starts from the first stream-`92` `4000004` object with
a proven request. Its official template-`210100` attack/death/reward chain has
the first HP response at 58.892 ms, health `12 -> 0`, an exact
mode-`1`/mode-`0` pair, a controller-level-`0` release 450.451 ms after spawn,
and a pickup request 2,938.908 ms after spawn while the player is 24 horizontal
and one vertical unit from the drop. The live replay retained that packet
family and animated-source offset, rewrote only current MP/EXP and position,
observed an active-target opcode-`52` attack, delivered its first HP response
at 53.681 ms, and released control after approximately 450 ms. Physical input
then produced a base opcode-`185` request 1,517.335 ms after the live spawn at
Manhattan distance three. The client retried every 3,000 ms until one
`[39,49,312]` response advanced Etc slot `7` from `74` to `75` and removed the
drop. At the validation snapshot the fold is valid and warning-free: 62 raw
requests form one admitted chain plus 61 retries, its effect/result/removal all
match, and all 900 heartbeat probes have responses. Typed PCAP transforms
rewrite only the sole captured opcode-`41` stat value and opcode-`311`
destination/animated-source positions; every other byte-bearing field is
preserved.

A second proven `4000004` object isolates the drop boundary from that prefix.
Its official pair has animated source offset `(+10,-3)`, a controller release
398.819 ms after spawn, and a request 1,591.279 ms after spawn at horizontal
distance seven. The live control sent only this exact mode-`1`/mode-`0` pair,
retargeted it to the current player while preserving the offset, and sent the
same controller release in 394.459 ms. No mob spawn, attack, health, leave,
reward record, or fresh input preceded the first opcode-`185` request, which
arrived in 1,584.485 ms; the fold consequently marks the source mob unknown.
This establishes that the admitted pair does not require the combat/reward
prefix. A reason-`1` cleanup interrupted that deliberately unanswered
ten-attempt chain. Reinjecting the same pair produced
another request in 1,595.243 ms before the deliberately delayed new input and
one `[39,49,312]` response changed `75 -> 76`. The aggregate live fold is
warning-free with 76 raw requests, three admitted chains, 73 retries, two
matched completions, one interruption, zero pending pickups, and 1,064/1,064
heartbeats.

A cold-client control initially appeared to exercise a neutral-state boundary.
The exact second admitted pair received a controller release 394.575 ms after
spawn and capture-timed physical pickup input but generated no request. The first
admitted combat/death/reward family was replayed next. A calibrated repeat
delivered its first HP update 64.085 ms after the real opcode-`52` attack,
released control 450.850 ms after spawn, and scheduled pickup input at the
previously successful live drop age of 1,517.335 ms; it also generated no
opcode `185` or `222`. After removing the injected object, the fresh fold is
active, valid, and warning-free with zero pickup requests/chains/pending work,
one baseline field-load drop, and 180/180 heartbeats. A later coordinate audit
showed that these controls used the global folded trailer `(633,-2677)` rather
than the same movement record's final absolute command `(633,-2693)`, so the
negative result is not evidence of a missing client-side admission state.

The typed live injector now prevents that ambiguity. It scans backward for the
latest same-field client opcode-`182` observation and retargets both
opcode-`311` records to its last absolute command `final_x/final_y`, while
preserving the global folded trailer as fallback and exposing both positions in
safe output. It retains the animated-source offset, allocates new drop/source
ids, reproduces the 398.819-ms release and 1,591.279-ms input schedule, and
waits for the matching aliased request before sending `[39,49,312]`.

The selector is capture-supported rather than specific to one live failure.
Across 54 stream-`92` pickup requests, the preceding movement command-final
has mean absolute X/Y deltas `35.815/6.296`, maxima `140/28`, and three exact
matches; the trailer has `77.093/12.167`, maxima `229/39`, and no exact match.
Across 197 stream-`126` requests, command-final has mean deltas
`28.695/3.249`, maxima `120/69`, and 17 exact matches, versus trailer
`41.878/5.756`, maxima `240/79`, and 13 exact matches.

The primed live client had moved to `(675,-2693)` while earlier probes still
used `(633,-2677)`; the first live-fold injection produced opcode `185` after
1,607.298 ms and completed `75 -> 76`. The decisive control used another
untouched client whose sole opcode-`182` record reported command-final
`(633,-2693)` and trailer `(633,-2677)`. With no movement, key-map, or skill
preflight, command-final placement produced authentic opcode `185` after
1,572.761 ms at request position `(633,-2694)` and completed `74 -> 75`. The
suspected readiness transition was therefore a coordinate-source bug.

## Item pickup (`client 185/222` -> `server 39/41`, `server 49`, `server 312`)

The capture-validated client request has a 23-byte base form and a 35-byte
extended form:

```text
uint16 opcode = 185
uint32 control_value                   # zero in all captured requests
uint8  field_epoch
uint32 client_tick
int16  position_x
int16  position_y
uint32 drop_object_id
uint32 item_validation_token           # role remains neutral
byte[0 or 12] optional_proof            # contents remain opaque
```

Stream `92` contains 54 requests: 48 base and six extended. Every `field_epoch`
equals the fold's current field epoch, the ticks preserve request ordering, and
all 54 packets round-trip. Normal reports replace `drop_object_id` with a
field-local `drop:N` alias, expose only token presence, and report the optional
proof length rather than its bytes.

Stream `126` adds six exact 19-byte opcode-`222` requests that omit only the
opcode-`185` control word and optional-proof branch:

```text
uint16 opcode = 222
uint8  field_epoch
uint32 client_tick
int16  position_x
int16  position_y
uint32 drop_object_id
uint32 item_validation_token = 0       # role remains neutral
```

One request carries field epoch `8`; the five-request burst carries epoch `9`.
Every epoch equals folded state, the ticks and signed positions track the local
player, and all six object ids resolve to active same-epoch drops. Each request
matches its opcode-`39` inventory or opcode-`41` mesos effect, opcode-`49` gain
notice, and exact-id opcode-`312` removal. All six removals use captured reason
`2`, while the opcode-`185` local chains use reason `5`; the source and
behavioral meaning of that shape/reason distinction remain neutral. The fold
therefore validates all 203 long-corpus pickup chains with zero unknown drops,
epoch/effect/result/removal mismatches, or pending requests. Safe output adds a
`compact` shape/counter while continuing to alias runtime drop ids and omit the
validation token itself.
Across both reference gameplay streams, the 234 base, 17 extended, and six
compact requests all pass independent manifest validation with exact byte
consumption. These 257 records now report full structural coverage while the
control, validation-token, and proof meanings remain neutral and redacted.

Requests repeating for the same `(field_epoch, drop_object_id)` before the
effect/result/removal completes are retry attempts on one logical chain, not
independent pickups. The fold preserves `item_pickup_requests` as the raw wire
count and separately reports `item_pickup_request_chains`,
`item_pickup_request_retries`, `item_pickup_admitted_drops`, admitted drop-kind
counts, and admitted item-template counts. Each request event carries its
one-based attempt number and retry flag. Effect/result/removal events correlate
to the latest attempt for latency while retaining the first request frame and
total attempt count. Stream `92` remains 54 chains/zero retries and proves four
admitted `4000004` objects; stream `126` remains 203 chains/zero retries. The
first live admitted control is one chain/61 retries, not 62 incomplete pickups.
A removal whose reason differs from the request's local-result reason and
arrives before any effect/result closes that chain as
`item_pickup_interrupted_chains`. It is neither a successful pickup removal nor
a mismatch and cannot remain pending. The expected local removal without its
effect/result remains a mismatch. The second live cut exercises one interrupted
ten-attempt chain followed by a completed four-attempt chain.

Each request event now includes `drop_spawn_frame` and `drop_age_ms` from the
first mode-`1` spawn, plus `source_controller_release_frame` and
`source_controller_release_age_ms` when the source has released control.
Controller-release events expose aliased `source_drop_release_delays_ms`;
mode-`0` refreshes preserve rather than restart the first-spawn clock. The four
official template-`4000004` requests have drop ages `2,938.908`, `1,591.279`,
`4,124.092`, and `2,378.920` ms. Their corresponding release ages at request
are `2,488.457`, `1,192.460`, `4,124.092`, and `1,988.300` ms. The third source
release precedes its drop spawn, so that family has no post-spawn release. The
three primed live admissions have drop ages `1,517.335`, `1,584.485`, and
`1,595.243` ms, while the fresh controls expose their matched release delays
without inventing a request event.

The corresponding short server opcode-`49` records have three exact variants:

```text
uint16 opcode = 49
uint8  result_flag                     # zero in all 54 records
uint8  kind

kind 0, item (12 bytes total):
    uint32 item_template_id
    uint32 quantity

kind 1, mesos (15 bytes total):
    uint8  subkind                     # zero in all 29 records
    uint64 amount
    uint16 tail                        # zero in all 29 records

kind 2, special (8 bytes total):
    uint32 special_value               # behavioral role remains neutral
```

There are 24 item, 29 mesos, and one special result. For item results, the fold
attaches the immediately preceding positive opcode-`39` add/quantity delta.
For mesos, it attaches the positive opcode-`41` previous/current delta. The
initial snapshot does not yet seed mesos, so the first result anchors an
inferred prior balance of `4100`; the other 28 are independently checked as
direct deltas. The special result has no inventory or stat effect. All 54
result chains match. Request-to-result latency is 27.801-111.964 ms, averaging
68.239 ms.
The pinned opcode-`49` handler independently confirms this result discriminator
and all three kind-selected branches. Consequently, neutral meanings for the
result flag, mesos subtype/tail, and special value no longer make the
byte-complete packet partial: all 257 pickup-result records across both
reference gameplay streams report full structural coverage and pass exact
independent manifest validation.

Field-drop removal opcode `312` has three exact widths:

```text
7 bytes:  uint16 opcode, uint8 reason, uint32 drop_object_id
11 bytes: uint16 opcode, uint8 reason, uint32 drop_object_id,
          uint32 actor_id
15 bytes: uint16 opcode, uint8 reason, uint32 drop_object_id,
          uint32 actor_id, uint32 trailing_value
```

All 100 records round-trip: 25 are seven-byte records (reason `0` or `1`), 10
are 11-byte records (reason `2`), and 65 are 15-byte records (reason `5`, zero
tail). Exact drop-id correlation identifies 54 of the 15-byte records as the
removals completing local pickup requests; the other 11 belong to other
actors. All 54 local removals follow a matching opcode-`49` result and leave no
pending pickup. Request-to-removal latency is 27.829-111.964 ms, averaging
79.723 ms. The behavioral meaning of the reason, actor, validation-token, and
optional-proof fields remains deliberately neutral.
The pinned opcode-`312` handler confirms the reason-selected 7/11/15-byte
branches, so neutral role names no longer make these structurally complete
records partial. All 545 reference-corpus removals now report full coverage and
pass the independent manifest validator with exact byte consumption.

For state-driven replay, a separate validated evidence transcript supplies the
deterministic item effect. Stream `92` proves template `4000004` four times as
an Etc quantity delta of one and an item gain notice quantity of one. The
reactive policy therefore accepts only a known active item drop, the current
field epoch, a deterministic captured template effect, and exactly one
existing stack with capacity. It emits opcodes `39`, `49`, and `312` in that
order and removes the drop from mutable state. The response mirrors the
request form: opcode `185` receives the captured 15-byte reason-`5` removal,
while opcode `222` receives the captured 11-byte reason-`2` removal. Mesos
pickups, special results, new-slot insertion, ambiguous stacks, and unknown
templates remain rejected.
Runtime annotations record pickup request, completed response, or rejection;
an exact rejection consumes its matching pending request without disconnecting
the client. An annotation without a matching observed request is invalid.

## Character stat deltas (`server 41`)

The capture-validated prefix and conditional-value grammar is:

```text
uint16 opcode = 41
bool   request_flag                  # role remains neutral
uint32 stat_mask
if stat_mask & 0x00000010: uint8  character_level
if stat_mask & 0x00000020: uint16 job_id
if stat_mask & 0x00000040: uint16 strength
if stat_mask & 0x00000080: uint16 dexterity
if stat_mask & 0x00000100: uint16 intelligence
if stat_mask & 0x00000200: uint16 luck
if stat_mask & 0x00000400: uint16 current_hp
if stat_mask & 0x00000800: uint16 max_hp
if stat_mask & 0x00001000: uint16 current_mp
if stat_mask & 0x00002000: uint16 max_mp
if stat_mask & 0x00004000: uint16 ability_points
if stat_mask & 0x00008000: uint16 skill_points
if stat_mask & 0x00010000: uint32 experience
if stat_mask & 0x00040000: uint64 mesos
bool   trailing_flag                 # role remains neutral
if trailing_flag: uint8 trailing_value
```

Conditional values occur in ascending mask-bit order. The pinned opcode-`41`
handler reads `request_flag` as a boolean, delegates the full mask/value body to
parser `0x1812ED210`, then reads `trailing_flag` as a boolean and one additional
u8 only when that flag is true. This types the former bounded tail without
assigning either trailing field a behavioral role. Both capture corpora
exercise false and true flags; true trailing values are
`1,2,3,5,7,9,11,13,15,17`.

Stream `92` contains 333 packets. Their masks/counts are `0x0:14`,
`0x400:35`, `0x1000:207`, `0x4300:1`, `0x10000:44`, `0x10400:3`, and
`0x40000:29`; request flags are `0:315` and `1:18`. All packets and all 324
conditional values parse and re-encode exactly. The combined `0x4300` packet
decodes INT `57`, LUK `15`, AP `0`, while `0x10400` concatenates current HP
and EXP. The fold applies each field independently, records previous/current
values in `player_stats_updated` events, and ends with HP `50`, MP `97`, EXP
`1464`, and mesos `4567` after all field resets and deltas.

Stream `126` contains 841 packets and exercises every field listed above. It
adds nine character-level updates, the job change to `200`, primary-stat and
max-HP/max-MP updates, ten SP updates, AP updates, EXP, and mesos. All packets
round-trip; the final fold reaches level `10`, HP `114/194`, MP `158/285`,
STR `4`, DEX `4`, INT `49`, LUK `13`, EXP `980`, and mesos `1472`.

With the handler-proven booleans and conditional tail, all 333 stream-`92`, 841
stream-`126`, and one stream-`114` stat packets are full structural coverage.
The independent manifest validates all 841 stream-`126` packets and all 334
opcode-`41` packets in its stream-`83/92/114` corpus with exact byte
consumption and no failures.

The state-driven replay emitter uses request flag `false`, current-HP mask
`0x00000400`, a bounded HP value, and trailing flag `false`. A real stream-`114`
client accepted generated plaintext `29000000040000010000`: its HUD changed
from `50/222` to `1/222`, the observed transcript folded the event as
`previous:50 -> current:1`, MP/EXP/map/inventory/progression stayed unchanged,
and heartbeat responses continued. This validates the predicted effect without
assigning behavioral semantics to the two flags.

The later live typed-injection validator repeated the smaller reversible
experiment against an already active browser-free client. Its plan predicted
only `current_hp 50 -> 49`, one `player_stats_updated` event, and no changes to
max HP, phase, field epoch, map, inventory, or progression. The real HUD showed
`49/222`; transcript frame `775` decoded the exact opcode-`41` mask and the fold
matched every invariant. A second independently planned operation observed the
current baseline and restored `49 -> 50` at frame `777`, again with all
invariants matched. The API's runtime injection annotation is separate from
the one predicted domain event.

## NPC spawn (`server 300`)

The complete spawn packet is 22 bytes:

```text
uint16 opcode = 300
uint32 object_id
uint32 template_id
int16  x
int16  cy
uint8  facing_value
uint16 foothold_id
int16  range_left
int16  range_right
uint8  hidden                       # boolean 0/1
```

The facing field is not boolean. Streams `92`, `114`, and `126` preserve the
observed values `0`, `1`, `2`, `4`, and `5`; all 78 stream-`126` spawns parse
and round-trip. The fold exposes the neutral byte as `facing_value` and keeps
the hidden field separately boolean.

`--generate-field-npc-spawns` turns those folded entities back into replay
frames. The planner requires a valid world fold, selects every `npc_spawn`
observation, emits and reparses the 22-byte record, preserves its server-frame
index, and rejects duplicate indices or explicit-patch conflicts. Its runtime
API key is `protocol.npc_spawn_emitter`; records expose session aliases,
templates, positions, footholds, ranges, facing, hidden state, and field epoch,
but never the runtime object ids. Stream `114` generates nine frames at server
indices `20..28`; stream `92` generates 53 across seven populated epochs.

The 2026-08-09 browser-free live run composed those nine frames with the typed
initial snapshot emitter. The client entered map `101000000` and rendered the
expected visible NPCs. The simultaneously recorded transcript folds validly to
`active` with nine active/spawned NPCs and 10/10 matched generated heartbeats.
This demonstrates client acceptance of the reconstructed entity packets rather
than only capture-side parsing.

## NPC lifecycle control (`server 302`)

Opcode `302` starts with a one-byte control and the field-local NPC object id.
The captured control-`1` branch is 23 bytes and reuses the complete spawn body
from opcode `300` after that id:

```text
uint16 opcode = 302
uint8  control = 1
uint32 object_id
uint32 template_id
int16  x
int16  cy
uint8  facing_value
uint16 foothold_id
int16  range_left
int16  range_right
uint8  hidden                       # boolean 0/1
```

All 36 stream-`126` records use that shape. Removing the opcode, control, and
object id leaves the same 16 bytes produced by `NpcSpawn` after its opcode and
object id; all 36 parse and re-encode exactly. They now emit full-coverage
`npc_lifecycle_spawn` observations, enter the entity into current-field NPC
state, and allow later opcode-`303` updates to resolve against the same alias.
That raises the long-corpus NPC spawn-event count from 78 direct spawns to 114
total without changing the distinction between opcode families.

The pinned client handler independently reads `u8 control` and `i32 object_id`.
When the control equals its runtime branch constant, it invokes a helper with
the packet reader and consumes the spawn body; the alternate helper receives
only the object id and cannot consume further bytes. The model uses control
`0` as the canonical compact encoding for that alternate branch:

```text
uint16 opcode = 302
uint8  control = 0
uint32 object_id
```

It removes the aliased NPC, tracks known versus unknown removals, and emits a
full-shape `npc_lifecycle_removal` observation. This seven-byte form is an
exact typed and unit-tested hypothesis, not capture evidence: no reference
PCAP contains it, and the first live attempt reached the configured one-hour
world hold boundary before the removal could be sent.

The same live session did accept a 23-byte control-`1` composition using the
captured object/template fields and the typed current-map position, foothold,
and range. Its transcript remained valid and `active`, folded nine direct NPCs
plus this lifecycle spawn, and matched 360/360 heartbeat pairs until the replay
closed at its configured one-hour boundary. This validates client acceptance
and the predicted spawn-state delta; it does not establish visible rendering
or the compact removal effect.

## Mob temporary-stat set/reset (`server 285`, `server 286`)

The pinned opcode-`285` and opcode-`286` handlers belong to the same client
type and each directly reads one signed 32-bit object id before delegating the
body. Stream `92` supplies the only reference instances: ten 33-byte set
records and five 23-byte reset records. The captured single-bit forms are:

```text
uint16 opcode = 285
uint32 mob_object_id                 # field-local; redacted/aliased
uint32 mask_words[4] = [0, 0, 0, 0x80]  # enabled bit index 103
uint16 value = 1
uint32 source_skill_id
uint16 source_level                  # neutral captured field name
uint16 duration_value                # units not yet proven
uint8  flag = 1

uint16 opcode = 286
uint32 mob_object_id                 # field-local; redacted/aliased
uint32 mask_words[4] = [0, 0, 0, 0x80]
uint8  flag = 1
```

All 15 packets consume and re-encode byte-for-byte. Every object id names an
active template-`3210800` mob. Each set follows within one or two server frames
of an opcode-`219` relay that targets the same mob and carries the same source
skill id, `3101005`; this correlation is 10/10. The set records use source
levels `5`/`6` and ten distinct duration values from `859` through `1142`, so
the model retains both names neutrally and does not assert time units.

The fold stores bit `103` on the field-local mob entity. Ten sets include three
refreshes. Of five resets, three remove a modeled active bit and two occur
before a corresponding set is visible in the bounded capture. Four remaining
active bits clear when their mobs leave, and the final active count is zero.
Events and reports expose the aliased mob, mask, source skill, neutral values,
and relay match without exposing the object id. Other masks, values, flags, or
packet widths remain unknown rather than inheriting this capture-bounded
grammar.

The typed live validator now joins this semantic model to the independently
generated IL2CPP shape dump. The pinned dump/export/validation covered all
35,316 packets from `111.pcapng` streams `83`, `92`, and `114`, with zero
unsupported packets or consumption failures. The validator selected the
captured base-spawn/set/reset sequence at server direction indices
`11006/11438/11506`, matched generated shapes
`mob_enter_field_short_status`, `server_opcode_285`, `server_opcode_286`, and
`mob_leave_field`, then rewrote only a redacted runtime object id and current-
map placement.

On the live map-`101000000` transcript, the base-spawn run folded opcode `279`
at frame `1516`, bit-103 set at `1518`, reset at `1522`, and leave at `1523`.
The active-status count followed `0 -> 1 -> 0`; the mob was present for set and
reset and absent after leave; all predicted counter deltas matched; phase,
field epoch, map, player state, inventory, and progression were unchanged; and
the control remained healthy at 1,424/1,424 heartbeats. The client visibly
rendered the spawned template and removed it after leave. Sampled spawn-only
and set-active frames showed the same sprite pose and no unique status marker,
so a specific visible immobilization/status meaning for bit `103` remains
unproven even though client acceptance and the folded lifecycle are now live-
validated.

## Mob health percentage (`server 293`)

The complete update is seven bytes:

```text
uint16 opcode = 293
uint32 mob_object_id
uint8  health_percentage             # inclusive 0..100
```

Stream `92` contains 208 updates and stream `126` contains 399. Every
long-corpus object id resolves to an active mob in the current field epoch;
189 values are zero and no value increases during one mob lifecycle. The fold
stores current/previous percentages and emits `mob_health_percentage_updated`.
A zero value does not itself remove the entity: membership still changes only
on the separate opcode-`280` leave packet.

When targeted client opcode `50`/`52` damage is pending for the same mob, each
nonzero damage word is one pending hit. One opcode-`293` packet consumes one
hit in order and adds the request frame, hit index/count, selected damage word,
complete damage array, response time, and count of modeled relay hits observed
for that mob since submission to the event. Zero-damage words do not need an
update. This accounts for all 399 stream-`126` health packets and all 208
stream-`92` packets; lifecycle removal clears 21 and 11 terminal hits,
respectively, and both folds finish with no pending effects.

For the 11 templates actually attacked in the two references, the model uses
version-specific `info/maxHP` values extracted from the official client's
`json_27ed12ab55c4464e7db01cade1a2e593.bundle` WZJS-v5 records:

| template | max HP | template | max HP |
|---:|---:|---:|---:|
| `100100` | 8 | `100101` | 15 |
| `120100` | 20 | `130100` | 40 |
| `130101` | 40 | `210100` | 50 |
| `1110100` | 250 | `1130100` | 300 |
| `1210100` | 75 | `1210102` | 80 |
| `9300018` | 8 |  |  |

The authoritative byte uses integer floor percentage:

```text
health_percentage = floor(current_hp * 100 / max_hp)
```

Therefore one percentage maps to a bounded integer-HP interval rather than an
exact value. The fold stores that interval on the mob and, when a previous
sample exists, subtracts the correlated hit from both bounds to predict the
next percentage range. Stream `92` matches all 161 testable predictions; floor
also explains seven cases that ceil/nearest quantization cannot represent.
Stream `126` matches 203/209 exactly. The six outliers are each exactly one HP
from the predicted interval and have response delays of `0.389..0.460`
seconds, so they are reported as semantic warnings instead of invalid shapes.
Subtracting the observed post-update HP bounds from the previous bounds yields
an inferred authoritative-damage interval on every testable event. All six
outliers have exact authoritative-minus-submitted deltas: five `+1`, one `-1`.
None has an intervening modeled opcode-`218`/`219` hit for the target.

### Generated custom-server mob-health response

The opt-in runtime policy intentionally has a narrower contract than captured
official combat. It requires an active mob with exact integer HP and a template
whose max HP is in the referenced table above. A later typed opcode-`279`
spawn initializes that mob at max HP; an opcode-`293` can be adopted only when
its percentage maps to one exact integer HP. The policy accepts only targeted
client opcode `50`/`52` actions with a decoded damage array and no high-bit
damage marker.

For each damage word, in packet order:

```text
damage == 0                 -> emit nothing
current_hp == 0             -> skip this already-terminal hit
otherwise                   -> current_hp = max(0, current_hp - damage)
                               emit server 293 with
                               floor(current_hp * 100 / max_hp)
new current_hp == 0         -> after the 293, emit server 280 reason 1
                               and remove the mob from active state
```

This exact rule is a custom-server state transition, not a claim that the six
official ±1 HP adjustments have been explained. It also does not synthesize
server attack relays `218`/`219`. Unknown or inactive targets, missing damage,
ambiguous HP, and high-bit damage are counted as rejected and receive no
modeled response; the held-open transport continues so ordinary untargeted
swings do not disconnect the client.

The real-client proof injected a typed template-`100100` spawn with `8/8` HP
at the stream-`114` player position. The client submitted opcode `52`, variant
`18`, with damage words `[27,32]`. The server predicted and emitted opcode
`293` percentage `0`, then opcode `280` reason `1`; the second hit was skipped
because the first was terminal. The observed fold contains one attack, one
zero-health update, one leave, zero active mobs, and zero pending effects while
the connection and generated heartbeat exchange remained active.

Recorded custom-server runs also emit identifier-free runtime policy events;
these do not alter the packet protocol. The live targeted opcode-`52` at frame
`85` records observed damage `[27,32]`. After generated opcode `293`/`280`
frames drain, frame `87` records the completed `8 -> 0` transition,
percentage `[0]`, removal, and one skipped terminal hit. A later untargeted
opcode-`52` records observation and rejection together at frame `99` without a
server response. The combined packet/policy fold is valid and warning-free
with two attacks, 59 submitted damage, one matched health effect, no pending
effect, and 17/17 matched heartbeats.

## Mob movement (`client 207`, `server 282/283`)

The client submits a field-local mob object, a sequence number, and one typed
movement path:

```text
uint16 opcode = 207
uint32 mob_object_id
uint16 sequence
uint8  option_flags
int8   activity_code
uint8  skill_id
uint8  skill_level
uint8  action_auxiliary_1
uint8  action_auxiliary_2
uint8  control_marker
uint32 control_value_1
uint32 control_value_2
uint32 control_value_3
int16  reference_x
int16  reference_y
uint8  command_count                 # nonzero
repeat command_count: mob_movement_command
uint8  trailer_marker = 0
int16  path_start_x
int16  path_start_y
int16  path_end_x
int16  path_end_y
```

The observed command tags are `0`, `1`, and `2`. Type `0` has signed position
and velocity pairs, uint16 foothold, stance, and duration; types `1` and `2`
have signed relative velocity, stance, and duration. All 12,100 stream-`92`
submissions, 40,090 commands, and nine-byte trailers parse and re-encode
exactly; stream `126` validates the same boundaries across another 22,855
submissions. The six-byte action prefix is also typed. The signed activity is
predominantly `-1`, with captured `12`, `13`, and `24` values; option flags are
captured as `0`, `1`, and `17`. The two auxiliary bytes retain neutral names,
and the following 13 bytes split exactly as one marker plus three little-endian
u32 values. The marker is always zero; `control_value_1` is `0` or `1`; and
both final values are the stable captured `0x00ffddcc`. Their behavioral roles
remain neutral.

This split follows the original v83 client writer, which emits six one-byte
arguments and then reserves 13 bytes before the reference point. Independent
v83 server handlers agree on option/activity and skill-id/level placement, but
disagree on whether the final pair is one uint16 option or two independent
bytes, so the model does not assign those two bytes behavioral meaning.
[Original client writer](https://github.com/ryantpayton/MapleStory-Client/blob/cbb0fe27cf9683a12eca0a569121d8033cdc2a4d/Net/Packets/GameplayPackets.h),
[Guida83 handler](https://github.com/v3921358/Guida83/blob/b6b3c69f099169c2a60c9ef156220a87dd4b09b1/src/main/java/guida/net/channel/handler/MoveLifeHandler.java),
and [gms083 handler](https://github.com/akhuting/gms083/blob/2ac781b5012ffdbf7c9c3200c756e660149ff00/src/main/java/net/server/channel/handlers/MoveLifeHandler.java)
provide the independent source anchors. Guida83 independently reads this tail
at the same `u8 + u32 + u32 + u32` boundary. With every byte structurally
typed, all 12,100 stream-`92` and 22,855 stream-`126` submissions are full
coverage.

Server opcode `282` broadcasts movement for one field-local mob without the
client sequence or nine-byte trailer:

```text
uint16 opcode = 282
uint32 mob_object_id
bool   control_flag_1
bool   control_flag_2
uint8  control_selector
uint32 control_value
int16  reference_x
int16  reference_y
uint8  command_count                 # nonzero
repeat command_count: mob_movement_command
```

The pinned opcode-`282` receive handler delegates the body to method
`c593a76f...`, whose first reads after the object id are exactly
`bool, bool, u8, u32`. The six observed seven-byte combinations therefore no
longer need an opaque prefix. Across streams `92` and `126`, all 13,366
broadcasts have `control_flag_1 = false`, selectors are `0x0c`, `0x0d`, or
`0xff`, and `control_value` is zero; `control_flag_2` exercises both values.
Those neutral names describe only the proven wire types, not behavioral roles.
The three command tags are also scalar-typed rather than width-only blobs, so
all 5,284 stream-`92` and 8,082 stream-`126` broadcasts now have full structural
coverage and pass independent manifest validation with exact byte consumption.

Stream `92` contains 18,874 commands and every referenced object is active.
The control combination `false,false,0xff,0` occurs 5,230 times. Of those,
1,509 packets use the exact one-command stationary placement shape: the
reference equals the absolute command position, velocity is zero, and duration
is 1,080 ms. Stances `2`, `4`, and `5` are all captured; stance `4` has 1,055
exact examples.

The complete acknowledgement is 13 plaintext bytes:

```text
uint16 opcode = 283
uint32 mob_object_id
uint16 sequence
uint8  status_flag                    # boolean 0/1
uint16 status_value
uint8  status_auxiliary_1
uint8  status_auxiliary_2
```

All 11,949 stream-`92` acknowledgements correlate with a prior submission.
The flag is exactly whether `option_flags` is nonzero, both auxiliary
bytes are always zero, and the status value is deterministic for every
field-local template: `100100 -> 0`, `130100 -> 30`, `210100 -> 35`,
`1110100 -> 25`, `1130100 -> 30`, `2110200 -> 35`, `3210800 -> 100`, and
`9999999 -> 0`. The behavioral name of the uint16 remains unknown.

The custom server can derive this mapping from one validated evidence stream
while using another transcript's final field. Typed later opcode-`279` entries
and opcode-`281` controller assignments populate field-local template state;
opcode `280` removes active membership but retains that identity until the next
field epoch, matching official post-leave acknowledgements. Unknown objects or
templates without deterministic evidence receive no guessed reply.

The real-client proof replayed stream `114`, derived values from stream `92`,
and injected matching typed entry/controller packets for template `100100` at
the final player position. The client produced 205 opcode-`207` submissions;
the server generated 205 opcode-`283` packets, and the independent transcript
fold matched all 205 with flag/value/auxiliary rules exact and no pending
movement. Heartbeats and the world connection remained active.

The current replay also records each reactive submission and outcome as a
safe runtime event. Request details retain template, sequence, command count,
the typed action prefix, four neutral control values, and reference/start/end
coordinates, but omit the runtime object id. A fresh browser-free run produced
13 alternating
`mob_movement_submission_observed` and
`mob_movement_acknowledgement_completed` events. All 58 generated opcode-`283`
packets independently matched their opcode-`207` submissions; the valid,
warning-free fold has no pending/unmatched movement and 7/7 heartbeats.
Unknown-object unit coverage records a nonfatal
`mob_movement_submission_rejected` event instead of inventing a response.

The state-driven broadcast proof used stream `114` as the held-open field and
stream `92` as shape evidence. A typed opcode-`279` introduced one
template-`100100` snail at `(433,-2677)` on foothold `635`; the custom server
then generated one opcode-`282` stationary placement for `(833,-2677)`, the
same foothold, and stance `4`. The real client rendered the snail at the
predicted target. The independent observed fold is valid and ends with that
exact mob position/stance, one known broadcast, one command, and 11/11 matched
heartbeats. This validates the stationary placement effect.

The multi-command proof selects stream-`92` server-direction frame `18818`,
whose template-`100100` opcode `282` moves from reference `(249,2024)` through
five absolute commands to `(297,2024)` in 1,080 ms. The command positions are
`(277,2024)`, `(278,2024)`, `(285,2022)`, `(289,2022)`, and `(297,2024)`;
their velocity, stance, and duration fields are preserved exactly. The planner
translates every position relative to the reference, requires the active mob
to be at that translated reference on the requested foothold, and rewrites
each command foothold to that continuous live foothold.

The real-client run translated this captured path to reference `(785,-2677)`
and endpoint `(833,-2677)` for the injected snail on foothold `635`. The client
rendered the snail at the predicted endpoint. The recorded transcript folds
validly with one known broadcast, five type-`0` commands, final stance `2`, and
9/9 matched heartbeats. This validates replay of a specific captured path and
its predicted state effect; it is not yet an autonomous path-selection policy.

The next layer removes the frame choice while retaining a strict capture
boundary. Given the active template, current position, requested endpoint, and
foothold, the server catalogs captured multi-command absolute paths with the
dominant control prefix. It keeps only paths whose endpoint-minus-reference
equals the requested displacement, then requires exactly one distinct relative
position/velocity/stance/duration shape. Repeated evidence for that same shape
is allowed; different matching shapes are an explicit ambiguity error.

For template `100100` and displacement `(48,0)`, stream `92` contains exactly
one matching path and one shape: server-direction frame `18818`. The automatic
mode therefore generated the same predicted packet without a frame hint. The
real client again rendered the snail at `(833,-2677)`, and the new observed
transcript folds validly with one five-command broadcast, no unknown mob, and
13/13 matched heartbeats.

Bounded composition uses those same unique displacement primitives rather than
inventing longer command arrays. The planner excludes every displacement that
has multiple relative motion shapes, then performs breadth-first search up to
the requested `2..8` step bound. Every step must strictly reduce Manhattan
distance to the endpoint, every intermediate absolute position must fit in
`int16`, and exactly one shortest displacement sequence must remain. Each
selected primitive becomes its own opcode `282`, so the ordinary gameplay fold
validates every intermediate state as well as the final endpoint.

For template `100100`, stream `92` provides 167 usable unique displacement
shapes and 38 ambiguous displacements that are excluded. No direct `(96,0)`
path exists, but the unique shortest composition is `(48,0) + (48,0)`, using
frame `18818` twice. Starting at `(785,-2677)`, the generated references were
`(785,-2677)` and `(833,-2677)`, with endpoints `(833,-2677)` and
`(881,-2677)`. The real client rendered the snail at final `(881,-2677)`.
The independent transcript folds validly with two known broadcasts, ten
type-`0` commands, final foothold `635`/stance `2`, and 11/11 matched
heartbeats.

At runtime those two packets are no longer represented only by a startup plan
and final sent counter. A per-connection scheduler validates that every step
retains the same entity/template/field/object and that each previous
position/foothold/stance equals the prior predicted result. It advances its
`current` state only after the expected encrypted write drains, retains the
confirmed opcode-`282` prefix for later planning folds, and exposes
`planned`, `in_progress`, or `complete` state plus last/next safe step reports.
Out-of-order plaintext is rejected without changing the model.

The live pacing proof repeated the `(48,0) + (48,0)` route with a dedicated
10-second movement-step delay. Runtime status observed the intermediate
`(833,-2677)` state at `1/2` sent rather than prematurely reporting the final
target, then completed at `(881,-2677)` and `2/2`. The independently folded
events are 10.002838 seconds apart and retain exact continuity:
`(785,-2677, stance 3) -> (833,-2677, stance 2) ->
(881,-2677, stance 2)` on foothold `635`. The transcript remains valid with
two broadcasts, ten type-`0` commands, and 10/10 heartbeats.

The next runtime boundary is a bounded decision queue, not a new packet shape.
Up to eight follow-up `MAX_STEPS:X:Y:FOOTHOLD` targets are fixed at startup.
After the current schedule's last opcode `282` write drains, the queue exposes
`planning` and invokes the same composition algorithm with the scheduler's
original baseline plus its confirmed broadcast prefix. No untransmitted
prediction enters that fold. The capture analysis is dispatched off the
asyncio event loop; `GET /api/v1/status` remains responsive and no HTTP
mutation route exists. During `planning`, the sent count includes the drained
prefix, `packets_remaining` is zero because the next packet count is not yet
known, and `decision_queue.planning_decision_index` identifies the pending
decision.

The real-client proof began with one automatically selected `(48,0)` packet,
then queued a two-step composed target. Runtime state progressed
`planned (785, 0/1) -> planning (833, 1/1 known) -> in_progress (833, 1/3) ->
in_progress (881, 2/3) -> complete (929, 3/3)`. The independent transcript is
valid and preserves exact foothold-`635`/stance-`2` continuity across all
three five-command broadcasts. Its movement events occur at 14.644652,
57.145568, and 67.147278 seconds: the 42.500916-second first gap includes
worker-backed evidence analysis plus the ten-second movement pace, while the
next gap is 10.001710 seconds. The final fold reports fifteen type-`0` commands
and 8/8 matched heartbeats, and the real client rendered the snail at the
predicted final endpoint `(929,-2677)`.

That first implementation rebuilt the same immutable evidence analysis inside
the follow-up call. The planner now receives a validated
`MobMovementPlanningContext` containing the replay analysis, evidence analysis,
5,284 parsed captured paths/broadcasts, and stationary-shape counts. Only the
connection-local confirmed prefix remains mutable. Building the stream-`92`
context once took 10.432799 seconds; using it took 0.000360 seconds for the
automatic first decision and 0.005125 seconds for the composed follow-up. The
context's safe cache counts are visible in runtime status so reuse is
inspectable.

The cached real-client transcript places the three movement events at
14.642526, 24.651246, and 34.653303 seconds. The resulting 10.008720- and
10.002057-second gaps are the configured ten-second movement pace plus normal
scheduling jitter; the prior 32.5-second repeated fold is absent. The fold is
again valid with exact `785 -> 833 -> 881 -> 929` continuity, three broadcasts,
fifteen type-`0` commands, final foothold `635`/stance `2`, and 6/6 matched
heartbeats.

The first bounded gameplay policy derives relative targets from confirmed
state rather than storing endpoint arguments. Its inputs are a `1..8` decision
count, a `2..8` composition bound, signed `(dx,dy)`, and a foothold. Once a
decision completes, the policy adds that displacement to the scheduler's
current coordinates, validates the result as `int16`, and submits the derived
target to the unchanged capture-backed composed planner. It cannot coexist
with the explicit target queue. This changes scheduling policy only; every
wire packet remains the same typed opcode `282` shape and every intermediate
state remains independently foldable.

The live policy used two `(+96,0)` decisions after an initial automatic
placement. It derived `929` only from confirmed `833`, then derived `1025` only
from confirmed `929`. Runtime completed three decisions, five planned/sent
packets, and final state `(1025,-2677)` on foothold `635`/stance `2`. The client
rendered that predicted endpoint. The frozen movement events preserve exact
continuity `785 -> 833 -> 881 -> 929 -> 977 -> 1025`; their four gaps are
3.011704, 3.000499, 3.008745, and 3.001274 seconds. The valid transcript has
five broadcasts, twenty-five type-`0` commands, and 6/6 matched heartbeats.

Policy scheduling can now consume the already-modeled heartbeat correlation
as its trigger rather than chaining immediately. In `matched-heartbeat` mode,
only a client opcode `23` observed while a server opcode `10` probe is pending
authorizes one follow-up decision. The initial movement remains unconditional,
the first opcode `282` of each authorized decision is immediate, and any later
opcode `282` packets in that same composed decision retain their configured
step delay. This is a runtime scheduling invariant and does not change any wire
shape.

The real-client proof used five-second probes and a one-second movement-step
delay. The first two matches authorized the two `(+96,0)` decisions; a third
matched response after completion was observed but ignored. The frozen event
order is `heartbeat response frame 78 -> movement frame 79`, then response
frame `83 -> movement frame 84`. Exact movement gaps are 5.326966, 1.000527,
3.999752, and 1.000549 seconds, separating the two event gates from each
decision's internal pace. The transcript remains valid with exact
`785 -> 833 -> 881 -> 929 -> 977 -> 1025` continuity, five broadcasts,
twenty-five type-`0` commands, and 21/21 matched heartbeats.

Event-trigger scheduling also has an optional shared cooldown invariant. A
configured `0..3600`-second window begins only when all opcode-`282` packets
in one authorized decision have drained. A qualifying heartbeat, served mob
submission, or proximity entry observed before expiry is counted and rejected
without planning or emitting a decision; the first qualifying event after
expiry may authorize exactly one. Cooldown configuration is invalid for the
immediate trigger. The HTTP model exposes the configured duration, rejection
count, last event outcome, and last observed remaining duration without adding
any field to the wire protocol.

In the five-second live proof, heartbeat response frame `78` authorized
opcode-`282` frames `79`/`80`. Response frames `82`, `84`, and `86` arrived
inside the window and have no intervening movement; frame `88` arrived after
expiry and authorized frames `89`/`90`. The runtime completion sample recorded
two started/completed decisions and three cooldown rejections. The independent
fold is valid with no warnings, exact
`785 -> 833 -> 881 -> 929 -> 977 -> 1025` continuity, five broadcasts,
twenty-five type-`0` commands, and 16/16 matched heartbeats.

An optional connection-local event budget is a separate scheduling invariant.
Its bound is `1..8`, and it applies only to event-driven triggers. Every
accepted trigger consumes one unit before planning; after the remaining count
reaches zero, later qualifying events are observed and rejected without
planning or emitting opcode `282`, even when no cooldown is active. Safe HTTP
state exposes configured/used/remaining counts plus
`events_rejected_by_budget`. Runtime rejection annotations use
`reason: event_budget`; no wire field or identifier is added. Encrypted test
coverage sends two valid heartbeat matches to a two-decision policy with a
budget of one and proves that exactly one follow-up decision drains.

Because trigger acceptance is server policy rather than a Maple wire packet,
observed replay JSONL can include a separate `runtime_event` record. Its
nanosecond timestamp, safe kind, and JSON-safe details carry the trigger mode,
decision index, outcome reason, and cooldown duration/remaining time. The
gameplay analyzer orders these annotations alongside decoded packet events,
marks their direction as `runtime`, and aligns each to the preceding packet
frame without treating it as protocol bytes. The writer caps annotations at
16,384 and places written/dropped counts in the close record; a nonzero drop
count becomes an explicit analysis warning.

The live annotation transcript directly emits observation/start events at
response frame `78`, completion at movement frame `80`, cooldown rejections at
frames `82`/`84`/`86`, re-arm/start at frame `88`, and final completion at
frame `90`. The rejection records preserve exact remaining times
`4.006931`, `2.007733`, and `0.006772` seconds. Its independent packet fold is
valid and warning-free at `(1025,-2677)` with five broadcasts, twenty-five
type-`0` commands, and 15/15 matched heartbeats.

A second event mode consumes the existing typed mob-controller protocol rather
than the heartbeat. `served-mob-movement` accepts only an opcode `207`
submission that the capture-derived acknowledgement policy validates for a
known active mob. The server first drains its typed opcode `283` response and
only then starts one pending relative decision. A rejected submission has no
scheduling effect. While no accepted event exists, explicit `awaiting_event`
telemetry distinguishes the gate from capture-backed path planning. Again,
this changes packet order and policy only, not the `207`, `283`, or `282` wire
shapes.

In the real-client proof, the initial opcode `282` ended at `833` in frame
`77`; authentic sequence-`1` opcode `207` arrived in frame `78`, its matched
opcode `283` was frame `79`, and the newly authorized opcode `282` packets were
frames `80` and `81`. They ended at `881` and `929`, with 0.008418 seconds from
the initial broadcast to the first gated broadcast and 1.000714 seconds inside
the composed decision. The valid fold reports three broadcasts/fifteen
type-`0` commands, one submitted/acknowledged/matched movement, zero pending or
unmatched movement, and 4/4 independently matched heartbeats.

The third event mode is a bounded predicate over an already typed packet.
`player-proximity` parses each live local-player opcode `182`, takes its
explicit trailer `path_end_x/path_end_y`, and computes Manhattan distance to
the scheduler's confirmed mob coordinates. A required radius is limited to
`1..4096`. Only an outside-to-inside edge (including the first observation
when it is inside) authorizes a decision; repeated in-radius submissions do
not. The server exposes only safe coordinates, distance, boolean result, and
observation/entry counts. This adds no new interpretation to movement command
payloads and changes no wire shape.

The live negative observations ended at `(633,-2673)` and `(548,-2652)`, both
outside radius `64`; the latter was distance `310` from confirmed mob
`(833,-2677)`, and neither sent an opcode `282`. After four rightward
submissions, frame `107` ended at `(855,-2695)`, distance `40`, and crossed the
predicate. Opcode-`282` frames `108`/`109` followed, ending at `881`/`929`; the
entry-to-first-broadcast gap was 0.009526 seconds and the configured internal
pace was 1.001263 seconds. The valid fold has seven player submissions, three
mob broadcasts/fifteen type-`0` commands, and 11/11 independently matched
heartbeats.

## Player movement (`client 182`, `server 202`)

Local-player movement submissions have this capture-validated shape:

```text
uint16 opcode = 182
uint32 control_value
int16  reference_x
int16  reference_y
uint8  command_count
repeat command_count: movement_command
uint8  trailer_marker = 0
int16  path_start_x
int16  path_start_y
int16  path_end_x
int16  path_end_y
```

Remote-player broadcasts use opcode `202`, insert a `uint32 object_id` before
the control value, and end immediately after the same reference/count/command
stream; they do not carry the nine-byte client trailer. Reports replace the
object id with a stable `player:N` alias.

The command discriminants and payload boundaries are exact across both
directions:

```text
type 0: int16 position_x/y, int16 velocity_x/y,
        uint16 foothold_id, uint8 stance, uint16 duration_ms  # 13 bytes
type 1: int16 velocity_x/y, uint8 stance, uint16 duration_ms # 7 bytes
type 3: int16 position_x/y, int16 neutral_value,
        uint8 stance, int16 duration_ms                       # 9 bytes
type 4: same 9-byte fields as type 3
type 5: same 13-byte fields as type 0
```

Stream `92` contains 531 client submissions with 3,606 commands
(`0:3506, 1:53, 3:20, 4:20, 5:7`) and 113 server broadcasts with 675 commands
(`0:642, 1:18, 3:4, 4:4, 5:7`). All 644 packets and 4,281 commands round-trip
byte-for-byte. Stream `126` independently exact-consumes 2,435 packets and
11,147 commands (`0:10736, 1:236, 3:61, 4:61, 5:53`). The type-`3`/`4`
layout is pinned to the current client's shared IL2CPP movement parser; its
third signed value is zero in both captures, so its role remains neutral. All
client control values are zero in stream `92`; the two stream-`114` broadcasts
demonstrate values zero and one, so that field also remains neutrally named.
The fold uses the client trailer endpoint for general local position and the
last positioned command for each observed remote player,
emitting typed events for both directions. Proximity-sensitive live pickup
placement is deliberately narrower: it prefers the latest same-field client
command-final coordinate and falls back to the trailer only when no such
observation exists. Stream `114` ends at local path endpoint `(633,-2677)` with
two identifier-safe remote-player aliases.

## Life movement relay (`client 47`, `server 217`)

This is a separate counted movement family. The client packet is:

```text
uint16 opcode = 47
uint8  local_object_index
uint32 client_token                 # redacted from safe reports
uint32 control_value                # neutral role
int16  reference_x
int16  reference_y
uint8  command_count
repeat command_count:
  uint8 command_type
  byte[command_payload_length(command_type)] command_payload
uint8  tail_type
uint8 tail_state_values[tail_payload_length(tail_type)]  # neutral per-byte state
uint8  tail_marker                  # neutral role
int16  path_start_x
int16  path_start_y
int16  path_end_x
int16  path_end_y
```

The server packet ends after the shared movement path:

```text
uint16 opcode = 217
uint32 object_id
int16  reference_x
int16  reference_y
uint8  command_count
repeat command_count: command_type + fixed command payload
```

Capture-derived command payload sizes, excluding the one-byte tag, are exact:

```text
type:    0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22
bytes:  13  7  7  9  9 13  7  9  9  9  1  9  7  7  9 15  7 13  7  7  3  3  7
```

The exact v83 [`MovementParser`](https://github.com/ryantpayton/MapleStory-Client/blob/cbb0fe27cf9683a12eca0a569121d8033cdc2a4d/Net/Handlers/Helpers/MovementParser.cpp)
and its [`Movement` record](https://github.com/ryantpayton/MapleStory-Client/blob/cbb0fe27cf9683a12eca0a569121d8033cdc2a4d/Gameplay/Movement.h)
independently name the supported layouts:

```text
types 0/5/17: position x/y, last x/y, foothold, stance, duration
types 1/2/6/12/13/16: relative delta x/y, stance, duration
type 10: equipment-change value
type 11: chair position x/y, neutral u16, stance, trailing i16
type 15: jump-down position x/y, two vectors, two neutral u16s,
         stance, trailing i16
types 3/4/7/8/9/14: teleport-like position x/y plus neutral middle/trailing values
```

Guida's v83
[`AbstractMovementPacketHandler`](https://github.com/v3921358/Guida83/blob/b6b3c69f099169c2a60c9ef156220a87dd4b09b1/src/main/java/guida/net/channel/handler/AbstractMovementPacketHandler.java)
confirms every captured payload width and identifies the nine-byte family as
teleport-like. It disagrees with the other parser about some middle/trailing
labels, so the codec intentionally does not promote those disputed words.

Client tail types `17`, `18`, `21`, and `24` carry `8`, `8`, `10`, and `11`
neutral byte-sized state values respectively. Stream `92` validates 963 client
packets with 3,869 commands and 305 server packets with 1,441 commands; it
observes every tail type and command tags `0/1/2/3/4/10/11/14/15`. Stream `126`
validates another 2,585 client packets with 8,189 commands and 347 server
packets with 1,399 commands. In the long corpus, all 347 server object ids name
players already active when the packet arrives. The fold
records that correlation and advances an already known remote-player alias to
the last positioned command. It emits redacted submission/broadcast events and
tracks decoded command, tail-type, tail-state-value, and tail-marker
distributions. All captured packets contain typed command tags and therefore
receive full structural coverage. Disputed command words, tail/control roles,
and unobserved tags `18..22` deliberately retain neutral names; a future packet
using one of those opaque tags remains partial.

## NPC state submission and echo (`client 217`, `server 303`)

The client-to-server opcode is a separate family from the server-to-client
life-movement opcode `217` above. Stream `126` proves that it submits the same
NPC state body later echoed by server opcode `303`. It has two variants:

```text
compact:
  uint16 opcode = 217
  uint32 npc_object_id
  uint8 action
  uint8 parameter

movement:
  uint16 opcode = 217
  uint32 npc_object_id
  uint8 action
  uint8 parameter
  int16 reference_x
  int16 reference_y
  uint8 command_count                # 1..255
  repeat command_count:
    uint8 command_type               # observed 0 or 2
    type 0: int16 position_x/y, int16 velocity_x/y,
            uint16 foothold_id, uint8 stance, uint16 duration_ms
    type 2: int16 velocity_x/y, uint8 stance, uint16 duration_ms
  uint8 trailer_marker = 0
  int16 path_start_x
  int16 path_start_y
  int16 path_end_x
  int16 path_end_y

server echo:
  uint16 opcode = 303
  byte[...] client_body_without_final_9_byte_movement_trailer
```

Stream `126` contains 937 instances. Of these, 345 are compact and 592 are
movement submissions. They carry 1,653 commands: 1,596 type `0` commands and
57 type `2` commands. Observed command counts per packet are:

```text
count:    1   2  3  4  5  6  7  8  9 10 11 12 13 14
packets: 332  71 21 18 37 40 27 22 11  1  4  5  1  2
```

Every client packet and all 1,279 server opcode-`303` packets parse to their
exact end and re-encode byte-for-byte. Exact FIFO matching pairs 930 of the 937
client submissions with later server updates: 339 compact and 591 movement
pairs. For every pair, the server response changes only the opcode and, for the
movement variant, removes the client-only final nine-byte marker/start/end
trailer. The remaining seven requests have no same-epoch captured response and
are cleared by later field changes; 349 server updates are independent of a
client submission. The fold records exact matches, latency, active-NPC
admission, command distributions, and final absolute positions. Higher-level
action/parameter intent remains neutral. The command field layouts match the
current client's pinned movement parser and make both variants full structural
coverage without assigning those higher-level action semantics.

The opt-in `--reactive-npc-state-responses` policy admits only object ids active
in the replay's final field, validates the two captured variants and command
types, and emits the exact typed opcode-`303` transformation. NPC spawn and
lifecycle packets keep the runtime admission set current.

Promoting the 592 movement-bearing requests and 683 movement-bearing updates
adds 1,275 full observations. Current stream `126` coverage is
`53,785/17,315/0/0` (full/partial/unknown/invalid). Streams `92` and `114`
remain `26,266/8,941/0/0` and `57/19/0/0`.

## Client opcode `122` selector envelopes

The long gameplay corpus establishes six exact client-to-server shapes:

```text
uint16 opcode = 122
uint8  selector
repeat captured_value_count(selector, packet_length):
  uint32 opaque_value               # redacted from safe output
```

The capture-bounded selector/count matrix is:

```text
selector  u32 values  packets  additional invariant
1         2           2        none
1         3          26        none
2         3           1        final value = 0xffffffff
2         4          25        final value = 0xffffffff
4         3           6        none
5         3           2        none
```

All 62 stream-`126` packets consume exactly and re-encode byte-for-byte. No
opcode-`122` packet occurs in gameplay streams `92` or `114`. Selector `1` and
selector `2` frequently appear as a pair with the same first value, and the
remaining words include coordinate-like packed values, but those correlations
do not establish field roles or a safe replay effect. The codec therefore
retains every u32 only for lossless re-emission while reports, events, JSON,
and HTTP-derived state expose selector, value count, shape, and terminal-
sentinel presence. The fold emits `client_opcode_122_submitted`; any selector/
count combination outside the matrix remains unknown instead of being parsed
through an observed variant.

## Empty notification/acknowledgement (`server 426`, `client 309`)

This family is exactly two opcode-only packets:

```text
server -> client: uint16 opcode = 426
client -> server: uint16 opcode = 309
```

The temporal relationship is exact in every gameplay reference. Stream `126`
has 299 pairs, stream `92` has 61, and stream `114` has one. In all 361 pairs,
the server notification arrives first, the client acknowledgement consumes the
only pending notification, and no unmatched packet remains at capture end.
The long-stream delay is 0.2681-4,643.4658 ms (13.3547 ms median); stream `92`
is 0.6815-83.8679 ms (28.0082 ms median), and stream `114` is 82.534 ms.

Pinned IL2CPP handler code independently confirms direction: the handler
registered for server opcode `426` constructs an outgoing opcode `309` packet,
writes no body fields, and sends it. The fold therefore names only the proven
notification/acknowledgement relationship, records matched/unmatched/pending
counts and round-trip times, and keeps the higher-level purpose distinct from
the separately modeled opcode-`10`/`23` heartbeat.

## Client opcode `101` HP/MP recovery request

The client packet is exactly 11 bytes:

```text
uint16 opcode = 101
uint8  reserved_prefix = 0
uint8  request_type = 20
uint16 reserved_value = 0
uint16 hp_recovery
uint16 mp_recovery
uint8  reserved_tail = 0
```

The old byte/u32/byte/u16/byte grouping hid the invariant boundary: every
packet starts `00 14 00 00`, ends in zero, and puts exactly one non-zero amount
in the two intervening u16 fields. Stream `126` has 33 HP-`10` and 113 MP-`3`
requests. All 146 match a following authoritative opcode-`41` update in the
same field: 136 apply the requested amount exactly, six HP updates are capped
by max HP, and four occur before a prior HP baseline is known. None remains
pending; maximum response time is `1,543.604` ms.

Stream `92` independently has seven HP-`10` and 66 MP-`5` requests. Every one
of its 73 following opcode-`41` updates applies the exact amount, none remains
pending, and response time is at most `105.781` ms. Stream `114` contains none.
Python and isolated native validation consume and re-emit all 219 records
exactly. Promoting the family to full coverage moves stream `126` to
`26,810/44,290/0/0` and stream `92` to `13,493/21,714/0/0`.

An earlier active local run supplies an independent no-response control. At
that checkpoint it had automatically emitted 178 HP-`10` and 274 MP-`5`
requests alongside the visible recovery cadence. Because that replay did not
serve opcode-`41` recovery updates, all 452 stay explicitly pending without
being treated as malformed. The same cadence was already running before the
controlled keypad-zero/action-`52` input; neither the packets nor the blue
recovery number are evidence for that still-unnamed action.

The opt-in `--reactive-client-recovery-responses` policy derives current/max HP
and MP from a validated world transcript. For each exact opcode-`101` request
it emits one typed opcode-`41` current-stat update whose value is
`min(maximum, current + requested)`. It cannot share opcode `101` with a
captured-reply rule. Runtime/HTTP telemetry reports source correlation counts,
observed/served/packet totals, the last safe response, and mutable HP/MP state.

A fresh browser-free stream-`114` login validated the generated direction and
cap behavior against the real client. The server served `39/39` requests with
one opcode-`41` response each; the independently folded live transcript has
`38` exact increments, one capped HP `220 -> 222` increment, zero pending
requests, no issues or warnings, and phase `active` on map `101000000`. The HUD
reached HP `222/222`, while heartbeat status remained matched at `42/42`.

The fold emits full `client_recovery_request` observations, HP/MP amount
distributions, authoritative stat-update matches, exact/capped/unverified
amount classes, pending counts, and response timing. A field snapshot clears
old-epoch pending requests.

## Attack actions (`client 50`, `52`, and `54`)

Client opcodes `50` and `52` share this exact prefix:

```text
uint16 opcode = 50 or 52
uint8  local_object_index
uint8  variant
uint32 client_token                 # redacted from safe reports
uint32 control_value                # neutral role
uint8  common_reserved_zero = 0
uint8  common_value_1              # neutral role
uint8  common_value_2              # neutral role
uint8  common_value_3              # neutral role
uint8  common_value_4              # neutral role
uint32 value_1                      # neutral role
uint32 value_2                      # mob object id in extended variants
if variant >> 4 == 1:
  uint8  target_value_1             # neutral role
  uint8  target_value_2             # neutral role
  uint8  target_value_3             # neutral role
  uint8  target_value_4             # neutral role
  int16  position_1_x
  int16  position_1_y
  int16  position_2_x
  int16  position_2_y
  uint16 trailing_value             # neutral role
  repeat (variant & 0x0f):
    uint32 raw_damage
      damage_value = raw_damage & 0x7fffffff
      high_bit_marker = raw_damage >> 31
  uint32 reserved_zero = 0
  int16  final_position_x
  int16  final_position_y
if opcode == 52:
  uint8  terminal_reserved_zero = 0
```

The accepted capture-bounded variants are:

```text
opcode  variant  suffix bytes  total bytes  target in value_2
50      1        0             25           no
50      17       26            51           yes
52      1        1             26           no
52      2        1             26           no
52      17       27            52           yes
52      18       31            56           yes
```

Stream `126` contains 552 opcode-`50` actions (264 variant `1`, 288 variant
`17`) and 130 opcode-`52` actions (16/8/80/26 variants `1/2/17/18`). Stream
`92` contains 128 opcode-`52` actions (15 variant `2`, 113 variant `18`). Every
extended action's `value_2` is a known mob object id. The extended suffix
decomposes exactly into the 14-byte prefix, one damage word per low-nibble hit,
and the opcode-specific tail above. Stream `126` contains 420 damage words with
low-31-bit magnitudes `1..42`, total `6964`, and stream `92` contains 226 with
magnitudes `0..49`, total `4864`. No client damage word in either capture sets
the high bit. The two coordinate pairs and final coordinate pair use signed
little-endian values; the four target bytes and trailing u16 retain neutral
names. Every target tail carries an exact zero u32, and every opcode-`52` form
ends in an exact zero byte.

Opcode `54` is an exact 24-byte member of the same action family:

```text
uint16 opcode = 54
uint32 control_value
uint8  flag_1
uint8  flag_2
uint32 value_1
uint32 value_2
uint32 target_object_id             # offset 16
uint32 tail_value
```

All 120 stream-`126` and 31 stream-`92` opcode-`54` packets carry a known mob
object id at offset 16. This replaces the earlier neutral `value_3`
interpretation. Across stream `126`, targeted opcode-`50`, opcode-`52`, and
opcode-`54` actions are followed by same-mob health or leave traffic often
enough to establish the attack-action family; stream `92` independently
confirms the targeted opcode-`52` shape. All 961 actions consume exactly and
round-trip byte-for-byte.
All three branches now report full structural coverage and pass independent
manifest validation. Promoting all 810 opcode-`50`/`52` actions moves stream
`126` to `69,349/1,751/0/0` and stream `92` to `34,391/816/0/0`; stream `114`
remains `61/15/0/0`.

The fold emits `client_attack_submitted`, aliases the mob target, distinguishes
currently active from previously known targets, and records per-mob damage/hit
totals. Each nonzero opcode-`50`/`52` damage word is queued separately. The
following same-mob opcode-`293` updates consume those hits in order, including
both responses to a two-hit action; terminal hits can instead be cleared by
opcode `280` or a field transition. Stream `126` correlates 399 hit responses
and clears 21 terminal hits. Stream `92` correlates 208, clears 11, and skips
seven zero-damage words. Both finish with zero pending effects. The fold does
not expose client tokens or raw target ids.

## Heartbeat transport (`server 10` -> `client 23`)

The server probe is the exact two-byte opcode with no body. The client response
has one complete fixed layout:

```text
uint16 opcode = 23
uint64 response_value
```

The response value is a neutral wire field, not an echoed challenge: the probe
has no value to echo, and the 380 gameplay samples are all nonzero and unique
without forming a monotonic sequence. Stream `126` contributes 304 responses,
stream `92` contributes 75, and stream `114` contributes one. Every response
matches the oldest pending probe, with no unmatched response or final pending
probe in those three sessions. The fixed layout round-trips and independently
validates at full coverage, moving stream `126` to `69,653/1,447/0/0`, stream
`92` to `34,466/741/0/0`, and stream `114` to `62/14/0/0`.

Safe packet details report only `response_value_present`, probe matching, and
round-trip timing. The current active-world transcript independently folds
343/343 pairs at full coverage with no warnings or pending probe. The running
listener's `GET /api/v1/status` aggregate reports 3,369 probes and 3,369
responses across its completed connections, with none pending; the HTTP model
publishes counters and latency only, never the response values.

## Attack relays (`server 218` and `219`)

Both server families use this capture-bounded envelope:

```text
uint16 opcode = 218 or 219
uint32 player_object_id             # aliased in safe reports
uint8  packed_counts

target_count = packed_counts >> 4
hit_count    = packed_counts & 0x0f

uint8  relay_tag
uint8  skill_level                  # zero in every captured opcode-218
if opcode == 219 and skill_level != 0:
  uint32 skill_id
uint8  unknown_value                # zero in both sustained captures
uint8  display
uint8  facing_flags                 # captured 0 or 0x80
uint8  attack_speed
if opcode == 218 and this is the short form:
  # metadata ends here; target must be the all-zero placeholder below
else:
  uint8  mastery
  if opcode == 218:
    uint32 auxiliary_value          # zero in every captured full form
  else:
    uint32 projectile_id
repeat target_count:
  uint32 mob_object_id              # aliased; zero in five 218 placeholders
  uint8  hit_action                 # 6 for every nonzero captured target
  repeat hit_count:
    uint32 raw_damage
      damage_value = raw_damage & 0x7fffffff
      high_bit_marker = raw_damage >> 31
if opcode == 219:
  int16 position_x
  int16 position_y
```

Opcode `218` has observed total lengths `18`, `22`, and `27`; opcode `219` has
lengths `22`, `26`, `31`, `35`, `39`, `44`, `53`, and `62`. Stream `126`
contains 41 opcode-`218` and 99 opcode-`219` relays. Stream `92` contains one
and 42. Every outer player object id is observed somewhere in the
same capture. The nibble split is supported by the manifest's packed
attack-count prefix and by body-length scaling. Given those counts, every body
decomposes exactly into the typed attack metadata, repeated target records, and
the opcode-`219` signed position. The codec now stores those components
directly as typed metadata and target records; it no longer retains an opaque
relay body.

All 42 close-range relays share the same typed six-byte metadata prefix. Stream
`126` has 36 full forms and five short forms; stream `92` adds one full form.
Every skill level and unknown byte is zero. Full forms append mastery `0` and
auxiliary u32 `0`. Each short form has packed counts `0x11` and exactly one
target record whose object id, hit action, and damage word are all zero. The
decoder treats that as a distinct capture-backed placeholder shape and rejects
a six-byte prefix paired with any nonzero or differently counted target. Stream
`126` observes relay tags `8`/`16`, displays `5`, `6`, `7`, `9`, `11`, `16`,
and `17`, facing flags `0`/`0x80`, and speeds `4`/`6`; stream `92` adds relay
tag `14` with display `17`, facing `0x80`, and speed `6`.

All 141 ranged relays obey the conditional skill-id rule: the prefix is 11
bytes when `skill_level == 0` and 15 bytes otherwise. Stream `126` contains 51
basic attacks, 45 level-8 skill `4001344` attacks, and three level-1 skill
`3001005` attacks. Its projectiles are `2060000` (54) and `2070000` (45).
Stream `92` independently contributes skill ids `3001005`, `3101005`, and
`4001344`, with projectile ids `2060000`, `2070009`, and `2070015`. These
values are emitted as numeric protocol fields; item/skill names are not inferred
by the decoder.

The final four bytes decode as two plausible signed field coordinates. All 99
stream-`126` ranged relays and 30 of 42 stream-`92` relays have an actor whose
last movement position was already observed. The fold records the packet
position and its delta from that prior position; common vertical differences
cluster around `-22..-28`, while larger differences coincide with stale remote
movement state. This establishes the coordinate shape and supports an attack-
position interpretation without treating that position as an authoritative
movement update.

Stream `126` has 123 target records and 166 damage words. Of those records,
118 name known mobs and use hit action `6`; five short opcode-`218` records are
all-zero placeholders. Low-31-bit damage magnitudes range from `0` to `80`,
and 12 raw words set the high bit. Stream `92` has 71 target records, all known
mobs with hit action `6`, and 88 damage words ranging from `1` to `366`; 20 set
the high bit. Thus all 194 target records and 254 damage words across the two
sustained captures consume exactly and re-encode as part of their relay.

The fold emits `server_attack_relay_received`, aliases the actor, records the
packed target/hit distributions, aliases each nonzero mob, and reports damage
magnitudes plus a neutral high-bit marker. Active mob entities accumulate the
observed relay hit/damage totals without replacing the authoritative opcode-
`293` health percentage. Raw ids remain hidden. The neutral relay-tag/unknown/
auxiliary/high-bit names do not obscure any bytes or prevent full structural
coverage. Promoting all 183 relays moves stream `126` to
`68,667/2,433/0/0` and stream `92` to `34,263/944/0/0`; stream `114` remains
`61/15/0/0`. An active local transcript also accepted one typed opcode-`218`
and one typed opcode-`219` packet at full coverage with zero unknown or invalid
observations. These captures validate action-to-health/leave correlations and
damage array boundaries. Client-side max HP now predicts 364/370 testable
percentage
transitions exactly and bounds the remaining six to a one-HP difference.
Relay-tag/unknown/auxiliary roles, the damage high bit, client target
prefix/tail fields, and the cause of those delayed one-HP differences remain
unresolved. The custom server therefore does not yet generate or replay
attacks.

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

The two repository-root PCAP references are deliberately kept outside Git:

```text
./111.pcapng       successful login (stream 83), long gameplay (92), short field (114)
./1-10FS.pcapng    level 1 through 10 gameplay (stream 126)
```

`1-10FS.pcapng` stream `126` is a 55-minute protocol-`300` world session from
`96.62.155.120:12324`. The transport prefixes 14 server bytes and 28 client
bytes before the ordinary 33-byte Maple greeting; PCAP normalization locates
the greeting, discards only those preludes, and records both byte counts in
transcript metadata. The resulting session contains 71,100 decrypted frames
(31,345 client and 39,755 server), one marker-`26` initial snapshot, 35 later
field snapshots, 841 stat updates, 256 inventory change sets, 78 direct NPC
spawns, 36 NPC lifecycle spawns,
436 drop-spawn packets, 203 pickup requests, eight skill-level requests, nine
skill-record updates, and nine skill-record acknowledgements.

All 203 pickup requests resolve to a known active drop and match their field
epoch after the marker-`26` initial snapshot is folded. The 197 opcode-`185`
requests also target a final mode-`0` spawn whose two owner words equal the
initial player id. The four mode-`2` field-load mesos records are exact 30-byte
shapes. Opcode `303` NPC-state movement paths and client opcode `158` mode `0`
keymap changes are now fully typed. Strict validation succeeds
across all 71,100 frames with 53,785
full, 17,315 partial, zero unknown, and zero invalid packet
observations. Stream `92` independently reaches 26,266 full, 8,941 partial,
zero unknown, and zero invalid; stream `114` reaches 57/19/0/0. The long fold
reaches level `10` and reports no unknown inventory-slot
modifications; its one remaining warning is a cross-packet state correlation:
an aggregate warning for six delayed combat predictions that differ by one
HP. That warning also records the
`{-1: 1, +1: 5}` inferred damage-delta histogram and that all six lack an
intervening modeled relay hit.

## Mob spawn and controller assignment (`server 279` / `281`)

Both spawn-bearing opcodes delegate to the same client parser. Opcode `279`
places the object id directly before the spawn body; opcode `281` places a
one-byte controller level before the object id and omits the spawn body when
that level is zero. The complete shared body is:

```text
uint8  spawn_marker = 1
uint32 template_id
uint32 temporary_status_mask[4]
if temporary_status_mask[3] & 0x00000080:
    int16 value
    int32 source_skill_id
    int16 duration_units
int32  status_control_value
bool   status_flag_1
bool   status_flag_2
int16  x
int16  y
uint8  stance
uint16 foothold_id
uint16 origin_foothold_id
int8   appear_type
uint8  team
int32  effect_item_id
```

The conditional status tuple accounts for the exact `42`/`50`-byte shared
body and `48`/`56`-byte opcode-`279` packet widths. A live GDB trace against
the pinned client injected one captured packet of each width and observed the
optional reads as exactly `i16 + i32 + i16`, followed in both branches by
`i32 + bool + bool`. The suffix trace and disassembly identify the former
signed-`i16` “spawn effect” as separate signed appear-type and team bytes, then
one client-read `i32` effect item id. All 1,884 spawn-bearing packets across
reference streams `92` and `126` parse and re-emit exactly; the mask/control
and optional tuple retain neutral behavioral names.

The independent manifest validator consumes every opcode-`279`/`281` packet
in both corpora without a failure. Promoting the 1,884 spawn-bearing records
from partial to full coverage moves stream `126` to `68,527/2,573/0/0` and
stream `92` to `34,220/987/0/0`; stream `114` remains `61/15/0/0`. The same
live trace transcript folds injected common and extended opcode-`279` packets
at full coverage and remains valid with no unknown observations.

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

- Gameplay framing is complete across reference gameplay streams `92`, `114`,
  and `126`; all packets are typed or capture-bounded and none remain unknown
  or invalid.
- The successful account shape is decoded, but the regional opcode mapping
  differs (`0` in the successful capture, `1` for the local handler), and
  several fields still have unknown semantics.
- Successful character-list records are typed and losslessly re-emitted. The
  seven appearance-style values, entry code, six-byte trailer roles, ranked
  branch semantics, and non-success response bodies remain neutrally named or
  opaque pending independent variants.
- The 19-byte handoff and large initial world snapshot are structurally
  validated; equipment-specific metadata, keyed-property roles, parts of the
  fixed trailers, the marker-`26` seven-byte variant header, and several
  one-time field bootstrap opcodes remain semantically neutral.
- The purpose and required state for the TLS `5050` connection remain unknown.
- The exact semantics of captured opcode-`0` result values other than the
  observed policy result `2` remain unknown.

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

Opcode `13` has four bounded envelopes in the observed sessions:

```text
acknowledgment (3 bytes)
uint16 opcode = 13
uint8  result

fixed client type-1 envelope (11 bytes)
uint16 opcode = 13
uint8  message_type = 1
byte[8] opaque body

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

## World opcode `43` neutral envelopes

Client and server opcode `43` use separate capture-bounded envelopes. The
leading client byte is named only as a sequence: values `1..12` occur once in
stream `92`, while stream `126` contains `1..29` and `32..35`. Identical values
do not select a stable layout across the captures, so the decoder branches on
the complete packet shape rather than inventing discriminator semantics:

```text
client identified-text envelope:
  uint16 opcode = 43
  uint8 sequence
  uint32 opaque_identifier          # redacted
  uint16 text_code_units
  utf16le[text_code_units] opaque_text
  uint8 zero_terminator = 0
  byte[6] opaque_tail

client compact envelope:
  uint16 opcode = 43
  uint8 sequence
  byte[9] opaque_body

server envelope:
  uint16 opcode = 43
  uint8 message_type
  byte[16] opaque_body
```

Stream `92` contributes nine identified-text clients, three compact clients,
and three server packets; all server message types are zero. Stream `126`
contributes 33 identified-text clients. Text lengths are `0:3`, `4:5`, `5:9`,
`6:27`, and `8:1` code units across client packets; zero represents the compact
form, not captured text. All 48 packets round-trip exactly as partial semantic
observations. Safe state/events expose only sequence, variant, text length,
message type, and opaque-byte counts; the identifier, text, and byte bodies are
never emitted.

The automatic shape manifest now uses two competing client candidates rather
than the earlier stream-`92` switch, which incorrectly treated sequence values
`4`, `8`, and `12` as compact-only. Exact packet length makes the candidates
unambiguous, and native validation consumes all 45 client packets without a
short read, trailing byte, unsupported variant, or ambiguity.

An exact captured 19-byte server envelope was injected into an already active
browser-free custom-server session. The fold added one partial opcode-`43`
event, core phase/map/player/inventory/progression state stayed unchanged,
matched heartbeats advanced from 173 to 176, and the connection remained
active with zero failures. No client opcode-`43` response appeared, so this
proves bounded non-stalling acceptance only—not security, status, or
request/response semantics.

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

Forty-three packets have prior opcode-`244`/`247` tutorial/UI traffic, with 29
within 30 seconds and a median gap of 15.285 seconds. That supports a possible
UI relationship but is too indirect to call the packet an acknowledgement.
The fold therefore emits neutral `client_opcode_114_submitted` events and
publishes only control and text-length distributions plus a redacted-value
count. Python and native manifest validators consume and re-emit all 44 packets
without ambiguity or failure. Because the family is client-originated and the
active idle level-12 client emits none, no server-to-client live replay or
client-visible effect is claimed.

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
byte[56] opaque_ticket
```

The first `uint32` after the opcode was previously mislabeled as the character
id. Cross-checking it against the large opcode-`157` snapshot in `111.pcapng`
streams `92` and `114`, and against `1-10FS.pcapng` stream `126`, proves that
the second word is the character id. The fold validates that equality while
redacting both the identifier and ticket bytes from normal reports.

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
records additionally expose a `uint16` quantity. Equipment-specific metadata
is retained as bounded raw record bytes until its conditional fields are named.

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

The later 95-byte opcode-`157` variant is `CompactFieldTransition`; it remains
fully decoded and updates transition sequence, map, portal, HP, and server
clock without replacing the initial player-stat model.

## Remote-player field lifecycle (`189`, `190`)

The pinned version-300 IL2CPP opcode-`189` handler reads a u32 object id, a u8
level, and a counted UTF-16 name before delegating the remaining player body.
The adjacent opcode-`190` handler reads exactly one u32 object id and removes
that player:

```text
opcode 189:
    uint16 opcode
    uint32 object_id                 # redacted
    uint8 level
    uint16 name_code_units
    utf16le[name_code_units] name    # retained only for re-emission
    byte[] opaque_player_body

opcode 190:
    uint16 opcode
    uint32 object_id                 # redacted
```

Streams `92/114/126` contain `58/4/52` entries and `29/0/10` leaves. All 153
packets round-trip exactly. The entry prefixes are structurally bounded and
their 36,450 remaining body bytes stay explicit, so the 114 entries are
partial; the 39 exact removals are full. Every removal references a player
introduced in the same field epoch. More importantly, all 563 opcode-`202`
player-movement broadcasts and all 652 server opcode-`217` life-movement
broadcasts now correlate with a prior entry instead of creating players from
movement alone.

The fold emits `remote_player_entered_field` and
`remote_player_left_field`, clears active players at field transitions, and
preserves entry metadata when later movement supplies a position. Safe state
exposes only an alias, level, name-code-unit count, position when known, and
opaque-byte count. It never emits the captured object id or name.

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

## Positioned visual effects (`320`, `322`, `323`)

The pinned version-300 handlers for opcodes `320`, `322`, and `323` live in the
same dictionary/list-backed manager. Each reads a primary int32 key plus signed
16-bit coordinates. The remaining value roles stay neutral:

```text
opcode 320:
    uint16 opcode
    int32 primary_value              # aliased/redacted
    uint8 control_value
    int16 x
    int16 y
    int16 numeric_value
    uint8 secondary_control_value
    uint8 trailing_value

opcode 322:
    uint16 opcode
    int32 primary_value              # aliased/redacted
    int32 numeric_value
    uint8 control_value
    int16 x
    int16 y
    uint8 trailing_value

opcode 323:
    uint16 opcode
    int32 primary_value              # aliased/redacted
    uint8 control_value
    int16 x
    int16 y
```

Stream `126` contains 12/50/20 packets respectively, all exactly 15/16/11
bytes and all exact full-coverage round trips. The field-scoped fold creates 36
aliased effect entities and applies 46 updates. Every opcode-`323` record
references an entity already observed in its current field epoch; field
snapshots clear the active effect map. State and `positioned_effect_observed`
events expose only aliases, coordinates, opcode/control distributions, and
whether a record created or updated the alias. Raw primary values are omitted.

A live exact opcode-`322` record at captured coordinates `(2609,-372)` was
accepted without a visible in-view change. A second typed record changed only
the i16 coordinates to the folded local-player position `(633,-2677)`. At 100
ms the client showed a transient blue `10` directly above the player; it was
gone at one second, HP remained `50/222`, and the connection stayed active.
The transcript folds the pair exactly as `effect:1` creation then update,
ending at `(633,-2677)` with zero unknown updates and 131/131 matched heartbeat
pairs. This validates the coordinate/effect interpretation, but not the
meaning of the displayed number or any neutral numeric/control field.

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

## Neutral server records (`69`, `93`, `94`, `137`, `148`, `201`, `205`, `276`, `379`)

These nine opcodes recur with capture-bounded layouts in the gameplay
streams. Their semantic roles remain neutral, and fields that may carry a
character/session value are redacted from safe output:

```text
opcode 69:
    uint16 opcode
    uint32 header_value
    byte[263] opaque_table

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
    int16 first_value               # redacted
    int32 second_value              # redacted
    int32 third_value               # redacted
    byte[72] opaque_tail

opcode 148:
    uint16 opcode
    uint8 variant
    variant 9: int32 record_count; byte[] records_blob when nonzero
    variant 10: no body
    variant 12 or 13: int32 primary_value; int32 secondary_value

opcode 201:
    uint16 opcode
    uint32 primary_value             # redacted
    uint32 secondary_value           # redacted
    uint8 flag_a
    uint8 flag_b
    byte[22] opaque_tail

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

Streams `92/114/126` contribute `52/6/123` records respectively. By opcode,
the combined counts are `69:50`, `93:7`, `94:3`, `137:3`, `148:23`, `201:46`,
`205:42`, `276:2`, and `379:5`. Every
opcode-`69` header is `7` and all 263 retained bytes are zero in these
captures. Every opcode-`93` packet counts four u32 values. Opcode `205` is
fully bounded, as is the counted opcode-`93` vector. The generated handler dump
independently supplies the exact direct-read sequences for opcodes `94`, `137`,
`276`, and `379`. Opcode `137` directly reads `i16/i32/i32`; the two stream-`92`
packets and one stream-`126` packet are all 84 bytes, leaving the same 72-byte
capture-bounded tail after that prefix. Both opcode-`276` packets are the
three-byte `0x05` true form, both opcode-`379` short packets use variant `35`,
and its three
four-datetime packets use variant `36`. Opcode `148` contributes one empty
variant-`9`, nine empty variant-`10`, nine variant-`12`, three variant-`13`, and
one nonempty variant-`9` packet. The current delegated IL2CPP record mask is
`0x9`; the legacy nonempty body does not consume under that current parser and
therefore retains 1,632 record bytes as one explicit partial observation.
Together the family provides 81 full and 100 partial observations with 16,010
opaque bytes rather than inventing suffix or record semantics.

The gamestate fold emits `neutral_server_record_received`, tracks packets by
opcode, typed-value counts, and opaque-byte totals, and exposes only redacted
safe details. All 181 packets reparse and round-trip byte-for-byte.

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

Client opcode `75` is an exact opcode-only marker:

```text
uint16 opcode = 75
```

It occurs once during the initial `field_loading` phase in `111.pcapng` stream
`92` and `1-10FS.pcapng` stream `126`. The browser-free local-Wine transcript
independently emits the same marker at field epoch `1`. No stronger semantic
role is assigned.

Both terminating `111.pcapng` world sessions share this client/server sequence:

```text
uint16 opcode = 241                    # empty world-exit request

uint16 opcode = 45 or 46               # stream 114 or 92
uint32 value                            # redacted status value

uint16 opcode = 9
byte[7] opaque_reason                   # existing terminal server packet
```

The request is emitted from `active`. Status opcode `46` follows by 64.396 ms
in stream `92`; status opcode `45` follows by 66.699 ms in stream `114`. The
final server packet follows the request by 165.073 and 167.004 ms respectively.
The fold enters `exit_requested`, reports the status value only as redacted,
then enters `terminated` and records FIFO correlation plus round-trip timing on
opcode `9`. Exact packet observations promote all three client boundaries to
full coverage. Stream `92` reaches `13,417/21,782/8/0`, stream `114` reaches
`54/22/0/0`, and stream `126` reaches `26,661/44,381/58/0`.

The current local client's game-menu confirmation did not emit opcode `241`,
so a terminal injection was intentionally not attempted. This leaves the
captured transaction exact and independently repeated, but its live UI trigger
unproven in the current replay state.

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

## Generated `u32` envelopes (`228`, `230`, `231`, `232`, `234`, `235`)

These six opcodes are registered on the same generated handler class. Each
handler makes exactly one direct `PacketReader` call, a `u32`, then invokes its
local state method without another reader call. The captures contain additional
bytes after that value, so the honest boundary is a typed leading value plus an
ignored, capture-bounded tail:

```text
uint16 opcode
uint32 primary_value
bytes  opaque_tail
```

Only these observed opcode/tail-length combinations are accepted:

| Opcode | Tail bytes | Packet bytes | Occurrences |
| ---: | ---: | ---: | ---: |
| `228` | `4` | `10` | `1` in stream `92` |
| `230` | `1` | `7` | `1` in stream `92`, `1` in stream `126` |
| `230` | `7` | `13` | `1` in stream `126` |
| `231` | `20` | `26` | `1` in stream `126` |
| `232` | `16` | `22` | `1` in stream `92` |
| `234` | `3` | `9` | `1` in stream `92`, `2` in stream `126` |
| `235` | `6` | `12` | `1` in stream `92`, `2` in stream `126` |

The shared Python envelope consumes and re-emits all 12 packets exactly.
Safe state and `neutral_server_record_received` events publish only opcode,
typed-value count, and opaque-tail length; the `u32` and tail bytes are
redacted. Observations remain partial because the client handler does not give
the tail bytes a readable role. Seven semantic manifest declarations replace
the five matching `111` opaque pins and add the two widths found only in
`1-10FS`; targeted native validation passes `12/12` with no unsupported or
consumption failures.

The family moves seven long-stream and five stream-`92` observations from
unknown to partial. Strict totals become `26,659/44,380/61/0` for stream `126`,
`13,410/21,760/37/0` for stream `92`, and `49/20/7/0` for stream `114`. Live
replay is deferred: the leading value may identify session-local state, and
replaying an untyped ignored tail across sessions would not be a bounded test.

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
to learned skill `2001002`. Other selector meanings, and all opcode-`156`
field meanings, remain neutral; no security meaning is inferred.

All four forms now have full shape coverage and exact typed round trips. The
fold records opcode/variant counts, 89 selector/value entries per expanded
opcode `385`, three typed int32 values per expanded opcode `156`, zero opaque
bytes, field epoch, and `variable_server_record_received` events. Safe output
retains only text length, flag, value/entry counts, and never the opcode-`156`
text or raw values. Expanded opcode `385` additionally updates the current
keyboard selector distribution and skill-binding map, validates bound skill ids
against initial progression, exposes the proven Left Ctrl binding, and emits a
`keyboard_bindings_loaded` event.

`--generate-variable-server-records` re-emits every bounded observation at its
original frame index after length/reparse/uniqueness/conflict validation.
`protocol.variable_server_record_emitter` exposes only frame index, opcode,
variant, text length, flag, value/entry counts, field epoch, patch count, and
the predicted unchanged player/phase state.

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

The fold gives all three packets full structural coverage, emits
`skill_level_change_requested`, `skill_records_updated`, and
`skill_record_update_acknowledged`, and reports request/ack correlations and
timing. The opcode-`46` trailing byte is deliberately not interpreted as skill
points: surrounding opcode-`41` stat updates independently change that stat.

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
and emits `client_skill_use_submitted`. It does not yet infer a required server
response or assign a meaning to `trailing_value` beyond the observed zero.

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
    bytes opaque_tail               # observed lengths 28, 29, or 36

variant 4:
    bytes opaque_body               # three bytes in both samples

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
non-pickup packets parse to their exact ends and round-trip byte-for-byte: 243
move from unknown to full coverage and 260 move from unknown to partial. The
partial records retain 7,607 opaque bytes. The fold emits
`server_opcode_49_received` and tracks variant, neutral shape, text-code-unit,
and opaque-byte distributions. Text is retained only in the typed object for
exact re-emission and is omitted from safe JSON, events, text reports, and
HTTP-derived analysis.

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
    bytes opaque_tail                  # observed lengths 4 or 117
```

Variant `3` always has its exact three-byte suffix. Variant `4` has 41 short
false forms and ten true forms with a terminated string. All 22 variant-`5`
packets use control pattern `03 0a 0a 02` and consume exactly. Variant `8`
retains 278 opaque bytes across 13 packets and therefore remains partial;
variants `3`, `4`, and `5` have full structural coverage.

Stream `92` contributes variants `3/4/5/8 = 152/13/9/6`, stream `114`
contributes `1/1/0/0`, and level-1-through-10 stream `126` contributes
`276/37/13/7`. Every packet reparses and round-trips exactly: 502 observations
move from unknown to full and 13 move to partial. The fold emits
`server_opcode_77_received`, tracks variant/control/value and text-length
distributions plus opaque-byte totals, and never copies any of the three text
fields into safe JSON, text reports, events, or HTTP status. The family keeps a
neutral name because the four variants span multiple visible-message forms;
frequency and readable strings alone do not establish one gameplay role.

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

The state-driven quantity emitter requires an existing stack item and sends a
single operation-`1` change. A real stream-`114` client accepted generated
plaintext `2700000101020f000100`, changing Use slot `15`, item template
`2000000`, from `27` to `1`. The inventory UI displayed quantity `1`; the
recorded transcript emitted the same previous/current event, preserved all
item counts and player state, remained active, and matched all 18 generated
heartbeats. The neutral update flag is deliberately not assigned a role.

## Consumable use (`client 80` -> `server 39`, `server 41`)

The capture-validated request is exactly 12 bytes:

```text
uint16 opcode = 80
uint32 client_tick                    # role beyond ordering remains neutral
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
requests at capture end. Effects for other item templates and the semantic role
of `client_tick` remain intentionally unknown.

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
rewrote both final mode-`2` owner words to the initial player id, and a second
probe sent a captured-shaped mode-`1`/mode-`0` pair at the player's position.
The client remained healthy and direct input was verified, but neither probe
emitted opcode `185`. Runtime status therefore reports only that the owner
fields match the initial player and predicts that additional client conditions
are required; it does not claim that the rewritten drop is pickup-eligible.

## Item pickup (`client 185` -> `server 39/41`, `server 49`, `server 312`)

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

For state-driven replay, a separate validated evidence transcript supplies the
deterministic item effect. Stream `92` proves template `4000004` four times as
an Etc quantity delta of one and an item gain notice quantity of one. The
reactive policy therefore accepts only a known active item drop, the current
field epoch, a deterministic captured template effect, and exactly one
existing stack with capacity. It emits opcodes `39`, `49`, and `312` in that
order and removes the drop from mutable state. Mesos pickups, special results,
new-slot insertion, ambiguous stacks, and unknown templates remain rejected.
Runtime annotations record pickup request, completed response, or rejection;
an exact rejection consumes its matching pending request without disconnecting
the client. An annotation without a matching observed request is invalid.

## Character stat deltas (`server 41`)

The capture-validated prefix and conditional-value grammar is:

```text
uint16 opcode = 41
uint8  request_flag                  # observed 0 or 1; role remains neutral
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
byte[] bounded_tail
```

Conditional values occur in ascending mask-bit order. Every nonzero-mask
packet ends with one zero byte. A zero mask has either a single-zero tail (one
packet) or a two-byte `01 xx` tail; these variants remain semantic unknowns
rather than being assigned a guessed result meaning.

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

The state-driven replay emitter uses request flag `0`, current-HP mask
`0x00000400`, a bounded HP value, and the one-zero tail. A real stream-`114`
client accepted generated plaintext `29000000040000010000`: its HUD changed
from `50/222` to `1/222`, the observed transcript folded the event as
`previous:50 -> current:1`, MP/EXP/map/inventory/progression stayed unchanged,
and heartbeat responses continued. This validates the predicted effect without
assigning semantics to the flag or tail marker.

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
byte[19] control_prefix
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
submissions. The 19 control bytes remain deliberately opaque.

Server opcode `282` broadcasts movement for one field-local mob without the
client sequence or nine-byte trailer:

```text
uint16 opcode = 282
uint32 mob_object_id
byte[7] control_prefix
int16  reference_x
int16  reference_y
uint8  command_count                 # nonzero
repeat command_count: mob_movement_command
```

Stream `92` contains 5,284 broadcasts and 18,874 commands; every referenced
object is active and every packet re-encodes exactly. Control prefix
`0000ff00000000` occurs 5,230 times. Of those, 1,509 packets use the exact
one-command stationary placement shape: the reference equals the absolute
command position, velocity is zero, and duration is 1,080 ms. Stances `2`,
`4`, and `5` are all captured; stance `4` has 1,055 exact examples.

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
The flag is exactly whether control-prefix byte zero is nonzero, both auxiliary
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
the control-byte predicate, and reference/start/end coordinates, but omit the
runtime object id. A fresh browser-free run produced 13 alternating
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
type 3: byte[5] bounded semantic unknown
type 5: same 13-byte fields as type 0
```

Stream `92` contains 531 client submissions with 3,606 commands
(`0:3526, 1:53, 3:20, 5:7`) and 113 server broadcasts with 675 commands
(`0:646, 1:18, 3:4, 5:7`). All 644 packets and 4,281 commands round-trip
byte-for-byte. All client control values are zero in that stream; the two
stream-`114` broadcasts demonstrate values zero and one, so the field remains
neutrally named. The fold uses the client trailer endpoint for local position
and the last absolute command for each observed remote player, emitting typed
events for both directions. Stream `114` ends at local path endpoint
`(633,-2677)` with two identifier-safe remote-player aliases.

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
  byte[command_payload_length(command_type)] opaque_payload
uint8  tail_type
byte[tail_payload_length(tail_type)] opaque_tail_state
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
repeat command_count: command_type + fixed opaque payload
```

Capture-derived command payload sizes, excluding the one-byte tag, are exact:

```text
type:    0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22
bytes:  13  7  7  9  9 13  7  9  9  9  1  9  7  7  9 15  7 13  7  7  3  3  7
```

Client tail types `17`, `18`, `21`, and `24` carry `8`, `8`, `10`, and `11`
opaque bytes respectively. Stream `92` validates 963 client packets with 3,869
commands and 305 server packets with 1,441 commands; it observes every tail
type and command tags `0/1/2/3/4/10/11/14/15`. Stream `126` validates another
2,585 client packets with 8,189 commands and 347 server packets with 1,399
commands. In the long corpus, 344 server object ids name players already active
when the packet arrives and three arrive before player discovery. The fold
therefore records that correlation without using the opaque command bodies to
change coordinates. It emits redacted submission/broadcast events and tracks
command, tail-type, and tail-marker distributions. The shape is exact, but the
command fields and control/tail roles remain semantically partial.

## Client opcode `217` neutral record envelope

The client-to-server opcode is a separate family from the server-to-client
life-movement opcode `217` above. It has two capture-bounded variants:

```text
compact:
  uint16 opcode = 217
  byte[6] opaque_body

record set:
  uint16 opcode = 217
  byte[10] opaque_prefix
  uint8 record_count                 # 1..255
  uint8 record_format                # observed 0 or 2
  repeat record_count:
    byte[14] record                  # format 0
    byte[11] record                  # format 2
  byte[8] opaque_trailer
```

Stream `126` contains 937 instances. Of these, 345 are compact and 592 are
record sets. Format `0` contributes 535 sets and 1,539 records; format `2`
contributes 57 sets and 114 records. Observed record counts per packet are:

```text
count:    1   2  3  4  5  6  7  8  9 10 11 12 13 14
packets: 332  71 21 18 37 40 27 22 11  1  4  5  1  2
```

Every packet parses to its exact end and re-encodes byte-for-byte. The fold
reports compact/set totals plus format and count distributions without
exposing opaque contents. No record-aligned little-endian 32-bit value matched
an active mob object id, and the next server opcode `219` was always more than
one second later. Those negative correlations are insufficient to identify an
attack or any other effect. The custom server therefore validates this family
but does not generate or replay it.

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

## Client opcode `101` neutral numeric record

The client packet is exactly 11 bytes:

```text
uint16 opcode = 101
uint8  header_value
uint32 primary_value
uint8  flag_value
uint16 secondary_value
uint8  tail_value
```

Stream `126` contains 146 records. Header, flag, and tail are zero throughout;
`(primary_value, secondary_value)` is `(20,3)` in 113 packets and
`(0x0a000014,0)` in 33. Stream `92` contains another 73 records: `(20,5)` in
66 and the same alternate `(0x0a000014,0)` in seven. Stream `114` contains
none. All 219 packets consume exactly and re-encode byte-for-byte.

The shape manifest tentatively labeled the 32-bit field `client_tick`, but its
two discrete, non-monotonic values do not support that semantic interpretation.
The codec and fold therefore preserve the exact numeric boundaries under
neutral names, emit value distributions and events, and classify the family as
partial semantic coverage.

## Attack actions (`client 50`, `52`, and `54`)

Client opcodes `50` and `52` share this exact prefix:

```text
uint16 opcode = 50 or 52
uint8  local_object_index
uint8  variant
uint32 client_token                 # redacted from safe reports
uint32 control_value                # neutral role
byte[5] opaque_common_state
uint32 value_1                      # neutral role
uint32 value_2                      # mob object id in extended variants
if variant >> 4 == 1:
  byte[14] opaque_target_prefix
  repeat (variant & 0x0f):
    uint32 raw_damage
      damage_value = raw_damage & 0x7fffffff
      high_bit_marker = raw_damage >> 31
  byte[8] opaque_target_tail        # opcode 50
  byte[9] opaque_target_tail        # opcode 52
else:
  byte[variant_suffix_length] opaque_suffix
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
the high bit. Prefix and tail field roles remain neutral.

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

The fold emits `client_attack_submitted`, aliases the mob target, distinguishes
currently active from previously known targets, and records per-mob damage/hit
totals. Each nonzero opcode-`50`/`52` damage word is queued separately. The
following same-mob opcode-`293` updates consume those hits in order, including
both responses to a two-hit action; terminal hits can instead be cleared by
opcode `280` or a field transition. Stream `126` correlates 399 hit responses
and clears 21 terminal hits. Stream `92` correlates 208, clears 11, and skips
seven zero-damage words. Both finish with zero pending effects. The fold does
not expose client tokens or raw target ids.

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
the opcode-`219` signed position.

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
`293` health percentage. Raw ids and raw body bytes remain hidden. These
captures validate action-to-health/leave correlations and damage array
boundaries. Client-side max HP now predicts 364/370 testable percentage
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
436 drop-spawn packets, 197 pickup requests, eight skill-level requests, nine
skill-record updates, and nine skill-record acknowledgements.

All 197 pickup requests resolve to a known active drop, match their field
epoch after the marker-`26` initial snapshot is folded, and target a final
mode-`0` spawn whose two owner words equal the initial player id. The four
mode-`2` field-load mesos records are exact 30-byte shapes. Variable opcode
`303` NPC-state tails and the client opcode-`158` stage-`0` variant (neutral
word `1` plus a nine-byte tail) are preserved and reported as partial semantic
coverage. Strict validation succeeds across all 71,100 frames with 26,661
full, 44,381 partial, 58 unknown-but-lossless, and zero invalid packet
observations. Stream `92` independently reaches 13,417 full, 21,782 partial,
8 unknown, and zero invalid; stream `114` reaches 54/22/0/0. The long fold
reaches level `10` and reports no unknown inventory-slot
modifications; its seven remaining warnings are cross-packet state
correlations: six pickup-effect mismatches plus one aggregate warning for six
delayed combat predictions that differ by one HP. That warning also records the
`{-1: 1, +1: 5}` inferred damage-delta histogram and that all six lack an
intervening modeled relay hit.

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

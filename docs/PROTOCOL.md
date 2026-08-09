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
contains 446 fixed type-`1` envelopes, 104 type-`6` length-prefixed envelopes,
and five type-`13` length-prefixed envelopes. Stream `126` contains 970 fixed
type-`1` envelopes. Every packet consumes exactly and round-trips byte-for-byte;
the fold emits type and opaque-byte counts without exposing any body. The
payload meanings remain partial rather than being labeled as security traffic.

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
537-byte inventory region round-trips; its following 172-byte progression
region remains opaque because it does not use the longer marker-`23`
progression/trailer grammar. Reports distinguish this with
`snapshot_marker: 26` and `progression_typed: false`.

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

The later 95-byte opcode-`157` variant is `CompactFieldTransition`; it remains
fully decoded and updates transition sequence, map, portal, HP, and server
clock without replacing the initial player-stat model.

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
extended action's `value_2` is a known mob object id. The opaque extended
suffix begins with byte `06` in these captures, but its inner fields are not
yet assigned roles.

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
currently active from previously known targets, and retains only packet counts,
opcode/variant shapes, and identifier-safe fields in normal reports. It does
not expose client tokens or raw target ids.

## Attack relays (`server 218` and `219`)

Both server families use this capture-bounded envelope:

```text
uint16 opcode = 218 or 219
uint32 player_object_id             # aliased in safe reports
uint8  packed_counts

target_count = packed_counts >> 4
hit_count    = packed_counts & 0x0f

byte[prefix_length] opaque_prefix   # 218: 6/11; 219: 11/15
repeat target_count:
  uint32 mob_object_id              # aliased; zero in five 218 placeholders
  uint8  hit_action                 # 6 for every nonzero captured target
  repeat hit_count:
    uint32 raw_damage
      damage_value = raw_damage & 0x7fffffff
      high_bit_marker = raw_damage >> 31
byte[4] opaque_tail                 # opcode 219 only
```

Opcode `218` has observed total lengths `18`, `22`, and `27`; opcode `219` has
lengths `22`, `26`, `31`, `35`, `39`, `44`, `53`, and `62`. Stream `126`
contains 41 opcode-`218` and 99 opcode-`219` relays. Stream `92` contains one
and 42. Every prefix object id is a player object id observed somewhere in the
same capture. The nibble split is supported by the manifest's packed
attack-count prefix and by body-length scaling. Given those counts, every body
decomposes exactly into a 6/11-byte opcode-`218` prefix or 11/15-byte opcode-
`219` prefix, repeated target records, and the opcode-`219` four-byte tail.

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
boundaries, but do not establish the varying attack prefixes, opcode-`219`
tail, high-bit meaning, or mob maximum HP needed to predict the next percentage
update. The custom server therefore does not yet generate or replay attacks.

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
field snapshots, 841 stat updates, 256 inventory change sets, 78 NPC spawns,
436 drop-spawn packets, and 197 pickup requests.

All 197 pickup requests resolve to a known active drop, match their field
epoch after the marker-`26` initial snapshot is folded, and target a final
mode-`0` spawn whose two owner words equal the initial player id. The four
mode-`2` field-load mesos records are exact 30-byte shapes. Variable opcode
`303` NPC-state tails and the client opcode-`158` stage-`0` variant (neutral
word `1` plus a nine-byte tail) are preserved and reported as partial semantic
coverage. Strict validation succeeds across all 71,100 frames with 25,597
full, 43,954 partial, 1,549 unknown-but-lossless, and zero invalid packet
observations. Stream `92` independently reaches 12,976 full, 21,604 partial,
627 unknown, and zero invalid; stream `114` remains 16/14/46/0. The long fold
reaches level `10` and reports no unknown inventory-slot
modifications; its 12 remaining warnings are cross-packet state correlations.

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
- The 19-byte handoff and large initial world snapshot are structurally
  validated; equipment-specific metadata, keyed-property roles, parts of the
  fixed trailer, the marker-`26` 172-byte progression region, and several
  one-time field bootstrap opcodes remain semantically neutral.
- The purpose and required state for the TLS `5050` connection remain unknown.
- The exact semantics of captured opcode-`0` result values other than the
  observed policy result `2` remain unknown.

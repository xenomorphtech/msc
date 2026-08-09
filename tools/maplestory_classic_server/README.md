# MapleStory Classic custom-server laboratory

This directory contains the first protocol-compatible server tooling for the
Taiwan/Hong Kong MapleStory Classic Unity client. It is deliberately isolated
from the Albion Phoenix application.

## Confirmed client endpoints

The serialized `GameConfig` and a post-bootstrap packet capture establish:

- login hostname: `tw-login.maplestoryclassic.games.gamania.com`
- login TCP port: `10282`
- observed login address: `35.73.142.21:10282`
- legacy HTTP probe/handoff: `54.238.121.146:58880`
- successful reference login: `43.142.194.25:10282` (`tcp.stream 83`)
- successful reference world: `43.142.194.150:8587` (`tcp.stream 92`)

The sustained world reference (`tcp.stream 92`) lasts about 12.6 minutes and
contains 35,207 decrypted Maple frames: 14,640 client frames and 20,567 server
frames. Login and world sessions use a 33-byte cleartext greeting followed by
encrypted frames whose four-byte headers encode payload length as the XOR of
two little-endian 16-bit words. The observed greeting identifies protocol
version `300`, subversion `300`, and locale `4`.

## Commands

Run commands from this directory:

```sh
python -m maple_server stub \
  --listen-host 0.0.0.0 \
  --listen-port 10282 \
  --transcript-dir captures
```

Proxy the official login endpoint while recording both directions:

```sh
export MAPLE_PROXY_USER='...'
export MAPLE_PROXY_PASSWORD='...'
python -m maple_server capture-proxy \
  --listen-host 0.0.0.0 \
  --listen-port 10282 \
  --upstream-host tw-login.maplestoryclassic.games.gamania.com \
  --upstream-port 10282 \
  --http-proxy-host 127.0.0.1 \
  --http-proxy-port 3128 \
  --transcript-dir captures
```

Replay a captured session:

```sh
python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 10282 \
  --transcript captures/session.jsonl \
  --transcript-dir captures/replay-observed
```

PCAP streams can be consumed directly. The loader uses `tshark` without a
shell, reassembles TCP sequence space, identifies the server from the Maple
handshake, and normalizes segment data to one event per encrypted frame:

```sh
python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 10282 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 83
```

Replay is strict by default: client bytes must match the recorded session.
This is useful for identifying which bytes are stable framing and which are
per-session authentication or cryptographic material. `--no-strict` is
available for exploratory runs. `--transcript-dir` records what the new client
actually sent as well as the replayed server bytes.

Exploratory login work also supports `--server-frame-patch`, reactive
`--reply-on-client-opcode`, ordered `--send-after-transcript` frames, a uniform
`--post-transcript-frame-delay-seconds`, and repeated
`--post-transcript-gap-delay-seconds` values. Gap-specific delays apply to the
combined queued-reactive-reply and appended-frame sequence; missing values
fall back to the uniform delay.

`--drop-server-frame INDEX` omits an encrypted captured frame. The replay first
decrypts the original sequence with the captured IVs, then re-encrypts every
emitted frame with the shortened IV sequence. This makes it safe to withhold a
captured response and send its plaintext later from a reactive opcode rule.

The observed completed world captures end with a nine-byte server opcode-`9`
termination envelope.
`--hold-open-seconds` alone does not keep a replay in the field because the
client acts on that packet before the hold begins. Use `--keep-world-open` to
validate that the capture has exactly one terminal opcode-`9` server frame,
require that it is the final server frame, and omit it with corrected IV
progression:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --repeat-final-field-npc-state-update \
  --world-heartbeat-interval-seconds 10 \
  --hold-open-seconds 600 \
  --transcript-dir captures/replay-observed
```

Plaintext frames may also be sourced privately at runtime with
`--send-after-transcript-from-pcap`,
`--server-frame-patch-from-pcap`, or
`--reply-on-client-opcode-from-pcap`. A repeated reactive opcode creates an
ordered response sequence. `--client-opcode-reply-delays` supplies one delay
per response, which is required for the observed 2.5-second gap between the
two server opcode-`402` channel-transition packets.
`--rewrite-channel-transition-world` binds the stage-1 world id to the live
client opcode-`4` selection instead of replaying the captured world verbatim.

`--rewrite-initial-current-hp HP` is the typed field-state mutation path. It
requires exactly one valid large opcode-`157` snapshot, validates the complete
gameplay fold, replaces only `InitialCharacterSnapshot.current_hp`, checks the
requested value against the decoded maximum, and round-trips the same-length
packet before replay patches and re-encrypts that server frame. It refuses an
explicit patch of the same frame. For example:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --rewrite-initial-current-hp 1 \
  --hold-open-seconds 300
```

`--emit-current-hp-update HP` generates a new typed server opcode-`41` after
the captured transcript. It validates the complete gameplay fold, bounds the
requested value by modeled max HP, constructs the observed current-HP mask,
round-trips the plaintext packet, and exposes the predicted delta through the
runtime API. It requires `--keep-world-open`; use
`--post-transcript-start-delay-seconds` when the effect should be delayed for
observation:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --emit-current-hp-update 1 \
  --post-transcript-start-delay-seconds 10 \
  --hold-open-seconds 300
```

`--emit-inventory-quantity-update INVENTORY:SLOT:QUANTITY` generates one
typed opcode-`39` stack update for an existing modeled `use`, `setup`, or
`etc` item. The planner requires the slot to exist, preserves its item
identity, bounds the quantity, round-trips the packet, and predicts an
unchanged item count. For example:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --emit-inventory-quantity-update use:15:1 \
  --post-transcript-start-delay-seconds 15 \
  --hold-open-seconds 300
```

`--reactive-item-use-responses` handles capture-validated potion requests
during the world hold-open period. Client opcode `80` is checked against the
current typed Use slot and template. For the two captured potion templates,
the server emits a typed opcode-`39` quantity decrement followed by the
captured opcode-`41` HP/MP effect, capped at the modeled maximum. The final-item
case is rejected until its remove-versus-zero-quantity shape is captured. The
option requires `--keep-world-open` and a positive hold duration:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --emit-inventory-quantity-update use:15:2 \
  --post-transcript-start-delay-seconds 15 \
  --reactive-item-use-responses \
  --world-heartbeat-interval-seconds 10 \
  --hold-open-seconds 300
```

`--rewrite-final-field-drop-position X:Y` changes only the typed position in
the final field's sole active mode-`2` item-drop packet.
`--rewrite-final-field-drop-owner-to-player` independently rewrites only its
two owner words to the character id validated between client opcode `8` and
the initial snapshot. The two rewrites may be composed on the same frame. The
owner rewrite does not assert pickup eligibility: live owner-only and
captured-shaped animated-drop probes both produced zero opcode-`185` requests.
Pair the position rewrite with
`--reactive-item-pickup-responses` to handle a real client opcode-`185`
request from modeled state. Pickup quantities and inventory targets must come
from validated evidence in the replay itself or from
`--item-pickup-evidence-transcript`; when replaying a PCAP, another stream in
that file can be selected with `--item-pickup-evidence-tcp-stream`. The policy
serves only a known active item drop with a matching epoch and a unique
existing stack, then emits opcodes `39`, `49`, and `312`:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --no-strict \
  --pcap /path/to/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --rewrite-final-field-drop-position 633:-2677 \
  --rewrite-final-field-drop-owner-to-player \
  --reactive-item-pickup-responses \
  --item-pickup-evidence-tcp-stream 92 \
  --world-heartbeat-interval-seconds 10 \
  --hold-open-seconds 300
```

The source stream's final drop is template `4000004`, Etc slot `7` already
contains quantity `74`, and stream `92` independently proves four pickups of
that template as an Etc delta/gain quantity of one. The server never invents a
drop id or validation token: it preserves the captured drop id, while the
official client supplies its own token in the request.

Runtime prediction for the owner patch reports
`drop_owner_fields: match_initial_player` and
`pickup_eligibility: requires_additional_client_conditions`; it never exposes
the captured or rewritten numeric owner id.

Validate a login capture and fold it into typed game state without printing
account or character identifiers:

```sh
python -m maple_server analyze-login \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 83 \
  --packets \
  --fail-on-invalid
```

`--packets` appends one frame-aligned structured record with direction, timing,
wire offsets, opcode, shape coverage, and decoded fields. `--json` exposes the
same packet records as machine-readable objects. The analyzer reports full,
partial, unknown, and invalid interpretations.
Account success, world records/sentinel, world/channel/character selections,
the two-stage opcode-`402` transition, and handoff are fully validated. The
character-list envelope is deliberately partial until its inner records are
decoded. Opcode-`13` acknowledgments and client status messages are fully
decoded; other length-prefixed type-`6`/type-`7` envelopes are structurally
bounded and intentionally reported as opaque. They use neutral opcode-envelope
names because adjacency in one capture does not establish security semantics.

Validate a world capture, fold it into field state, and optionally emit the
timestamped gameplay event stream:

```sh
python -m maple_server analyze-gameplay \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 92 \
  --events \
  --fail-on-invalid
```

Repository-root `111.pcapng` supplies login stream `83` and gameplay streams
`92`/`114`. Repository-root `1-10FS.pcapng` supplies 71,100-frame level-1-to-10
gameplay on stream `126`; it now passes `--fail-on-invalid` with 24,999 full,
40,959 partial, 5,142 unknown, and zero invalid packet observations. PCAP
normalization locates the Maple greeting after its 14-byte server and 28-byte
client transport preludes and records the trimmed byte counts in transcript
metadata.

The gameplay fold currently models these capture-backed boundaries:

- client opcode `8`: exact 66-byte world-entry envelope (`entry_value`,
  character id, and 56-byte opaque ticket),
- server opcode `157`: field snapshot/change envelope; the initial 4.4 KB
  variant has a typed 112-byte character/stat prefix plus bounded equipment,
  use, setup, etc, and cash inventory lists, while the repeated 95-byte compact
  transition variant is fully bounded; the level-1 corpus also validates a
  marker-`26` initial character/inventory prefix with an opaque 172-byte
  progression region,
- client opcode `158`: the complete `1 -> 2` field-load stage sequence plus a
  stage-`0` variant with neutral word `1` and a bounded nine-byte opaque tail,
- server opcode `39`: inventory change sets with empty, add, stack-quantity,
  equip-slot move, and remove operations plus lossless equipment, stack, and
  cash item records; cash-tab adds accept both captured stack and cash records,
- client opcode `80`: a 12-byte Use-item request containing client tick, signed
  slot, and item template; the fold correlates it with the following opcode-`39`
  quantity change and captured opcode-`41` potion effect,
- client opcode `185`: 23-byte and 35-byte item-pickup requests containing the
  folded field epoch, client tick, position, aliased drop id, neutral validation
  token, and optional 12-byte proof,
- server opcode `311`: 44-byte animated item, 36-byte animated mesos, 38-byte
  field-load item, and 30-byte field-load mesos drop spawns; the fold tracks
  mode-`1`/mode-`0` refresh pairs, source mobs, ownership-neutral fields, and
  active lifecycle,
- server opcode `49`: the three pickup-result variants for item quantity, mesos
  amount, and a still-neutral special value,
- server opcode `312`: the 7/11/15-byte field-drop removal variants, correlated
  to local pickup requests by the exact aliased drop id,
- server opcode `41`: masked player-stat deltas for level, job, STR, DEX, INT,
  LUK, current/max HP and MP, AP, SP, EXP, and 64-bit mesos, plus bounded
  neutral flag/tail values,
- client opcode `47`: structurally exact life-movement relay with local object
  index, redacted client token, neutral control value, fixed-width command
  stream, capture-bounded tail variant, marker, and start/end coordinates,
- client opcode `182`: local-player movement with a neutral 32-bit control
  value, signed reference position, typed command stream, and zero-marked
  start/end-position trailer,
- server opcode `202`: remote-player movement with an aliased object id, the
  same control value and command stream, and no client-only trailer,
- server opcode `217`: structurally exact life-movement broadcast with an
  aliased object id and the same fixed-width command stream as opcode `47`,
- server opcode `300`: complete 22-byte NPC spawn records whose facing field is
  preserved as the observed byte value rather than narrowed to a boolean,
- server opcode `303`: an 8-byte typed NPC state prefix plus a losslessly
  preserved optional opaque tail,
- server opcode `279`: mob-entry envelope with object id, template id,
  temporary-status block, position/stance/footholds, spawn effect, and tail,
- server opcode `280`: complete object-id plus one-byte mob-leave record,
- server opcode `281`: controller level/object id with spawn data for nonzero
  controller assignments and no body for level zero,
- server opcode `282`: server mob-movement broadcast with a seven-byte control
  prefix, signed reference position, and the same typed movement commands,
- client opcode `207`: correlated mob movement submissions with a bounded
  19-byte control prefix, signed reference position, command count, typed
  commands, and zero-marked start/end-position trailer,
- server opcode `283`: complete correlated mob movement acknowledgements with
  a one-byte boolean flag, 16-bit little-endian status/resource value, and two
  one-byte auxiliary fields,
- server opcode `293`: exact object-id plus one-byte mob-health percentage;
  zero is retained as state and does not replace the separate leave packet,
- client opcode `301`: the world-bootstrap acknowledgement envelope,
- server opcode `10`: the exact empty-body heartbeat probe, followed by client
  opcode `23`: a response with an opaque eight-byte token,
- server opcode `9`: the exact nine-byte world-session termination envelope;
  its seven-byte reason body remains opaque.

Unknown opcodes remain lossless frame observations and do not acquire semantic
names from frequency or adjacency alone. Default reports replace character and
runtime object ids with stable session-local aliases such as `npc:1`; use
`--show-identifiers` only for private debugging.

The full stream-`92` validation reaches `active` across 13 field epochs and
then changes to `terminated` on its final server opcode-`9` packet. All 26
field-load messages form 13 ordered stage pairs; all 53 NPC spawns and 77 NPC
state updates validate; all 531 local-player movement submissions and 113
remote-player broadcasts round-trip; 11,949 mob movement acknowledgements
match prior captured submissions; and all 75 server heartbeat probes pair with
the next 75 client responses. All 963 opcode-`47` submissions and 305
opcode-`217` broadcasts are structurally exact. All 54 pickup requests also
match their value effect, opcode-`49` result, and opcode-`312` removal. All 100
removal packets round-trip. Two mob movement submissions remain pending at
capture end.

Twelve of the 13 opcode-`157` packets use an exact 95-byte compact transition
shape (two-byte opcode plus 93-byte body). `CompactFieldTransition` decodes the
marker/reserved fields, transition sequence, map id, portal index, current HP,
two one-character UTF-16 strings with trailing zero bytes, one 16-character
UTF-16 string, fixed integers, a `1900-01-01` FILETIME sentinel, a server-local
FILETIME value, and a final unnamed `u32`. All 12 round-trip byte-for-byte and
their sequences exactly match field epochs `2..13`. The map sequence is drawn
from `100050000`, `100040100`, `100040000`, `100040110`, and `101000000`; the
final folded state is map `101000000`, portal `6`, HP `50`. After accounting for
UTC+8, each server-local clock value precedes packet capture by 1.097-1.183
seconds. Reports expose string lengths, not their potentially identifying text,
and retain neutral names for the three text roles and final integer. The first
large opcode-`157` packet now decodes through its 112-byte plaintext prefix:
marker/branch flags, three connection-local integers, signed `-1` sentinel,
character-data flags, character id, UTF-16 name, appearance, level/job, four
base stats, HP/MP pairs, AP/SP, EXP, fame, map id, portal, and two still-neutral
state fields. The character name is omitted from reports; only its UTF-16 code
unit count is exposed. The following tail parser preserves a 30-byte preamble
and bounds five equipment-record groups plus the use/setup/etc/cash lists.
Stream `92` contains
`4/1/4/0/0` equipment records plus `24` use, `2` setup, `17` etc, and `1`
cash record; stream `114` has one additional etc record. Common item fields
include slot, record type, template id, cash flag, expiration, and stack
quantity where present. Variable equipment metadata remains lossless inside
each bounded record. Both complete packets and their extracted inventory
regions round-trip byte-for-byte. The shared 1,422-byte continuation then
decodes six skill-level pairs, seven keyed UTF-16 values, 35 keyed timestamps,
16 saved-map slots, 12 extended keyed UTF-16 values, and a fixed 112-byte
trailer. All keyed string contents remain redacted; reports expose keys and
UTF-16 code-unit counts. The complete continuation also round-trips, and the
embedded character id matches the preceding world-entry request in both
streams.

The initial snapshot now seeds player and field game state immediately. For
stream `114`, the emitted `field_snapshot_received` event reports level `12`,
job `200`, map `101000000`, portal `6`, HP `50/222`, MP `97/342`, and the
remaining base/progression values without exposing the character name or raw
identifier. The same event includes per-group item counts and slot/template/
quantity records. Its packet observation is deliberately `partial`, because
equipment-specific metadata and several progression/trailer roles are
structurally bounded but not yet semantically named.

The typed HP rewrite was validated through the real client using stream `114`.
The planner predicted HP `1/222` with map, inventory, progression, and phase
unchanged. The client entered the field and displayed `HP 1 / 222`; analysis of
the replay-observed transcript independently folded to `active`, map
`101000000`, HP `1/222`, the same inventory/progression state, nine NPCs, and
matched heartbeat probes/responses with none pending. The source packet held
HP `50/222`, so this is a controlled field effect rather than passive replay
liveness.

Player movement is now a separate typed family rather than being confused with
the mob controller protocol. In stream `92`, client opcode `182` contains 531
local submissions and 3,606 commands; server opcode `202` contains 113 remote
broadcasts and 675 commands. Only tags `0/1/3/5` occur. Their payload lengths
are exactly `13/7/5/13` bytes, excluding the tag. Tags `0` and `5` expose
signed position/velocity pairs, foothold, stance, and duration; tag `1`
exposes relative velocity, stance, and duration; tag `3` remains a bounded
five-byte semantic unknown. Every packet round-trips. The fold updates the
local path endpoint, maintains session-local aliases and final absolute
positions for observed remote players, and emits `player_movement_submitted`
and `remote_player_movement_broadcast` events. Short stream `114` folds its one
local submission to `(633,-2677)` and its two broadcasts to two redacted
remote-player aliases.

The separate life-movement relay family is now bounded without assigning
meaning to its command bodies. Client opcode `47` carries a local object index,
a redacted 32-bit client token, a neutral 32-bit control value, a signed
reference position, a counted command stream, one of four typed tail layouts,
a marker, and signed start/end coordinates. Server opcode `217` carries an
object id plus the same reference/count/command stream. Stream `92` validates
963 submissions containing 3,869 commands and 305 broadcasts containing 1,441
commands. Stream `126` validates another 2,585 submissions with 8,189 commands
and 347 broadcasts with 1,399 commands; 344 of those broadcasts name a player
already active when received, while three precede player discovery. All 2,932
long-corpus packets consume exactly and round-trip. Command tags `0..22` and
client tail tags `17/18/21/24` have capture-derived fixed widths; their field
roles, the client control value, and the tail marker remain neutral, so reports
classify the family as partial semantic coverage and omit the token value.

Server opcode `41` now folds stat deltas instead of remaining an unknown
packet. The stable prefix is a one-byte request flag and 32-bit mask. Observed
values follow in ascending mask-bit order. The level is one byte; job, STR,
DEX, INT, LUK, current/max HP and MP, AP, and SP are 16-bit; EXP is 32-bit;
mesos is 64-bit. A nonzero mask ends in one zero byte. All 333 stream-`92`
packets and 324 emitted field values round-trip, including combined HP+EXP and
INT+LUK+AP masks. Fourteen zero-mask packets are bounded as either a single
zero or a two-byte `01 xx` variant; their semantics and the request flag remain
neutral. The final fold reports HP `50`, MP `97`, EXP `1464`, and mesos `4567`.

The level-1-to-10 stream adds the remaining stat-mask variants. All 841 stat
updates now round-trip and fold, including nine level changes, the job change
to `200`, STR/DEX/INT/LUK changes, max-HP/max-MP changes, AP/SP changes, EXP,
and mesos. Its final player state is level `10`, job `200`, HP `114/194`, MP
`158/285`, STR `4`, DEX `4`, INT `49`, LUK `13`, EXP `980`, and mesos `1472`.

A live stream-`114` replay then generated one typed current-HP update from
`50 -> 1`. The real HUD showed `HP 1/222` while MP stayed `97/342` and EXP
stayed `1464`. The recorded exchange independently folded to `active`, emitted
one `player_stats_updated` event with previous/current HP `50/1`, and matched
every generated heartbeat. Runtime telemetry reported one planned and one sent
opcode-`41` packet.

Server opcode `39` now mutates the typed inventory instead of remaining
unknown. Its stable prefix is a neutral byte followed by a modification count.
Each modification has an operation, inventory type, and signed 16-bit slot.
Observed operation `0` adds a complete item record, `1` replaces a stack's
16-bit quantity, `2` moves or swaps a slot, and `3` removes a slot. Stream `92`
contains 69 packets and 71 modifications: 40 quantity updates, 16 adds, and 15
removes; 13 packets are empty. The adds comprise one etc stack plus 15 cash
remove/add refreshes. All 69 packets round-trip, every mutation applies to a
known slot where required, and the final inventory matches stream `114` with
24 Use, 18 Etc, two Setup, and one Cash item. The level-1-to-10 stream expands
coverage to 256 packets and 232 modifications: 93 adds, 79 quantity updates,
two equip moves, and 58 removes, with zero unknown-slot mutations.

A typed stream-`114` replay changed existing Use slot `15`, item template
`2000000`, from quantity `27 -> 1`. The real inventory window displayed `1` in
that slot. The recorded exchange independently folded the same
previous/current quantity event, retained the item count and all player state,
remained `active`, and matched all 18 generated heartbeat responses. Runtime
telemetry reported exactly one planned and one sent opcode-`39` packet.

Client opcode `80` now connects the inventory and stat models into one
request/effect chain. Stream `92` contains 17 exact 12-byte requests: 13 blue
potions (`2000014`, Use slot `21`) and four red potions (`2000000`, Use slot
`15`). Every request names the modeled slot template, is followed by an exact
quantity decrement, and is followed by the captured stat effect: blue restores
80 MP with max-MP capping, while red restores 50 HP. A live stream-`114` run
first changed red-potion quantity `27 -> 2`; one real double-click then produced
opcode `80`, and the reactive server emitted opcodes `39,41`. The UI and the
independently folded transcript both showed quantity `2 -> 1` and HP
`50/222 -> 100/222`, with one inventory match, one effect match, no pending or
mismatched request, and all 20 heartbeat pairs matched.

Client opcode `185` now connects field drops to inventory and mesos state.
Stream `92` contains 54 requests: 48 exact 23-byte base records and six records
with one additional opaque 12-byte proof. Every request's one-byte field epoch
matches the folded field epoch. The stable prefix contains a neutral 32-bit
control value, the epoch, client tick, signed position, runtime drop id, and a
neutral 32-bit validation token. Reports replace the runtime id with a
field-local `drop:N` alias and expose only whether the neutral token is present.

The matching opcode-`49` result set contains 24 item/quantity records, 29
64-bit mesos-amount records, and one still-neutral special-value record. The
fold attaches the preceding positive opcode-`39` inventory delta or opcode-`41`
mesos delta FIFO, checks it against that result, then closes the request when
opcode `312` removes the same drop id. The first mesos pickup infers its prior
balance as `4100` because the initial snapshot does not yet decode the mesos
baseline; the remaining 28 validate by direct previous/current deltas. All 54
effect/result checks and all 54 removals match, with no pending requests. The
100 opcode-`312` packets divide into 25 drop-only, 10 actor-bearing, and 65
actor-plus-tail records; 54 of the last group are the local correlated pickups
and 11 belong to other actors. Actor and reason roles remain neutral.

Opcode `311` closes the previously missing boundary. Stream `92` contains 125
spawn packets for 66 unique drops: 59 exact mode-`1`/mode-`0` pairs and seven
mode-`2` field-load items. Every one of the 54 pickup requests names a known
active spawn, every result value matches that spawn, and every local removal
closes the same drop. Stream `114` actually retains one mode-`2` item drop at
hold-open; the typed rewrite can move it from `(-863,-1742)` to the final
player position `(633,-2677)` without changing its captured identity.

All 12,100 movement submissions now validate through the command-stream
boundary: 40,090 commands total, comprising 39,282 type-`0` commands with
13-byte payloads, 706 type-`1` commands with seven-byte payloads, and 102
type-`2` commands with seven-byte payloads. Including each one-byte type tag,
their wire sizes are 14, 8, and 8 bytes. No other command type occurs and every
body ends exactly at its nine-byte zero-marker/start/end trailer. Type `0`
decodes into signed position and velocity pairs, an unsigned foothold id,
stance byte, and duration; types `1` and `2` decode into signed relative
velocity, stance, and duration. All 40,090 typed commands and all 12,100 paths
round-trip byte-for-byte. The 19-byte control prefix remains intentionally
opaque. Reports emit reference/start/end coordinates and the decoded command
records instead of one undifferentiated movement blob.

All 11,949 acknowledgement bodies also fit one exact primitive boundary: flag
`0` or `1`, a 16-bit little-endian value in `{0,25,30,35,100}`, and two zero
auxiliary bytes. `MobMovementAcknowledgement` parses and writes those four
fields directly; no acknowledgement bytes remain bundled as an opaque status
blob. The fold reports all nine observed combinations and their counts while
leaving the behavioral meaning of the 16-bit value unnamed.

The fold now tracks the mob lifecycle needed by a future reactive opcode-`283`
generator. All 337 entry records, 175 leaves, 589 controller changes, and 5,284
server movement broadcasts validate and round-trip exactly. The broadcasts
contain 18,874 commands: 18,610 type `0`, 222 type `1`, and 42 type `2`. Every
leave and broadcast resolves to an active modeled mob.

After respecting field-epoch resets, the acknowledgement flag matches whether
submission control-prefix byte `0` is nonzero in all 11,949 correlated pairs.
Both auxiliary fields are zero in all 11,949 pairs. The 16-bit value is
deterministic by the field-local mob template for every pair: `100100 -> 0`,
`130100 -> 30`, `210100 -> 35`, `1110100 -> 25`, `1130100 -> 30`,
`2110200 -> 35`, `3210800 -> 100`, and `9999999 -> 0`.

Visible mob membership and protocol identity are intentionally separate in the
fold. Opcode `280` removes a mob from the active visible set, but its template
is retained until the next opcode-`157` field reset because the capture keeps
submitting and acknowledging movement for that object afterward. This resolves
all 11,949 acknowledgement values to templates. There are 1,502 submissions
whose mob is no longer active, including 1,414 after a leave and one after a
controller release. Only 87 submissions have no field-local template at all;
none receives an acknowledgement before its field epoch resets or the capture
ends. The acknowledgement-time unknown-active-entity count remains 1,380, a
different and now explicitly named lifecycle metric.

`derive_mob_movement_acknowledgement_policy()` turns that evidence into a
conservative generator. It validates every correlated flag and auxiliary
field, refuses any template with more than one observed value, retains the
final field's explicit field-local object-to-template knowledge, and emits
opcode `283` with the submitted object id and sequence. Its safe report includes
template ids, values, evidence counts, and separate known/active mob counts but
no runtime object ids. Calling it for an object without field-local template
state or a template without deterministic evidence raises instead of guessing.
Stream `92` ends after a new field reset with zero known or active explicit
mobs, so the policy proves the mapping but deliberately cannot generate a
post-capture live response from that final state.

`--reactive-mob-movement-acknowledgements` wires the policy into hold-open
replay. Each live opcode `207` is parsed, the submitted object and sequence are
copied into a typed opcode `283`, the flag is derived from control byte zero,
the deterministic template value is selected, and the two auxiliary fields are
zeroed. The option requires `--keep-world-open`, refuses a simultaneous
capture-sourced opcode-`207` rule, and rejects startup when the final field has
no explicit field-local mob-template state. Runtime unit replay verifies the
encrypted request/response path and telemetry. Neither reference stream is a
valid live A/B target yet: short stream `114` contains no mob packets, while
stream `92` resets all explicit mob-template state before its final hold-open
point. A real-client effect test therefore remains gated on a short capture
that ends with a known mob, or on generated field state after the field body is
decoded.

The heartbeat direction is established by capture order, not opcode frequency:
in every sustained stream-`92` pair, server opcode `10` precedes client opcode
`23`. The client responds 0.65-90.91 ms later (20.76 ms average). The fold
tracks matched, unmatched, and pending probes, so reversing this interpretation
or losing a response is visible in state and warnings.

A live replay A/B used the short stream-`114` field and repeated its server
frame `55`, an opcode-`303` update for an already spawned NPC. Baseline and
injected sessions both reached `active` with nine NPCs. The injected fold had
one additional server frame and one additional `npc_state_updated` event
(`2 -> 3`) while entity count and session phase stayed unchanged, matching the
prediction. Both sessions returned to login because the short capture's final
opcode-`9` packet explicitly terminates the world session, not because of
opcode `303`.

`--repeat-final-field-npc-state-update` makes that experiment typed and
repeatable. It first validates the gameplay fold, selects the last complete
opcode-`303` update for an NPC still known in the final field epoch, generates
the eight-byte packet through `NpcStateUpdate.to_bytes()`, and sends it once
after the capture. The option requires `--keep-world-open`; it refuses captures
without a safe final-field candidate. Its identifier-free prediction is one
additional `npc_state_updated` event and state-update count, with no change to
the active NPC count or phase.

The typed option was then exercised through the real client and local handoff.
Runtime status reported one planned and one sent packet for final-field alias
`npc:8`. Compared with a keep-open baseline, the observed fold changed NPC
state updates and corresponding events from `2 -> 3`, while both sessions
remained `active` with nine NPCs. The injected run completed its full configured
600-second hold with no termination packet and matched all 60 heartbeat
probe/response pairs (one captured plus 59 generated), confirming the predicted
field-local effect and continued client liveness.

Repeating the real-client stream-`114` replay with its validated terminal
server frame omitted kept the character in the field for the complete
configured 600-second hold. The observed connection lasted 605.85 seconds
including replay/setup, remained `active` with nine NPCs, and closed only when
the hold expired. This validates the predicted difference between replaying
and omitting the modeled termination event; it does not yet establish an
indefinitely self-sustaining world server.

With `--world-heartbeat-interval-seconds 10`, replay begins emitting fresh,
properly encrypted opcode-`10` probes after the captured stream. A real client
logged in through the local login handoff, reached `active` field epoch 1 with
nine NPCs, and answered all 29 generated probes with opcode `23`. Generated
round trips were 0.91-17.17 ms (9.72 ms average). The final fold reported 30
total matched pairs including the captured pair, zero unmatched or pending
probes, no termination packet, and phase `active` for 309.19 seconds including
replay/setup. The transport closed only after the configured 300-second hold.
This validates both the corrected probe/response model and the generated
packet's live effect.

## Runtime HTTP API

Listener commands can expose read-only, identifier-free runtime status on a
loopback address:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 8799 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --hold-open-seconds 600

curl http://127.0.0.1:8799/healthz
curl http://127.0.0.1:8799/api/v1/status
```

`GET /healthz` returns `{"ok":true}`. `GET /api/v1/status` reports the
listener mode/address, safe replay configuration, start time,
accepted/active/completed/failed connection counters, and a `protocol` object.
When periodic world heartbeats are enabled,
`protocol.world_heartbeat` reports the interval, probes sent, responses
observed, pending probes, and last/maximum round-trip milliseconds.
When the initial player HP is rewritten,
`protocol.initial_player_hp_rewrite` reports the original/current/max values,
the patched server-frame index, patch count, and the identifier-free predicted
unchanged state components.
When a post-transcript HP stat update is generated,
`protocol.player_stat_update` reports opcode/mask/flag, field epoch,
original/emitted/max HP, the predicted unchanged state components, and planned
versus sent packet counts.
When a typed stack quantity is emitted,
`protocol.inventory_quantity_update` reports inventory, slot, item template,
original/emitted quantity, opcode/flag, field epoch, predicted unchanged state,
and planned versus sent packet counts.
When reactive item-use responses are enabled, `protocol.item_use_responses`
reports modeled potion slots and stats, observed/served/rejected request
counts, response packet count, last response, and the current predicted
inventory/stat state.
When the final drop position is rewritten,
`protocol.final_field_drop_position_rewrite` reports its alias/template,
original and rewritten coordinates, field epoch, server-frame index, patch
count, and predicted unchanged state. When its owner words are rewritten,
`protocol.final_field_drop_owner_rewrite` reports the alias/template,
ownership flag, field epoch, server-frame index, patch count, redacted
character identifiers, and the conservative pickup-eligibility prediction.
When reactive pickup responses are
enabled, `protocol.item_pickup_responses` reports the eligible aliased drops,
captured correlation evidence, observed/served/rejected request counts,
response packet count, last identifier-free response, and current mutable
inventory/drop state.
When a typed final-field NPC update is repeated, `protocol.npc_state_replay`
reports its session-local entity alias, field epoch, decoded action/parameter,
planned/sent packet counts, and the predicted fold delta. When reactive mob
movement acknowledgements are enabled,
`protocol.mob_movement_acknowledgements` reports the identifier-free derived
policy, its full-capture evidence, observed submissions, sent responses, and
rejections. Other
methods are rejected with `405`; unknown paths return `404`. The API
deliberately has no remote binding or mutating route: startup rejects
non-loopback addresses, so the current local-only threat model relies on
OS/namespace access rather than application authentication. Add authentication
before introducing any remote binding or mutating route. If the listener runs
in `mapleproxy`, query the API from that namespace as well.

Inspect a transcript without dumping its entire payload:

```sh
python -m maple_server inspect captures/session.jsonl
```

Compare two sessions without printing their potentially sensitive payloads:

```sh
python -m maple_server compare captures/session-one.jsonl captures/session-two.jsonl
```

Transcripts are JSONL files created with mode `0600`. Every data record has a
nanosecond timestamp, direction, and base64 payload. Credentials are read from
environment variables and are never stored in a transcript.

## Keep MapleStory audio muted

The included user service discovers PipeWire output nodes by stable
application identity (`Maplestory_Classic.exe`) rather than a changing numeric
node ID:

```sh
systemctl --user link \
  /home/sdancer/ms/tools/maplestory_classic_server/maplestory-audio-mute.service
systemctl --user enable --now maplestory-audio-mute.service
systemctl --user status maplestory-audio-mute.service
```

It checks every 250 ms and mutes newly created/recreated MapleStory streams
without affecting other applications.

## Browser-free local launch

Once the login listener is active inside `mapleproxy`, launch the local client
without Chromium, CDP, NGM, or a website ticket:

```sh
cd /home/sdancer/ms
python tools/maplestory_classic_server/tools/launch_local_game.py --restart
```

The script discovers nested Sway/Xwayland, checks both namespace listeners,
requires the Maple-only audio mute service to be active, launches the local
placeholder argument tuple, waits for a Maple window whose PID belongs to the
newly live client process set, and focuses that exact Sway container. This keeps
stale Xwayland Maple nodes from satisfying launch readiness.
It intentionally cannot launch an authenticated official session.

## Current implementation steps

1. Run the replay listener inside the client's network namespace; host-only
   listeners do not receive namespace-local port redirects.
2. Validate the successful login reference before sourcing any replay frames.
3. Withhold captured server frame `4` and return the successful stream's server
   frame `13` only after native client opcode `6`. This preserves the proven
   NGSX request/response ordering even when a fresh client emits extra frames.
4. Acknowledge native client opcode `13`, then return the validated account,
   world records, and world-list sentinel as one reactive sequence.
5. Return server opcode `402` frames for client opcode `4` with delays
   `0,2.5`, and use `--rewrite-channel-transition-world`; the client otherwise
   stalls before emitting channel opcode `5` when the captured world differs.
6. Return the partially decoded character list, server time, and captured
   type-`7` envelope for opcode `5`.
7. Rewrite the validated opcode-`5` handoff to the local stream-`92` replay
   listener only after opcode `7`. The ordered NGSX run produced opcode `7`, a
   valid `handoff_ready` fold, and a real connection to the local world replay.
8. Use `analyze-gameplay` to validate field epochs, NPC state, movement
   request/ack correlation, and heartbeat traffic before replay experiments.
9. Repeat only a modeled, field-local packet in a baseline/injected A/B and
   compare the emitted state events rather than inferring effects from client
   liveness alone.
10. Model the terminal server opcode-`9` envelope and omit it with
    `--keep-world-open`; a real client remained in-field for the full
    600-second hold and left only when the configured hold expired.
11. Correct the heartbeat direction from temporal evidence, correlate opcode
    `10 -> 23` pairs, and emit periodic post-replay probes. A real client
    answered every generated probe while remaining active in the field.
12. Promote the validated NPC-update A/B into a typed final-field replay plan,
    generated packet, and identifier-free runtime prediction/telemetry.
13. Bound all captured opcode-`207` movement command streams and fold command
    counts/types plus reference/start/end positions into gameplay state/events.
14. Decode type-`0` absolute and type-`1`/`2` relative movement fields with
    exact command/path round trips, while retaining the 19-byte control prefix
    as opaque.
15. Decode and fold mob entry/leave/controller/broadcast lifecycle, separating
    visible membership from field-local template knowledge retained after leave.
16. Fully type opcode `283`, validate its flag/auxiliary rules across every
    correlated pair, derive a generator gated on explicit field-local template
    state and deterministic capture evidence, and wire it into hold-open replay.
17. Capture a short world session that ends with a known mob and run the typed
    acknowledgement policy through a real-client prediction/effect A/B.
18. Decode and fold the repeated compact opcode-`157` transition into sequence,
    map, portal, HP, bounded text/timestamps, and field reset state.
19. Decode the large initial field snapshot through player, inventory, and
    progression state while keeping the inner character-list records as the
    remaining login-side boundary.
20. Generate a same-length initial field snapshot with typed HP `1`, validate
    the packet before encryption, and confirm the predicted value in both the
    real client HUD and the independently folded replay transcript.
21. Separate player movement from mob movement, bound client opcode `182` and
    server opcode `202`, round-trip all 644 captured packets and 4,281 commands,
    and fold local/remote positions into identifier-safe events and state.
22. Decode masked server opcode `41` stat deltas, round-trip all 333 long-stream
    packets, generate a typed current-HP update, and confirm the predicted
    `50/222 -> 1/222` effect in the HUD, runtime telemetry, and observed fold.
23. Decode server opcode `39` inventory change sets, fold all 71 captured
    modifications, generate a guarded Use-slot quantity update, and confirm
    `27 -> 1` in the real inventory UI, runtime telemetry, and observed fold.
24. Decode client opcode `80`, correlate all 17 captured potion requests with
    exact quantity/stat effects, serve the request reactively, and confirm the
    predicted live red-potion quantity `2 -> 1` and HP `50 -> 100` effects.
25. Decode server opcode `311`, round-trip all 125 long-stream records, fold 66
    drop lifecycles, and prove all 54 pickup values/removals against an active
    spawn while retaining ownership/security fields as neutral.
26. Derive a guarded item-pickup responder from stream `92`, rewrite only the
    final stream-`114` drop position, and compare the predicted Etc quantity
    `74 -> 75` plus drop removal in a controlled real-client A/B.
27. Decode and fold server opcode `293` mob-health percentages across both
    sustained captures while keeping lifecycle removal on opcode `280`.
28. Bound and round-trip client opcode `47` and server opcode `217` life
    movement, fold command/tail distributions into identifier-safe events,
    and validate all 2,932 long-corpus packets without assigning opaque roles.

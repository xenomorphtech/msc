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
Appending `?character-list` to a PCAP frame reference requires a valid typed
opcode-`4` response and re-emits it from the decoded character-list state. Use
it for the first opcode-`5` reply, for example
`5=/path/to/reference.pcapng@83:17?character-list`; malformed records are
rejected before replay encryption.

`--generate-initial-field-snapshot` is the typed field-state emitter. It
requires exactly one valid large opcode-`157` snapshot, materializes the
character, all nine inventory groups and their bounded item records, the
marker-`23` keyed-property or marker-`26` compact progression variant, and the
trailer. It re-encodes and reparses the same-length packet before replay
replaces that server frame. `--rewrite-initial-current-hp HP` uses the same
emitter while replacing only `InitialCharacterSnapshot.current_hp` and
checking the requested value against the decoded maximum. Either mode refuses
an explicit patch of the same frame. For example, exact baseline emission is:

```sh
python -m maple_server replay \
  --listen-host 127.0.0.1 \
  --listen-port 12857 \
  --no-strict \
  --pcap /path/to/reference.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --generate-initial-field-snapshot \
  --hold-open-seconds 300
```

Use `--rewrite-initial-current-hp 1` in place of the generation flag for the
capture-validated controlled HP mutation.

`--generate-fixed-server-records` regenerates every capture-validated member
of the fixed-width server-record family at its original frame index. This
currently covers opcodes `11`, `24`, `56`, `58`, `59`, `96`, `105`, `178`,
`386`, `388`, and `389`. The planner folds the complete transcript, emits and
reparses each typed record, verifies its original length and unique frame
index, and rejects conflicts with explicit patches. Opcode `59` is tied to the
selected character but runtime telemetry exposes only whether it matched, not
the identifier. Add the flag to the command above; it composes with both the
initial snapshot and NPC emitters.

`--generate-variable-server-records` handles the capture-bounded opcode-`156`
and `385` variants. Both begin with a one-byte discriminator. The level-1
variants end there. Expanded opcode `156` contains a packet UTF-16 string,
bool, and three int32 values; expanded opcode `385` contains 89 keyboard
bindings whose tuple index is the key code. Selector `1` binds a skill id, and
key code `29` is the validated evdev Left Ctrl binding. The emitter round-trips
and replaces the complete records; other selector meanings and opcode-`156`
field meanings remain neutral.

Use `?keyboard-skill=KEY_CODE:SKILL_ID` on an expanded opcode-`385` PCAP
reference to replace only the value of an existing selector-`1` binding. For
example, `111.pcapng@114:9?keyboard-skill=29:2001004` preserves all other 88
entries and the captured selector. A live A/B/A changed physical Left Ctrl from
skill `2001005`'s two-hit opcode-`52` variant `18`, to skill `2001004`'s one-hit
variant `17`, and back to variant `18`; the client stayed active and matched
91/91 heartbeats.

The second captured selector-`1` binding is also causal. Physical evdev key
code `71` under `71 -> 2001002` emitted client opcode `104` as the exact
13-byte shape `uint32 client_tick, uint32 skill_id, uint8 skill_level, uint16
trailing_value`. Both captured/restored samples carried skill `2001002`, learned
level `1`, and trailing zero. Rebinding only key `71` to `2001004` switched the
same input to opcode-`52` variant `17`; restoring the original binding restored
opcode `104`. The gameplay fold reports these as full
`client_skill_use_request` observations and `client_skill_use_submitted` events,
including progression/binding correlations and tick deltas. No opcode-`104`
sample occurs in reference streams `92`, `114`, or `126`, and no required
server response is inferred yet.

Server opcode `42` now has a deliberately partial
`LocalTemporaryStatSetHeader` decoder. It reads four `uint32` mask words; only
the all-zero branch's following two bytes and signed `int16` are structurally
decoded, while nonzero records and every remainder stay opaque. The gameplay
fold emits `local_temporary_stat_set_header` observations and
`local_temporary_stat_set_received` events, reports mask/value/opaque-byte
counts, and leaves modeled HP/MP unchanged for a zero mask. The opcode is
absent from reference streams `92`, `114`, and `126`.

The live probe does not establish a valid response. A 160-byte padded all-zero
packet reached the HTTP injection writer but was followed by stalled heartbeat
responses; the exact 22-byte minimal form was sent only after the connection
was already stalled. The padded packet folds as the modeled prefix plus 138
opaque bytes, and both observations report `network_progression_proven: false`.
A fresh browser-free control then reached map `101000000`, emitted one exact
opcode-`104` request for skill id `2001002`/level `1` from direct nested-Wayland
key `71`, and matched 16/16 heartbeats with none pending. An HTTP `accepted`
result proves a serialized socket write only, not client acceptance or semantic
correctness.

For controlled live experiments, replay mode also accepts
`--enable-http-packet-injection` together with `--http-api-port`. It enables
loopback-only `POST /api/v1/server-packets` with exact JSON
`{"plaintext_hex":"..."}`. The endpoint is disabled by default, requires exactly
one active replay connection, caps packets at 64 KiB and bodies at 128 KiB,
serializes encryption/writes with generated traffic, records successful sends
in the transcript, and exposes only safe counters through
`GET /api/v1/status`. It has no application authentication and therefore
assumes every caller inside the local namespace/OS boundary is trusted.

For the modeled current-HP operation, prefer the typed live validator over
hand-written `plaintext_hex`. It loads the actively written world transcript,
derives and round-trips opcode `41`, sends it through the same endpoint, and
does not report success until the new packet folds back out of the transcript.
It requires exactly one stat-update delta and verifies that max HP, phase,
field epoch, map, inventory, and progression did not change:

```sh
sudo ip netns exec mapleproxy sudo -u "$USER" \
  python -m maple_server inject-current-hp \
  --transcript /path/to/live-world.jsonl \
  --current-hp 49 \
  --http-api-url http://127.0.0.1:12858/api/v1/server-packets \
  --json
```

The command accepts only plain HTTP to the fixed packet path on `localhost` or
a numeric loopback address. Its safe result contains the typed prediction, API
acceptance metadata, the matched decoded frame, and invariant checks; it omits
packet bytes and private identifiers.

Mob temporary-stat experiments have a similarly typed path that consumes the
automatically generated IL2CPP shape dump and its private exported packet
JSONL. It verifies matching version/protocol metadata, payload hashes, exact
generated shapes, and a captured template-`3210800` spawn/set/reset pair. It
prefers the 48-byte base spawn over the 56-byte extended-status variant,
rewrites only the field-local object id and placement, and cleans the mob up
with typed opcode `280` after observing set and reset in the live fold:

```sh
sudo ip netns exec mapleproxy sudo -u "$USER" \
  python -m maple_server inject-mob-temporary-stat \
  --transcript /path/to/live-world.jsonl \
  --il2cpp-shape-dump /path/to/current-il2cpp-packets.json \
  --evidence-jsonl /path/to/private/111.streams-83-92-114.jsonl \
  --evidence-tcp-stream 92 \
  --spawn-hold-seconds 2 \
  --set-hold-seconds 2 \
  --reset-hold-seconds 2 \
  --http-api-url http://127.0.0.1:12858/api/v1/server-packets \
  --json
```

The optional holds make direct client observation possible without changing
the modeled packet order. Success requires four observed folds—spawn, bit-103
set, bit-103 reset, and leave—plus exact counter deltas and unchanged phase,
field epoch, map, player state, inventory, and progression. A disappearing
connection or HTTP `409` is a failed experiment, not API acceptance.

`--generate-field-npc-spawns` applies the same boundary to every fully typed
opcode-`300` observation. It validates the complete fold, reconstructs each
22-byte NPC spawn from its aliased entity state, reparses it, checks frame
length and patch conflicts, and replaces the corresponding replay frame. The
runtime plan never exposes NPC object ids. It composes with the initial field
emitter; add it to the command above to generate stream `114` server frames
`20` through `28` as well as frame `3`.

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

With `--transcript-dir`, item use records bounded runtime request, completion,
and rejection events. Policy rejections are correlated with and remove the
matching pending request; they do not tear down the client connection. In the
fresh browser-free proof, direct Wayland PageUp input first produced `[39,41]`
with quantity `2 -> 1` and HP `50 -> 100`, then a second PageUp was rejected at
the intentionally unsupported last-item boundary. The transcript folds validly
without warnings, with one explicit rejection, no pending item uses, and 90/90
heartbeats.

`--rewrite-final-field-drop-position X:Y` changes only the typed position in
the final field's sole active mode-`2` item-drop packet.
`--rewrite-final-field-drop-owner-to-player` independently rewrites only its
two owner words to the character id validated between client opcode `8` and
the initial snapshot. The two rewrites may be composed on the same frame. The
owner rewrite does not assert pickup eligibility: live owner-only and
captured-shaped animated-drop probes both produced zero opcode-`185` requests.
Pair the position rewrite with
`--reactive-item-pickup-responses` to handle a real client opcode-`185` or
compact opcode-`222` request from modeled state. Pickup quantities and
inventory targets must come
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

Reactive pickup also records request/completion/rejection runtime events. A
rejected request for a missing or already removed drop stays nonfatal and is
folded out of pending pickup accounting when it matches the observed request.

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
successful character-list shape is also fully decoded: two reserved `uint32`
values, a byte record count, typed character-stat/appearance records with an
optional four-value ranking block, and a six-byte trailer. Unknown appearance
and trailer roles retain neutral names and round-trip losslessly. Opcode-`13`
acknowledgments and client status messages are fully decoded; other
length-prefixed type-`6`/type-`7` envelopes are structurally bounded and
intentionally reported as opaque. They use neutral opcode-envelope names
because adjacency in one capture does not establish security semantics.

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
gameplay on stream `126`; it now passes `--fail-on-invalid` with 26,661 full,
44,439 partial, zero unknown, and zero invalid packet observations. PCAP
normalization locates the Maple greeting after its 14-byte server and 28-byte
client transport preludes and records the trimmed byte counts in transcript
metadata. Stream `92` independently passes with 13,417 full, 21,788 partial,
2 unknown, and zero invalid observations; short stream `114` reaches 54 full,
22 partial, zero unknown, and zero invalid.

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
- client opcode `79`: exact 13-byte inventory-move requests with typed client
  tick, inventory type, signed source/destination slots, and a neutral trailing
  signed count; both long-corpus requests FIFO-match the authoritative
  same-slot server opcode-`39` move, and safe analysis exposes only structural
  fields plus request/match/pending/latency counters,
- client opcode `80`: a 12-byte Use-item request containing client tick, signed
  slot, and item template; the fold correlates it with the following opcode-`39`
  quantity change and captured opcode-`41` potion effect,
- client opcodes `185`/`222`: 23-/35-byte full and 19-byte compact item-pickup
  requests containing the folded field epoch, client tick, position, aliased
  drop id, neutral validation token, and an opcode-`185` optional proof; all
  203 long-corpus requests complete their effect/result/removal chain,
- server opcode `311`: 44-byte animated item, 36-byte animated mesos, 38-byte
  field-load item, and 30-byte field-load mesos drop spawns; the fold tracks
  mode-`1`/mode-`0` refresh pairs, source mobs, ownership-neutral fields, and
  active lifecycle,
- server opcode `49`: the three pickup-result variants for item quantity, mesos
  amount, and a still-neutral special value,
- server opcode `77`: redacted variants `3`/`4`/`5` fully bound one to three
  counted UTF-16 fields plus their fixed neutral controls/value, while variant
  `8` preserves only its 4- or 117-byte tail as opaque; safe state, events,
  JSON, text output, and HTTP status expose lengths/distributions but never
  captured text,
- server opcode `312`: the 7/11/15-byte field-drop removal variants, correlated
  to local pickup requests by the exact aliased drop id,
- server opcode `41`: masked player-stat deltas for level, job, STR, DEX, INT,
  LUK, current/max HP and MP, AP, SP, EXP, and 64-bit mesos, plus bounded
  neutral flag/tail values,
- client opcode `13`: neutral fixed type-`1` and length-prefixed type-`6`/`13`
  envelopes whose bodies remain opaque and are omitted from safe reports,
- server opcode `13`: the same handler-confirmed discriminator followed by a
  capture-bounded `uint32` body length for types `7`, `12`, and `14`; safe
  state/events expose only type and body-length distributions,
- client/server opcode `43`: neutral, redacted status envelopes; the client
  uses either a sequence, opaque identifier, counted UTF-16 field, and six-byte
  tail or a 12-byte compact form, while the server uses a message byte and
  fixed 16-byte body; no security or request/response meaning is inferred,
- client opcode `114`: one neutral redacted envelope with a control byte,
  counted UTF-16 field, required zero terminator, and omitted trailing u32;
  tutorial/UI timing remains a hypothesis rather than a semantic name,
- client opcode `101`: exact 11-byte five-value record whose numeric widths and
  distributions are typed while all field roles remain neutral,
- client opcode `122`: capture-bounded selector envelopes containing two to
  four redacted u32 values; selectors `1`/`2` have short and long forms,
  selectors `4`/`5` have one form, selector `2` requires terminal
  `0xffffffff`, and every unobserved selector/count combination remains
  unknown,
- client opcodes `50`/`52`: capture-bounded attack-action envelopes with exact
  variant/suffix lengths, redacted client tokens, and an aliased mob target in
  extended variants, plus typed per-hit damage words between bounded opaque
  target prefix/tail regions; each nonzero word becomes one pending hit effect,
- client opcode `54`: exact 24-byte attack action whose third trailing u32 is
  an aliased mob target; the other numeric roles remain neutral,
- client opcode `217`: neutral compact and counted record-set envelopes with
  capture-bounded format-`0`/`2` record widths; opaque bytes remain redacted,
  and no effect or replay behavior is inferred,
- client opcode `47`: structurally exact life-movement relay with local object
  index, redacted client token, neutral control value, fixed-width command
  stream, capture-bounded tail variant, marker, and start/end coordinates,
- client opcode `182`: local-player movement with a neutral 32-bit control
  value, signed reference position, typed command stream, and zero-marked
  start/end-position trailer,
- server opcode `202`: remote-player movement with an aliased object id, the
  same control value and command stream, and no client-only trailer,
- server opcode `189`: remote-player entry with an aliased object id, level,
  redacted counted UTF-16 name, and a losslessly retained version-specific
  body; server opcode `190` is the exact object-id removal, and the fold now
  requires movement broadcasts to reference a current-field entry,
- server opcode `224`: exact remote-player/mob-template value record with a
  fixed `0xff` marker, a repeated neutral u32 value, flag `0`/`1`, and zero
  reserved u16; the fold requires no meaning for the value but correlates the
  aliased player and active mob template,
- server opcodes `285`/`286`: capture-bounded single-bit mob temporary-stat
  set/reset records with an aliased active-mob id, four-word mask, source skill,
  neutral source-level/duration values, and relay/refresh/reset/lifecycle
  correlation; unobserved masks and values remain unknown,
- server opcode `217`: structurally exact life-movement broadcast with an
  aliased object id and the same fixed-width command stream as opcode `47`,
- server opcode `239`: capture-bounded selector envelopes for counted
  u32/i32 records, empty selectors `9`/`13`, and a redacted terminated counted
  UTF-16 selector-`21` branch with one trailing u32; roles remain neutral and
  unobserved selectors remain unknown,
- server opcode `244` selector `8`: a live-validated instructional-dialogue
  request with three signed 32-bit neutral values; other branches remain
  unknown rather than inheriting this exact 15-byte shape,
- server opcode `247`: a fully bounded tutorial-UI instruction containing
  redacted terminated counted UTF-16 text, two signed 16-bit values, a control
  byte, and a handler-confirmed optional pair of signed 32-bit values,
- server opcodes `320`/`322`/`323`: exact positioned-effect records with an
  aliased primary key, signed coordinates, neutral controls, and current-field
  update correlation,
- client opcode `225`: exact 16-byte positioned-effect actions with a redacted
  primary key, two neutral u32 values, and one neutral u16 trailer; all 15
  long-corpus keys resolve to a current-field effect alias and all 15 packets
  immediately follow opcode `50` in client direction order, while safe output
  exposes aliases and aggregate distributions rather than primary keys,
- client opcode `276`: a live nine-byte selector-`17` compact form with three
  reserved zero bytes and a 210-byte stream-`126` selector-`24` form with two
  redacted headers, five counted groups, and 19 redacted u32 pairs; safe output
  exposes only selector/shape/group/pair counts and field epoch,
- client opcode `298`: exact 76-byte item-acquisition requests whose kind,
  item template, and quantity correlate with same-epoch server opcode-`39`
  additions; all 12 match by kind-derived inventory and item template, serials
  stay redacted, and safe state distinguishes nine exact Use quantities from
  two differing and one unavailable Cash response quantities,
- server opcode `169`: selector `3` followed by one redacted, terminated
  counted UTF-16 value; the automatic dump plus native jump-table arm proves
  exact consumption, while safe state/events expose only selector, code-unit
  count, and field epoch,
- server opcode `348`: capture-bounded redacted text envelopes with a common
  u8/i32/selector/i32 prefix, terminated counted UTF-16 text, and two trailing
  controls only on observed selector `0`; selectors `3`/`6`/`17` end after the
  text terminator and all other selectors remain unknown,
- client opcode `66`: the correlated response to server opcode `348`, with a
  selector/status pair and one redacted optional u32 on the captured `6/1`
  branch; the fold matches same-selector requests FIFO, emits acknowledgement
  events, and reports pending/unmatched transactions and round-trip timing,
- server opcodes `69`/`93`/`94`/`137`/`148`/`201`/`205`/`276`/`379`:
  capture-bounded neutral record families; numeric fields are typed,
  potentially identifying primary values are omitted from safe output, fixed
  unknown regions remain explicit, and the opcode-`94`/`137`/`148`/`276`/`379`
  layouts come directly from the generated IL2CPP read dump; opcode `137`
  retains a redacted 72-byte tail, opcode `276` preserves captured boolean byte
  `0x05` while folding it as true, and opcode `148` retains one legacy nonempty
  record body as opaque,
- server opcode `27`: a counted integer/control/text ledger with required
  trailing-zero UTF-16 strings; safe state reports only entry and text-length
  distributions,
- server opcode `28`: a counted ledger of neutral integer pairs and two
  trailing-zero UTF-16 strings per record; all keys, values, and text remain
  redacted,
- server opcode `29`: a delegated `u8`-counted ledger whose record constructor
  reads two signed integers, one trailing-zero UTF-16 value, another signed
  integer, and a neutral signed 16-bit value; both byte-identical stream-`92`/`114`
  packets consume and round-trip exactly while safe output exposes only counts
  and text lengths,
- server opcode `135`: a four-section bootstrap ledger proven by the automatic
  handler dump plus an executed local-Wine reader trace; nested `u8`, `i16`, and
  `i32` counts bound integer vectors, integer pairs, and two integer/byte groups,
  while safe output exposes only structural totals and boolean counts,
- server opcode `394` and client opcode `279`: exact 57-code-unit redacted
  UTF-16 envelopes separated by 57.92 ms in stream `92`; the client adds one
  neutral byte and changes only code-unit span `10..14`. The fold reports FIFO
  correlation and observed gap, not a guaranteed response: exact local-Wine
  injection produced no opcode `279` while the field client stayed responsive,
- client opcode `75`: an exact empty field-bootstrap marker repeated in streams
  `92`/`126` and independently emitted by the current local-Wine client,
- client opcode `241`, client status opcode `45`/`46`, and terminal server
  opcode `9`: a repeated world-exit transaction that enters `exit_requested`,
  redacts the one-u32 status, and reaches `terminated` after 165–167 ms,
- client opcodes `100`, `307`, `308`, and `311`: exact fixed-width redacted
  records whose bodies remain opaque; the latter two additionally expose only
  their observed approximately 300/600-second intervals. Client opcode `310`
  is a separate 41-byte live-only record repeated by three controlled
  direct-Wayland menu confirmations, with no opcode-`241` or phase transition,
- server opcode `142`: a boolean-gated header and counted keyed text/control
  records with two raw-byte-preserving IL2CPP booleans and two signed values per
  entry; zero is false and every nonzero byte is true, and the three-byte
  disabled branch is also modeled,
- server opcode `147`: two signed-`i32` rectangles followed by a counted
  signed-`i32` vector; the fold redacts vector values while reporting the
  rectangle and count shapes,
- server opcode `272`: a fully consumed field-configuration ledger containing
  a neutral header, 11 counted entries, two booleans and two counted groups of
  signed-`i32` triples per entry, plus a terminal signed value; entry selectors
  and triple values remain redacted,
- server opcode `425`: a primitive-traced `u16` count, repeated signed values,
  and four-word trailer; all three gameplay captures use count `12`, trailer
  `(0,0,1,1)`, and the repeated values are redacted,
- server opcodes `228`/`230`/`231`/`232`/`234`/`235`: generated-handler
  envelopes with one redacted `u32` followed by an explicitly ignored,
  capture-bounded tail; the fold reports opcode/tail-length distributions and
  keeps all 12 observations partial,
- server opcodes `11`/`24`/`56`/`58`/`59`/`60`/`96`/`105`/`178`/`386`/`388`/`389`:
  complete fixed-width neutral records, including a character-context record
  whose identifier must match world entry; `--generate-fixed-server-records`
  reconstructs every occurrence rather than assuming they are bootstrap-only,
- server opcodes `156`/`385`: capture-bounded discriminator variants; compact
  records have no tail, expanded records preserve 18/445 opaque bytes and stay
  partial until primitive-reader evidence can type those tails,
- server opcode `300`: complete 22-byte NPC spawn records whose facing field is
  preserved as the observed byte value rather than narrowed to a boolean;
  `--generate-field-npc-spawns` can reconstruct all such replay frames from
  folded, aliased entity state,
- server opcode `302`: a control byte and aliased object id followed, for
  captured control `1`, by the exact 16-byte opcode-`300` spawn body; the
  handler-backed compact control-`0` branch is modeled as removal but remains
  absent from reference captures and not yet live-proven,
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
  zero is retained as state and does not replace the separate leave packet;
  pending client hits add request-frame/hit-index/damage/timing correlation,
  while reference max HP yields authoritative integer-HP bounds and a predicted
  next percentage range,
- server opcodes `218`/`219`: attack-relay envelopes with an aliased player
  object id, packed target/hit counts, and typed mob/hit-action/damage arrays;
  opcode `219` additionally exposes its conditional skill id, display/facing/
  speed/mastery bytes, projectile id, and signed attack position, while the
  opcode-`218` branch types the same first six metadata bytes plus the full
  form's mastery/auxiliary fields and validates its short zero-target form,
- client opcode `301`: the world-bootstrap acknowledgement envelope,
- server opcode `10`: the exact empty-body heartbeat probe, followed by client
  opcode `23`: a response with an opaque eight-byte token,
- server opcode `426`: an exact empty notification followed one-for-one by the
  exact empty client opcode-`309` acknowledgement; the fold tracks ordering and
  round-trip time without assigning a broader gameplay role,
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

The level-1 stream-`126` marker-`26` snapshot now follows the same fold and
emitter path. Its 823 bytes split into the shared typed character state, a
537-byte inventory region with five items across nine groups, and a typed
172-byte compact progression containing skill pair `12 -> 0`, 16 saved-map
slots, a seven-byte neutral variant header, and the compact trailer. It reports
`progression_typed: true` and `progression_shape: compact`; the complete packet
re-emits byte-for-byte.

The unmodified generator was also exercised through the real client with
stream `114`. Runtime status reported frame `3`, one patch, nine inventory
groups/54 items, six skills, `keyed_properties` variant `2`, and predicted HP
`50/222 -> 50/222`. The client entered the field and displayed level `12`, HP
`50/222`, MP `97/342`, and EXP `1464`. The concurrently recorded world
transcript independently folded validly to `active` with identical player,
inventory, and progression state and 7/7 matched heartbeats. This validates
the no-mutation generator path through encryption and the client parser, not
only offline byte equality.

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

Opcode `13` also continues in both directions on the world connection. The
fixed client type-`1`
variant is exactly 11 bytes: opcode, discriminator, and eight opaque bytes.
Types `6` and `13` carry a 32-bit byte count followed by that many opaque
bytes. Stream `92` has 446 type-`1`, 104 type-`6`, and five type-`13` packets;
stream `126` has 970 type-`1` packets. Every envelope round-trips exactly. The
server uses the same length prefix: stream `92` has 14 type-`7`, one type-`12`,
and five type-`14` envelopes, while stream `114` has one each of type `12` and
`14`. The fold records direction-specific type/body-size distributions and
emits redacted events without assigning a security meaning to any body.

Client opcode `217` is distinct from the server-to-client life-movement opcode
with the same number. In stream `126`, 345 packets use an exact eight-byte
compact envelope. Another 592 carry a ten-byte opaque prefix, one-byte record
count, one-byte format, counted fixed-width records, and an eight-byte opaque
trailer. Format `0` uses 14-byte records (1,539 records in 535 packets), while
format `2` uses 11-byte records (114 records in 57 packets). All 937 packets
consume exactly and round-trip; the fold emits only variant/count/format
distributions. No record-aligned 32-bit value matched an active mob id, and no
following server opcode `219` occurred within one second, so this family is
not named as an attack and is not generated or replayed.

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

Long stream `126` adds six opcode-`222` compact pickup requests. Their exact
19-byte form removes the opcode-`185` control word and proof branch but retains
the field epoch, client tick, signed position, runtime drop id, and neutral
validation token. All six epochs and drop ids match folded active state, and
every request matches its opcode-`39` inventory or opcode-`41` mesos effect,
opcode-`49` result, and exact-id opcode-`312` removal. Compact removals use
captured reason `2` while opcode-`185` local removals use reason `5`; no source
meaning is assigned from that distinction. Combined long-corpus pickup
telemetry is 203 requests and 203 complete chains with zero mismatches or
pending requests.

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

The fold tracks the mob lifecycle used by the reactive opcode-`283` generator
and state-driven opcode-`282` planner. All 337 entry records, 175 leaves, 589
controller changes, and 5,284
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
field and refuses any template with more than one observed value. Replay state
and evidence may come from different validated transcripts: the replay supplies
the final field epoch while `--mob-movement-evidence-transcript` or
`--mob-movement-evidence-tcp-stream` supplies the deterministic mapping. The
policy then adopts typed opcode-`279` entries and opcode-`281` controller
assignments sent after replay, retains field-local object-to-template knowledge
after opcode `280`, and tracks active membership separately. Its safe report
contains template ids, values, evidence counts, and separate known/active mob
counts but no runtime object ids. Calling it for an object without field-local
template state or a template without deterministic evidence raises instead of
guessing.

`--reactive-mob-movement-acknowledgements` wires the policy into hold-open
replay. Each live opcode `207` is parsed, the submitted object and sequence are
copied into a typed opcode `283`, the flag is derived from control byte zero,
the deterministic template value is selected, and the two auxiliary fields are
zeroed. The option requires `--keep-world-open`, refuses a simultaneous
capture-sourced opcode-`207` rule, and leaves rejected unknown submissions
unanswered without closing the held-open connection. Stream `114` can therefore
provide the stable held-open field while stream `92` supplies evidence and
typed post-transcript opcodes `279`/`281` establish one live snail.

That arrangement is now real-client validated. The browser-free login reached
map `101000000`; after the typed template-`100100` entry and controller grant,
the client submitted 205 opcode-`207` movements and received 205 generated
opcode-`283` acknowledgements. The final observed transcript folded all 205 as
matched, with the predicted flag, value `0`, zero auxiliary bytes, no unknown
template, and no pending movement while the connection and heartbeat exchange
remained active. Generated opcode-`280` packets from the health responder also
update the movement policy's active set, so the two state owners cannot diverge
when a mob dies.

With transcript recording enabled, each reactive submission now emits a safe
request event containing template/sequence/path-shape data but no runtime
object id. It is followed by a completed acknowledgement event after opcode
`283` drains, or by a nonfatal rejection event. The fresh browser-free proof
contains 58 alternating request/completion pairs; all 58 also match in the
packet fold, with no pending/unmatched movement and 7/7 heartbeats.

`--emit-mob-movement-broadcast X:Y:FOOTHOLD[:STANCE]` appends one
state-driven opcode `282` for the sole active modeled mob after all explicit
post-transcript frames. `plan_mob_movement_broadcast()` validates the replay
and optional separate movement-evidence transcript, adopts typed entries,
controller spawns, leaves, and earlier broadcasts, then emits only the exact
captured stationary shape: control `0000ff00000000`, reference equal to the
single absolute command, zero velocity, and duration 1,080 ms. Stream `92`
contains 5,284 broadcasts, 5,230 with that control prefix, 1,509 exact
stationary placements across the captured stances, and 1,055 for default
stance `4`.

The real-client proof injected a template-`100100` snail at `(433,-2677)` on
foothold `635`, generated one placement at `(833,-2677)`/stance `4`, and kept
stream `114` open. The snail appeared at the predicted right-side location;
runtime status reported one planned/sent packet. The independently observed
transcript folded validly to the exact predicted mob position and stance with
one broadcast/command and 11 matched heartbeats.

`--emit-mob-movement-path EVIDENCE_SERVER_FRAME:X:Y:FOOTHOLD` is mutually
exclusive with the stationary option. It selects an exact evidence frame for
the same active template, requires two or more absolute commands and the
dominant control prefix, translates every captured position to the requested
endpoint, preserves velocities/stances/durations, and rewrites footholds only
when the live origin already has the requested foothold. Stream-`92`
server-direction frame `18818` provides a five-command, 48-pixel, 1,080-ms
path. A live run translated it from reference `(785,-2677)` to endpoint
`(833,-2677)` for template `100100`; the client rendered that endpoint and the
transcript folded validly with five type-`0` commands and 9/9 matched
heartbeats. This proves explicit replay of a captured path, not autonomous path
selection.

`--emit-mob-movement-auto-path X:Y:FOOTHOLD` removes the evidence-frame input.
It filters the capture catalog by active template and exact
endpoint-minus-current displacement, groups candidates by relative
position/velocity/stance/duration shape, and refuses zero or multiple distinct
shapes. Stream `92` has one path and one shape for template `100100` movement
`(48,0)`, so the live selector chose frame `18818`, produced the same endpoint,
and rendered the snail at `(833,-2677)`. The new transcript folds validly with
five type-`0` commands and 13/13 matched heartbeats.

`--emit-mob-movement-composed-path MAX_STEPS:X:Y:FOOTHOLD` performs bounded
breadth-first composition from unique capture-backed displacement shapes. It
excludes ambiguous displacements, requires every step to reduce Manhattan
distance, checks all intermediate `int16` positions, and refuses multiple
shortest sequences. Stream `92` has 167 usable and 38 ambiguous displacements
for template `100100`. The unique route from `(785,-2677)` to `(881,-2677)` is
frame `18818` twice; the client rendered the final endpoint and the independent
fold validated two broadcasts, ten commands, and 11/11 heartbeats.

`--mob-movement-step-delay-seconds SECONDS` gives the generated movement
sequence its own nonnegative inter-step pace without delaying unrelated
post-transcript packets. Explicit per-gap delays retain precedence. Each
connection constructs a mutable `MobMovementBroadcastScheduler`; it validates
entity/template/field/object identity and exact position/foothold/stance
continuity, then advances only after the expected encrypted packet drains.
Its confirmed packet prefix can be supplied to the existing planner, so a
later in-process decision starts from the last transmitted intermediate state.
The real-client proof observed `planned (785) -> in_progress (833) -> complete
(881)` at `0/2`, `1/2`, and `2/2` packets. The folded movement events were
10.002838 seconds apart, with ten type-`0` commands and 10/10 heartbeats.

`--queue-mob-movement-composed-path MAX_STEPS:X:Y:FOOTHOLD` adds up to eight
startup-configured follow-up decisions after any initial movement emission.
A target is not planned until the preceding schedule's final write drains;
the planner receives only the original baseline plus confirmed movement
frames. Its capture fold runs through `asyncio.to_thread`, keeping the client
and status API responsive in the explicit `planning` phase. HTTP remains
read-only. The live proof sent an automatic path to `833`, planned a two-step
follow-up only afterward, then sent `881` and `929`. Status progressed through
`planning (833, 1/1 known)`, `in_progress (881, 2/3)`, and `complete (929,
3/3)`. The independent transcript is valid with three broadcasts, fifteen
type-`0` commands, exact position/foothold/stance continuity, and 8/8
heartbeats.

Movement evidence is folded into one immutable `MobMovementPlanningContext` at
listener startup and reused by the initial and queued planners. The safe API
`planning_cache` block reports replay/evidence frame, captured path/broadcast,
and stationary-stance counts. On `111.pcapng`, building the context took
10.432799 seconds; cached automatic and composed planning then took 0.000360
and 0.005125 seconds. A second live run preserved the same three-packet result
with movement gaps of 10.008720 and 10.002057 seconds, eliminating the prior
32.5-second refold from the first gap. Its valid transcript contains fifteen
type-`0` commands and 6/6 matched heartbeats.

`--mob-movement-relative-policy DECISIONS:MAX_STEPS:DX:DY:FOOTHOLD` replaces
an explicit follow-up target list with a small deterministic state policy. It
derives each next endpoint from the last confirmed position, permits `1..8`
decisions and `2..8` composed steps, rejects zero displacement or out-of-range
coordinates, and remains mutually exclusive with explicit queued targets. A
live two-decision `(+96,0)` policy produced
`833 -> 929 -> 1025` after the initial packet. The scheduler sent five packets
total, the client rendered the final endpoint, and the independent fold
validated all five broadcasts/twenty-five commands with four approximately
three-second gaps and 6/6 heartbeats.

`--mob-movement-policy-trigger matched-heartbeat` makes each relative
follow-up wait for a client opcode `23` that matches an outstanding periodic
server opcode `10`; it therefore also requires
`--world-heartbeat-interval-seconds`. One match starts at most one decision.
The initial movement is still sent normally, the authorized decision's first
packet is immediate, and the movement-step delay applies only between its
remaining packets. Safe `policy_trigger` API counters report matched events,
started/completed decisions, events ignored after completion, and whether a
pending decision is currently `awaiting_event`.

A browser-free real-client run with five-second heartbeats and one-second
movement pacing again reached `785 -> 833 -> 881 -> 929 -> 977 -> 1025`.
Heartbeat response frames `78` and `83` immediately preceded movement frames
`79` and `84`; the four movement gaps were 5.326966, 1.000527, 3.999752, and
1.000549 seconds. The valid transcript contains five broadcasts, twenty-five
type-`0` commands, and 21/21 matched heartbeats. Runtime finished two gated
decisions and ignored one later matched event after completion; the HTTP API
remains read-only.

`--mob-movement-policy-cooldown-seconds SECONDS` applies the same bounded
post-decision cooldown to any event-driven trigger. Values are limited to
`0..3600`; a positive value conflicts with the immediate trigger. The timer is
armed only after a complete decision drains. Qualifying events inside it are
counted in `events_rejected_by_cooldown` but neither plan nor send movement;
the first qualifying event after expiry can re-arm one pending decision. Safe
API state also reports `cooldown_seconds`, `last_event_outcome`, and
`last_cooldown_remaining_seconds`.

In the browser-free five-second live proof, heartbeat response frame `78`
authorized movement frames `79`/`80`; response frames `82`, `84`, and `86`
were rejected during cooldown; response frame `88` re-armed movement frames
`89`/`90`. Runtime completed two gated decisions with three cooldown
rejections. The valid, warning-free transcript ends at `(1025,-2677)` with
five broadcasts, twenty-five type-`0` commands, and 16/16 matched heartbeats.

When transcript recording is enabled, the scheduler also writes identifier-free
`runtime_event` annotations for trigger observations, decision
starts/completions, cooldown rejections, and completed-queue ignores. The
gameplay analyzer emits them in timestamp order with `direction: runtime` and
the preceding packet frame index. The writer caps annotations at 16,384,
stores written/dropped counts in the close record, and turns any drop into an
analysis warning. In the live proof, frames `78`/`80` mark decision 2,
`82`/`84`/`86` carry cooldown rejections with 4.006931/2.007733/0.006772
seconds remaining, and `88`/`90` mark the re-armed decision 3. The independent
fold is valid and warning-free at `(1025,-2677)` with 15/15 heartbeats.

`--mob-movement-policy-trigger served-mob-movement` is the client-originated
alternative. It requires `--reactive-mob-movement-acknowledgements`; one
opcode-`207` submission starts one decision only after the modeled policy
accepts it and its opcode-`283` acknowledgement drains. Rejected submissions
do not authorize movement. The API uses `awaiting_event` to distinguish this
state from an active capture-backed planning call.

In the browser-free live proof, the initial movement was frame `77`, the real
client's sequence-`1` submission was frame `78`, its matched acknowledgement
was frame `79`, and the gated movement packets were frames `80`/`81`. The
server reached `833 -> 881 -> 929`; the internal packet gap was 1.000714
seconds. The valid transcript contains three broadcasts/fifteen type-`0`
commands, one submitted/acknowledged/matched movement with nothing pending,
and 4/4 independently matched heartbeats. Runtime completed one gated decision
and cleared `awaiting_event`; HTTP remains read-only.

`--mob-movement-policy-trigger player-proximity` uses typed local-player
opcode-`182` path endpoints and requires
`--mob-movement-proximity-radius PIXELS` in `1..4096`. It compares Manhattan
distance with the scheduler's confirmed mob position and is edge-triggered:
the first inside observation or a later outside-to-inside transition may start
one decision, while repeated inside observations may not. Identifier-free
`proximity` API state reports safe positions, distance, radius, and event/entry
counts.

In the live negative control, direct nested-Wayland Left input produced an
endpoint 310 pixels from the mob and no movement decision. Direct Right later
produced frame `107` at `(855,-2695)`, 40 pixels from confirmed
`(833,-2677)` inside radius `64`. Generated movement frames `108`/`109`
followed 0.009526/1.001263 seconds later and completed
`833 -> 881 -> 929`. The valid transcript contains six live predicate
observations/one entry, three broadcasts/fifteen type-`0` commands, and 11/11
independently matched heartbeats. HTTP remains read-only.

The heartbeat direction is established by capture order, not opcode frequency:
in every sustained stream-`92` pair, server opcode `10` precedes client opcode
`23`. The client responds 0.65-90.91 ms later (20.76 ms average). The fold
tracks matched, unmatched, and pending probes, so reversing this interpretation
or losing a response is visible in state and warnings.

Server opcode `426` and client opcode `309` form a second, payload-free pair;
they are not conflated with the opcode-`10`/`23` heartbeat. Stream `126` has
299 exact notification/acknowledgement pairs, stream `92` has 61, and stream
`114` has one. Every server packet precedes its client packet, no capture has
an unmatched or pending member, and the pending queue never exceeds one. The
pinned client handler independently constructs and sends an opcode-only `309`
packet when `426` arrives. The fold emits full-coverage events plus last/max
round-trip telemetry, while the still-unknown higher-level purpose remains
neutral.

Client opcode `101` is an exact 11-byte numeric record: one byte, one
little-endian 32-bit value, one byte, one little-endian 16-bit value, and a
final byte after the opcode. Stream `126` has 146 packets and stream `92` has
73; stream `114` has none. The outer bytes and flag are always zero. In stream
`126`, the `(primary, secondary)` pairs are `(20,3)` 113 times and
`(0x0a000014,0)` 33 times; stream `92` uses `(20,5)` 66 times and the alternate
pair seven times. Every packet consumes exactly and round-trips. Because the
32-bit value is two discrete, non-monotonic values, the earlier tentative
`client_tick` label is not retained; the fold emits neutral numeric
distributions and partial semantic coverage.

Client opcodes `50`, `52`, and `54` are a capture-correlated attack-action
family. Stream `126` contains 552 opcode-`50`, 130 opcode-`52`, and 120
opcode-`54` actions; stream `92` adds 128 opcode-`52` and 31 opcode-`54`
actions. The extended `50`/`52` variants place a known mob object id at offset
21, and every opcode-`54` packet places one at offset 16. The fold aliases that
target, distinguishes active/previously-known/unknown mobs, redacts client
tokens, and emits one `client_attack_submitted` event per action. In a targeted
`50`/`52` suffix, a 14-byte opaque target prefix is followed by one u32 damage
word per hit and an opcode-specific 8/9-byte opaque tail. Stream `126` exposes
420 client damage words (`1..42`, total `6964`) and stream `92` exposes 226
(`0..49`, total `4864`); no client damage word sets the high bit. Exact variant
and suffix boundaries round-trip, while control/value and target prefix/tail
roles remain neutral.

The fold queues each nonzero damage word from targeted `50`/`52` submissions
as an individual hit effect for that mob. Each opcode-`293` update consumes one
hit, so multi-hit actions produce multiple correlations; zero-damage words need
no response. Stream `126` matches all 399 health packets and clears 21 terminal
hits at mob/field lifecycle boundaries. Stream `92` matches all 208 health
packets, clears 11 terminal hits, and accounts for seven zero-damage words.
Both finish with no pending hit. Health events carry the action frame, hit
index, damage array, selected damage word, and response time.

For the 11 mob templates attacked in these captures, `REFERENCE_MOB_MAX_HP`
contains the official client's version-specific WZJS `info/maxHP` values. The
fold interprets opcode `293` as `floor(current_hp * 100 / max_hp)`, retains the
corresponding integer-HP interval, and predicts the next interval after each
correlated hit. Stream `92` validates all 161 transitions with a prior health
sample exactly. Stream `126` validates 203 of 209 exactly; the other six differ
by one HP, all with response delays of `0.389..0.460` seconds. These remain
explicit semantic warnings rather than packet-shape failures. No mismatch has
an intervening modeled attack-relay hit. Integer HP bounds infer authoritative-
minus-submitted damage of `+1` for five and `-1` for one.

Server opcodes `218` and `219` form the corresponding capture-bounded attack
relay family. Their prefix is opcode, player object id, and one packed byte;
the high nibble is the target count and the low nibble is the hit count. Stream
`126` contains 41/99 relays and stream `92` contains 1/42. Every actor id is a
player id known somewhere in its capture. Packed counts bound repeated records
of mob id, hit-action byte, and one u32 damage word per hit. Stream `126`
contains 123 target records: 118 name known mobs and five are all-zero opcode-
`218` placeholders; its 166 damage words have low-31-bit magnitudes `0..80` and
12 set high-bit markers. Stream `92` has 71 known-mob records and 88 damage
words (`1..366`, 20 high-bit markers). Every nonzero target uses hit action
`6`. The fold aliases actors and targets and reports damage telemetry while
accumulating hit/damage totals on each currently active mob. It retains the
damage high-bit meaning as opaque.

All 42 opcode-`218` relays also have typed metadata. Their first six bytes are
relay tag, captured-zero skill level, one still-unknown byte, display, facing
flags, and attack speed. The 37 full forms append mastery `0` and auxiliary u32
`0`. The five stream-`126` short forms stop after attack speed and each carries
exactly one all-zero target/hit/damage placeholder; the decoder rejects that
length for any other target shape. Stream `126` observes relay tags `8`/`16`,
displays `5`, `6`, `7`, `9`, `11`, `16`, and `17`, facing flags `0`/`0x80`,
and speeds `4`/`6`; the one stream-`92` relay independently uses tag `14`,
display `17`, facing `0x80`, and speed `6`.

All 141 opcode-`219` relays have a typed ranged prefix. It starts with a relay
tag and skill level, inserts a little-endian skill id exactly when the level is
nonzero, then carries one still-unknown byte, display, facing flags, attack
speed, mastery, and a projectile item id. The four-byte tail is two signed
16-bit position coordinates. Stream `126` contributes skill ids `3001005` and
`4001344` plus projectiles `2060000`/`2070000`; stream `92` independently adds
skill `3101005` and projectile variants `2070009`/`2070015`. At packet time,
all 99 stream-`126` positions and 30 of 42 stream-`92` positions can be compared
with a previously observed remote-player position; common vertical deltas are
roughly 22-28 pixels, while larger deltas follow stale movement broadcasts.
The fold emits both positions and their deltas as validation evidence. Relay-
tag/unknown/auxiliary roles, the damage high bit, client target prefix/tail
fields, and the six delayed one-HP prediction differences still prevent a
claim that captured official combat relays or authority adjustments can be
reproduced exactly.

The custom server does have a narrower opt-in mob-health responder for state it
owns. `--reactive-mob-health-responses` derives exact active HP where possible,
adopts later typed opcode-`279` spawns whose template has a referenced max HP,
and handles targeted client opcode `50`/`52` during hold-open. Each nonzero,
non-high-bit damage word subtracts from integer HP in order and emits one typed
opcode-`293` floor-percentage update. Zero damage emits nothing; damage after
HP reaches zero in the same multi-hit action is skipped. A transition to zero
emits opcode `293` with percentage `0`, then opcode `280` with leave reason `1`,
and removes the mob from mutable state. Unknown/inactive targets, absent damage
arrays, ambiguous adopted HP, and high-bit damage are rejected rather than
guessed.

For a controlled final-field target, a typed opcode-`279` PCAP source supports
`?mob-spawn=X:Y` or `?mob-spawn=X:Y:FOOTHOLD:ORIGIN`. This rewrites only the
validated signed position and optional foothold fields while preserving the
captured object/template/remaining spawn shape. The live proof used stream
`114`, injected stream-`92` frame `563` (template `100100`, max HP `8`) at the
player position, and received a real opcode-`52` variant-`18` attack with
damage `[27,32]`. The responder emitted opcodes `[293,280]`: the first hit
produced `8 -> 0`, the already-terminal second hit was skipped, and the client
remained active with generated heartbeats. The observed transcript folds
validly with one attack, one zero-health update, one leave, no active mob, and
no pending hit effect. This validates the modeled request/effect/lifecycle;
because the injected spawn had no preceding opcode-`293` sample, it is not an
additional offline next-percentage prediction sample.

With transcript recording enabled, reactive combat also emits bounded runtime
events for request observation, response completion, and safe rejection. In a
fresh browser-free run, targeted opcode-`52` frame `85` recorded damage
`[27,32]`; completion frame `87` recorded `8 -> 0`, percentage `[0]`, emitted
opcodes `[293,280]`, removal, and one skipped terminal hit. A second physical
Ctrl swing produced an untargeted observation/rejection at frame `99` and no
response. The valid, warning-free fold has two attacks/59 damage, one matched
health effect, no active mob or pending effect, and 17/17 heartbeats.

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
Inventory-move and item-acquisition request/match/pending/latency counters,
redacted opcode-`276` selector/shape/group/pair counters, and client positioned-
effect action alias/distribution counters belong to the finalized
`analyze-gameplay --json` state. The runtime route intentionally reports
connection and configured-protocol telemetry rather than continuously
refolding an incomplete transcript, and neither route exposes plaintext.
When periodic world heartbeats are enabled,
`protocol.world_heartbeat` reports the interval, probes sent, responses
observed, pending probes, and last/maximum round-trip milliseconds.
When the baseline initial snapshot is generated,
`protocol.initial_field_snapshot_emitter` reports its frame index, emitter,
inventory group/item counts, skill count, progression shape/variant,
original/emitted/max HP, prediction, and patch count. When initial player HP is
rewritten, the same fields appear under
`protocol.initial_player_hp_rewrite`.
When fixed-width server records are generated,
`protocol.fixed_server_record_emitter` reports every original frame index,
opcode, neutral shape/value, field epoch, patch count, and the predicted
unchanged player/phase state. Character ids are omitted; opcode `59` reports
only its flag, zero-reserved invariant, and world-entry match.
When variable server records are generated,
`protocol.variable_server_record_emitter` reports the two frame indices,
opcodes, discriminator values, opaque-tail lengths, field epochs, patch count,
and unchanged player/phase prediction. Opaque bytes are never returned.
When NPC spawn frames are generated, `protocol.npc_spawn_emitter` reports the
typed emitter, frame/patch count, represented field epochs, identifier-free
alias/template/position/range records, and the predicted capture-equivalent
NPC state.
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
`protocol.mob_movement_acknowledgements.state` reports the identifier-free
derived policy, evidence, final field epoch, and known/active counts. The parent
object reports observed submissions, sent responses, rejections, the last safe
response (template, sequence, flag/value/auxiliary fields), and the last safe
rejection. A planned placement or captured path appears under
`protocol.mob_movement_broadcast`, including the aliased entity/template,
previous and predicted position/foothold/stance, typed packet fields, evidence
counts, `mode`, optional source server-frame index, and planned/sent counters.
Automatic plans also report the number of matching displacement paths and
distinct relative motion shapes, making the uniqueness decision inspectable.
Composed plans additionally report their step bound, selected source-frame
sequence, intermediate step plans, usable/ambiguous displacement counts, and
shortest-sequence count. The parent reports planned/sent/remaining packet
counts. Its mutable `state` reports `planned`/`planning`/`in_progress`/
`complete`, current and target position/foothold/stance, last sent and next
safe step, confirmed movement-frame count, and the baseline-plus-confirmed
frame count available to later planning. Queued runs also expose the bounded
decision totals, planned/completed/remaining counts, active or planning
decision index, and pending safe targets under `state.decision_queue`.
`packets_remaining` counts only packets already planned; it is zero during a
worker-backed `planning` phase even though an unplanned target remains. State
changes after the socket write drains; it is not a client acknowledgement.
The sibling `planning_cache` object reports the immutable evidence material
available to those decisions; it never contains raw object or character IDs.
When reactive mob-health responses are
enabled,
`protocol.mob_health_responses.state` reports field epoch, aliased active mobs,
template/current/max HP, floor percentage, capture-evidence counters, and the
exact response rules. The parent object reports observed/served/rejected
requests, response packets sent, and the last identifier-free response plan,
including submitted damage, HP before/after, percentages, skipped zero or
already-terminal hits, removal, and emitted opcode numbers. A safe
`last_rejection` explains the most recent no-response decision without closing
the held-open connection. The six official
one-HP differences remain visible in offline `analyze-gameplay --json`
evidence; runtime generation applies the documented exact custom-server rule.
Other methods are rejected with `405`;
unknown paths return `404`. The API
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
nanosecond timestamp, direction, and base64 payload. Recorded replays may also
contain bounded, JSON-safe `runtime_event` annotations; those records never
stand in for wire bytes. Close records report written/dropped annotation
counts, and the gameplay analyzer warns if the bound discarded any. Credentials
are read from environment variables and are never stored in a transcript.

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

If discovery is ambiguous, pass the known nested endpoints explicitly:

```sh
python tools/maplestory_classic_server/tools/launch_local_game.py --restart \
  --display :1 \
  --sway-socket /run/user/1000/sway-ipc.1000.195243.sock
```

The script discovers nested Sway/Xwayland, checks both namespace listeners,
requires the Maple-only audio mute service to be active, launches the local
placeholder argument tuple, waits for a Maple window whose PID belongs to the
newly live client process set, and focuses that exact Sway container. This keeps
stale Xwayland Maple nodes from satisfying launch readiness.
It intentionally cannot launch an authenticated official session.
The socket/display values are not stable across compositor restarts; the
explicit flags are a deterministic fallback when automatic selection finds
zero or multiple candidates.

Pointer input should use `swaymsg -s SOCKET 'seat seat0 cursor ...'` against
the nested compositor. For Unity raw keyboard input, send a physical evdev code
directly to that Wayland seat:

```sh
XDG_RUNTIME_DIR=/run/user/1000 WAYLAND_DISPLAY=wayland-2 \
python tools/maplestory_classic_server/tools/send_wayland_evdev_key.py \
  leftctrl --hold-ms 100
```

The helper builds/caches its checked-in C client and does not use X11 or move
the main desktop cursor. It was required because named `wtype` events did not
preserve distinct Unity scan codes in this setup.

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
6. Parse and re-emit the typed character list with the `?character-list`
   transform, then return server time and the captured type-`7` envelope for
   opcode `5`.
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
    progression state, then reuse its stat prefix to decode and emit the login
    character-list records without opaque record bytes.
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
    predicted live red-potion quantity `2 -> 1` and HP `50 -> 100` effects;
    record request/completion/rejection events and prove the last-item
    rejection leaves the client and heartbeat exchange active.
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
29. Reuse the neutral opcode-`13` family on world sessions, add its fixed
    type-`1` envelope, and validate all 970 long-corpus instances plus the
    type-`1`/`6`/`13` variants in stream `92` without exposing their bodies.
30. Bound both client opcode-`217` variants and their format-`0`/`2` counted
    records, fold only safe structural distributions, and keep the family out
    of replay until an effect correlation establishes its semantics.
31. Type the empty server opcode-`426` notification and client opcode-`309`
    acknowledgement, prove one-for-one temporal matching in every reference
    world stream, and retain a neutral name for their higher-level purpose.
32. Bound client opcode `101` as a fixed five-value record, validate all 219
    sustained-capture instances, and keep its non-monotonic 32-bit field
    neutral instead of preserving an unsupported `client_tick` interpretation.
33. Bound client opcode `54` as a fixed seven-value record, validate all 151
    sustained-capture packets, and recover its third trailing u32 as the mob
    target while leaving the other numeric roles neutral.
34. Correlate client opcodes `50`/`52`/`54` with mob targets, bound server
    attack relays `218`/`219`, fold identifier-safe combat events and packed
    count distributions, and leave damage/replay semantics explicitly opaque.
35. Decode every relay target/hit-action/damage array, validate 194 target
    records and 254 damage words across both sustained captures, and keep
    replay disabled until attack metadata and mob HP mapping are recovered.
36. Type all 141 opcode-`219` ranged prefixes and signed positions, validate
    conditional skill ids plus projectile/display/facing/speed/mastery fields
    across both sustained captures, and correlate packet positions with the
    fold's previously observed remote-player positions.
37. Type all 42 opcode-`218` metadata prefixes, distinguish 37 full forms from
    five short all-zero target placeholders, and enforce that short-form target
    invariant during parse and re-encoding.
38. Decode all 646 targeted client damage words, fold their per-mob totals, and
    establish an initial action-level set of 490 opcode-`50`/`52` to opcode-
    `293`/lifecycle correlations.
39. Refine attack correlation to one effect per nonzero damage word, account
    for all 607 opcode-`293` responses and 32 terminal hits, recover the 11
    referenced mob max-HP values from the official WZJS bundle, and validate
    364/370 bounded next-percentage predictions exactly with the six remaining
    observations differing by one HP.
40. Infer an authoritative damage range from consecutive integer-HP bounds and
    record attack-relay hits between submission and response. All six long-
    stream mismatches have no intervening modeled relay and exact authoritative-
    minus-submitted damage deltas `{-1: 1, +1: 5}`.
41. Add an opt-in exact-HP mob responder, typed opcode-`279` spawn-position
    transform, runtime API telemetry, and encrypted request/response tests.
42. Inject a typed `100100` mob into the real stream-`114` field, receive a
    two-hit opcode-`52`, emit the predicted zero-health/leave sequence, fold
    the resulting transcript validly, and preserve active heartbeats. Retain a
    separate boundary around unresolved official ±1 HP authority adjustments.
43. Bound the initial neutral server set `69`/`93`/`201`/`205`, consume and
    round-trip its 145 reference packets exactly, and expose safe numeric
    distributions without leaking potentially identifying primary values;
    item 54 records the later generated-shape expansion.
44. Model opcode-`189`/`190` remote-player entry and removal from pinned client
    handlers, validate all 153 lifecycle packets, and live-test an exact
    enter/move/leave/enter sequence against the rendered client.
45. Fully decode opcode-`247` tutorial-UI instructions, round-trip all 33
    reference packets, and verify that two exact live injections are accepted
    without blocking the active client while leaving rendering state-gated.
46. Decode opcode-`244` selector `8`, round-trip all 54 reference packets, and
    reproduce its instructional NPC dialogue on the live client while keeping
    the three signed 32-bit value roles neutral.
47. Decode all 82 opcode-`320`/`322`/`323` positioned-effect records, correlate
    every update within its field epoch, and live-validate that changing only
    typed coordinates moves a transient visual effect to the predicted player
    position without changing HP.
48. Decode all 36 opcode-`302` NPC lifecycle spawns, reuse the exact typed
    opcode-`300` body, fold later NPC updates against the new entities, and
    live-validate client acceptance of a position-composed spawn. Keep the
    handler-backed control-`0` removal branch marked as unobserved until a live
    A/B can complete before the replay hold expires.
49. Bound observed opcode-`239` selectors `3`/`9`/`13`/`21`, round-trip all 60
    reference packets, fold their structural distributions, and redact every
    record key and UTF-16 string while leaving unobserved selectors unknown.
50. Bound observed opcode-`348` selectors `0`/`3`/`6`/`17`, round-trip all 31
    level-1-to-10 packets, emit identifier-safe structural events, and keep
    the primary values and UTF-16 strings out of reports and HTTP state.
51. Bound all six observed client opcode-`122` selector/count shapes, round-trip
    all 62 level-1-to-10 packets, fold their redacted structural distributions,
    and preserve unobserved shapes as unknown without assigning meanings to
    their u32 values.
52. Decode all 29 cross-corpus opcode-`224` records, prove that each references
    an active remote player and active mob template, enforce the marker/flag/
    reserved/repeated-value invariants, and keep the shared u32 value neutral.
53. Decode the ten opcode-`285` sets and five opcode-`286` resets, fold the
    captured status bit into field-local mob state, match every set to its
    preceding attack-relay target/skill, and preserve source-level/duration
    values as neutral pending a live effect test.
54. Consume the automatic IL2CPP dump's exact opcode-`60` `i32`, opcode-`94`
    `bool + i32 + i32`, and opcode-`379` discriminator/datetime reads; promote
    all 14 reference packets to full events, add native boolean validation to
    the Rust shape engine, and replay a typed opcode-`94` packet into the live
    client with unchanged world/player/inventory/progression state and a fresh
    matched heartbeat.
55. Add the automatic dump's delegated opcode-`148` envelope, round-trip all
    23 cross-corpus packets, retain the one legacy nonempty record body as an
    explicit partial observation, and live-replay the bounded empty variant
    with unchanged gamestate, advancing heartbeats, and no connection failure.
56. Replace the stream-specific opcode-`43` manifest switch with its two real
    client envelopes, model the fixed server envelope, round-trip all 48
    cross-corpus packets, and live-replay the server branch with unchanged core
    state, advancing heartbeats, and no client or injection failure.
57. Bound all 44 client opcode-`114` packets as one redacted text envelope,
    preserve the control and trailing-value roles as neutral, publish only safe
    structural distributions, and reduce the long-corpus unknown count to 105.
58. Bound all 31 client opcode-`66` packets, match each one FIFO to the prior
    same-selector server opcode-`348` envelope, publish only selector/status/
    shape and timing evidence, and reduce the long-corpus unknown count to 74.
    An exact selector-`0` server packet from the level-1-to-10 session did not
    elicit opcode `66` from the active level-12 short-stream client and the
    world connection closed, so cross-state replay remains explicitly unsafe.
59. Drive server opcodes `147` and `272` from the automatic IL2CPP dump plus a
    focused live primitive-reader trace, promote all six cross-corpus packets
    to exact full coverage, fold their redacted structural ledgers, and replay
    opcode `272` twice through the active real client with the predicted core
    gamestate unchanged.
60. Drive server opcodes `27`, `28`, `142`, and `425` from the automatic dump
    plus exact cross-corpus parsing, promote all 11 gameplay packets to full
    coverage, and validate all 13 selected private-regression packets natively
    and through round-trip Python codecs. Trace opcode `425` live, replay it
    through the loopback packet API, observe the predicted second neutral
    ledger event with unchanged core state, then restore a browser-free,
    direct-Wayland, audio-muted client to the field.
61. Bound server opcodes `228`, `230`, `231`, `232`, `234`, and `235` from
    their generated one-`u32` handlers, preserve all seven observed ignored-tail
    widths without inventing semantics, and move all 12 packets from unknown
    to redacted partial neutral events. Defer live replay because the leading
    value and tails may be session-local state.
62. Replace the 3,725-byte opcode-`135` opaque pin with the automatic handler's
    complete four-section count grammar, validate its 1,350 primitive reads and
    exact Python/Rust consumption, fold only redacted structural totals, and
    replay the captured plaintext through the sole local-Wine connection with
    the world socket and generated heartbeats still active.
63. Replace the opcode-`394` and client-opcode-`279` opaque pins with exact
    redacted UTF-16 envelopes, correlate the sole captured pair without
    inventing security semantics, validate both codecs and manifest shapes,
    and record the local-Wine negative replay result that kept gameplay healthy
    but emitted no opcode `279`.
64. Promote the repeated client opcode-`75` field-bootstrap marker and both
    opcode-`241`/status/terminal world-exit sequences into exact redacted
    gamestate events, close every unknown packet in short stream `114`, and
    confirm opcode `75` independently in the running local-Wine transcript.
65. Fold client opcodes `100`, `307`, `308`, and `311` as exact-width redacted
    records, publish only counts, body widths, phases/epochs, and the captured
    `308`/`311` cadence, then bound the three controlled local-Wine menu
    confirmations as a separate opaque opcode-`310` record. Validate both
    sustained captures plus the live transcript without equating opcode `310`
    with the captured opcode-`241` exit request.
66. Decode both client opcode-`79` inventory-move requests, match each FIFO to
    the authoritative same-inventory/source/destination server opcode-`39`
    move, validate the 13-byte shape natively and in Python, expose safe
    request/match/pending/latency telemetry, and reduce stream `126` to 37
    unknown packets without assigning a meaning to the trailing signed count.
67. Decode all 15 fixed client opcode-`225` positioned-effect actions, redact
    their primary keys behind the existing effect aliases, prove that every key
    is current-field-known and every packet follows opcode `50` in client order,
    validate the 16-byte shape natively, and reduce stream `126` to 22 unknown
    packets without naming the two u32 values or u16 trailer.
68. Decode all 12 client opcode-`298` item-acquisition requests, redact their
    serial values, correlate each request with the next same-epoch opcode-`39`
    additions by kind-derived inventory and item template, retain Cash quantity
    distinctions as telemetry, validate exact Python/Rust consumption, and
    reduce stream `126` to 10 unknown packets.
69. Decode the sole 210-byte stream-`126` opcode-`276` selector-`24` grouped
    record plus the active client's nine-byte selector-`17` compact form,
    redact all header/group/pair values, validate both exact branches, remove
    the live transcript's final unknown, and reduce stream `126` to nine
    unknown packets without assigning a higher-level opcode role.
70. Decode all six client opcode-`222` compact pickup requests, prove their
    field epochs and drop ids against folded active state, correlate every
    inventory/mesos effect, gain notice, and reason-`2` exact-id removal,
    validate Python/Rust exact consumption, eliminate the six pickup-chain
    warnings, and reduce stream `126` to three unknown packets without naming
    the compact/full source distinction.
71. Decode both 10-byte client opcode-`64` position actions, prove their signed
    coordinates against the last same-epoch opcode-`47` life-movement endpoint,
    correlate the next opcode `348`, and validate exact Python/Rust consumption
    without assigning the neutral u32 or a causal request role.
72. Decode the sole eight-byte client opcode-`111` Cash-slot action, correlate
    signed slot `3` with the next opcode-`39` Cash remove/add, preserve the u32
    and higher-level purpose as neutral, validate exact Python/Rust consumption,
    and reduce stream `126` to zero unknown packets.

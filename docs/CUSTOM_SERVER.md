# Custom server laboratory

## Location

```text
/home/sdancer/ms/tools/maplestory_classic_server/
```

This is a standalone Python tool (with PyCryptodome for Maple AES and optional
`tshark` for PCAP input). It is intentionally not part of the Albion Phoenix
application.

## Tests

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server
python -m unittest discover -s tests -v
```

The last run passed all 126 tests.

## Inspect and compare captures

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

python -m maple_server inspect \
  /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl

python -m maple_server compare \
  /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  /home/sdancer/ms/downloads/maple_protocol_captures/1786118506764535468_52.193.141.80_10282.jsonl
```

`inspect` prints structural information without dumping payloads. `compare`
reports event sizes, common prefixes/suffixes, and equal-position counts while
keeping sensitive bytes out of terminal output.

For PCAP or JSONL login logs, use the typed state fold instead:

```sh
python -m maple_server analyze-login \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 83 \
  --packets \
  --fail-on-invalid
```

It reassembles TCP, validates cipher headers and IV progression, parses known
packet shapes, and applies them to account/world/channel/character/handoff
state. `--packets` prints frame-aligned decoded fields and timing; `--json`
emits the same records for tooling. Account and character IDs are redacted
unless explicitly requested.

World logs use the corresponding gameplay fold:

```sh
python -m maple_server analyze-gameplay \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --packets \
  --events \
  --fail-on-invalid
```

It validates frame shapes and state invariants, emits typed field events, and
folds the initial player/map/inventory/progression snapshot plus subsequent
NPC, mob, movement, transition, termination, and heartbeat traffic.

The repository-root level-1-to-10 corpus is stream `126`:

```sh
python -m maple_server analyze-gameplay \
  --pcap /home/sdancer/ms/1-10FS.pcapng \
  --tcp-stream 126
```

Normalization removes its measured 14-byte server and 28-byte client
transport preludes before the Maple greeting. It then decrypts 71,100 frames,
folds one marker-`26` initial snapshot plus 35 later field epochs, and validates
all 197 pickup requests against known drops and matching epochs. It now passes
`--fail-on-invalid`: 25,597 observations are full, 43,954 partial, 1,549
unknown-but-lossless, and none invalid. The 12 remaining warnings are state
correlations, not shape failures. The opcode-`158` stage-`0` variant keeps its
neutral word `1` and nine-byte tail as partial semantic coverage.

Player movement appears as decoded opcode-`182` submissions and opcode-`202`
broadcasts. The short stream prints one local path ending at `(633,-2677)` and
two remote-player broadcasts under session-local aliases. The long stream
validates and round-trips 531 submissions, 113 broadcasts, and all 4,281
commands, with fixed tags `0/1/3/5` and payload sizes `13/7/5/13` bytes.

The analyzer also bounds client opcode `47` and server opcode `217` as a
separate life-movement relay family. Stream `126` contributes 2,585 client
submissions and 347 server broadcasts, all consuming exactly; stream `92`
exercises all fixed client-tail variants. Command bytes and neutral control/
tail roles remain opaque, so these packets are partial rather than full.

Client opcode `13` is shared with the login protocol but persists in gameplay.
The analyzer now accepts the exact 11-byte type-`1` shape and the existing
length-prefixed type-`6`/`13` variants, exposing only type and opaque-byte
counts. Stream `126` contains 970 type-`1` packets; stream `92` contains 555
packets across all three observed variants, all with exact round trips.
Together, these latest modeled families leave the long-corpus totals at 25,597
full, 43,954 partial, 1,549 unknown-but-lossless, and zero invalid.

Client opcode `217` is modeled separately from server opcode `217`. Its 345
compact packets are exactly eight bytes. The other 592 packets contain a
ten-byte opaque prefix, count/format bytes, fixed records (14 bytes for format
`0`, 11 for format `2`), and an eight-byte opaque trailer. All 937 stream-`126`
instances round-trip and fold into safe count/format distributions. No active
mob-id or sub-second server opcode-`219` correlation was found, so the server
does not synthesize or replay this still-neutral client family.

The analyzer separately matches exact empty server opcode `426` notifications
to exact empty client opcode `309` acknowledgements. All 299 stream-`126`, 61
stream-`92`, and one stream-`114` pairs are ordered and matched, with no pending
or unsolicited member. Pinned client code confirms that handling `426`
constructs and sends opcode `309` without a body. State and events expose pair
counts and round-trip timing, while deliberately leaving the higher-level role
neutral and distinct from the opcode-`10`/`23` heartbeat.

Client opcode `101` is now structurally decoded as an exact 11-byte record
containing byte/u32/byte/u16/byte values. All 146 stream-`126` and 73
stream-`92` instances round-trip. Reports expose only numeric distributions;
the 32-bit field takes two discrete, non-monotonic values, so it remains
neutral rather than using the shape manifest's tentative `client_tick` label.

Client opcodes `50`/`52`/`54` now fold into one attack-action model. Stream
`126` has 802 actions and stream `92` has 159. Extended opcode-`50`/`52`
variants and every opcode-`54` action carry a capture-correlated mob target;
safe output aliases it and omits client tokens. Server opcodes `218`/`219`
likewise fold as 140 and 43 attack relays, with aliased actors and packed
target/hit counts. Their remaining bodies and exact damage fields stay opaque,
so the custom server validates but does not generate or replay combat yet.

## Replay the login capture locally

The network namespace redirects the client's destination port `10282` to local
port `12082` **inside that namespace**. Start the listener inside
`mapleproxy`; a host-only listener will not receive the redirected socket:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/login
```

Replay is strict by default. A fresh launch has ticket/session-dependent client
bytes, so use `--no-strict` for exploratory client behavior after confirming
where the strict mismatch occurs:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --no-strict \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/login
```

## Current capture-backed login/world experiment

`111.pcapng` stream `83` is a successful login reference and stream `92` is
its successful world connection. PCAP plaintext is resolved inside the server
process, so private account/character records never appear as command-line hex
or committed fixtures. The working login composition is:

1. replay the proven local HK bootstrap/NGS transcript, but omit captured
   server frame `4` (opcode `23`);
2. on native client opcode `6`, send successful stream `83` server frame `13`
   (the six-byte opcode-`23` response);
3. on native client opcode `13`, send the local acknowledgment followed by
   successful account frame `3` (opcode rewritten `0` to local handler `1`),
   world frames `5` through `9`, and sentinel frame `10`;
4. on client opcode `4`, send frames `15` and `16` with delays `0,2.5`, and
   rewrite frame `16`'s stage-1 world id from the live selection;
5. on client opcode `5`, send character frames `17`, `18`, and `19` with
   delays `0,0,1.0`;
6. on client opcode `7`, send handoff frame `20` after transforming only its
   endpoint to `127.0.0.1:12857`.

Repeated `--reply-on-client-opcode-from-pcap` options for one opcode form the
ordered response sequence. Configure the capture-faithful waits with:

```text
--drop-server-frame 4
--reply-on-client-opcode-from-pcap 6=/home/sdancer/ms/111.pcapng@83:13
--client-opcode-reply-delays 4=0,2.5
--client-opcode-reply-delays 5=0,0,1.0
--rewrite-channel-transition-world
```

Dropping an encrypted server frame is not a ciphertext splice. The replay
decrypts the original stream with its captured IV progression and re-encrypts
all emitted later frames after removing one IV step. Reactive frames then use
the resulting post-transcript IV, so the client remains synchronized.

The live client now renders all five world tabs and their online channels.
The first untimed run sent both opcode-`402` frames back-to-back: selecting
world `2` made the client emit opcode `4` twice, receive both `402` frames, and
then stall without emitting channel opcode `5`. This is the evidence for the
2.5-second reactive delay, not a guessed UI delay.
The next timed run exposed a separate packet-shape mismatch: the client chose
world `1`, while captured frame `16` still named world `4`. The typed fold now
rejects this combination before replay, and the reactive rewrite binds the
stage-1 response to the triggering opcode-`4` world id.

The corrected timing and live-world rewrite now produce client opcode `5`
reliably and reach the character-selection controller. Frames `17` and `18`
are sufficient to reach that controller. A native authenticated A/B run then
replayed the same sequence without frame `19`: it reached the identical
“connecting to server” overlay, and character/start clicks still emitted no
opcode `7`. The earlier run that did send frame `19` also emitted no later
packet. Therefore type `7` is neither required to reach character selection nor
sufficient to complete it; the capture's following type-`6` packets do not by
themselves prove a request/response security relationship.

Sending the valid transformed handoff frame `20` proactively still only blanks
the scene: no TCP connection reaches `12857`, and the client exits after the
login connection closes. This bounded the then-missing requirement to a
client-side completion/selection transition rather than server validation of
frame `19`; the ordered opcode-`6` experiment below resolves that transition.

A follow-up live probe sent the successful capture's server opcode `23` again
after the character list, time, and type-`7` envelope. The client answered with
an opcode-`13` type-`15` status carrying an empty message, remained at character
selection, and emitted neither opcode `7` nor another type-`6` packet. That
proved a late duplicate is insufficient, but it did not test the capture's
request/response ordering.

The decisive clean run withheld bootstrap server frame `4` until the real
client opcode `6` appeared. The client then received the same six-byte opcode
`23`, returned a non-empty type-`15` status, entered world/channel/character
selection without any synthetic NGSX-success patch, and emitted character
opcode `7` after the Start click. The typed fold reached valid `handoff_ready`,
the transformed frame `20` was returned, and the client opened the local world
replay on port `12857`. Security completion is therefore required, and opcode
`23` must follow the actual opcode `6`; replaying it by captured event count can
send it too early when a fresh client emits extra frames.

For subsequent runs, start the listener composition, then launch the client
without the browser:

```sh
cd /home/sdancer/ms
python tools/maplestory_classic_server/tools/launch_local_game.py --restart
```

The launcher checks both namespace listeners, nested Sway/Xwayland, and the
persistent Maple-only audio mute service before using the local placeholder
arguments.

Start the local target for the transformed handoff separately:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 92 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/world
```

PCAP replay normalizes TCP segments to handshake/frame-aligned transcript
events before serving them. The login handoff builder validates that the
selected and handed-off character IDs match before rewriting the endpoint.

## Typed initial-HP effect validation

The first state-driven field mutation uses the complete large opcode-`157`
model instead of a raw byte offset. Start the stream-`114` world target inside
`mapleproxy` with:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --rewrite-initial-current-hp 1 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/initial_hp_1 \
  --timing-scale 1 \
  --hold-open-seconds 300
```

The planner first requires a valid gameplay fold and exactly one typed initial
snapshot. It bounds HP by the decoded maximum, replaces only the nested
`current_hp`, requires the generated packet to retain its length, parses it
back, and refuses a raw patch targeting the same server frame. The loopback
status route is:

```sh
sudo ip netns exec mapleproxy curl \
  http://127.0.0.1:12858/api/v1/status
```

The 2026-08-08 real-client run planned captured HP `50/222 -> 1/222`, patched
one frame, entered map `101000000`, and displayed `HP 1 / 222`. Runtime status
reported one completed connection, all 29 generated probes answered, and none
pending. Its observed transcript folded validly to `active`, HP `1/222`, the
original inventory and progression, nine NPCs, and all 30 heartbeat pairs
matched including the captured pair. This matches the planner's
identifier-free prediction across packet, client, and folded-state evidence.

## Typed post-transcript HP update validation

Opcode `41` is the captured player-stat delta family. The model decodes the
observed INT, LUK, HP, MP, AP, EXP, and 64-bit mesos mask bits, folds each
field independently, and preserves the neutral request flag and final marker.
To emit a new current-HP delta after stream `114`:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --emit-current-hp-update 1 \
  --post-transcript-start-delay-seconds 10 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/current_hp_stat_1 \
  --timing-scale 1 \
  --hold-open-seconds 180
```

The planner validates current/max HP, bounds the requested value, generates
`29000000040000010000`, parses it back, and publishes
`protocol.player_stat_update` with its prediction and sent count. The real
client accepted the packet and displayed `HP 1/222`, while MP remained
`97/342` and EXP remained `1464`. The recorded exchange folded validly to
`active`, with one HP event carrying `previous:50` and `current:1`, and all
nine generated heartbeats matched in the completed transcript. This is a
post-entry state delta, separate from rewriting the initial snapshot.

## Typed inventory-quantity effect validation

Opcode `39` carries inventory change sets. The decoder handles the observed
empty, add, stack-quantity, and remove operations, reuses the initial-inventory
stack/cash record grammar, and applies modifications to known slots. To mutate
an existing stack after stream `114`:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --emit-inventory-quantity-update use:15:1 \
  --post-transcript-start-delay-seconds 15 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/inventory_use15_1 \
  --timing-scale 1 \
  --hold-open-seconds 180
```

The planner resolves Use slot `15` to item template `2000000`, validates its
captured quantity `27`, bounds the replacement, generates
`2700000101020f000100`, parses it back, and publishes
`protocol.inventory_quantity_update`. The real inventory window displayed
quantity `1` in that slot. The completed observed transcript folded validly to
`active`, recorded `previous_quantity:27` and `quantity:1`, retained the item
count and player state, resolved every slot, and matched all 18 generated
heartbeat pairs.

## Reactive consumable-use validation

Client opcode `80` is the capture-validated Use-item request. The typed policy
checks its signed slot and item template against current inventory state, then
emits the observed two-packet response: opcode `39` decrements the stack and
opcode `41` applies the captured HP/MP effect with maximum-stat capping. Only
red potion `2000000` (`+50 HP`) and blue potion `2000014` (`+80 MP`) are enabled;
unknown templates, mismatched/empty slots, capped stats, and the still-unknown
last-item removal shape are rejected.

The live red-potion experiment used:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --world-heartbeat-interval-seconds 10 \
  --emit-inventory-quantity-update use:15:2 \
  --post-transcript-start-delay-seconds 15 \
  --reactive-item-use-responses \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/reactive_item_use_red \
  --timing-scale 1 \
  --hold-open-seconds 300
```

Stream `92` supplies 17 independent request/effect examples: 13 blue potions
and four red potions. All 17 requests are exact 12-byte shapes, match the
modeled Use slot/template, decrement quantity by one, and match the following
stat effect. In the live run, the initial typed update visibly changed red
potions `27 -> 2`; using one produced client opcode `80`. Runtime telemetry
reported one observed/served request, zero rejections, and two response
packets. The client displayed quantity `1` and HP `100/222`, exactly matching
the `2 -> 1` and `50 -> 100` prediction. The completed transcript folded with
one inventory match, one stat-effect match, zero mismatches/pending requests,
and 20/20 matched heartbeat pairs.

## Pickup request/effect validation

The gameplay analyzer now decodes the complete capture-observed pickup chain:
server opcode `311`, client opcode `185`, the positive opcode-`39` inventory or
opcode-`41` mesos effect, server opcode `49`, and server opcode `312`. Stream
`92` contains 125 spawns for 66 unique drops, 54 requests (48 base plus six
with a 12-byte opaque proof), 54 short result records, and 100 removals. All
records round-trip. Fifty-nine drops have an exact mode-`1`/mode-`0` refresh
pair and seven are mode-`2` field-load items. Every pickup request names a
known active spawn; all 54 result values and all 54 local removals match that
spawn, with zero pending requests. Reports use field-local `drop:N` aliases and
do not print runtime drop, owner, source-mob, or actor ids.

Stream `114` ends with one active mode-`2` drop: item template `4000004` at
`(-863,-1742)`. The final folded player position is `(633,-2677)`, and Etc
slot `7` contains the same item at quantity `74`. Stream `92` independently
proves four pickups of template `4000004`, each as an Etc quantity delta of one,
an item gain notice quantity of one, and a reason-`5` removal whose actor equals
the spawn's two captured owner values.

The replay now has two typed controls for a real pickup A/B:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer env \
  PYTHONPATH=/home/sdancer/ms/tools/maplestory_classic_server \
  /usr/bin/python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12857 \
  --http-api-host 127.0.0.1 \
  --http-api-port 12858 \
  --no-strict \
  --pcap /home/sdancer/ms/111.pcapng \
  --tcp-stream 114 \
  --keep-world-open \
  --rewrite-final-field-drop-position 633:-2677 \
  --rewrite-final-field-drop-owner-to-player \
  --reactive-item-pickup-responses \
  --item-pickup-evidence-tcp-stream 92 \
  --world-heartbeat-interval-seconds 10 \
  --transcript-dir \
  /home/sdancer/ms/downloads/maple_custom_server_observed/reactive_item_pickup \
  --timing-scale 1 \
  --hold-open-seconds 300
```

The rewrite changes only the typed coordinates in the 38-byte captured spawn;
the drop id, item template, ownership-neutral fields, expiration, and flags are
preserved and round-trip. The reactive policy accepts only the known active
drop, current field epoch, deterministic captured template effect, and exactly
one existing stack with capacity. It predicts and emits opcode `39` (`74 ->
75`), opcode `49` (item `4000004`, quantity `1`), and opcode `312` (reason `5`)
in that order, then removes the drop from mutable server state. Mesos, special,
new-slot, ambiguous-stack, and unknown-template cases remain rejected. The
client still supplies its own validation token; the server does not synthesize
or assign semantics to it.

The owner rewrite is a separate same-length typed patch. It validates exactly
one initial player and one final field-load item, then changes only the two
neutral owner words. `protocol.final_field_drop_owner_rewrite` exposes the
aliased drop, item template, flag, frame/field epoch, patch count, and the
identifier-free prediction fields `drop_owner_fields: match_initial_player`
and `pickup_eligibility: requires_additional_client_conditions`.

That conservative prediction follows the real-client result: rewriting the
mode-`2` owner words did not produce opcode `185`, and neither did a second
probe that sent a captured-shaped mode-`1`/mode-`0` pair at the final player
position. The client stayed responsive, the pickup key binding and direct
Wayland input were verified, and the reactive API recorded zero pickup
requests. Owner equality and proximity are therefore not sufficient on their
own; the next experiment must isolate the remaining client eligibility state
instead of treating a generated response as proof that the client accepted
the drop.

## Historical synthetic staging experiment

The replay can patch captured server frames, react to a decrypted client
opcode, append plaintext frames, and control every gap independently. The
current experiment uses these post-transcript plaintext messages in order:

```text
queued opcode-13 acknowledgment
opcode-1 bounded account-success probe
opcode-2 world 0 / channel 0 record
opcode-2 signed-id -1 sentinel
```

Use repeated `--post-transcript-gap-delay-seconds` values for the gaps in that
combined sequence. The current diagnostic timing is `0,15,120`: no wait before
the account frame, 15 seconds before the world record, then two minutes before
the sentinel. The long final gap permits a pre-sentinel structural dump because
the sentinel consumes or clears the controller's staging list. If fewer gap
values are supplied, later gaps fall back to
`--post-transcript-frame-delay-seconds`.

`--send-after-transcript` and `--send-zero-filled-after-transcript` share one
argument destination, so their command-line order is preserved. This matters:
an earlier implementation grouped explicit frames ahead of zero-filled frames
and accidentally sent the world list before the account transition.

Captured server frame index `3` is a 12-byte opcode-`0` status whose result
byte is `2`; replaying it produces the policy-restriction dialog. Replace the
whole frame with heartbeat `0a00`. Rewriting only its result byte to zero is
not a success path—it displays “Logging in, please wait.”

The two-byte opcode-`1` transition probe bypasses required controller setup.
Use `--send-zero-filled-after-transcript 1:128:0` to let the original handler
initialize its state. The current canonical diagnostic command is:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --no-strict \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/login \
  --initial-delay-seconds 20 \
  --hold-open-seconds 300 \
  --server-frame-patch 0=000000010000000000000400740065007300740000000000000000000000000000000000 \
  --server-frame-patch 3=0a00 \
  --reply-on-client-opcode 13=0d0000 \
  --send-zero-filled-after-transcript 1:128:0 \
  --send-after-transcript 0200000400740065007300740000000000000000000001060074006500730074002d0031000000000000000000000000000000 \
  --send-after-transcript 0200ff \
  --post-transcript-gap-delay-seconds 0 \
  --post-transcript-gap-delay-seconds 15 \
  --post-transcript-gap-delay-seconds 120
```

For a structural run, arm
`tools/gdb_stage_opcode2_controller_capture.py` with action `arm` after the
module is loaded, poll with action `status`, restore after capture, and use
action `dump` before the sentinel. It validates the handler and executable
padding bytes and never remains attached. Do not use the persistent breakpoint
probe for timing-sensitive runs; it stalls Wine rendering.

## Replay the `58880` exchange

The namespace redirects destination port `58880` to local port `12080`:

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server

sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server replay \
  --listen-host 0.0.0.0 \
  --listen-port 12080 \
  --no-strict \
  --transcript /home/sdancer/ms/downloads/maple_protocol_captures/1786118312530175497_54.238.121.146_58880.jsonl \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/world
```

Start both listeners in separate terminals, then use the direct client launch
from `CLIENT.md`.

## Stub and capture-proxy modes

Minimal stub:

```sh
sudo ip netns exec mapleproxy sudo -u sdancer python -m maple_server stub \
  --listen-host 0.0.0.0 \
  --listen-port 12082 \
  --transcript-dir /home/sdancer/ms/downloads/maple_custom_server_observed/stub
```

The package also provides a direct `capture-proxy` mode. Its proxy password is
read from `MAPLE_PROXY_PASSWORD`; never pass it as a CLI argument. See the
project's own `README.md` for all options.

## Proven behavior

- The custom login replay served 22,074 bytes identical to the recorded
  official server stream.
- A fresh client sent 1,335 bytes; the first 159 bytes matched the recorded
  client session before per-session material diverged.
- Both login and `58880` connections were served locally; the upstream relay
  saw neither port during the proof run.
- The finite transcript closes after its recorded events. The client then
  reconnects approximately every 2.2 seconds, so stop it promptly or add a
  hold-open/stateful server behavior before long tests.
- The screenshot of the local replay result is at
  `/home/sdancer/ms/downloads/maple_custom_server_replay.png`.
- Native client opcode `13` is decryptable and can be acknowledged reactively.
- Direct transition probes reached the real world and character scenes.
- Replaying captured frame `3` causes the policy dialog; replacing it with a
  heartbeat removes the dialog while preserving the remaining setup stream.
- The original account handler accepts the bounded zero-filled probe, creates
  an empty world staging list, and reaches the world-selection UI after its
  informational modal is dismissed.
- A corrected 51-byte opcode-`2` record is structurally intended to describe
  one world and one channel; its strings require a trailing byte after their
  UTF-16LE contents. The handler is confirmed to run, but the live count must
  still be sampled before the sentinel clears the staging list.
- Uniform post-frame timing delivered world packets during the opcode-`1`
  scene change, before the opcode-`2` handler was active. Per-gap scheduling
  was added specifically to remove that race.
- The successful PCAP account packet, five full 60-channel worlds, sentinel,
  selections, and handoff all pass the typed packet/state validator.
- A live capture-backed replay renders the five world tabs and their online
  channels. Client opcode `4` identifies the selected world.
- The two opcode-`402` packets require their observed 2.5-second gap; sending
  them together stalls before the client emits channel opcode `5`.
- With the gap and live-world rewrite, the client emits opcode `5` and accepts
  the character list and server time. Withholding the captured opcode-`23`
  response until native client opcode `6` completes the security exchange; the
  client then emits character opcode `7`, accepts the rewritten handoff, and
  connects to the local world replay.
- Proactively sending a valid handoff without that gate produces a black scene,
  no world-port connection, and client exit after the login socket closes.
- The MapleStory PipeWire stream is kept muted by the enabled
  `maplestory-audio-mute.service`, using application identity rather than a
  changing node number.
- A typed initial opcode-`157` HP rewrite changed `50/222 -> 1/222`; the real
  HUD and independently folded active game state both reported `1/222` while
  map, inventory, progression, and client liveness matched the prediction.
- The gameplay analyzer now emits typed local/remote player movement records
  and folds their endpoints instead of reporting opcodes `182` and `202` as
  unknown packets. Both PCAP world streams validate without warnings.
- The analyzer now structurally decodes life movement opcodes `47`/`217`,
  folds command and client-tail distributions, redacts the client token, and
  validates all 2,932 packets from stream `126` without a shape failure.
- World-session opcode `13` now uses the neutral fixed/length-prefixed envelope
  decoder, accounting for all 970 long-corpus packets without exposing bodies.
- Client opcode `217` now has bounded compact and counted-record envelopes,
  accounting for all 937 long-corpus packets while deliberately remaining out
  of replay until its effect semantics are established.
- Empty server opcode `426` and client opcode `309` now fold as a one-for-one
  notification/acknowledgement pair across all three gameplay streams, with
  full shape coverage and explicit unmatched/pending telemetry.
- Client opcode `101` now folds all 219 sustained-capture packets into neutral
  five-field distributions with exact byte consumption and round trips.
- Client opcodes `50`/`52`/`54` now fold 961 sustained-capture attack actions
  with aliased mob targets where present; server opcodes `218`/`219` fold 183
  attack relays with packed target/hit counts. Opaque damage bodies remain out
  of generation and replay.
- All 333 long-stream opcode-`41` stat packets now round-trip and fold into
  player state. A generated HP-mask packet produced the predicted live
  `50/222 -> 1/222` HUD and event-state change without disturbing liveness.
- All 69 stream-`92` opcode-`39` packets now round-trip and fold 71 inventory
  modifications. A generated Use-slot quantity update produced the predicted
  live `27 -> 1` inventory UI and event-state effect without losing liveness.
- All 17 stream-`92` opcode-`80` requests now round-trip and correlate with
  exact stack decrements plus potion stat effects. A reactive live request
  produced the predicted red-potion `2 -> 1` and HP `50 -> 100` effects, with
  zero mismatches and continued heartbeats.
- All 125 stream-`92` opcode-`311` packets round-trip and fold into 66 drop
  lifecycles. All 54 pickup requests, gain values, effects, and local removals
  correlate with an active spawn; stream `114` ends with one modeled active
  item drop rather than none.
- The typed stream-`114` pickup plan resolves `drop:1`, item `4000004`, Etc
  slot `7`, quantity `74`, and the four matching stream-`92` effects. Its
  position rewrite round-trips at the same 38-byte width, and encrypted replay
  tests produce the predicted opcodes `39,49,312` and mutable `74 -> 75` state.
- Live owner-only and captured-shaped animated-drop probes both produced zero
  opcode-`185` requests, so runtime telemetry now treats owner equality as a
  modeled field relation rather than proof of pickup eligibility.

## Next server milestone

Replace the remaining opaque replay portions with stateful handling:

1. Decode the inner 167 bytes of each character-list response record and emit
   it from typed player state.
2. Isolate the additional client-side drop eligibility condition using the
   now-falsified owner/proximity baseline, then run the reactive pickup effect
   only after the real client emits opcode `185`.
3. Expand the proven typed opcode-`157` mutation into a generated initial field
   snapshot, then replace subsequent capture frames with state-driven packets.
4. Obtain a short final-field capture with a known mob and validate the typed
   movement-acknowledgement policy through the real client.
5. Name the remaining neutral account, equipment, progression, and trailer
   fields only when independent captures or controlled effects support them.

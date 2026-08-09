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

The last run passed all 105 tests.

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
  --pcap /home/sdancer/Downloads/111.pcapng \
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
  --pcap /home/sdancer/Downloads/111.pcapng \
  --tcp-stream 114 \
  --packets \
  --events \
  --fail-on-invalid
```

It validates frame shapes and state invariants, emits typed field events, and
folds the initial player/map/inventory/progression snapshot plus subsequent
NPC, mob, movement, transition, termination, and heartbeat traffic.

Player movement appears as decoded opcode-`182` submissions and opcode-`202`
broadcasts. The short stream prints one local path ending at `(633,-2677)` and
two remote-player broadcasts under session-local aliases. The long stream
validates and round-trips 531 submissions, 113 broadcasts, and all 4,281
commands, with fixed tags `0/1/3/5` and payload sizes `13/7/5/13` bytes.

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
--reply-on-client-opcode-from-pcap 6=/home/sdancer/Downloads/111.pcapng@83:13
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
  --pcap /home/sdancer/Downloads/111.pcapng \
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
  --pcap /home/sdancer/Downloads/111.pcapng \
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
  --pcap /home/sdancer/Downloads/111.pcapng \
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
- All 333 long-stream opcode-`41` stat packets now round-trip and fold into
  player state. A generated HP-mask packet produced the predicted live
  `50/222 -> 1/222` HUD and event-state change without disturbing liveness.

## Next server milestone

Replace the remaining opaque replay portions with stateful handling:

1. Decode the inner 167 bytes of each character-list response record and emit
   it from typed player state.
2. Continue the completed stat-delta model with short, isolated inventory
   request/effect pairs and fold item changes into game-state events.
3. Expand the proven typed opcode-`157` mutation into a generated initial field
   snapshot, then replace subsequent capture frames with state-driven packets.
4. Obtain a short final-field capture with a known mob and validate the typed
   movement-acknowledgement policy through the real client.
5. Name the remaining neutral account, equipment, progression, and trailer
   fields only when independent captures or controlled effects support them.

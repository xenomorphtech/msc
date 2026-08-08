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

The gameplay fold currently models these capture-backed boundaries:

- client opcode `8`: world-entry envelope (character id plus opaque ticket),
- server opcode `157`: field snapshot/change envelope (opaque body),
- client opcode `158`: the complete `1 -> 2` field-load stage sequence,
- server opcode `300`: complete 22-byte NPC spawn records,
- server opcode `303`: complete 8-byte NPC state updates,
- client opcode `207` and server opcode `283`: correlated mob movement headers
  with opaque movement/status bodies,
- client opcode `301`: the world-bootstrap acknowledgement envelope, and
- client opcode `23` / server opcode `10`: heartbeat
  request/acknowledgement, and
- server opcode `9`: the exact nine-byte world-session termination envelope;
  its seven-byte reason body remains opaque.

Unknown opcodes remain lossless frame observations and do not acquire semantic
names from frequency or adjacency alone. Default reports replace character and
runtime object ids with stable session-local aliases such as `npc:1`; use
`--show-identifiers` only for private debugging.

The full stream-`92` validation reaches `active` across 13 field epochs and
then changes to `terminated` on its final server opcode-`9` packet. All 26
field-load messages form 13 ordered stage pairs; all 53 NPC spawns and 77 NPC
state updates validate; 11,949 movement acknowledgements match prior captured
submissions; and all 75 heartbeats pair. Two movement submissions remain
pending at capture end.

A live replay A/B used the short stream-`114` field and repeated its server
frame `55`, an opcode-`303` update for an already spawned NPC. Baseline and
injected sessions both reached `active` with nine NPCs. The injected fold had
one additional server frame and one additional `npc_state_updated` event
(`2 -> 3`) while entity count and session phase stayed unchanged, matching the
prediction. Both sessions returned to login because the short capture's final
opcode-`9` packet explicitly terminates the world session, not because of
opcode `303`.

Repeating the real-client stream-`114` replay with its validated terminal
server frame omitted kept the character in the field for the complete
configured 600-second hold. The observed connection lasted 605.85 seconds
including replay/setup, remained `active` with nine NPCs, and closed only when
the hold expired. This validates the predicted difference between replaying
and omitting the modeled termination event; it does not yet establish an
indefinitely self-sustaining world server.

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
  --hold-open-seconds 600

curl http://127.0.0.1:8799/healthz
curl http://127.0.0.1:8799/api/v1/status
```

`GET /healthz` returns `{"ok":true}`. `GET /api/v1/status` reports the
listener mode/address, safe replay configuration, start time, and
accepted/active/completed/failed connection counters. Other methods are
rejected with `405`; unknown paths return `404`. The API deliberately has no
remote binding or mutating route: startup rejects non-loopback addresses, so
the current local-only threat model relies on OS/namespace access rather than
application authentication. Add authentication before introducing any remote
binding or mutating route. If the listener runs in `mapleproxy`, query the API
from that namespace as well.

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
placeholder argument tuple, waits for the window, and focuses it through Sway.
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
11. Decode the inner character list, player records, field snapshot body, and
    the reactive heartbeat/gameplay responses needed to make the world server
    self-sustaining beyond a finite replay hold.

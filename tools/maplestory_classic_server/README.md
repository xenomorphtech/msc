# MapleStory Classic custom-server laboratory

This directory contains the first protocol-compatible server tooling for the
Taiwan/Hong Kong MapleStory Classic Unity client. It is deliberately isolated
from the Albion Phoenix application.

## Confirmed client endpoints

The serialized `GameConfig` and a post-bootstrap packet capture establish:

- login hostname: `tw-login.maplestoryclassic.games.gamania.com`
- login TCP port: `10282`
- observed login address: `35.73.142.21:10282`
- observed world handoff: `54.238.121.146:58880`

The world connection exchanged 77 client bytes and 218 server bytes before it
closed. Login uses a 33-byte cleartext greeting followed by encrypted frames
whose four-byte headers encode payload length as the XOR of two little-endian
16-bit words. The observed greeting identifies protocol version `300`,
subversion `300`, and locale `4`.

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

## Current implementation steps

1. Run the replay listener inside the client's network namespace; host-only
   listeners do not receive namespace-local port redirects.
2. Replace captured server frame `3` with a heartbeat and use the bounded
   128-byte opcode-`1` payload to initialize the original account handler.
3. Delay the opcode-`2` sentinel and dump the world/channel staging list with
   `tools/gdb_stage_opcode2_controller_capture.py` before it is cleared.
4. Capture and decode the channel-selection and character-list exchange.
5. Implement stateful account, character, and map handlers incrementally.

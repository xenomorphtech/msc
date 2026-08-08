# Custom server laboratory

## Location

```text
/home/sdancer/ms/tools/maplestory_classic_server/
```

This is a standalone Python standard-library project. It is intentionally not
part of the Albion Phoenix application.

## Tests

```sh
cd /home/sdancer/ms/tools/maplestory_classic_server
python -m unittest discover -s tests -v
```

The last run passed all 31 tests.

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

## Current staged login/world experiment

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

## Next server milestone

Replace transcript replay with stateful handling:

1. Dump the one-world/one-channel staging list before the delayed sentinel.
2. Select its channel and capture the next client operation.
3. Implement the minimum character list and selection response.
4. Implement the first map handoff.
5. Replace the bounded account probe with a fully decoded account payload.

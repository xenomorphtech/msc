# Network and proxy setup

## Credential source

Raw account and proxy values are stored only in:

```text
/home/sdancer/ms/.env
```

The file is mode `0600`. It contains separate Taiwan and Hong Kong proxy
profiles plus generic `MAPLE_PROXY_*` variables selecting the current default.
Load it without echoing it:

```sh
set -a
. /home/sdancer/ms/.env
set +a
```

See `SECURITY.md` before copying commands or captures elsewhere.

## Known official endpoints

```text
tw-login.maplestoryclassic.games.gamania.com:10282  login
54.238.121.146:58880                                HTTP probe/handoff
54.65.46.47:5050                                   TLS bootstrap observed
```

The login hostname resolved to different AWS addresses across sessions,
including `13.115.120.13`, `52.193.141.80`, and `35.73.142.21`. Do not hard-code
one login address when proxying the official service.

## `mapleproxy` namespace

The browser and game were run in a Linux network namespace named
`mapleproxy`. TCP egress was transparently redirected to the local CONNECT
relay at port `12345`, while explicit returns prevented loops for loopback,
the namespace subnet, and proxy-server addresses.

Inspect the existing setup with:

```sh
sudo ip netns list
sudo ip netns exec mapleproxy ip address
sudo ip netns exec mapleproxy ip route
sudo ip netns exec mapleproxy iptables -t nat -S OUTPUT
```

The last custom-server layout added these redirects before the general relay:

```text
destination TCP 10282 -> local 12082  (login replay/server)
destination TCP 58880 -> local 12080  (HTTP probe/world replay)
all other selected TCP -> local 12345 (transparent HTTP CONNECT relay)
```

These are namespace-local redirects. A replay process bound only on the host
does not receive them even if it listens on `0.0.0.0`; run ports `12082` and
`12080` inside `mapleproxy` or install an explicit namespace-to-host bridge.
This topology error caused the earlier false conclusion that an all-HK launch
never opened the login socket.

Loopback and the namespace's own `10.207.0.0/24` subnet must return before the
general redirect. The upstream proxy addresses must also return or the relay
will proxy itself recursively.

## Transparent CONNECT relay

Implementation:

```text
/home/sdancer/ms/.codex_tmp/maple_transparent_proxy.py
```

It obtains the original destination with `SO_ORIGINAL_DST`, opens an HTTP
CONNECT tunnel through the selected proxy, and records configured ports as
lossless JSONL. It expects:

```text
MAPLE_PROXY_HOST
MAPLE_PROXY_PORT
MAPLE_PROXY_USER
MAPLE_PROXY_PASSWORD
MAPLE_CAPTURE_DIR           optional
MAPLE_CAPTURE_PORTS         default: 10282,58880
MAPLE_CAPTURE_MAX_BYTES     default: 16777216 per direction
```

Start it only after loading `.env`; do not place credentials directly in a
command line because process listings can reveal them. A launch pattern is:

```sh
set -a
. /home/sdancer/ms/.env
set +a
export MAPLE_CAPTURE_DIR=/home/sdancer/ms/downloads/maple_protocol_captures
sudo --preserve-env=MAPLE_PROXY_HOST,MAPLE_PROXY_PORT,MAPLE_PROXY_USER,MAPLE_PROXY_PASSWORD,MAPLE_CAPTURE_DIR \
  ip netns exec mapleproxy \
  sudo -u sdancer --preserve-env=MAPLE_PROXY_HOST,MAPLE_PROXY_PORT,MAPLE_PROXY_USER,MAPLE_PROXY_PASSWORD,MAPLE_CAPTURE_DIR \
  python /home/sdancer/ms/.codex_tmp/maple_transparent_proxy.py
```

If captures for a new port are needed, also export `MAPLE_CAPTURE_PORTS` and
preserve that variable through both `sudo` calls.

## Capture directories

```text
/home/sdancer/ms/downloads/maple_protocol_captures/
/home/sdancer/ms/downloads/maple_custom_server_observed/login/
/home/sdancer/ms/downloads/maple_custom_server_observed/world/
```

Capture directories are mode `0700`; transcripts are mode `0600`. JSONL data
records contain timestamps, direction, and base64 payload. They can include
session tickets or identifiers even though proxy credentials are not recorded.

## What the proxy experiments showed

- The full HK browser/game route reaches the custom login server when the
  replay listener runs inside `mapleproxy`. It is the current laboratory route.
- The policy-restriction dialog seen during replay came from captured server
  frame index `3` (opcode `0`, result `2`), not from Wine or proxy geography.
- Direct host egress produced a system error.
- Taiwan routing can also reach the local redirects, but it is no longer
  preferred over a consistent all-HK launch.
- After the dedicated browser cookies were deliberately cleared, fresh login
  attempts through both HK and Taiwan returned Beanfun timeout `01004`. The
  identical result on both exits rules out proxy country as the immediate
  cause; wait for the login transaction cooldown before further launches.
- Proxifying the game itself fixed local-routing leakage after excluding
  loopback from transparent redirection.
- Local redirects for `10282` and `58880` were proven: the upstream relay saw
  neither connection during the replay test.

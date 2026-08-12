# MapleStory Classic Wine deployment on Vast.ai

`tools/maplestory_classic_server/tools/deploy_vast_wine_client.sh` installs and
runs the Windows MapleStory Classic client and the capture-backed custom server
on one disposable Vast.ai node. It downloads the official game payload from the
NGM CDN, validates every manifest chunk and final file, starts a private display,
starts the login and world servers, and launches the client through Wine.

The game, captures, credentials, and Vast API key are deliberately not committed
to the repository. Keep the API key in the repository's ignored `.env` file and
provide the capture artifacts when preparing the deployment bundle.

## Node requirements

Provision an Ubuntu 24.04 Vast.ai instance with direct SSH and:

- an NVIDIA GPU and the Vast NVIDIA driver/runtime;
- at least 8 GB RAM;
- at least 25 GB of disk;
- outbound HTTPS access to `tw-ngm.maplestoryclassic.games.gamania.com`.

The script automatically binds headless Xorg to the GPU reported by
`nvidia-smi`, including hosts that expose several NVIDIA device nodes. It checks
that GLX reports an NVIDIA renderer before launching Wine. If no NVIDIA Xorg
driver is available, it falls back to Xvfb; that fallback is useful for
diagnostics but is normally too slow for interactive Unity rendering.

Vast instances continue billing until they are destroyed. Note the instance ID
when provisioning and destroy the instance after collecting the required logs.

## Required local artifacts

Prepare these files before deployment:

| Bundle path | Local source | Purpose |
| --- | --- | --- |
| `server/` | `tools/maplestory_classic_server/` | Custom login/world server |
| `deploy_vast_wine_client.sh` | `tools/maplestory_classic_server/tools/` | Deployment entry point |
| `manual_ngm_extract.mjs` | `downloads/manual_ngm_extract.mjs` | Integrity-checking CDN downloader |
| `manifest.json` | `downloads/maplestory_classic_manifest.json` | Captured NGM game manifest |
| `login.jsonl` | a successful login transcript | Login bootstrap/replay source |
| `111.pcapng` | a successful login/world capture | Dynamic login replies and world stream |

The default login transcript used during development was
`downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl`.
The script also accepts alternate locations through `MAPLE_SERVER_ROOT`,
`MAPLE_DOWNLOADER`, `MAPLE_MANIFEST`, `MAPLE_LOGIN_TRANSCRIPT`, and
`MAPLE_PCAP`.

Do not add raw captures to a commit without reviewing them for account,
character, host, and packet data.

## Build and upload the bundle

From the repository root, create an isolated bundle. `CAPTURE_PCAP` and
`LOGIN_TRANSCRIPT` must point to the reviewed local artifacts:

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
BUNDLE_DIR="$(mktemp -d)"
CAPTURE_PCAP="${REPO_ROOT}/111.pcapng"
LOGIN_TRANSCRIPT="${REPO_ROOT}/downloads/maple_protocol_captures/1786118307321677094_13.115.120.13_10282.jsonl"

install -d "${BUNDLE_DIR}/server"
rsync -a --exclude '__pycache__/' \
  "${REPO_ROOT}/tools/maplestory_classic_server/" "${BUNDLE_DIR}/server/"
install -m 0755 \
  "${REPO_ROOT}/tools/maplestory_classic_server/tools/deploy_vast_wine_client.sh" \
  "${BUNDLE_DIR}/deploy_vast_wine_client.sh"
install -m 0644 "${REPO_ROOT}/downloads/manual_ngm_extract.mjs" \
  "${BUNDLE_DIR}/manual_ngm_extract.mjs"
install -m 0600 "${REPO_ROOT}/downloads/maplestory_classic_manifest.json" \
  "${BUNDLE_DIR}/manifest.json"
install -m 0600 "${LOGIN_TRANSCRIPT}" "${BUNDLE_DIR}/login.jsonl"
install -m 0600 "${CAPTURE_PCAP}" "${BUNDLE_DIR}/111.pcapng"
```

Set the direct SSH endpoint shown by Vast and upload the bundle:

```bash
VAST_HOST="203.0.113.10"
VAST_SSH_PORT="22022"
SSH_KEY="/absolute/path/to/id_ed25519"

ssh -i "${SSH_KEY}" -p "${VAST_SSH_PORT}" root@"${VAST_HOST}" \
  'install -d -m 0755 /workspace/maple-vast'
rsync -az -e "ssh -i ${SSH_KEY} -p ${VAST_SSH_PORT}" \
  "${BUNDLE_DIR}/" root@"${VAST_HOST}":/workspace/maple-vast/
```

Remove the temporary local bundle after the upload. The remote bundle remains
under `/workspace/maple-vast` until the Vast instance is destroyed.

## Install and run

The `all` command is safe to rerun. Existing valid game files are revalidated
and retained, and only processes tracked by the deployment are restarted.

```bash
ssh -t -i "${SSH_KEY}" -p "${VAST_SSH_PORT}" root@"${VAST_HOST}" \
  '/workspace/maple-vast/deploy_vast_wine_client.sh all'
```

The official manifest currently contains 168 files, about 2.11 GB compressed
and 3.05 GB uncompressed. The download command does not report success until
all files pass their manifest size and SHA-1 checks.

For incremental operation, use:

```bash
/workspace/maple-vast/deploy_vast_wine_client.sh install
/workspace/maple-vast/deploy_vast_wine_client.sh download
/workspace/maple-vast/deploy_vast_wine_client.sh display
/workspace/maple-vast/deploy_vast_wine_client.sh servers
/workspace/maple-vast/deploy_vast_wine_client.sh launch
```

The script maps the official login hostname to `127.0.0.1` on the node. The
custom login server listens on `127.0.0.1:10282`, hands the selected character
to the world server on `127.0.0.1:12857`, and exposes identifier-safe world
status on `127.0.0.1:12858`. None of these ports is exposed publicly.

## Verify the deployment

Confirm GPU acceleration:

```bash
grep -E 'direct rendering|OpenGL vendor|OpenGL renderer|OpenGL version' \
  /opt/maple-vast/logs/glxinfo.log
```

Expected output includes `direct rendering: Yes` and an NVIDIA renderer. Check
the custom world after the client has selected a character:

```bash
/workspace/maple-vast/deploy_vast_wine_client.sh status
```

A successful in-game session has one active world connection, an emitted
initial field snapshot, and heartbeat response counters that continue to rise.
The startup TCP readiness probe intentionally produces one completed/failed
zero-byte connection before the game connects; evaluate the active connection
and heartbeat counters rather than that probe alone.

Capture the virtual desktop for visual confirmation:

```bash
/workspace/maple-vast/deploy_vast_wine_client.sh screenshot \
  /opt/maple-vast/logs/maple-field.png
```

Relevant logs and evidence are under `/opt/maple-vast/logs/`:

- `wine-client.log` and the Wine prefix's Unity `Player.log`;
- `login-server.log` and `login/*.jsonl`;
- `world-server.log` and `world/*.jsonl`;
- `xorg.log`, `glxinfo.log`, and screenshots.

The Unity log is normally located below
`/opt/maple-vast/wineprefix/drive_c/users/maple/AppData/LocalLow/Nexon/`.

## Stop and destroy

Stop only this deployment's PID-tracked processes with:

```bash
/workspace/maple-vast/deploy_vast_wine_client.sh stop
```

Stopping the processes does not stop Vast billing. Download any evidence you
need, then destroy the instance through the Vast console, CLI, or API.

## Overrides

Common environment overrides include:

- `MAPLE_DISPLAY_BACKEND=auto|nvidia|xvfb`;
- `MAPLE_SCREEN=1360x768x24`;
- `MAPLE_DOWNLOAD_CONCURRENCY=8`;
- `MAPLE_CDN_BASE=https://...`;
- `MAPLE_RUNTIME_ROOT=/opt/maple-vast`;
- the five artifact-path variables listed above.

Run `deploy_vast_wine_client.sh --help` for the complete command list.

#!/usr/bin/env bash
set -Eeuo pipefail

# Deploy and run the MapleStory Classic Wine client and the capture-backed
# custom server on one disposable Vast.ai instance.  The deployment bundle is
# expected to contain this script plus:
#   server/                 the maplestory_classic_server directory
#   manual_ngm_extract.mjs  the integrity-checking NGM CDN downloader
#   manifest.json           the captured NGM file manifest
#   login.jsonl             the local bootstrap/login transcript
#   111.pcapng              successful login/world reference streams

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly MAPLE_RUNTIME_ROOT="${MAPLE_RUNTIME_ROOT:-/opt/maple-vast}"
readonly MAPLE_SERVER_ROOT="${MAPLE_SERVER_ROOT:-${SCRIPT_DIR}/server}"
readonly MAPLE_DOWNLOADER="${MAPLE_DOWNLOADER:-${SCRIPT_DIR}/manual_ngm_extract.mjs}"
readonly MAPLE_MANIFEST="${MAPLE_MANIFEST:-${SCRIPT_DIR}/manifest.json}"
readonly MAPLE_LOGIN_TRANSCRIPT="${MAPLE_LOGIN_TRANSCRIPT:-${SCRIPT_DIR}/login.jsonl}"
readonly MAPLE_PCAP="${MAPLE_PCAP:-${SCRIPT_DIR}/111.pcapng}"
readonly MAPLE_CDN_BASE="${MAPLE_CDN_BASE:-https://tw-ngm.maplestoryclassic.games.gamania.com}"
readonly MAPLE_USER="${MAPLE_USER:-maple}"
readonly MAPLE_DISPLAY="${MAPLE_DISPLAY:-:99}"
readonly MAPLE_SCREEN="${MAPLE_SCREEN:-1360x768x24}"
readonly MAPLE_GAME_DIR="${MAPLE_GAME_DIR:-${MAPLE_RUNTIME_ROOT}/game}"
readonly MAPLE_WINEPREFIX="${MAPLE_WINEPREFIX:-${MAPLE_RUNTIME_ROOT}/wineprefix}"
readonly MAPLE_LOG_DIR="${MAPLE_LOG_DIR:-${MAPLE_RUNTIME_ROOT}/logs}"
readonly MAPLE_RUN_DIR="${MAPLE_RUN_DIR:-${MAPLE_RUNTIME_ROOT}/run}"
readonly MAPLE_VENV="${MAPLE_VENV:-${MAPLE_RUNTIME_ROOT}/venv}"
readonly MAPLE_EXE="${MAPLE_GAME_DIR}/Maplestory_Classic.exe"

log() {
  printf '[maple-vast] %s\n' "$*"
}

fail() {
  log "ERROR: $*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || fail "this command must run as root"
}

require_file() {
  [[ -f "$1" ]] || fail "required file is missing: $1"
}

as_maple() {
  runuser -u "$MAPLE_USER" -- env \
    HOME="${MAPLE_RUNTIME_ROOT}/home" \
    XDG_RUNTIME_DIR="${MAPLE_RUNTIME_ROOT}/runtime" \
    DISPLAY="$MAPLE_DISPLAY" \
    WINEPREFIX="$MAPLE_WINEPREFIX" \
    WINEARCH=win64 \
    WINEDEBUG=-all \
    "$@"
}

prepare_directories() {
  require_root
  if ! id "$MAPLE_USER" >/dev/null 2>&1; then
    useradd --create-home --home-dir "${MAPLE_RUNTIME_ROOT}/home" --shell /bin/bash "$MAPLE_USER"
  fi
  install -d -o "$MAPLE_USER" -g "$MAPLE_USER" -m 0755 \
    "$MAPLE_RUNTIME_ROOT" "$MAPLE_GAME_DIR" "$MAPLE_WINEPREFIX" \
    "$MAPLE_LOG_DIR" "$MAPLE_RUN_DIR" "${MAPLE_RUNTIME_ROOT}/home"
  install -d -o "$MAPLE_USER" -g "$MAPLE_USER" -m 0700 \
    "${MAPLE_RUNTIME_ROOT}/runtime"
}

install_dependencies() {
  require_root
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    ca-certificates curl jq mesa-utils nodejs openbox procps python3 python3-pip \
    python3-venv scrot tshark wine wine64 x11-utils xdotool xserver-xorg-core xvfb
  prepare_directories
  if [[ ! -x "${MAPLE_VENV}/bin/python" ]]; then
    python3 -m venv "$MAPLE_VENV"
  fi
  "${MAPLE_VENV}/bin/pip" install --disable-pip-version-check --upgrade pip
  "${MAPLE_VENV}/bin/pip" install --disable-pip-version-check \
    'pycryptodome>=3.23,<4'
}

download_game() {
  require_root
  prepare_directories
  require_file "$MAPLE_DOWNLOADER"
  require_file "$MAPLE_MANIFEST"
  log "downloading and validating the game from ${MAPLE_CDN_BASE}"
  as_maple node "$MAPLE_DOWNLOADER" \
    --manifest "$MAPLE_MANIFEST" \
    --output "$MAPLE_GAME_DIR" \
    --base-url "$MAPLE_CDN_BASE" \
    --concurrency "${MAPLE_DOWNLOAD_CONCURRENCY:-8}"
  require_file "$MAPLE_EXE"
}

pid_is_running() {
  local pid_file="$1"
  [[ -f "$pid_file" ]] || return 1
  local pid
  read -r pid < "$pid_file"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null
}

stop_managed_process() {
  local pid_file="$1"
  local expected="$2"
  [[ -f "$pid_file" ]] || return 0
  local pid
  read -r pid < "$pid_file"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    local command_line
    command_line="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
    [[ "$command_line" == *"$expected"* ]] || \
      fail "refusing to stop PID ${pid}: command does not contain ${expected}"
    kill "$pid"
    for _ in $(seq 1 50); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
  fi
  rm -f -- "$pid_file"
}

start_display() {
  require_root
  prepare_directories
  local display_pid_file="${MAPLE_RUN_DIR}/display.pid"
  local xvfb_pid_file="${MAPLE_RUN_DIR}/xvfb.pid"
  local openbox_pid_file="${MAPLE_RUN_DIR}/openbox.pid"
  local display_backend="${MAPLE_DISPLAY_BACKEND:-auto}"
  local expected_process=Xvfb

  if [[ "$display_backend" == auto ]]; then
    if command -v Xorg >/dev/null 2>&1 && command -v nvidia-smi >/dev/null 2>&1 && \
       [[ -f /usr/lib/x86_64-linux-gnu/nvidia/xorg/nvidia_drv.so ]]; then
      display_backend=nvidia
    else
      display_backend=xvfb
    fi
  fi

  if [[ "$display_backend" == nvidia ]]; then
    expected_process=Xorg
    stop_managed_process "$xvfb_pid_file" Xvfb
    if ! pid_is_running "$display_pid_file"; then
      local dimensions="${MAPLE_SCREEN%x*}"
      local depth="${MAPLE_SCREEN##*x}"
      local width="${dimensions%x*}"
      local height="${dimensions#*x}"
      local pci_bus_id pci_bus_hex pci_device_hex pci_function_hex xorg_bus_id
      [[ "$width" =~ ^[0-9]+$ && "$height" =~ ^[0-9]+$ && "$depth" =~ ^[0-9]+$ ]] || \
        fail "invalid MAPLE_SCREEN: ${MAPLE_SCREEN}"
      pci_bus_id="$(nvidia-smi --query-gpu=pci.bus_id --format=csv,noheader | head -n 1)"
      IFS=':.' read -r _ pci_bus_hex pci_device_hex pci_function_hex <<< "$pci_bus_id"
      [[ "$pci_bus_hex" =~ ^[0-9A-Fa-f]+$ && "$pci_device_hex" =~ ^[0-9A-Fa-f]+$ && \
         "$pci_function_hex" =~ ^[0-9A-Fa-f]+$ ]] || fail "invalid NVIDIA PCI bus ID: ${pci_bus_id}"
      xorg_bus_id="PCI:$((16#$pci_bus_hex)):$((16#$pci_device_hex)):$((16#$pci_function_hex))"
      local xorg_config="${MAPLE_RUNTIME_ROOT}/xorg-nvidia.conf"
      printf '%s\n' \
        'Section "Files"' \
        '  ModulePath "/usr/lib/x86_64-linux-gnu/nvidia/xorg"' \
        '  ModulePath "/usr/lib/xorg/modules"' \
        'EndSection' \
        'Section "Device"' \
        '  Identifier "MapleGPU"' \
        '  Driver "nvidia"' \
        "  BusID \"${xorg_bus_id}\"" \
        '  Option "AllowEmptyInitialConfiguration" "True"' \
        'EndSection' \
        'Section "Screen"' \
        '  Identifier "MapleScreen"' \
        '  Device "MapleGPU"' \
        "  DefaultDepth ${depth}" \
        '  Option "UseDisplayDevice" "None"' \
        '  SubSection "Display"' \
        "    Depth ${depth}" \
        "    Virtual ${width} ${height}" \
        '  EndSubSection' \
        'EndSection' > "$xorg_config"
      nohup Xorg "$MAPLE_DISPLAY" -noreset -nolisten tcp -ac \
        -config "$xorg_config" -logfile "${MAPLE_LOG_DIR}/xorg.log" \
        >"${MAPLE_LOG_DIR}/xorg-stdout.log" 2>&1 &
      echo $! > "$display_pid_file"
    fi
  elif [[ "$display_backend" == xvfb ]]; then
    stop_managed_process "$display_pid_file" Xorg
    display_pid_file="$xvfb_pid_file"
    if ! pid_is_running "$display_pid_file"; then
      as_maple bash -c '
        nohup Xvfb "$1" -screen 0 "$2" -nolisten tcp -noreset -ac +extension GLX +render \
          >"$3" 2>&1 &
        echo $! >"$4"
      ' bash "$MAPLE_DISPLAY" "$MAPLE_SCREEN" "${MAPLE_LOG_DIR}/xvfb.log" "$display_pid_file"
    fi
  else
    fail "MAPLE_DISPLAY_BACKEND must be auto, nvidia, or xvfb"
  fi
  for _ in $(seq 1 100); do
    as_maple xdpyinfo >/dev/null 2>&1 && break
    sleep 0.1
  done
  as_maple xdpyinfo >/dev/null 2>&1 || {
    tail -n 80 "${MAPLE_LOG_DIR}/xorg.log" "${MAPLE_LOG_DIR}/xvfb.log" 2>/dev/null || true
    fail "${expected_process} did not become ready"
  }
  if [[ "$display_backend" == nvidia ]]; then
    as_maple glxinfo -B > "${MAPLE_LOG_DIR}/glxinfo.log"
    grep -q 'OpenGL renderer string: NVIDIA' "${MAPLE_LOG_DIR}/glxinfo.log" || \
      fail "headless Xorg is not using the NVIDIA renderer"
  fi
  if ! pid_is_running "$openbox_pid_file"; then
    as_maple bash -c '
      nohup openbox >"$1" 2>&1 &
      echo $! >"$2"
    ' bash "${MAPLE_LOG_DIR}/openbox.log" "$openbox_pid_file"
  fi
}

initialize_wine() {
  require_root
  start_display
  if [[ ! -f "${MAPLE_WINEPREFIX}/system.reg" ]]; then
    log "initializing the 64-bit Wine prefix"
    as_maple wineboot --init
    as_maple wineserver -w
  fi
}

wait_for_tcp() {
  local port="$1"
  local description="$2"
  for _ in $(seq 1 200); do
    if python3 - "$port" <<'PY'
import socket
import sys

with socket.socket() as sock:
    sock.settimeout(0.1)
    raise SystemExit(sock.connect_ex(("127.0.0.1", int(sys.argv[1]))))
PY
    then
      return 0
    fi
    sleep 0.1
  done
  fail "${description} did not listen on port ${port}"
}

start_servers() {
  require_root
  prepare_directories
  require_file "${MAPLE_SERVER_ROOT}/maple_server/__main__.py"
  require_file "$MAPLE_LOGIN_TRANSCRIPT"
  require_file "$MAPLE_PCAP"
  [[ -x "${MAPLE_VENV}/bin/python" ]] || fail "run install before start-servers"

  if ! grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+tw-login\.maplestoryclassic\.games\.gamania\.com([[:space:]]|$)' /etc/hosts; then
    printf '127.0.0.1 tw-login.maplestoryclassic.games.gamania.com\n' >> /etc/hosts
  fi

  local world_pid_file="${MAPLE_RUN_DIR}/world.pid"
  local login_pid_file="${MAPLE_RUN_DIR}/login.pid"
  stop_managed_process "$world_pid_file" "maple_server"
  stop_managed_process "$login_pid_file" "maple_server"

  PYTHONPATH="$MAPLE_SERVER_ROOT" nohup "${MAPLE_VENV}/bin/python" -m maple_server replay \
    --listen-host 127.0.0.1 \
    --listen-port 12857 \
    --http-api-host 127.0.0.1 \
    --http-api-port 12858 \
    --no-strict \
    --pcap "$MAPLE_PCAP" \
    --tcp-stream 114 \
    --keep-world-open \
    --world-heartbeat-interval-seconds 5 \
    --generate-initial-field-snapshot \
    --generate-field-npc-spawns \
    --generate-fixed-server-records \
    --generate-variable-server-records \
    --transcript-dir "${MAPLE_LOG_DIR}/world" \
    --timing-scale 1 \
    --hold-open-seconds 7200 \
    >"${MAPLE_LOG_DIR}/world-server.log" 2>&1 &
  echo $! > "$world_pid_file"
  wait_for_tcp 12857 "world server"
  wait_for_tcp 12858 "world status API"

  PYTHONPATH="$MAPLE_SERVER_ROOT" nohup "${MAPLE_VENV}/bin/python" -m maple_server replay \
    --listen-host 127.0.0.1 \
    --listen-port 10282 \
    --no-strict \
    --transcript "$MAPLE_LOGIN_TRANSCRIPT" \
    --transcript-dir "${MAPLE_LOG_DIR}/login" \
    --server-frame-patch 0=000000010000000000000400740065007300740000000000000000000000000000000000 \
    --server-frame-patch 3=0a00 \
    --drop-server-frame 4 \
    --reply-on-client-opcode-from-pcap "6=${MAPLE_PCAP}@83:13" \
    --reply-on-client-opcode 13=0d0000 \
    --reply-on-client-opcode-from-pcap "13=${MAPLE_PCAP}@83:3?opcode=1" \
    --reply-on-client-opcode-from-pcap "13=${MAPLE_PCAP}@83:5" \
    --reply-on-client-opcode-from-pcap "13=${MAPLE_PCAP}@83:6" \
    --reply-on-client-opcode-from-pcap "13=${MAPLE_PCAP}@83:7" \
    --reply-on-client-opcode-from-pcap "13=${MAPLE_PCAP}@83:8" \
    --reply-on-client-opcode-from-pcap "13=${MAPLE_PCAP}@83:9" \
    --reply-on-client-opcode-from-pcap "13=${MAPLE_PCAP}@83:10" \
    --reply-on-client-opcode-from-pcap "4=${MAPLE_PCAP}@83:15" \
    --reply-on-client-opcode-from-pcap "4=${MAPLE_PCAP}@83:16" \
    --client-opcode-reply-delays 4=0,2.5 \
    --rewrite-channel-transition-world \
    --reply-on-client-opcode-from-pcap "5=${MAPLE_PCAP}@83:17?character-list" \
    --reply-on-client-opcode-from-pcap "5=${MAPLE_PCAP}@83:18" \
    --reply-on-client-opcode-from-pcap "5=${MAPLE_PCAP}@83:19" \
    --client-opcode-reply-delays 5=0,0,1.0 \
    --reply-on-client-opcode-from-pcap "7=${MAPLE_PCAP}@83:20?handoff=127.0.0.1:12857" \
    --validate-login-state \
    --post-transcript-start-delay-seconds 5 \
    --hold-open-seconds 7200 \
    >"${MAPLE_LOG_DIR}/login-server.log" 2>&1 &
  echo $! > "$login_pid_file"
  wait_for_tcp 10282 "login server"
}

launch_client() {
  require_root
  require_file "$MAPLE_EXE"
  initialize_wine
  local game_pid_file="${MAPLE_RUN_DIR}/game.pid"
  stop_managed_process "$game_pid_file" "Maplestory_Classic.exe"
  as_maple bash -c '
    cd -- "$1"
    nohup wine "$2" 1 dummy 1 1 >"$3" 2>&1 &
    echo $! >"$4"
  ' bash "$MAPLE_GAME_DIR" "$MAPLE_EXE" "${MAPLE_LOG_DIR}/wine-client.log" "$game_pid_file"
  for _ in $(seq 1 600); do
    if as_maple xdotool search --onlyvisible --class maplestory_classic >/dev/null 2>&1; then
      log "MapleStory Wine window is ready"
      return 0
    fi
    pid_is_running "$game_pid_file" || fail "Wine client exited before opening a window"
    sleep 0.1
  done
  fail "MapleStory Wine window did not appear"
}

take_screenshot() {
  require_root
  start_display
  local output="${1:-${MAPLE_LOG_DIR}/screen.png}"
  as_maple scrot --overwrite "$output"
  printf '%s\n' "$output"
}

show_status() {
  curl --fail --silent --show-error http://127.0.0.1:12858/api/v1/status | jq '{
    service,
    listener,
    connections,
    initial_field_snapshot: .protocol.initial_field_snapshot_emitter,
    npc_spawns: .protocol.npc_spawn_emitter,
    fixed_records: .protocol.fixed_server_record_emitter,
    variable_records: .protocol.variable_server_record_emitter,
    heartbeat: .protocol.world_heartbeat
  }'
}

stop_all() {
  require_root
  stop_managed_process "${MAPLE_RUN_DIR}/game.pid" "Maplestory_Classic.exe"
  stop_managed_process "${MAPLE_RUN_DIR}/login.pid" "maple_server"
  stop_managed_process "${MAPLE_RUN_DIR}/world.pid" "maple_server"
  stop_managed_process "${MAPLE_RUN_DIR}/openbox.pid" "openbox"
  stop_managed_process "${MAPLE_RUN_DIR}/display.pid" "Xorg"
  stop_managed_process "${MAPLE_RUN_DIR}/xvfb.pid" "Xvfb"
}

usage() {
  cat <<'EOF'
Usage: deploy_vast_wine_client.sh COMMAND [ARG]

Commands:
  install        Install Wine, GPU/Xvfb display, UI tools, tshark, Node, and Python deps.
  download       Download and integrity-check the complete game from the CDN.
  display        Start a private NVIDIA-Xorg (or Xvfb fallback) desktop.
  servers        Start the capture-backed login and held-open world servers.
  launch         Initialize Wine and launch the client with local arguments.
  screenshot     Save the virtual desktop (optional output path argument).
  status         Print identifier-safe custom-world runtime evidence.
  stop           Stop only processes tracked by this deployment.
  all            Run install, download, display, servers, and launch.
EOF
}

main() {
  local command="${1:-}"
  case "$command" in
    install) install_dependencies ;;
    download) download_game ;;
    display) start_display ;;
    servers) start_servers ;;
    launch) launch_client ;;
    screenshot) take_screenshot "${2:-}" ;;
    status) show_status ;;
    stop) stop_all ;;
    all)
      install_dependencies
      download_game
      start_display
      start_servers
      launch_client
      ;;
    -h|--help|help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"

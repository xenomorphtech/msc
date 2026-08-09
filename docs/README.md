# MapleStory Classic lab notes

These notes preserve the working context for the Taiwan/Hong Kong MapleStory
Classic Unity client, its Wine environment, network capture setup, and the
custom-server experiment as of 2026-08-07.

## Start here

- [CLIENT.md](CLIENT.md) — run the isolated Sway desktop, browser, NGM, and
  client; switch between Xwayland and native Wayland; mute only the game.
- [NETWORK.md](NETWORK.md) — proxy namespace, transparent relay, endpoint
  routing, and packet capture.
- [CUSTOM_SERVER.md](CUSTOM_SERVER.md) — run, inspect, compare, and replay
  protocol transcripts.
- [PROTOCOL.md](PROTOCOL.md) — confirmed framing, endpoints, captures, and
  unknowns.
- [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) — IL2CPP/Cpp2IL/GDB work and
  the cipher investigation.
- [STATUS.md](STATUS.md) — what works, what was proven, and the next tasks.
- [SECURITY.md](SECURITY.md) — handling the local credentials and captures.

## Directory layout

```text
/home/sdancer/ms/
├── 111.pcapng                    # successful login + gameplay reference; untracked
├── 1-10FS.pcapng                 # level 1-10 gameplay reference; untracked
├── .env                         # credentials and proxy profiles; mode 0600
├── .codex_tmp/                  # launch, proxy, Sway, IL2CPP, and RE tools
├── docs/                        # these notes
├── downloads/
│   ├── maplestory_classic_wine_prefix/
│   ├── maplestory_classic_manual_binaries/
│   ├── maplestory_classic_il2cpp/
│   ├── maple_protocol_captures/
│   └── maple_custom_server_observed/
└── tools/maplestory_classic_server/
```

The MapleStory work is deliberately separate from the Phoenix application in
`/home/sdancer/albion-trade`.

## Fast path for custom-server work

1. Start or reuse the nested Sway instance described in `CLIENT.md`.
2. Start the local login/world replay listeners from `CUSTOM_SERVER.md`.
3. Verify the `mapleproxy` namespace redirects ports `10282` and `58880` to
   those listeners.
4. Launch `Maplestory_Classic.exe` directly with the placeholder arguments.
   NGM is not required for local protocol iterations.
5. Keep `maplestory-audio-mute.service` active; it discovers and mutes each new
   MapleStory PipeWire node by application identity after restarts.

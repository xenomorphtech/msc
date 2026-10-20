#!/usr/bin/env python3
"""Local native CW bootstrap and capture playback; not a complete game server."""
import argparse
import asyncio
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

from sandbox import WorldSandbox

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cw_packet_decode"))
from decode import crypt_aes, shuffle_iv


LOGIN_GREETING = bytes.fromhex(
    "340001000300303a300b583a2e7156bc6001000100010000000300303a30"
    "0b583a2e7156bc6001640000006400000000000000010005"
)
WORLD_GREETING = bytes.fromhex("1300010001000000010030b079ec9967984b140104")
PROFILES = {
    "login": (61, LOGIN_GREETING, bytes.fromhex("0b583a2e"), bytes.fromhex("7156bc60")),
    "world": (91, WORLD_GREETING, bytes.fromhex("b079ec99"), bytes.fromhex("67984b14")),
}


def load(path):
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for row in rows:
        body = bytes.fromhex(row["plaintext_hex"])
        if len(body) != row["length"] or hashlib.sha256(body).hexdigest() != row["plaintext_sha256"]:
            raise ValueError("capture plaintext hash or length mismatch")
    return rows


async def connection(reader, writer, role, rows, args):
    stream, greeting, client_iv, server_iv = PROFILES[role]
    stamp = time.time_ns()
    logpath = args.logs / f"{stamp}-{role}.jsonl"
    log = logpath.open("w")
    logpath.chmod(0o600)
    started = time.monotonic()
    received = defaultdict(int)
    condition = asyncio.Condition()
    write_lock = asyncio.Lock()
    greeting_ready = asyncio.Event()
    sandbox = WorldSandbox(args.logs / "sandbox", stamp) if role == "world" and args.world_mode == "sandbox" else None
    print(f"connected role={role} session={stamp}", flush=True)

    def record(direction, opcode, body):
        log.write(json.dumps({"timestamp_ns": time.time_ns(), "direction": direction,
                              "opcode": opcode, "length": len(body),
                              "plaintext_hex": body.hex()}, separators=(",", ":")) + "\n")
        log.flush()

    async def read_client():
        iv = client_iv
        while True:
            header = await reader.readexactly(4)
            first, second = struct.unpack("<HH", header)
            if first ^ int.from_bytes(iv[2:], "little") != 0xdf:
                raise ValueError("client IV/header mismatch")
            body = crypt_aes(await reader.readexactly(first ^ second), iv)
            iv = shuffle_iv(iv)
            opcode = int.from_bytes(body[:2], "little")
            record("client_to_server", opcode, body)
            print(f"recv role={role} opcode={opcode} bytes={len(body)}", flush=True)
            async with condition:
                received[opcode] += 1
                condition.notify_all()
            if sandbox:
                await sandbox.receive(opcode, body, send_packet)

    async def send_packet(opcode, body):
        nonlocal server_iv
        async with write_lock:
            if sandbox:
                sandbox.observe_server(opcode, body)
            first = int.from_bytes(server_iv[2:], "little") ^ 0xfffe
            encoded = (crypt_aes(body, server_iv) if role == "login"
                       else bytes((v + server_iv[0]) & 255 for v in body))
            writer.write(struct.pack("<HH", first, first ^ len(body)) + encoded)
            await writer.drain()
            server_iv = shuffle_iv(server_iv)
            record("server_to_client", opcode, body)
            print(f"send role={role} opcode={opcode} bytes={len(body)}", flush=True)

    async def heartbeat():
        await greeting_ready.wait()
        opcode = 26 if role == "login" else 1579
        while True:
            await asyncio.sleep(10)
            await send_packet(opcode, struct.pack("<H", opcode))

    async def write_server():
        origin = rows[0]["timestamp_ns"]
        writer.write(greeting)
        await writer.drain()
        greeting_ready.set()
        for row in rows:
            if row["direction"] != "server_to_client":
                continue
            if row["opcode"] == (26 if role == "login" else 1579):
                continue
            if sandbox and row["timestamp_ns"] - origin > 1_400_000_000:
                # All field/stat/NPC initialization finishes in this initial
                # burst. Later recording events include another player's
                # decisions, quest changes and map transitions.
                break
            # The captured handoff assumes a real channel/character choice.
            # Sending it on a timer before the live UI selects one exits the client.
            barrier = ({14: 117, 17: 118, 16: 121}.get(row["opcode"])
                       if role == "login" else (125 if row["index"] == 0 else None))
            if barrier is not None:
                print(f"waiting role={role} request_opcode={barrier}", flush=True)
                async with condition:
                    await condition.wait_for(lambda: received[barrier] > 0)
            delay = (row["timestamp_ns"] - origin) / 1e9 / args.speed - (time.monotonic() - started)
            if delay > 0:
                await asyncio.sleep(delay)
            body = bytes.fromhex(row["plaintext_hex"])
            if role == "login" and row["opcode"] == 16:
                # Captured successful handoff: IPv4 at +6, port at +10.
                if len(body) != 61:
                    raise ValueError("unexpected captured handoff width")
                body = body[:6] + bytes([127, 0, 0, 1]) + struct.pack("<H", args.world_port) + body[12:]
            await send_packet(row["opcode"], body)
        print(f"{'sandbox_ready' if sandbox else 'playback_complete'} role={role}", flush=True)
        if sandbox:
            await sandbox.start(send_packet)
        # read_client owns the reader for the connection's entire lifetime.
        await asyncio.Future()

    tasks = [asyncio.create_task(read_client()), asyncio.create_task(write_server()),
             asyncio.create_task(heartbeat())]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except (asyncio.IncompleteReadError, ConnectionError) as error:
        print(f"disconnected role={role} error={type(error).__name__}", flush=True)
    except Exception as error:
        print(f"failed role={role} error={error}", flush=True)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass
        log.close()
        if sandbox:
            pending = list(sandbox.tasks)
            sandbox.close()
            await asyncio.gather(*pending, return_exceptions=True)


async def run(args):
    args.logs.mkdir(parents=True, exist_ok=True)
    args.logs.chmod(0o700)
    servers = []
    for role, port in [("login", args.login_port), ("world", args.world_port)]:
        stream = PROFILES[role][0]
        rows = load(args.capture_dir / f"stream-{stream}.jsonl")
        async def accept(reader, writer, role=role, rows=rows):
            await connection(reader, writer, role, rows, args)
        servers.append(await asyncio.start_server(accept, "127.0.0.1", port))
        print(f"listening role={role} address=127.0.0.1 port={port}", flush=True)
    await asyncio.gather(*(server.serve_forever() for server in servers))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--logs", type=Path, required=True)
    parser.add_argument("--login-port", type=int, default=8484)
    parser.add_argument("--world-port", type=int, default=8541)
    parser.add_argument("--speed", type=float, default=1)
    parser.add_argument("--world-mode", choices=["replay", "sandbox"], default="replay")
    args = parser.parse_args()
    if args.speed <= 0:
        parser.error("speed must be positive")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

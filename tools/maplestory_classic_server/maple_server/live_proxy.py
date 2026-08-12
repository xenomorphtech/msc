from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any

from .gamestate import PacketObservation, PlainFrame
from .gameplay import GameplayStateFold
from .protocol import (
    Handshake,
    ProtocolError,
    crypt_payload,
    decode_frame_length,
    encode_frame_header,
    parse_handshake,
    shuffle_iv,
)
from .server import CaptureProxyConfig, MAX_ENCRYPTED_FRAME_BYTES, open_upstream
from .transcript import TranscriptWriter


DEFAULT_STATE_FILE = Path("/tmp/maple-live-gamestate.json")


@dataclass(frozen=True)
class LiveProxyConfig:
    transport: CaptureProxyConfig
    state_file: Path = DEFAULT_STATE_FILE


class AtomicStatePublisher:
    """Publish complete snapshots without exposing partially-written JSON."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def publish(self, snapshot: dict[str, object]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(snapshot, output, separators=(",", ":"), sort_keys=True)
                output.write("\n")
                output.flush()
            os.replace(temporary_path, self.path)
        finally:
            temporary_path.unlink(missing_ok=True)


def _publish_best_effort(
    publisher: AtomicStatePublisher,
    session: "LiveGameStateSession",
    *,
    status: str,
    error: str | None = None,
) -> None:
    """Keep state-file failures out of the forwarded network data path."""

    try:
        publisher.publish(session.snapshot(status=status, error=error))
    except Exception as exception:
        message = f"state publish: {type(exception).__name__}: {exception}"
        if not session.decode_errors or session.decode_errors[-1] != message:
            session.decode_errors.append(message)


def _platforms(state: Any) -> list[dict[str, object]]:
    """Infer visible platform spans from modeled foothold-bearing entities.

    The current protocol model does not decode the map's static foothold graph.
    NPC ranges provide bounded spans; mob positions provide point observations.
    Unknown footholds are grouped into coarse Y bands and explicitly labeled as
    position-only estimates.
    """

    groups: dict[str, dict[str, Any]] = {}

    def add(
        foothold_id: int,
        x_min: int,
        x_max: int,
        y: int,
        source: str,
    ) -> None:
        key = (
            f"foothold:{foothold_id}"
            if foothold_id
            else f"position-y:{round(y / 25) * 25}"
        )
        record = groups.setdefault(
            key,
            {
                "id": key,
                "foothold_id": foothold_id or None,
                "x_min": x_min,
                "x_max": x_max,
                "ys": [],
                "sources": set(),
                "npc_count": 0,
                "enemy_count": 0,
            },
        )
        record["x_min"] = min(record["x_min"], x_min)
        record["x_max"] = max(record["x_max"], x_max)
        record["ys"].append(y)
        record["sources"].add(source)
        record[f"{source}_count"] += 1

    for npc in state.npcs.values():
        spawn = npc.spawn
        add(
            spawn.foothold_id,
            spawn.range_left,
            spawn.range_right,
            spawn.cy,
            "npc",
        )
    for enemy in state.mobs.values():
        add(
            enemy.foothold_id,
            enemy.x - 40,
            enemy.x + 40,
            enemy.y,
            "enemy",
        )

    if not groups and state.player_x is not None and state.player_y is not None:
        add(0, state.player_x - 120, state.player_x + 120, state.player_y, "enemy")
        only = next(iter(groups.values()))
        only["enemy_count"] = 0
        only["sources"] = {"player_position"}

    platforms: list[dict[str, object]] = []
    for record in groups.values():
        ys = sorted(record.pop("ys"))
        sources = sorted(record.pop("sources"))
        if "npc" in sources:
            confidence = "npc_range"
        elif record["foothold_id"] is not None:
            confidence = "foothold_entity"
        else:
            confidence = "position_only"
        platforms.append(
            {
                **record,
                "y": ys[len(ys) // 2],
                "sources": sources,
                "confidence": confidence,
            }
        )
    return sorted(platforms, key=lambda item: (int(item["y"]), str(item["id"])))


def _nearest_platform(
    x: int | None, y: int | None, platforms: list[dict[str, object]]
) -> str | None:
    if x is None or y is None or not platforms:
        return None
    candidates = sorted(
        platforms,
        key=lambda platform: (
            0
            if int(platform["x_min"]) - 80 <= x <= int(platform["x_max"]) + 80
            else 1,
            abs(int(platform["y"]) - y),
        ),
    )
    nearest = candidates[0]
    if abs(int(nearest["y"]) - y) > 120:
        return None
    return str(nearest["id"])


class LiveGameStateSession:
    """Incrementally decrypt and fold one byte-for-byte proxied Maple session."""

    def __init__(self, *, upstream_host: str, upstream_port: int, peer: str) -> None:
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.peer = peer
        self.connected_at_ns = time.time_ns()
        self.updated_at_ns = self.connected_at_ns
        self.handshake: Handshake | None = None
        self.fold = GameplayStateFold()
        self.frame_index = 0
        self.direction_indices = {
            "client_to_server": 0,
            "server_to_client": 0,
        }
        self.wire_offsets = {
            "client_to_server": 0,
            "server_to_client": 0,
        }
        self.ivs: dict[str, bytes | None] = {
            "client_to_server": None,
            "server_to_client": None,
        }
        self.version_masks: dict[str, int | None] = {
            "client_to_server": None,
            "server_to_client": None,
        }
        self.last_frame: PlainFrame | None = None
        self.last_observation: PacketObservation | None = None
        self.decode_errors: list[str] = []

    def accept_handshake(self, wire_bytes: bytes) -> None:
        handshake = parse_handshake(wire_bytes)
        self.handshake = handshake
        self.ivs["client_to_server"] = handshake.first_iv
        self.ivs["server_to_client"] = handshake.second_iv
        self.wire_offsets["server_to_client"] = handshake.wire_length
        self.updated_at_ns = time.time_ns()

    def accept_frame(
        self,
        direction: str,
        header: bytes,
        encrypted_payload: bytes,
        *,
        timestamp_ns: int | None = None,
    ) -> PacketObservation | None:
        iv = self.ivs.get(direction)
        if iv is None:
            self.decode_errors.append(f"{direction}: cipher IV is not initialized")
            return None
        if len(header) != 4:
            self.decode_errors.append(f"{direction}: frame header is not four bytes")
            return None

        version_mask = self.version_masks[direction]
        if version_mask is None:
            version_mask = int.from_bytes(header[:2], "little") ^ int.from_bytes(
                iv[2:4], "little"
            )
            self.version_masks[direction] = version_mask
        expected_header = encode_frame_header(len(encrypted_payload), iv, version_mask)
        if header != expected_header:
            self.decode_errors.append(
                f"{direction} frame {self.direction_indices[direction]} has an "
                "unexpected cipher header"
            )

        plaintext = crypt_payload(encrypted_payload, iv)
        now = timestamp_ns if timestamp_ns is not None else time.time_ns()
        frame = PlainFrame(
            index=self.frame_index,
            direction_index=self.direction_indices[direction],
            timestamp_ns=now,
            direction=direction,
            wire_offset=self.wire_offsets[direction],
            wire_length=4 + len(encrypted_payload),
            plaintext=plaintext,
        )
        try:
            observation = self.fold.consume(frame)
        except Exception as error:  # keep inspection failure off the data path
            self.decode_errors.append(
                f"{direction} frame {frame.direction_index}: "
                f"{type(error).__name__}: {error}"
            )
            observation = None
        self.last_frame = frame
        self.last_observation = observation
        self.frame_index += 1
        self.direction_indices[direction] += 1
        self.wire_offsets[direction] += frame.wire_length
        self.ivs[direction] = shuffle_iv(iv)
        self.updated_at_ns = now
        return observation

    def finish(self) -> None:
        try:
            self.fold.finish(self.last_frame, transport_closed=True)
        except Exception as error:
            self.decode_errors.append(f"fold finish: {type(error).__name__}: {error}")
        self.updated_at_ns = time.time_ns()

    def snapshot(
        self, *, status: str, error: str | None = None
    ) -> dict[str, object]:
        state = self.fold.state
        platforms = _platforms(state)
        enemies = [
            {
                "entity": enemy.alias,
                "template_id": enemy.spawn.template_id,
                "x": enemy.x,
                "y": enemy.y,
                "foothold_id": enemy.foothold_id or None,
                "stance": enemy.stance,
                "controller_level": enemy.controller_level,
                "health_percentage": enemy.health_percentage,
                "max_hp": enemy.max_hp,
                "health_hp_min": enemy.health_hp_min,
                "health_hp_max": enemy.health_hp_max,
                "temporary_stat_bits": sorted(enemy.temporary_stats),
            }
            for enemy in sorted(state.mobs.values(), key=lambda item: item.alias)
        ]
        inventory = [
            {
                "name": name,
                "items": [
                    {
                        "slot": item.slot,
                        "item_id": item.item_id,
                        "record_type": item.record_type,
                        "cash_item": item.cash_item,
                        "quantity": item.quantity,
                    }
                    for item in items
                ],
            }
            for name, items in sorted(state.inventory_items.items())
        ]
        player_platform = _nearest_platform(
            state.player_x, state.player_y, platforms
        )
        snapshot: dict[str, object] = {
            "schema_version": 1,
            "connection": {
                "status": status,
                "upstream_host": self.upstream_host,
                "upstream_port": self.upstream_port,
                "peer": self.peer,
                "connected_at_ns": self.connected_at_ns,
                "updated_at_ns": self.updated_at_ns,
                "error": error,
            },
            "handshake": (
                None
                if self.handshake is None
                else {
                    "version": self.handshake.version,
                    "subversion": self.handshake.subversion,
                    "locale": self.handshake.locale,
                    "client_version_mask": self.version_masks["client_to_server"],
                    "server_version_mask": self.version_masks["server_to_client"],
                }
            ),
            "state": {
                "phase": state.phase.value,
                "field_epoch": state.field_epoch,
                "map_id": state.map_id,
                "portal_index": state.portal_index,
                "packets": dict(state.packets_by_direction),
                "player": {
                    "x": state.player_x,
                    "y": state.player_y,
                    "platform": player_platform,
                    "current_hp": state.current_hp,
                    "max_hp": state.max_hp,
                    "current_mp": state.current_mp,
                    "max_mp": state.max_mp,
                    "level": state.character_level,
                    "job_id": state.job_id,
                    "mesos": state.mesos,
                },
                "platforms": platforms,
                "enemies": enemies,
                "remote_players": [
                    {
                        "entity": player.alias,
                        "x": player.x,
                        "y": player.y,
                        "level": player.level,
                    }
                    for player in sorted(
                        state.observed_players.values(), key=lambda item: item.alias
                    )
                ],
                "drops": [
                    {
                        "drop": drop.alias,
                        "kind": drop.spawn.kind_name,
                        "value": drop.spawn.value,
                        "x": drop.spawn.position_x,
                        "y": drop.spawn.position_y,
                    }
                    for drop in sorted(
                        state.field_drops.values(), key=lambda item: item.alias
                    )
                ],
                "inventory": inventory,
            },
            "fold": {
                "issues": self.fold.issues[-8:],
                "warnings": self.fold.warnings[-8:],
                "decode_errors": self.decode_errors[-8:],
                "events": len(self.fold.events),
                "last_packet": (
                    None
                    if self.last_observation is None
                    else {
                        "frame_index": self.last_observation.frame_index,
                        "direction": self.last_observation.direction,
                        "opcode": self.last_observation.opcode,
                        "kind": self.last_observation.kind,
                        "coverage": self.last_observation.coverage.value,
                        "length": self.last_observation.length,
                    }
                ),
            },
        }
        return snapshot


async def copy_live_maple_streams(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    transcript: TranscriptWriter,
    session: LiveGameStateSession,
    publisher: AtomicStatePublisher,
) -> None:
    handshake_ready = asyncio.Event()

    async def server_to_client() -> None:
        prefix = await upstream_reader.readexactly(2)
        packet_length = int.from_bytes(prefix, "little")
        if packet_length > MAX_ENCRYPTED_FRAME_BYTES:
            raise ProtocolError(f"Live handshake is too large: {packet_length} bytes")
        handshake_bytes = prefix + await upstream_reader.readexactly(packet_length)
        transcript.data("server_to_client", handshake_bytes)
        client_writer.write(handshake_bytes)
        await client_writer.drain()
        try:
            session.accept_handshake(handshake_bytes)
        except Exception as exception:
            session.decode_errors.append(
                f"handshake: {type(exception).__name__}: {exception}"
            )
        _publish_best_effort(publisher, session, status="connected")
        handshake_ready.set()

        while True:
            try:
                header = await upstream_reader.readexactly(4)
            except asyncio.IncompleteReadError as incomplete:
                if incomplete.partial:
                    transcript.data("server_to_client", incomplete.partial)
                    client_writer.write(incomplete.partial)
                    await client_writer.drain()
                    raise
                client_writer.close()
                return
            payload_length = decode_frame_length(header)
            if payload_length > MAX_ENCRYPTED_FRAME_BYTES:
                raise ProtocolError(
                    f"Live encrypted frame is too large: {payload_length} bytes"
                )
            try:
                payload = await upstream_reader.readexactly(payload_length)
            except asyncio.IncompleteReadError as incomplete:
                partial = header + incomplete.partial
                transcript.data("server_to_client", partial)
                client_writer.write(partial)
                await client_writer.drain()
                raise
            received_at_ns = time.time_ns()
            wire = header + payload
            transcript.data("server_to_client", wire)
            client_writer.write(wire)
            session.accept_frame(
                "server_to_client",
                header,
                payload,
                timestamp_ns=received_at_ns,
            )
            await client_writer.drain()
            _publish_best_effort(publisher, session, status="connected")

    async def client_to_server() -> None:
        await handshake_ready.wait()
        while True:
            try:
                header = await client_reader.readexactly(4)
            except asyncio.IncompleteReadError as incomplete:
                if incomplete.partial:
                    transcript.data("client_to_server", incomplete.partial)
                    upstream_writer.write(incomplete.partial)
                    await upstream_writer.drain()
                    raise
                if upstream_writer.can_write_eof():
                    upstream_writer.write_eof()
                    await upstream_writer.drain()
                return
            payload_length = decode_frame_length(header)
            if payload_length > MAX_ENCRYPTED_FRAME_BYTES:
                raise ProtocolError(
                    f"Live encrypted frame is too large: {payload_length} bytes"
                )
            try:
                payload = await client_reader.readexactly(payload_length)
            except asyncio.IncompleteReadError as incomplete:
                partial = header + incomplete.partial
                transcript.data("client_to_server", partial)
                upstream_writer.write(partial)
                await upstream_writer.drain()
                raise
            received_at_ns = time.time_ns()
            wire = header + payload
            transcript.data("client_to_server", wire)
            upstream_writer.write(wire)
            session.accept_frame(
                "client_to_server",
                header,
                payload,
                timestamp_ns=received_at_ns,
            )
            await upstream_writer.drain()
            _publish_best_effort(publisher, session, status="connected")

    await asyncio.gather(server_to_client(), client_to_server())


async def live_proxy_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    config: LiveProxyConfig,
) -> None:
    peer = repr(client_writer.get_extra_info("peername"))
    transport = config.transport
    session = LiveGameStateSession(
        upstream_host=transport.upstream_host,
        upstream_port=transport.upstream_port,
        peer=peer,
    )
    publisher = AtomicStatePublisher(config.state_file)
    transcript = TranscriptWriter(
        transport.transcript_directory,
        label=f"live_{transport.upstream_host}_{transport.upstream_port}",
        metadata={
            "mode": "live_gamestate_proxy",
            "upstream_host": transport.upstream_host,
            "upstream_port": transport.upstream_port,
            "peer": peer,
            "state_file": str(config.state_file),
        },
        max_bytes_per_direction=transport.max_capture_bytes,
    )
    _publish_best_effort(publisher, session, status="connecting")
    upstream_writer: asyncio.StreamWriter | None = None
    error: str | None = None
    try:
        upstream_reader, upstream_writer = await open_upstream(transport)
        await copy_live_maple_streams(
            client_reader,
            client_writer,
            upstream_reader,
            upstream_writer,
            transcript,
            session,
            publisher,
        )
    except Exception as exception:
        error = f"{type(exception).__name__}: {exception}"
        raise
    finally:
        session.finish()
        _publish_best_effort(
            publisher, session, status="disconnected", error=error
        )
        transcript.close(error=error)
        client_writer.close()
        if upstream_writer is not None:
            upstream_writer.close()
        await client_writer.wait_closed()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m maple_server live-proxy",
        description="Byte-transparent Maple proxy with a live gameplay-state fold"
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--upstream-port", type=int, required=True)
    parser.add_argument("--transcript-dir", type=Path, default=Path("captures/live"))
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    parser.add_argument("--http-proxy-host")
    parser.add_argument("--http-proxy-port", type=int)
    parser.add_argument(
        "--http-proxy-username", default=os.environ.get("MAPLE_PROXY_USER")
    )
    parser.add_argument(
        "--http-proxy-password", default=os.environ.get("MAPLE_PROXY_PASSWORD")
    )
    parser.add_argument(
        "--max-capture-bytes", type=int, default=16 * 1024 * 1024
    )
    return parser


async def async_main(arguments: argparse.Namespace) -> None:
    if not 0 <= arguments.listen_port <= 65535:
        raise ValueError("listen port must be between 0 and 65535")
    if not 1 <= arguments.upstream_port <= 65535:
        raise ValueError("upstream port must be between 1 and 65535")
    if arguments.max_capture_bytes < 0:
        raise ValueError("max capture bytes cannot be negative")
    if bool(arguments.http_proxy_host) != (arguments.http_proxy_port is not None):
        raise ValueError("HTTP proxy host and port must be supplied together")

    transport = CaptureProxyConfig(
        upstream_host=arguments.upstream_host,
        upstream_port=arguments.upstream_port,
        transcript_directory=arguments.transcript_dir,
        http_proxy_host=arguments.http_proxy_host,
        http_proxy_port=arguments.http_proxy_port,
        http_proxy_username=arguments.http_proxy_username,
        http_proxy_password=arguments.http_proxy_password,
        max_capture_bytes=arguments.max_capture_bytes,
    )
    config = LiveProxyConfig(transport=transport, state_file=arguments.state_file)

    tasks: set[asyncio.Task[None]] = set()

    def completed(task: asyncio.Task[None]) -> None:
        tasks.discard(task)
        if task.cancelled():
            return
        exception = task.exception()
        if exception is not None:
            print(
                f"live proxy connection failed: {type(exception).__name__}: "
                f"{exception}",
                file=sys.stderr,
                flush=True,
            )

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.create_task(live_proxy_connection(reader, writer, config))
        tasks.add(task)
        task.add_done_callback(completed)

    server = await asyncio.start_server(
        accept, arguments.listen_host, arguments.listen_port
    )
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(
        f"listening mode=live-gamestate-proxy addresses={addresses} "
        f"upstream={arguments.upstream_host}:{arguments.upstream_port} "
        f"state_file={arguments.state_file}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> None:
    arguments = build_parser().parse_args(argv)
    try:
        asyncio.run(async_main(arguments))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

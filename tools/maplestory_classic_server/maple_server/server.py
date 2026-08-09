from __future__ import annotations

import argparse
import asyncio
import base64
from collections import deque
from dataclasses import dataclass
import functools
from ipaddress import IPv4Address
import os
from pathlib import Path
import sys
from typing import Awaitable, Callable

from .gamestate import (
    ShapeCoverage,
    analyze_login_transcript,
    decode_transcript,
    normalize_maple_transcript,
    render_login_analysis,
)
from .gameplay import (
    MobMovementAcknowledgementPolicy,
    analyze_gameplay_transcript,
    derive_mob_movement_acknowledgement_policy,
    plan_current_hp_stat_update,
    plan_final_field_npc_state_replay,
    plan_initial_player_hp_rewrite,
    render_gameplay_analysis,
    world_session_termination_frame_index,
)
from .http_api import ServerRuntime, start_runtime_http_api
from .packets import (
    ChannelTransitionResponse,
    HeartbeatProbe,
    MobMovementSubmission,
    PacketShapeError,
    WorldHandoff,
    WorldSelection,
)
from .pcap import load_pcap_tcp_stream
from .protocol import (
    ProtocolError,
    crypt_payload,
    decode_frame_length,
    encode_frame_header,
    parse_encrypted_frames,
    parse_handshake,
    shuffle_iv,
)
from .transcript import Transcript, TranscriptWriter, data_events


@dataclass(frozen=True)
class CaptureProxyConfig:
    upstream_host: str
    upstream_port: int
    transcript_directory: Path
    http_proxy_host: str | None = None
    http_proxy_port: int | None = None
    http_proxy_username: str | None = None
    http_proxy_password: str | None = None
    max_capture_bytes: int = 16 * 1024 * 1024
    client_opcode_result_rewrites: tuple[tuple[int, int], ...] = ()
    server_opcode_byte_rewrites: tuple[tuple[int, int, int], ...] = ()


MAX_ENCRYPTED_FRAME_BYTES = 16 * 1024 * 1024


async def open_upstream(
    config: CaptureProxyConfig,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if not config.http_proxy_host:
        return await asyncio.open_connection(config.upstream_host, config.upstream_port)
    if config.http_proxy_port is None:
        raise ValueError("An HTTP proxy port is required when a proxy host is configured")

    reader, writer = await asyncio.open_connection(
        config.http_proxy_host, config.http_proxy_port
    )
    authority = f"{config.upstream_host}:{config.upstream_port}"
    headers = [
        f"CONNECT {authority} HTTP/1.1",
        f"Host: {authority}",
        "Proxy-Connection: Keep-Alive",
    ]
    if config.http_proxy_username is not None:
        credentials = base64.b64encode(
            f"{config.http_proxy_username}:{config.http_proxy_password or ''}".encode(
                "utf-8"
            )
        ).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {credentials}")
    writer.write(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    status_line = response.split(b"\r\n", 1)[0]
    if b" 200 " not in status_line:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(
            f"HTTP proxy CONNECT failed: {status_line.decode('latin-1', 'replace')}"
        )
    return reader, writer


async def copy_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    transcript: TranscriptWriter,
    direction: str,
) -> int:
    byte_count = 0
    try:
        while data := await reader.read(65536):
            byte_count += len(data)
            transcript.data(direction, data)
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
    return byte_count


async def capture_proxy_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    config: CaptureProxyConfig,
) -> None:
    peer = client_writer.get_extra_info("peername")
    transcript = TranscriptWriter(
        config.transcript_directory,
        label=f"{config.upstream_host}_{config.upstream_port}",
        metadata={
            "mode": "capture_proxy",
            "upstream_host": config.upstream_host,
            "upstream_port": config.upstream_port,
            "peer": repr(peer),
            "client_result_rewrite_opcodes": sorted(
                opcode for opcode, _ in config.client_opcode_result_rewrites
            ),
            "server_byte_rewrites": sorted(
                (opcode, offset)
                for opcode, offset, _ in config.server_opcode_byte_rewrites
            ),
        },
        max_bytes_per_direction=config.max_capture_bytes,
    )
    upstream_writer: asyncio.StreamWriter | None = None
    error: str | None = None
    try:
        upstream_reader, upstream_writer = await open_upstream(config)
        if (
            config.client_opcode_result_rewrites
            or config.server_opcode_byte_rewrites
        ):
            await copy_maple_streams_with_rewrites(
                client_reader,
                client_writer,
                upstream_reader,
                upstream_writer,
                transcript,
                dict(config.client_opcode_result_rewrites),
                {
                    (opcode, offset): value
                    for opcode, offset, value in config.server_opcode_byte_rewrites
                },
            )
        else:
            await asyncio.gather(
                copy_stream(
                    client_reader,
                    upstream_writer,
                    transcript,
                    "client_to_server",
                ),
                copy_stream(
                    upstream_reader,
                    client_writer,
                    transcript,
                    "server_to_client",
                ),
            )
    except Exception as exception:
        error = f"{type(exception).__name__}: {exception}"
        raise
    finally:
        transcript.close(error=error)
        client_writer.close()
        if upstream_writer is not None:
            upstream_writer.close()
        await client_writer.wait_closed()


async def copy_maple_streams_with_rewrites(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
    transcript: TranscriptWriter,
    result_rewrites: dict[int, int],
    server_byte_rewrites: dict[tuple[int, int], int],
) -> None:
    """Forward Maple frames while applying selected plaintext-byte rewrites.

    The server handshake supplies the client cipher IV.  Only byte offset 2 of
    explicitly selected plaintext opcodes is changed; frame length, header, IV
    progression, and every other payload byte remain unchanged.
    """
    handshake_ready = asyncio.Event()
    client_iv: bytes | None = None
    server_iv: bytes | None = None

    async def server_to_client() -> None:
        nonlocal client_iv, server_iv
        prefix = await upstream_reader.readexactly(2)
        packet_length = int.from_bytes(prefix, "little")
        if packet_length > MAX_ENCRYPTED_FRAME_BYTES:
            raise ProtocolError(
                f"Live handshake is too large: {packet_length} bytes"
            )
        handshake_bytes = prefix + await upstream_reader.readexactly(packet_length)
        handshake = parse_handshake(handshake_bytes)
        client_iv = handshake.first_iv
        server_iv = handshake.second_iv
        transcript.data("server_to_client", handshake_bytes)
        client_writer.write(handshake_bytes)
        await client_writer.drain()
        handshake_ready.set()
        while True:
            try:
                header = await upstream_reader.readexactly(4)
            except asyncio.IncompleteReadError as error:
                if error.partial:
                    transcript.data("server_to_client", error.partial)
                    raise
                client_writer.close()
                return
            payload_length = decode_frame_length(header)
            if payload_length > MAX_ENCRYPTED_FRAME_BYTES:
                raise ProtocolError(
                    f"Live encrypted frame is too large: {payload_length} bytes"
                )
            try:
                encrypted_payload = await upstream_reader.readexactly(payload_length)
            except asyncio.IncompleteReadError as error:
                transcript.data("server_to_client", header + error.partial)
                raise
            if server_iv is None:
                raise ProtocolError("Server cipher state is not initialized")
            plaintext = bytearray(crypt_payload(encrypted_payload, server_iv))
            opcode = (
                int.from_bytes(plaintext[:2], "little")
                if len(plaintext) >= 2
                else None
            )
            rewritten = False
            if opcode is not None:
                for (selected_opcode, offset), value in server_byte_rewrites.items():
                    if opcode == selected_opcode and offset < len(plaintext):
                        plaintext[offset] = value
                        rewritten = True
            if rewritten:
                encrypted_payload = crypt_payload(bytes(plaintext), server_iv)
            outgoing = header + encrypted_payload
            transcript.data("server_to_client", outgoing)
            client_writer.write(outgoing)
            await client_writer.drain()
            server_iv = shuffle_iv(server_iv)

    async def client_to_server() -> None:
        nonlocal client_iv
        await handshake_ready.wait()
        if client_iv is None:
            raise ProtocolError("Server handshake did not initialize the client IV")
        while True:
            try:
                header = await client_reader.readexactly(4)
            except asyncio.IncompleteReadError as error:
                if error.partial:
                    transcript.data("client_to_server", error.partial)
                    raise
                return
            payload_length = decode_frame_length(header)
            if payload_length > MAX_ENCRYPTED_FRAME_BYTES:
                raise ProtocolError(
                    f"Live encrypted frame is too large: {payload_length} bytes"
                )
            try:
                encrypted_payload = await client_reader.readexactly(payload_length)
            except asyncio.IncompleteReadError as error:
                transcript.data("client_to_server", header + error.partial)
                raise
            plaintext = bytearray(crypt_payload(encrypted_payload, client_iv))
            opcode = (
                int.from_bytes(plaintext[:2], "little")
                if len(plaintext) >= 2
                else None
            )
            if opcode in result_rewrites and len(plaintext) >= 3:
                plaintext[2] = result_rewrites[opcode]
                encrypted_payload = crypt_payload(bytes(plaintext), client_iv)
            outgoing = header + encrypted_payload
            transcript.data("client_to_server", outgoing)
            upstream_writer.write(outgoing)
            await upstream_writer.drain()
            client_iv = shuffle_iv(client_iv)

    await asyncio.gather(server_to_client(), client_to_server())


def rewrite_channel_transition_world_from_selection(
    replies: tuple[bytes, ...], client_plaintext: bytes
) -> tuple[bytes, ...]:
    """Bind captured stage-1 opcode-402 replies to the live world selection."""

    selection = WorldSelection.parse(client_plaintext)
    rewritten: list[bytes] = []
    found_stage_one = False
    for reply in replies:
        opcode = int.from_bytes(reply[:2], "little") if len(reply) >= 2 else None
        if opcode != 402:
            rewritten.append(reply)
            continue
        transition = ChannelTransitionResponse.parse(reply)
        if transition.stage == 1:
            transition = ChannelTransitionResponse(
                stage=1, world_id=selection.world_id
            )
            found_stage_one = True
        rewritten.append(transition.to_bytes())
    if not found_stage_one:
        raise PacketShapeError(
            "reactive world-selection replies contain no opcode-402 stage 1"
        )
    return tuple(rewritten)


async def replay_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    transcript: Transcript,
    *,
    strict: bool = True,
    timing_scale: float = 0.0,
    transcript_directory: Path | None = None,
    listen_port: int | None = None,
    hold_open_seconds: float = 0.0,
    initial_delay_seconds: float = 0.0,
    server_frame_patches: dict[int, bytes] | None = None,
    dropped_server_frames: set[int] | None = None,
    post_transcript_server_frames: tuple[bytes, ...] = (),
    post_transcript_start_delay_seconds: float = 0.0,
    post_transcript_frame_delay_seconds: float = 0.0,
    post_transcript_gap_delays_seconds: tuple[float, ...] = (),
    post_transcript_replies: tuple[bytes, ...] = (),
    client_opcode_replies: dict[int, bytes | tuple[bytes, ...]] | None = None,
    client_opcode_reply_delays: dict[int, tuple[float, ...]] | None = None,
    rewrite_channel_transition_world: bool = False,
    keep_world_open: bool = False,
    world_heartbeat_interval_seconds: float | None = None,
    npc_state_replay_plaintext: bytes | None = None,
    player_stat_update_plaintext: bytes | None = None,
    mob_movement_acknowledgement_policy: (
        MobMovementAcknowledgementPolicy | None
    ) = None,
    runtime_protocol: dict[str, object] | None = None,
) -> None:
    if hold_open_seconds < 0:
        raise ValueError("hold_open_seconds cannot be negative")
    if (
        world_heartbeat_interval_seconds is not None
        and world_heartbeat_interval_seconds <= 0
    ):
        raise ValueError("world_heartbeat_interval_seconds must be positive")
    if world_heartbeat_interval_seconds is not None and hold_open_seconds <= 0:
        raise ValueError(
            "world heartbeat probes require a positive hold_open_seconds"
        )
    if (
        mob_movement_acknowledgement_policy is not None
        and hold_open_seconds <= 0
    ):
        raise ValueError(
            "reactive mob movement acknowledgements require a positive "
            "hold_open_seconds"
        )
    if initial_delay_seconds < 0:
        raise ValueError("initial_delay_seconds cannot be negative")
    if post_transcript_start_delay_seconds < 0:
        raise ValueError(
            "post_transcript_start_delay_seconds cannot be negative"
        )
    if post_transcript_frame_delay_seconds < 0:
        raise ValueError("post_transcript_frame_delay_seconds cannot be negative")
    if any(delay < 0 for delay in post_transcript_gap_delays_seconds):
        raise ValueError("post_transcript_gap_delays_seconds cannot be negative")
    if any(
        delay < 0
        for delays in (client_opcode_reply_delays or {}).values()
        for delay in delays
    ):
        raise ValueError("client_opcode_reply_delays cannot be negative")
    if strict and client_opcode_replies:
        raise ValueError("client opcode replies require non-strict replay")
    if (
        mob_movement_acknowledgement_policy is not None
        and 207 in (client_opcode_replies or {})
    ):
        raise ValueError(
            "client opcode 207 cannot use both captured and modeled replies"
        )
    if (
        npc_state_replay_plaintext is not None
        and npc_state_replay_plaintext not in post_transcript_server_frames
    ):
        raise ValueError(
            "npc_state_replay_plaintext must be a post-transcript server frame"
        )
    if (
        player_stat_update_plaintext is not None
        and player_stat_update_plaintext not in post_transcript_server_frames
    ):
        raise ValueError(
            "player_stat_update_plaintext must be a post-transcript server frame"
        )
    previous_timestamp_ns: int | None = None
    patched_server_events = iter(
        patch_server_event_data(
            transcript,
            server_frame_patches or {},
            dropped_server_frames,
        )
    )
    remaining_opcode_replies = {
        opcode: (payloads if isinstance(payloads, tuple) else (payloads,))
        for opcode, payloads in (client_opcode_replies or {}).items()
    }
    pending_opcode_replies: list[bytes] = []
    pending_periodic_heartbeats: deque[float] = deque()
    heartbeat_metrics = (
        runtime_protocol.get("world_heartbeat")
        if runtime_protocol is not None
        else None
    )
    if heartbeat_metrics is not None and not isinstance(
        heartbeat_metrics, dict
    ):
        raise TypeError("runtime world_heartbeat telemetry must be a dictionary")
    npc_state_replay_metrics = (
        runtime_protocol.get("npc_state_replay")
        if runtime_protocol is not None
        else None
    )
    if npc_state_replay_metrics is not None and not isinstance(
        npc_state_replay_metrics, dict
    ):
        raise TypeError("runtime npc_state_replay telemetry must be a dictionary")
    player_stat_update_metrics = (
        runtime_protocol.get("player_stat_update")
        if runtime_protocol is not None
        else None
    )
    if player_stat_update_metrics is not None and not isinstance(
        player_stat_update_metrics, dict
    ):
        raise TypeError(
            "runtime player_stat_update telemetry must be a dictionary"
        )
    mob_acknowledgement_metrics = (
        runtime_protocol.get("mob_movement_acknowledgements")
        if runtime_protocol is not None
        else None
    )
    if mob_acknowledgement_metrics is not None and not isinstance(
        mob_acknowledgement_metrics, dict
    ):
        raise TypeError(
            "runtime mob_movement_acknowledgements telemetry must be a dictionary"
        )
    client_iv = (
        parse_handshake(transcript.server_bytes).first_iv
        if (
            client_opcode_replies
            or world_heartbeat_interval_seconds is not None
            or mob_movement_acknowledgement_policy is not None
        )
        else None
    )
    observed = (
        TranscriptWriter(
            transcript_directory,
            label=f"replay_{listen_port or 'unknown'}",
            metadata={
                "mode": "replay",
                "source_transcript": str(transcript.path),
                "listen_port": listen_port,
                "hold_open_seconds": hold_open_seconds,
                "initial_delay_seconds": initial_delay_seconds,
                "server_frame_patch_indices": sorted(server_frame_patches or {}),
                "dropped_server_frame_indices": sorted(
                    dropped_server_frames or set()
                ),
                "post_transcript_reply_lengths": [
                    len(payload) for payload in post_transcript_replies
                ],
                "post_transcript_server_frame_lengths": [
                    len(payload) for payload in post_transcript_server_frames
                ],
                "post_transcript_start_delay_seconds": (
                    post_transcript_start_delay_seconds
                ),
                "post_transcript_frame_delay_seconds": (
                    post_transcript_frame_delay_seconds
                ),
                "post_transcript_gap_delays_seconds": list(
                    post_transcript_gap_delays_seconds
                ),
                "client_reply_opcodes": sorted(remaining_opcode_replies),
                "client_reply_delays": {
                    str(opcode): list(delays)
                    for opcode, delays in (client_opcode_reply_delays or {}).items()
                },
                "rewrite_channel_transition_world": (
                    rewrite_channel_transition_world
                ),
                "keep_world_open": keep_world_open,
                "world_heartbeat_interval_seconds": (
                    world_heartbeat_interval_seconds
                ),
                "repeat_final_field_npc_state_update": (
                    npc_state_replay_plaintext is not None
                ),
                "emit_current_hp_update": (
                    player_stat_update_plaintext is not None
                ),
                "reactive_mob_movement_acknowledgements": (
                    mob_movement_acknowledgement_policy is not None
                ),
            },
        )
        if transcript_directory is not None
        else None
    )
    error: str | None = None

    async def read_live_frame() -> tuple[bytes, int | None, bytes]:
        nonlocal client_iv
        if client_iv is None:
            raise RuntimeError("Client cipher state is not initialized")
        frame = await read_and_record_encrypted_frame(client_reader, observed)
        plaintext = crypt_payload(frame[4:], client_iv)
        client_iv = shuffle_iv(client_iv)
        opcode = (
            int.from_bytes(plaintext[:2], "little")
            if len(plaintext) >= 2
            else None
        )
        return frame, opcode, plaintext

    async def send_encrypted_frame(frame: bytes) -> None:
        if observed is not None:
            observed.data("server_to_client", frame)
        client_writer.write(frame)
        await client_writer.drain()

    async def send_reactive_plaintexts(
        opcode: int,
        plaintexts: tuple[bytes, ...],
        client_plaintext: bytes,
    ) -> None:
        if rewrite_channel_transition_world and opcode == 4:
            plaintexts = rewrite_channel_transition_world_from_selection(
                plaintexts, client_plaintext
            )
        delays = (client_opcode_reply_delays or {}).get(
            opcode, (0.0,) * len(plaintexts)
        )
        if len(delays) != len(plaintexts):
            raise ValueError(
                f"client opcode {opcode} has {len(plaintexts)} replies but "
                f"{len(delays)} delays"
            )
        for delay, reactive_plaintext in zip(delays, plaintexts, strict=True):
            if delay > 0:
                await asyncio.sleep(delay)
            await send_encrypted_frame(
                encrypt_next_server_frame(reactive_plaintext)
            )

    try:
        if initial_delay_seconds > 0:
            await asyncio.sleep(initial_delay_seconds)
        for event in data_events(transcript.events):
            if timing_scale > 0 and previous_timestamp_ns is not None:
                delay = max(0, event.timestamp_ns - previous_timestamp_ns) / 1e9
                await asyncio.sleep(delay * timing_scale)
            previous_timestamp_ns = event.timestamp_ns

            if event.direction == "client_to_server":
                if remaining_opcode_replies:
                    while True:
                        received, opcode, client_plaintext = await read_live_frame()
                        if opcode not in remaining_opcode_replies:
                            break
                        plaintexts = remaining_opcode_replies.pop(opcode)
                        if rewrite_channel_transition_world and opcode == 4:
                            plaintexts = (
                                rewrite_channel_transition_world_from_selection(
                                    plaintexts, client_plaintext
                                )
                            )
                        pending_opcode_replies.extend(plaintexts)
                elif client_iv is not None:
                    received, _, _ = await read_live_frame()
                elif strict:
                    received = await read_and_record_exactly(
                        client_reader, len(event.data), observed
                    )
                else:
                    received = await read_and_record_encrypted_frame(
                        client_reader, observed
                    )
                if strict and received != event.data:
                    mismatch = next(
                        (
                            index
                            for index, (actual, expected) in enumerate(
                                zip(received, event.data, strict=True)
                            )
                            if actual != expected
                        ),
                        0,
                    )
                    raise ValueError(
                        f"Client transcript mismatch at event offset {mismatch}"
                    )
            elif event.direction == "server_to_client":
                outgoing = next(patched_server_events)
                await send_encrypted_frame(outgoing)

        needs_server_cipher = bool(
            post_transcript_server_frames
            or post_transcript_replies
            or pending_opcode_replies
            or remaining_opcode_replies
            or world_heartbeat_interval_seconds is not None
            or mob_movement_acknowledgement_policy is not None
        )
        if needs_server_cipher:
            server_iv, server_version_mask = post_transcript_server_cipher_state(
                transcript, dropped_server_frames
            )
        else:
            server_iv, server_version_mask = b"", 0

        def encrypt_next_server_frame(plaintext: bytes) -> bytes:
            nonlocal server_iv
            if not server_iv:
                raise RuntimeError("Server cipher state is not initialized")
            outgoing = (
                encode_frame_header(
                    len(plaintext), server_iv, server_version_mask
                )
                + crypt_payload(plaintext, server_iv)
            )
            server_iv = shuffle_iv(server_iv)
            return outgoing

        post_transcript_plaintexts = (
            tuple(pending_opcode_replies) + post_transcript_server_frames
        )
        if post_transcript_plaintexts and post_transcript_start_delay_seconds > 0:
            await asyncio.sleep(post_transcript_start_delay_seconds)
        for index, plaintext in enumerate(post_transcript_plaintexts):
            if index > 0:
                gap_index = index - 1
                gap_delay_seconds = (
                    post_transcript_gap_delays_seconds[gap_index]
                    if gap_index < len(post_transcript_gap_delays_seconds)
                    else post_transcript_frame_delay_seconds
                )
                if gap_delay_seconds > 0:
                    await asyncio.sleep(gap_delay_seconds)
            await send_encrypted_frame(encrypt_next_server_frame(plaintext))
            if (
                npc_state_replay_plaintext is not None
                and plaintext == npc_state_replay_plaintext
                and npc_state_replay_metrics is not None
            ):
                npc_state_replay_metrics["packets_sent"] = (
                    int(npc_state_replay_metrics.get("packets_sent", 0)) + 1
                )
            if (
                player_stat_update_plaintext is not None
                and plaintext == player_stat_update_plaintext
                and player_stat_update_metrics is not None
            ):
                player_stat_update_metrics["packets_sent"] = (
                    int(player_stat_update_metrics.get("packets_sent", 0)) + 1
                )

        for plaintext in post_transcript_replies:
            if remaining_opcode_replies:
                while True:
                    _, opcode, client_plaintext = await read_live_frame()
                    if opcode not in remaining_opcode_replies:
                        break
                    await send_reactive_plaintexts(
                        opcode,
                        remaining_opcode_replies.pop(opcode),
                        client_plaintext,
                    )
            else:
                if client_iv is not None:
                    await read_live_frame()
                else:
                    await read_and_record_encrypted_frame(client_reader, observed)
            await send_encrypted_frame(encrypt_next_server_frame(plaintext))

        if hold_open_seconds > 0:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + hold_open_seconds
            next_heartbeat_at = (
                loop.time() + world_heartbeat_interval_seconds
                if world_heartbeat_interval_seconds is not None
                else None
            )
            while (remaining := deadline - loop.time()) > 0:
                now = loop.time()
                if next_heartbeat_at is not None and now >= next_heartbeat_at:
                    await send_encrypted_frame(
                        encrypt_next_server_frame(HeartbeatProbe().to_bytes())
                    )
                    pending_periodic_heartbeats.append(loop.time())
                    if heartbeat_metrics is not None:
                        heartbeat_metrics["probes_sent"] = (
                            int(heartbeat_metrics.get("probes_sent", 0)) + 1
                        )
                        heartbeat_metrics["pending"] = (
                            int(heartbeat_metrics.get("pending", 0)) + 1
                        )
                    next_heartbeat_at += world_heartbeat_interval_seconds
                    if next_heartbeat_at <= now:
                        next_heartbeat_at = (
                            now + world_heartbeat_interval_seconds
                        )
                    continue
                timeout = remaining
                if next_heartbeat_at is not None:
                    timeout = min(timeout, next_heartbeat_at - now)
                try:
                    if client_iv is not None:
                        received, opcode, client_plaintext = await asyncio.wait_for(
                            read_live_frame(), timeout=timeout
                        )
                    else:
                        received = await asyncio.wait_for(
                            client_reader.read(65536), timeout=timeout
                        )
                        opcode = None
                        if received and observed is not None:
                            observed.data("client_to_server", received)
                except TimeoutError:
                    if next_heartbeat_at is not None:
                        continue
                    break
                except asyncio.IncompleteReadError:
                    break
                if not received:
                    break
                if opcode == 23 and pending_periodic_heartbeats:
                    sent_at = pending_periodic_heartbeats.popleft()
                    round_trip_ms = (loop.time() - sent_at) * 1000
                    if heartbeat_metrics is not None:
                        heartbeat_metrics["responses_observed"] = (
                            int(
                                heartbeat_metrics.get(
                                    "responses_observed", 0
                                )
                            )
                            + 1
                        )
                        heartbeat_metrics["pending"] = max(
                            0,
                            int(heartbeat_metrics.get("pending", 0)) - 1,
                        )
                        heartbeat_metrics["last_round_trip_ms"] = round(
                            round_trip_ms, 3
                        )
                        prior_max = heartbeat_metrics.get(
                            "max_round_trip_ms"
                        )
                        heartbeat_metrics["max_round_trip_ms"] = round(
                            max(float(prior_max or 0.0), round_trip_ms), 3
                        )
                if (
                    opcode == 207
                    and mob_movement_acknowledgement_policy is not None
                ):
                    movement = MobMovementSubmission.parse(client_plaintext)
                    if mob_acknowledgement_metrics is not None:
                        mob_acknowledgement_metrics["submissions_observed"] = (
                            int(
                                mob_acknowledgement_metrics.get(
                                    "submissions_observed", 0
                                )
                            )
                            + 1
                        )
                    try:
                        acknowledgement = (
                            mob_movement_acknowledgement_policy.acknowledge(
                                movement
                            )
                        )
                    except ValueError:
                        if mob_acknowledgement_metrics is not None:
                            mob_acknowledgement_metrics[
                                "submissions_rejected"
                            ] = (
                                int(
                                    mob_acknowledgement_metrics.get(
                                        "submissions_rejected", 0
                                    )
                                )
                                + 1
                            )
                        raise
                    await send_encrypted_frame(
                        encrypt_next_server_frame(
                            acknowledgement.to_bytes()
                        )
                    )
                    if mob_acknowledgement_metrics is not None:
                        mob_acknowledgement_metrics["responses_sent"] = (
                            int(
                                mob_acknowledgement_metrics.get(
                                    "responses_sent", 0
                                )
                            )
                            + 1
                        )
                if opcode in remaining_opcode_replies:
                    await send_reactive_plaintexts(
                        opcode,
                        remaining_opcode_replies.pop(opcode),
                        client_plaintext,
                    )
    except Exception as exception:
        error = f"{type(exception).__name__}: {exception}"
        raise
    finally:
        if observed is not None:
            observed.close(error=error)
        client_writer.close()
        await client_writer.wait_closed()


def patch_server_frames(
    transcript: Transcript,
    frame_patches: dict[int, bytes],
    dropped_frame_indices: set[int] | None = None,
) -> bytes:
    """Return the server stream with selected frames replaced or omitted.

    Replacements are plaintext and may change the encrypted frame length.  When a
    frame is omitted, all later frames are decrypted with the captured IV stream
    and re-encrypted with the emitted IV stream so the client remains synchronized.
    """
    dropped_frame_indices = dropped_frame_indices or set()
    server_bytes = transcript.server_bytes
    if not frame_patches and not dropped_frame_indices:
        return server_bytes
    edited_indices = set(frame_patches) | dropped_frame_indices
    if any(index < 0 for index in edited_indices):
        raise ValueError("Server frame edit indices cannot be negative")
    overlap = sorted(set(frame_patches) & dropped_frame_indices)
    if overlap:
        raise ValueError(
            f"Server frames cannot be both patched and dropped: {overlap}"
        )

    handshake = parse_handshake(server_bytes)
    frames = parse_encrypted_frames(server_bytes, offset=handshake.wire_length)
    missing = sorted(edited_indices - set(range(len(frames))))
    if missing:
        raise ValueError(
            f"Server frame edit indices are out of range: {missing}; "
            f"capture has {len(frames)} frames"
        )

    patched = bytearray(server_bytes[: handshake.wire_length])
    source_offset = handshake.wire_length
    captured_iv = handshake.second_iv
    emitted_iv = handshake.second_iv
    for index, frame in enumerate(frames):
        patched.extend(server_bytes[source_offset : frame.offset])
        original_plaintext = crypt_payload(frame.payload, captured_iv)
        version_mask = int.from_bytes(
            frame.header[:2], "little"
        ) ^ int.from_bytes(captured_iv[2:4], "little")
        captured_iv = shuffle_iv(captured_iv)

        if index not in dropped_frame_indices:
            plaintext = frame_patches.get(index, original_plaintext)
            patched.extend(
                encode_frame_header(len(plaintext), emitted_iv, version_mask)
                + crypt_payload(plaintext, emitted_iv)
            )
            emitted_iv = shuffle_iv(emitted_iv)
        source_offset = frame.offset + frame.wire_length
    patched.extend(server_bytes[source_offset:])
    return bytes(patched)


def patch_server_event_data(
    transcript: Transcript,
    frame_patches: dict[int, bytes],
    dropped_frame_indices: set[int] | None = None,
) -> tuple[bytes, ...]:
    """Map an edited server stream back onto captured server event timing.

    Event boundaries inside a resized frame are moved proportionally through its
    payload; boundaries inside an omitted frame collapse to its former start.
    This preserves every client/server ordering point while allowing a frame to
    grow, shrink, or disappear.
    """
    dropped_frame_indices = dropped_frame_indices or set()
    server_events = tuple(
        event
        for event in data_events(transcript.events)
        if event.direction == "server_to_client"
    )
    if not frame_patches and not dropped_frame_indices:
        return tuple(event.data for event in server_events)

    original = transcript.server_bytes
    patched = patch_server_frames(
        transcript, frame_patches, dropped_frame_indices
    )
    handshake = parse_handshake(original)
    frames = parse_encrypted_frames(original, offset=handshake.wire_length)
    edits: list[tuple[int, int, int, int]] = []
    cumulative_delta = 0
    for index, frame in enumerate(frames):
        replacement = frame_patches.get(index)
        dropped = index in dropped_frame_indices
        if replacement is None and not dropped:
            continue
        old_start = frame.offset
        old_end = frame.offset + frame.wire_length
        new_start = old_start + cumulative_delta
        new_end = (
            new_start
            if dropped
            else new_start + len(frame.header) + len(replacement)
        )
        edits.append((old_start, old_end, new_start, new_end))
        cumulative_delta += (new_end - new_start) - (old_end - old_start)

    def translate_boundary(boundary: int) -> int:
        delta = 0
        for old_start, old_end, new_start, new_end in edits:
            if boundary <= old_start:
                return boundary + delta
            if boundary >= old_end:
                delta += (new_end - new_start) - (old_end - old_start)
                continue
            if new_start == new_end:
                return new_start

            relative = boundary - old_start
            header_length = 4
            if relative <= header_length:
                return new_start + relative
            old_payload_length = old_end - old_start - header_length
            new_payload_length = new_end - new_start - header_length
            old_payload_offset = relative - header_length
            mapped_payload_offset = round(
                old_payload_offset * new_payload_length / old_payload_length
            )
            return new_start + header_length + mapped_payload_offset
        return boundary + delta

    chunks: list[bytes] = []
    original_boundary = 0
    patched_boundary = 0
    for event in server_events:
        original_boundary += len(event.data)
        next_patched_boundary = translate_boundary(original_boundary)
        chunks.append(patched[patched_boundary:next_patched_boundary])
        patched_boundary = next_patched_boundary
    if patched_boundary != len(patched):
        raise ProtocolError(
            "Patched server event mapping did not consume the complete stream"
        )
    return tuple(chunks)


def post_transcript_server_cipher_state(
    transcript: Transcript,
    dropped_frame_indices: set[int] | None = None,
) -> tuple[bytes, int]:
    """Return server cipher state after all emitted captured frames."""
    dropped_frame_indices = dropped_frame_indices or set()
    handshake = parse_handshake(transcript.server_bytes)
    captured_frames = parse_encrypted_frames(
        transcript.server_bytes, offset=handshake.wire_length
    )
    if not captured_frames:
        raise ProtocolError(
            "Cannot infer the server frame version mask without a captured frame"
        )

    iv = handshake.second_iv
    version_mask = int.from_bytes(
        captured_frames[0].header[:2], "little"
    ) ^ int.from_bytes(
        iv[2:4], "little"
    )
    missing = sorted(dropped_frame_indices - set(range(len(captured_frames))))
    if missing:
        raise ValueError(
            f"Dropped server frame indices are out of range: {missing}; "
            f"capture has {len(captured_frames)} frames"
        )
    for index, _ in enumerate(captured_frames):
        if index in dropped_frame_indices:
            continue
        iv = shuffle_iv(iv)
    return iv, version_mask


def build_post_transcript_server_frames(
    transcript: Transcript, plaintexts: tuple[bytes, ...]
) -> tuple[bytes, ...]:
    """Encrypt replies sent after the captured transcript.

    Server IV state advances once per captured or generated server frame,
    independently of the client direction.
    """
    if not plaintexts:
        return ()

    iv, version_mask = post_transcript_server_cipher_state(transcript)

    encrypted: list[bytes] = []
    for plaintext in plaintexts:
        encrypted.append(
            encode_frame_header(len(plaintext), iv, version_mask)
            + crypt_payload(plaintext, iv)
        )
        iv = shuffle_iv(iv)
    return tuple(encrypted)


def parse_server_frame_patch(specification: str) -> tuple[int, bytes]:
    """Parse one CLI INDEX=PLAINTEXT_HEX server-frame replacement."""
    index_text, separator, payload_text = specification.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(
            "server frame patch must have the form INDEX=PLAINTEXT_HEX"
        )
    try:
        index = int(index_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid server frame index: {index_text!r}"
        ) from error
    if index < 0:
        raise argparse.ArgumentTypeError("server frame index cannot be negative")
    try:
        payload = bytes.fromhex(payload_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("server frame payload is not valid hex") from error
    return index, payload


def parse_plaintext_hex(specification: str) -> bytes:
    """Parse one CLI plaintext payload without logging its contents."""
    try:
        return bytes.fromhex(specification)
    except ValueError as error:
        raise argparse.ArgumentTypeError("payload is not valid hex") from error


def parse_ipv4_endpoint(specification: str) -> tuple[IPv4Address, int]:
    try:
        address_text, port_text = specification.rsplit(":", 1)
        address = IPv4Address(address_text)
        port = int(port_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "endpoint must be an IPv4 address and port, such as 127.0.0.1:8587"
        ) from error
    if not 1 <= port <= 0xFFFF:
        raise argparse.ArgumentTypeError("endpoint port must be between 1 and 65535")
    return address, port


def parse_non_negative_int(specification: str) -> int:
    try:
        value = int(specification, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"expected a non-negative integer, got {specification!r}"
        ) from error
    if value < 0:
        raise argparse.ArgumentTypeError("value cannot be negative")
    return value


@functools.lru_cache(maxsize=8)
def _load_pcap_plaintexts(path: str, tcp_stream: int) -> tuple[bytes, ...]:
    transcript = load_pcap_tcp_stream(Path(path), tcp_stream)
    decoded = decode_transcript(transcript)
    return tuple(
        frame.plaintext
        for frame in decoded.frames
        if frame.direction == "server_to_client"
    )


def parse_pcap_plaintext_reference(specification: str) -> bytes:
    """Resolve PCAP@STREAM:SERVER_FRAME[?TRANSFORM] without logging payload."""
    reference, separator, transform = specification.partition("?")
    source_text, index_separator, frame_index_text = reference.rpartition(":")
    path_text, stream_separator, stream_text = source_text.rpartition("@")
    if not index_separator or not stream_separator or not path_text:
        raise argparse.ArgumentTypeError(
            "pcap frame reference must have the form PCAP@STREAM:SERVER_FRAME"
        )
    try:
        tcp_stream = int(stream_text, 0)
        frame_index = int(frame_index_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "pcap stream and server frame index must be integers"
        ) from error
    if tcp_stream < 0 or frame_index < 0:
        raise argparse.ArgumentTypeError(
            "pcap stream and server frame index cannot be negative"
        )
    try:
        payload = _load_pcap_plaintexts(path_text, tcp_stream)[frame_index]
    except IndexError as error:
        raise argparse.ArgumentTypeError(
            f"pcap stream {tcp_stream} has no server frame {frame_index}"
        ) from error
    if not separator:
        return payload
    if transform.startswith("opcode="):
        try:
            opcode = int(transform.removeprefix("opcode="), 0)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                "pcap opcode transform must be an integer"
            ) from error
        if not 0 <= opcode <= 0xFFFF:
            raise argparse.ArgumentTypeError(
                "pcap opcode transform must be between 0 and 65535"
            )
        if len(payload) < 2:
            raise argparse.ArgumentTypeError(
                "cannot rewrite the opcode of a plaintext shorter than 2 bytes"
            )
        return opcode.to_bytes(2, "little") + payload[2:]
    if transform.startswith("handoff="):
        endpoint = parse_ipv4_endpoint(transform.removeprefix("handoff="))
        try:
            original = WorldHandoff.parse(payload)
        except ValueError as error:
            raise argparse.ArgumentTypeError(
                "pcap handoff transform requires a validated handoff packet"
            ) from error
        address, port = endpoint
        return WorldHandoff(
            result=original.result,
            address=address,
            port=port,
            character_id=original.character_id,
            trailing=original.trailing,
            opcode=original.opcode,
        ).to_bytes()
    raise argparse.ArgumentTypeError(
        "unknown pcap frame transform; use opcode=N or handoff=IPV4:PORT"
    )


def parse_client_opcode_pcap_reply(specification: str) -> tuple[int, bytes]:
    opcode_text, separator, reference = specification.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(
            "pcap client opcode reply must have the form OPCODE=REFERENCE"
        )
    try:
        opcode = int(opcode_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid client opcode: {opcode_text!r}"
        ) from error
    if not 0 <= opcode <= 0xFFFF:
        raise argparse.ArgumentTypeError(
            "client opcode must be between 0 and 65535"
        )
    return opcode, parse_pcap_plaintext_reference(reference)


def parse_client_opcode_reply_delays(
    specification: str,
) -> tuple[int, tuple[float, ...]]:
    opcode_text, separator, delays_text = specification.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(
            "reply delays must have the form OPCODE=SECONDS[,SECONDS...]"
        )
    try:
        opcode = int(opcode_text, 0)
        delays = tuple(float(value) for value in delays_text.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "reply opcode and delays must be numeric"
        ) from error
    if not 0 <= opcode <= 0xFFFF:
        raise argparse.ArgumentTypeError(
            "client opcode must be between 0 and 65535"
        )
    if not delays or any(delay < 0 for delay in delays):
        raise argparse.ArgumentTypeError(
            "reply delays must contain non-negative seconds"
        )
    return opcode, delays


def parse_server_frame_pcap_patch(specification: str) -> tuple[int, bytes]:
    index_text, separator, reference = specification.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(
            "pcap server frame patch must have the form INDEX=REFERENCE"
        )
    try:
        index = int(index_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid server frame index: {index_text!r}"
        ) from error
    if index < 0:
        raise argparse.ArgumentTypeError("server frame index cannot be negative")
    return index, parse_pcap_plaintext_reference(reference)


def drop_normalized_client_frames(
    transcript: Transcript, frame_indices: set[int]
) -> Transcript:
    found: set[int] = set()
    events = []
    for event in transcript.events:
        frame_index = (
            event.metadata.get("frame_index")
            if event.metadata is not None
            else None
        )
        if (
            event.event == "data"
            and event.direction == "client_to_server"
            and isinstance(frame_index, int)
            and frame_index in frame_indices
        ):
            found.add(frame_index)
            continue
        events.append(event)
    missing = frame_indices - found
    if missing:
        raise ValueError(
            f"client frame indices are absent from normalized transcript: "
            f"{sorted(missing)}"
        )
    return Transcript(path=transcript.path, events=tuple(events))


def build_handoff_frame_patch(
    transcript: Transcript, endpoint: tuple[IPv4Address, int]
) -> tuple[int, bytes]:
    analysis = analyze_login_transcript(transcript)
    handoffs = [
        observation
        for observation in analysis.observations
        if observation.kind == "world_handoff"
        and observation.coverage == ShapeCoverage.FULL
    ]
    if len(handoffs) != 1:
        raise ValueError(
            f"expected exactly one validated world handoff, found {len(handoffs)}"
        )
    observation = handoffs[0]
    if not isinstance(observation.parsed, WorldHandoff):
        raise RuntimeError("validated handoff observation has no parsed packet")
    address, port = endpoint
    original = observation.parsed
    replacement = WorldHandoff(
        result=original.result,
        address=address,
        port=port,
        character_id=original.character_id,
        trailing=original.trailing,
        opcode=original.opcode,
    )
    return observation.direction_index, replacement.to_bytes()


def parse_zero_filled_frame(specification: str) -> bytes:
    """Parse one CLI OPCODE:LENGTH[:BYTE2] mostly-zero plaintext frame."""
    parts = specification.split(":")
    if len(parts) not in (2, 3):
        raise argparse.ArgumentTypeError(
            "zero-filled frame must have the form OPCODE:LENGTH[:BYTE2]"
        )
    try:
        opcode = int(parts[0], 0)
        length = int(parts[1], 0)
        byte2 = int(parts[2], 0) if len(parts) == 3 else 0
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "zero-filled frame values must be integers"
        ) from error
    if opcode < 0 or opcode > 0xFFFF:
        raise argparse.ArgumentTypeError("frame opcode must be a ushort")
    if length < 2 or length > MAX_ENCRYPTED_FRAME_BYTES:
        raise argparse.ArgumentTypeError(
            f"frame length must be between 2 and {MAX_ENCRYPTED_FRAME_BYTES}"
        )
    if byte2 < 0 or byte2 > 0xFF:
        raise argparse.ArgumentTypeError("frame byte 2 must be between 0 and 255")
    frame = bytearray(opcode.to_bytes(2, "little") + bytes(length - 2))
    if len(frame) >= 3:
        frame[2] = byte2
    return bytes(frame)


def parse_client_opcode_reply(specification: str) -> tuple[int, bytes]:
    """Parse one CLI OPCODE=PLAINTEXT_HEX reactive reply."""
    opcode_text, separator, payload_text = specification.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(
            "client opcode reply must have the form OPCODE=PLAINTEXT_HEX"
        )
    try:
        opcode = int(opcode_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"invalid client opcode: {opcode_text!r}"
        ) from error
    if opcode < 0 or opcode > 0xFFFF:
        raise argparse.ArgumentTypeError(
            "client opcode must be between 0 and 65535"
        )
    return opcode, parse_plaintext_hex(payload_text)


def parse_client_opcode_result_rewrite(specification: str) -> tuple[int, int]:
    """Parse one CLI OPCODE=RESULT_BYTE capture rewrite."""
    opcode_text, separator, result_text = specification.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(
            "client result rewrite must have the form OPCODE=RESULT_BYTE"
        )
    try:
        opcode = int(opcode_text, 0)
        result = int(result_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "client result rewrite values must be integers"
        ) from error
    if opcode < 0 or opcode > 0xFFFF:
        raise argparse.ArgumentTypeError(
            "client opcode must be between 0 and 65535"
        )
    if result < 0 or result > 0xFF:
        raise argparse.ArgumentTypeError(
            "client result byte must be between 0 and 255"
        )
    return opcode, result


def parse_server_opcode_byte_rewrite(
    specification: str,
) -> tuple[int, int, int]:
    """Parse one CLI OPCODE:OFFSET=BYTE server-frame rewrite."""
    selector, separator, value_text = specification.partition("=")
    opcode_text, offset_separator, offset_text = selector.partition(":")
    if not separator or not offset_separator:
        raise argparse.ArgumentTypeError(
            "server byte rewrite must have the form OPCODE:OFFSET=BYTE"
        )
    try:
        opcode = int(opcode_text, 0)
        offset = int(offset_text, 0)
        value = int(value_text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "server byte rewrite values must be integers"
        ) from error
    if opcode < 0 or opcode > 0xFFFF:
        raise argparse.ArgumentTypeError(
            "server opcode must be between 0 and 65535"
        )
    if offset < 2 or offset > MAX_ENCRYPTED_FRAME_BYTES:
        raise argparse.ArgumentTypeError(
            "server plaintext offset must be at least 2"
        )
    if value < 0 or value > 0xFF:
        raise argparse.ArgumentTypeError(
            "server replacement byte must be between 0 and 255"
        )
    return opcode, offset, value


async def read_and_record_exactly(
    reader: asyncio.StreamReader,
    size: int,
    observed: TranscriptWriter | None,
) -> bytes:
    """Read one expected replay event without hiding a shorter live packet."""
    received = bytearray()
    while len(received) < size:
        chunk = await reader.read(size - len(received))
        if not chunk:
            raise asyncio.IncompleteReadError(bytes(received), size)
        received.extend(chunk)
        if observed is not None:
            observed.data("client_to_server", chunk)
    return bytes(received)


async def read_and_record_encrypted_frame(
    reader: asyncio.StreamReader,
    observed: TranscriptWriter | None,
) -> bytes:
    """Read one complete live frame whose size may differ from the capture."""
    header = await read_and_record_exactly(reader, 4, observed)
    payload_length = decode_frame_length(header)
    if payload_length > MAX_ENCRYPTED_FRAME_BYTES:
        raise ProtocolError(
            f"Live encrypted frame is too large: {payload_length} bytes"
        )
    payload = await read_and_record_exactly(reader, payload_length, observed)
    return header + payload


async def stub_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    transcript_directory: Path,
    listen_port: int,
) -> None:
    peer = client_writer.get_extra_info("peername")
    transcript = TranscriptWriter(
        transcript_directory,
        label=f"stub_{listen_port}",
        metadata={"mode": "stub", "listen_port": listen_port, "peer": repr(peer)},
    )
    try:
        while data := await client_reader.read(65536):
            transcript.data("client_to_server", data)
    finally:
        transcript.close()
        client_writer.close()
        await client_writer.wait_closed()


async def run_listener(
    host: str,
    port: int,
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
    *,
    runtime: ServerRuntime,
    http_api_host: str,
    http_api_port: int | None,
) -> None:
    tasks: set[asyncio.Task[None]] = set()

    async def tracked_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        runtime.connection_started()
        error: Exception | None = None
        try:
            await handler(reader, writer)
        except Exception as exception:
            error = exception
            raise
        finally:
            runtime.connection_finished(error)

    def start_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(tracked_handler(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        task.add_done_callback(report_task_error)

    server = await asyncio.start_server(start_handler, host, port)
    runtime.listener_addresses = tuple(
        str(socket.getsockname()) for socket in server.sockets or []
    )
    addresses = ", ".join(runtime.listener_addresses)
    print(f"listening mode={handler_name(handler)} addresses={addresses}", flush=True)
    http_server = (
        await start_runtime_http_api(runtime, http_api_host, http_api_port)
        if http_api_port is not None
        else None
    )
    if http_server is not None:
        http_addresses = ", ".join(
            str(socket.getsockname()) for socket in http_server.sockets or []
        )
        print(f"http_api addresses={http_addresses}", flush=True)
    if http_server is None:
        async with server:
            await server.serve_forever()
    else:
        async with server, http_server:
            await asyncio.gather(
                server.serve_forever(), http_server.serve_forever()
            )


def handler_name(handler: object) -> str:
    if isinstance(handler, functools.partial):
        return getattr(handler.func, "__name__", type(handler.func).__name__)
    return getattr(handler, "__name__", type(handler).__name__)


def report_task_error(task: asyncio.Task[None]) -> None:
    if task.cancelled():
        return
    try:
        task.result()
    except Exception as exception:
        print(
            f"connection failed: {type(exception).__name__}: {exception}",
            file=sys.stderr,
            flush=True,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture, inspect, and replay MapleStory Classic TCP sessions"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser(
        "capture-proxy", help="Proxy an official TCP endpoint and record both directions"
    )
    add_listener_arguments(capture)
    capture.add_argument("--upstream-host", required=True)
    capture.add_argument("--upstream-port", required=True, type=int)
    capture.add_argument("--transcript-dir", required=True, type=Path)
    capture.add_argument("--http-proxy-host")
    capture.add_argument("--http-proxy-port", type=int)
    capture.add_argument(
        "--http-proxy-user-env", default="MAPLE_PROXY_USER", metavar="ENV"
    )
    capture.add_argument(
        "--http-proxy-password-env", default="MAPLE_PROXY_PASSWORD", metavar="ENV"
    )
    capture.add_argument(
        "--max-capture-bytes", type=int, default=16 * 1024 * 1024
    )
    capture.add_argument(
        "--rewrite-client-opcode-result",
        action="append",
        default=[],
        type=parse_client_opcode_result_rewrite,
        metavar="OPCODE=RESULT_BYTE",
        help=(
            "decrypt matching Maple client frames and replace plaintext byte "
            "offset 2 before forwarding; may be repeated for distinct opcodes"
        ),
    )
    capture.add_argument(
        "--rewrite-server-opcode-byte",
        action="append",
        default=[],
        type=parse_server_opcode_byte_rewrite,
        metavar="OPCODE:OFFSET=BYTE",
        help=(
            "decrypt matching Maple server frames and replace one plaintext "
            "byte before forwarding; may be repeated"
        ),
    )

    replay = subparsers.add_parser(
        "replay", help="Replay one captured server session to a client"
    )
    add_listener_arguments(replay)
    replay_source = replay.add_mutually_exclusive_group(required=True)
    replay_source.add_argument("--transcript", type=Path)
    replay_source.add_argument(
        "--pcap", type=Path, help="read one Maple TCP stream directly from pcap"
    )
    replay.add_argument(
        "--tcp-stream",
        type=int,
        help="Wireshark tcp.stream index (required with --pcap)",
    )
    replay.add_argument(
        "--tshark", default="tshark", help="tshark executable used for pcap input"
    )
    replay.add_argument(
        "--transcript-dir",
        type=Path,
        help="optionally record the live client/replay exchange",
    )
    replay.add_argument("--no-strict", action="store_true")
    replay.add_argument("--timing-scale", type=float, default=0.0)
    replay.add_argument(
        "--hold-open-seconds",
        type=float,
        default=0.0,
        help="keep the replay connection open and record client traffic afterward",
    )
    replay.add_argument(
        "--initial-delay-seconds",
        type=float,
        default=0.0,
        help="delay transcript playback after accept (useful for debugger attach)",
    )
    replay.add_argument(
        "--rewrite-initial-current-hp",
        type=int,
        metavar="HP",
        help=(
            "rewrite only the typed current-HP field in the initial opcode-157 "
            "snapshot after validating the complete packet model"
        ),
    )
    replay.add_argument(
        "--emit-current-hp-update",
        type=int,
        metavar="HP",
        help=(
            "generate one typed opcode-41 current-HP stat update after replay; "
            "requires --keep-world-open and the validated stat-update model"
        ),
    )
    replay.add_argument(
        "--server-frame-patch",
        action="append",
        default=[],
        type=parse_server_frame_patch,
        metavar="INDEX=PLAINTEXT_HEX",
        help=(
            "replace a captured server frame with plaintext (length may change); "
            "may be repeated"
        ),
    )
    replay.add_argument(
        "--server-frame-patch-from-pcap",
        dest="server_frame_patch",
        action="append",
        type=parse_server_frame_pcap_patch,
        metavar="INDEX=PCAP@STREAM:SERVER_FRAME[?TRANSFORM]",
        help="replace a captured replay frame with plaintext sourced from pcap",
    )
    replay.add_argument(
        "--drop-server-frame",
        action="append",
        default=[],
        type=parse_non_negative_int,
        metavar="INDEX",
        help=(
            "omit one captured encrypted server frame and re-encrypt every later "
            "frame with corrected IV progression; may be repeated"
        ),
    )
    replay.add_argument(
        "--keep-world-open",
        action="store_true",
        help=(
            "validate and omit the final server opcode-9 world-session "
            "termination packet; requires --hold-open-seconds"
        ),
    )
    replay.add_argument(
        "--world-heartbeat-interval-seconds",
        type=float,
        help=(
            "after replay, periodically send the modeled server opcode-10 "
            "heartbeat probe while holding the world open"
        ),
    )
    replay.add_argument(
        "--repeat-final-field-npc-state-update",
        action="store_true",
        help=(
            "select the final fully modeled update for a known NPC in the "
            "capture's final field and send it once after replay; requires "
            "--keep-world-open"
        ),
    )
    replay.add_argument(
        "--reactive-mob-movement-acknowledgements",
        action="store_true",
        help=(
            "during hold-open, derive the validated opcode-283 policy and "
            "acknowledge opcode-207 submissions only for field-local mobs "
            "with known templates; requires --keep-world-open"
        ),
    )
    replay.add_argument(
        "--send-after-transcript",
        dest="post_transcript_server_frames",
        action="append",
        default=[],
        type=parse_plaintext_hex,
        metavar="PLAINTEXT_HEX",
        help=(
            "send this plaintext frame immediately after the captured transcript; "
            "may be repeated"
        ),
    )
    replay.add_argument(
        "--send-zero-filled-after-transcript",
        dest="post_transcript_server_frames",
        action="append",
        type=parse_zero_filled_frame,
        metavar="OPCODE:LENGTH[:BYTE2]",
        help=(
            "send a plaintext frame containing a two-byte opcode followed by "
            "zeros after the captured transcript; may be repeated"
        ),
    )
    replay.add_argument(
        "--send-after-transcript-from-pcap",
        dest="post_transcript_server_frames",
        action="append",
        type=parse_pcap_plaintext_reference,
        metavar="PCAP@STREAM:SERVER_FRAME[?TRANSFORM]",
        help=(
            "append plaintext extracted and validated from one pcap server frame; "
            "may be repeated"
        ),
    )
    replay.add_argument(
        "--post-transcript-start-delay-seconds",
        type=float,
        default=0.0,
        help="delay before the first post-transcript server frame",
    )
    replay.add_argument(
        "--post-transcript-frame-delay-seconds",
        type=float,
        default=0.0,
        help="delay between consecutive post-transcript server frames",
    )
    replay.add_argument(
        "--post-transcript-gap-delay-seconds",
        dest="post_transcript_gap_delays_seconds",
        action="append",
        default=[],
        type=float,
        metavar="SECONDS",
        help=(
            "delay for the next gap in the post-transcript send sequence; "
            "repeat once per gap, including queued opcode replies"
        ),
    )
    replay.add_argument(
        "--reply-after-client-frame",
        action="append",
        default=[],
        type=parse_plaintext_hex,
        metavar="PLAINTEXT_HEX",
        help=(
            "after the transcript, wait for one complete client frame and reply "
            "with this plaintext; may be repeated"
        ),
    )
    replay.add_argument(
        "--reply-after-client-frame-from-pcap",
        dest="reply_after_client_frame",
        action="append",
        type=parse_pcap_plaintext_reference,
        metavar="PCAP@STREAM:SERVER_FRAME[?TRANSFORM]",
        help="reply to the next client frame with pcap-sourced plaintext",
    )
    replay.add_argument(
        "--reply-on-client-opcode",
        action="append",
        default=[],
        type=parse_client_opcode_reply,
        metavar="OPCODE=PLAINTEXT_HEX",
        help=(
            "in non-strict replay, skip one matching client frame and send this "
            "plaintext after the captured transcript (or immediately if it "
            "arrives during hold-open); may be repeated for distinct opcodes"
        ),
    )
    replay.add_argument(
        "--reply-on-client-opcode-from-pcap",
        dest="reply_on_client_opcode",
        action="append",
        type=parse_client_opcode_pcap_reply,
        metavar="OPCODE=PCAP@STREAM:SERVER_FRAME[?TRANSFORM]",
        help=(
            "react to a client opcode with pcap-sourced plaintext; repeated "
            "entries for one opcode form an ordered response sequence"
        ),
    )
    replay.add_argument(
        "--client-opcode-reply-delays",
        action="append",
        default=[],
        type=parse_client_opcode_reply_delays,
        metavar="OPCODE=SECONDS[,SECONDS...]",
        help=(
            "delay before each ordered response for one reactive opcode; the "
            "number of delays must match that opcode's response count"
        ),
    )
    replay.add_argument(
        "--rewrite-channel-transition-world",
        action="store_true",
        help=(
            "rewrite opcode-402 stage-1 reactive replies with the world id "
            "from the triggering client opcode-4 selection"
        ),
    )
    replay.add_argument(
        "--validate-login-state",
        action="store_true",
        help="validate interpreted login packet shapes/state before listening",
    )
    replay.add_argument(
        "--rewrite-handoff",
        type=parse_ipv4_endpoint,
        metavar="IPV4:PORT",
        help=(
            "replace the validated login handoff endpoint while preserving its "
            "result and selected character id"
        ),
    )
    replay.add_argument(
        "--drop-client-frame",
        action="append",
        default=[],
        type=parse_non_negative_int,
        metavar="INDEX",
        help=(
            "omit one frame-aligned captured client event before replay; intended "
            "for launcher-only frames and may be repeated"
        ),
    )

    stub = subparsers.add_parser(
        "stub", help="Accept and record clients without sending a response"
    )
    add_listener_arguments(stub)
    stub.add_argument("--transcript-dir", required=True, type=Path)

    inspect_parser = subparsers.add_parser(
        "inspect", help="Print a safe structural summary of a transcript"
    )
    inspect_parser.add_argument("transcript", type=Path)

    compare_parser = subparsers.add_parser(
        "compare", help="Compare transcript structure without dumping payloads"
    )
    compare_parser.add_argument("first", type=Path)
    compare_parser.add_argument("second", type=Path)

    analyze_parser = subparsers.add_parser(
        "analyze-login",
        help=(
            "decrypt a transcript or pcap stream, fold interpreted packets into "
            "login game state, and validate packet shapes"
        ),
    )
    source = analyze_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--transcript", type=Path)
    source.add_argument("--pcap", type=Path)
    analyze_parser.add_argument(
        "--tcp-stream",
        type=int,
        help="Wireshark tcp.stream index (required with --pcap)",
    )
    analyze_parser.add_argument(
        "--tshark", default="tshark", help="tshark executable used for pcap input"
    )
    analyze_parser.add_argument("--json", action="store_true")
    analyze_parser.add_argument(
        "--packets",
        action="store_true",
        help=(
            "append one structured, frame-aligned decoded packet record to "
            "the text report for every plaintext frame"
        ),
    )
    analyze_parser.add_argument(
        "--show-identifiers",
        action="store_true",
        help="include account/character numeric identifiers in output",
    )
    analyze_parser.add_argument(
        "--fail-on-invalid",
        action="store_true",
        help="exit with status 2 if a shape or state invariant is invalid",
    )

    gameplay_parser = subparsers.add_parser(
        "analyze-gameplay",
        help=(
            "decrypt a world transcript or pcap stream, fold gameplay events "
            "into field state, and validate packet shapes"
        ),
    )
    gameplay_source = gameplay_parser.add_mutually_exclusive_group(required=True)
    gameplay_source.add_argument("--transcript", type=Path)
    gameplay_source.add_argument("--pcap", type=Path)
    gameplay_parser.add_argument(
        "--tcp-stream",
        type=int,
        help="Wireshark tcp.stream index (required with --pcap)",
    )
    gameplay_parser.add_argument(
        "--tshark", default="tshark", help="tshark executable used for pcap input"
    )
    gameplay_parser.add_argument("--json", action="store_true")
    gameplay_parser.add_argument(
        "--events",
        action="store_true",
        help="append the timestamped, state-changing gameplay event stream",
    )
    gameplay_parser.add_argument(
        "--packets",
        action="store_true",
        help="append one structured packet record for every plaintext frame",
    )
    gameplay_parser.add_argument(
        "--show-identifiers",
        action="store_true",
        help="include character and runtime object identifiers in output",
    )
    gameplay_parser.add_argument(
        "--fail-on-invalid",
        action="store_true",
        help="exit with status 2 if a shape or state invariant is invalid",
    )
    return parser


def add_listener_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument(
        "--http-api-host",
        default="127.0.0.1",
        help="loopback address for the optional runtime HTTP API",
    )
    parser.add_argument(
        "--http-api-port",
        type=int,
        help="enable the runtime HTTP API on this loopback port",
    )


def inspect_transcript(path: Path) -> None:
    transcript = Transcript.load(path)
    data_records = tuple(data_events(transcript.events))
    print(f"path={transcript.path}")
    print(f"events={len(transcript.events)} data_events={len(data_records)}")
    print(
        f"client_bytes={len(transcript.client_bytes)} "
        f"server_bytes={len(transcript.server_bytes)}"
    )
    for direction, payload in (
        ("client_to_server", transcript.client_bytes),
        ("server_to_client", transcript.server_bytes),
    ):
        preview = payload[:32].hex(" ")
        print(f"{direction}_preview={preview}")

    try:
        handshake = parse_handshake(transcript.server_bytes)
        client_frames = parse_encrypted_frames(transcript.client_bytes)
        server_frames = parse_encrypted_frames(
            transcript.server_bytes, offset=handshake.wire_length
        )
    except ProtocolError:
        return

    print(
        f"handshake=version:{handshake.version} subversion:{handshake.subversion!r} "
        f"locale:{handshake.locale} packet_length:{handshake.packet_length}"
    )
    print(
        f"handshake_ivs={handshake.first_iv.hex()},{handshake.second_iv.hex()} "
        f"trailing={handshake.trailing.hex()}"
    )
    print(f"client_frame_lengths={tuple(len(frame.payload) for frame in client_frames)}")
    print(f"server_frame_lengths={tuple(len(frame.payload) for frame in server_frames)}")


def compare_transcripts(first_path: Path, second_path: Path) -> None:
    first = Transcript.load(first_path)
    second = Transcript.load(second_path)
    print(f"first={first.path}")
    print(f"second={second.path}")

    for direction, first_payload, second_payload in (
        ("client_to_server", first.client_bytes, second.client_bytes),
        ("server_to_client", first.server_bytes, second.server_bytes),
    ):
        overlap = min(len(first_payload), len(second_payload))
        equal_positions = sum(
            left == right
            for left, right in zip(
                first_payload[:overlap], second_payload[:overlap], strict=True
            )
        )
        common_prefix = common_prefix_length(first_payload, second_payload)
        common_suffix = common_suffix_length(first_payload, second_payload)
        equality_percent = 100.0 if overlap == 0 else equal_positions / overlap * 100
        first_events = event_lengths(first, direction)
        second_events = event_lengths(second, direction)

        print(f"direction={direction}")
        print(f"  bytes={len(first_payload)},{len(second_payload)}")
        print(f"  event_lengths={first_events},{second_events}")
        print(f"  common_prefix={common_prefix} common_suffix={common_suffix}")
        print(
            f"  equal_positions={equal_positions}/{overlap} "
            f"({equality_percent:.1f}%) identical={first_payload == second_payload}"
        )


def event_lengths(transcript: Transcript, direction: str) -> tuple[int, ...]:
    return tuple(
        len(event.data)
        for event in data_events(transcript.events)
        if event.direction == direction
    )


def common_prefix_length(first: bytes, second: bytes) -> int:
    return next(
        (
            index
            for index, (left, right) in enumerate(
                zip(first, second, strict=False)
            )
            if left != right
        ),
        min(len(first), len(second)),
    )


def common_suffix_length(first: bytes, second: bytes) -> int:
    return common_prefix_length(first[::-1], second[::-1])


async def async_main(arguments: argparse.Namespace) -> None:
    runtime_config: dict[str, object]
    runtime_protocol: dict[str, object] = {}
    if arguments.command == "capture-proxy":
        client_result_rewrites = dict(arguments.rewrite_client_opcode_result)
        if len(client_result_rewrites) != len(
            arguments.rewrite_client_opcode_result
        ):
            raise ValueError("Each rewritten client opcode may be specified only once")
        server_byte_rewrites = {
            (opcode, offset): value
            for opcode, offset, value in arguments.rewrite_server_opcode_byte
        }
        if len(server_byte_rewrites) != len(
            arguments.rewrite_server_opcode_byte
        ):
            raise ValueError(
                "Each rewritten server opcode/offset pair may be specified only once"
            )
        config = CaptureProxyConfig(
            upstream_host=arguments.upstream_host,
            upstream_port=arguments.upstream_port,
            transcript_directory=arguments.transcript_dir,
            http_proxy_host=arguments.http_proxy_host,
            http_proxy_port=arguments.http_proxy_port,
            http_proxy_username=os.environ.get(arguments.http_proxy_user_env),
            http_proxy_password=os.environ.get(arguments.http_proxy_password_env),
            max_capture_bytes=arguments.max_capture_bytes,
            client_opcode_result_rewrites=tuple(
                client_result_rewrites.items()
            ),
            server_opcode_byte_rewrites=tuple(
                (opcode, offset, value)
                for (opcode, offset), value in server_byte_rewrites.items()
            ),
        )
        handler = functools.partial(capture_proxy_connection, config=config)
        runtime_config = {
            "upstream_host": arguments.upstream_host,
            "upstream_port": arguments.upstream_port,
            "capture_enabled": True,
        }
    elif arguments.command == "replay":
        if arguments.pcap is not None:
            if arguments.tcp_stream is None:
                raise ValueError("--tcp-stream is required with --pcap")
            transcript = load_pcap_tcp_stream(
                arguments.pcap,
                arguments.tcp_stream,
                tshark=arguments.tshark,
            )
        else:
            if arguments.tcp_stream is not None:
                raise ValueError("--tcp-stream is only valid with --pcap")
            transcript = Transcript.load(arguments.transcript)
        server_frame_patches = dict(arguments.server_frame_patch)
        if len(server_frame_patches) != len(arguments.server_frame_patch):
            raise ValueError("Each server frame patch index may be specified only once")
        dropped_server_frames = set(arguments.drop_server_frame)
        if len(dropped_server_frames) != len(arguments.drop_server_frame):
            raise ValueError("Each dropped server frame index may be specified once")
        if arguments.keep_world_open:
            if arguments.hold_open_seconds <= 0:
                raise ValueError(
                    "--keep-world-open requires a positive --hold-open-seconds"
                )
            termination_index = world_session_termination_frame_index(transcript)
            if termination_index in server_frame_patches:
                raise ValueError(
                    f"terminal server frame {termination_index} is also patched"
                )
            dropped_server_frames.add(termination_index)
        if arguments.world_heartbeat_interval_seconds is not None:
            if not arguments.keep_world_open:
                raise ValueError(
                    "--world-heartbeat-interval-seconds requires "
                    "--keep-world-open"
                )
            if arguments.world_heartbeat_interval_seconds <= 0:
                raise ValueError(
                    "--world-heartbeat-interval-seconds must be positive"
                )
            heartbeat_analysis = analyze_gameplay_transcript(transcript)
            if not heartbeat_analysis.valid:
                raise ValueError(
                    "world transcript failed packet/state validation"
                )
            if heartbeat_analysis.state.heartbeat_probes == 0:
                raise ValueError(
                    "world transcript has no modeled server heartbeat probe"
                )
            if (
                heartbeat_analysis.state.unmatched_heartbeat_responses
                or heartbeat_analysis.state.pending_heartbeat_probes
            ):
                raise ValueError(
                    "world transcript heartbeat probes/responses do not pair"
                )
        npc_state_replay_plan = None
        if arguments.repeat_final_field_npc_state_update:
            if not arguments.keep_world_open:
                raise ValueError(
                    "--repeat-final-field-npc-state-update requires "
                    "--keep-world-open"
                )
            npc_state_replay_plan = plan_final_field_npc_state_replay(transcript)
            runtime_protocol["npc_state_replay"] = {
                **npc_state_replay_plan.safe_dict(),
                "packets_planned": 1,
                "packets_sent": 0,
            }
        current_hp_stat_update_plan = None
        if arguments.emit_current_hp_update is not None:
            if not arguments.keep_world_open:
                raise ValueError(
                    "--emit-current-hp-update requires --keep-world-open"
                )
            current_hp_stat_update_plan = plan_current_hp_stat_update(
                transcript, arguments.emit_current_hp_update
            )
            runtime_protocol["player_stat_update"] = {
                **current_hp_stat_update_plan.safe_dict(),
                "packets_planned": 1,
                "packets_sent": 0,
            }
        mob_movement_acknowledgement_policy = None
        if arguments.reactive_mob_movement_acknowledgements:
            if not arguments.keep_world_open:
                raise ValueError(
                    "--reactive-mob-movement-acknowledgements requires "
                    "--keep-world-open"
                )
            mob_movement_acknowledgement_policy = (
                derive_mob_movement_acknowledgement_policy(transcript)
            )
            if not mob_movement_acknowledgement_policy.known_mob_templates:
                raise ValueError(
                    "world transcript final field has no explicit "
                    "mob-template state for reactive acknowledgements"
                )
            runtime_protocol["mob_movement_acknowledgements"] = {
                **mob_movement_acknowledgement_policy.safe_dict(),
                "submissions_observed": 0,
                "responses_sent": 0,
                "submissions_rejected": 0,
            }
        if arguments.validate_login_state or arguments.rewrite_handoff:
            analysis = analyze_login_transcript(transcript)
            print(render_login_analysis(analysis))
            if not analysis.valid:
                raise ValueError("login transcript failed packet/state validation")
        if arguments.rewrite_handoff:
            handoff_index, handoff_payload = build_handoff_frame_patch(
                transcript, arguments.rewrite_handoff
            )
            if handoff_index in server_frame_patches:
                raise ValueError(
                    f"server frame {handoff_index} is set by both "
                    "--server-frame-patch and --rewrite-handoff"
                )
            server_frame_patches[handoff_index] = handoff_payload
        if (
            arguments.pcap is not None
            or arguments.world_heartbeat_interval_seconds is not None
        ):
            transcript = normalize_maple_transcript(transcript)
        elif arguments.drop_client_frame:
            raise ValueError("--drop-client-frame currently requires --pcap")
        if len(set(arguments.drop_client_frame)) != len(
            arguments.drop_client_frame
        ):
            raise ValueError("Each dropped client frame index may be specified once")
        if arguments.drop_client_frame:
            transcript = drop_normalized_client_frames(
                transcript, set(arguments.drop_client_frame)
            )
        initial_hp_replay_plan = None
        if arguments.rewrite_initial_current_hp is not None:
            initial_hp_replay_plan = plan_initial_player_hp_rewrite(
                transcript, arguments.rewrite_initial_current_hp
            )
            if initial_hp_replay_plan.server_frame_index in server_frame_patches:
                raise ValueError(
                    f"server frame {initial_hp_replay_plan.server_frame_index} "
                    "is set by both --server-frame-patch and "
                    "--rewrite-initial-current-hp"
                )
            server_frame_patches[initial_hp_replay_plan.server_frame_index] = (
                initial_hp_replay_plan.replacement.to_bytes()
            )
            runtime_protocol["initial_player_hp_rewrite"] = {
                **initial_hp_replay_plan.safe_dict(),
                "frames_patched": 1,
            }
        grouped_client_opcode_replies: dict[int, list[bytes]] = {}
        for opcode, payload in arguments.reply_on_client_opcode:
            grouped_client_opcode_replies.setdefault(opcode, []).append(payload)
        client_opcode_replies = {
            opcode: tuple(payloads)
            for opcode, payloads in grouped_client_opcode_replies.items()
        }
        if (
            mob_movement_acknowledgement_policy is not None
            and 207 in client_opcode_replies
        ):
            raise ValueError(
                "--reactive-mob-movement-acknowledgements conflicts with "
                "a captured client opcode 207 reply"
            )
        client_opcode_reply_delays = dict(arguments.client_opcode_reply_delays)
        if len(client_opcode_reply_delays) != len(
            arguments.client_opcode_reply_delays
        ):
            raise ValueError("Each reactive client opcode may define delays once")
        for opcode, delays in client_opcode_reply_delays.items():
            replies = client_opcode_replies.get(opcode)
            if replies is None:
                raise ValueError(
                    f"client opcode {opcode} defines delays but has no replies"
                )
            if len(delays) != len(replies):
                raise ValueError(
                    f"client opcode {opcode} has {len(replies)} replies but "
                    f"{len(delays)} delays"
                )
        if (
            arguments.rewrite_channel_transition_world
            and 4 not in client_opcode_replies
        ):
            raise ValueError(
                "--rewrite-channel-transition-world requires reactive "
                "client opcode 4 replies"
            )
        patch_server_frames(
            transcript, server_frame_patches, dropped_server_frames
        )
        post_transcript_server_frames = tuple(
            arguments.post_transcript_server_frames
        )
        npc_state_replay_plaintext = None
        if npc_state_replay_plan is not None:
            npc_state_replay_plaintext = npc_state_replay_plan.update.to_bytes()
            post_transcript_server_frames += (npc_state_replay_plaintext,)
        player_stat_update_plaintext = None
        if current_hp_stat_update_plan is not None:
            player_stat_update_plaintext = (
                current_hp_stat_update_plan.update.to_bytes()
            )
            post_transcript_server_frames += (player_stat_update_plaintext,)
        handler = functools.partial(
            replay_connection,
            transcript=transcript,
            strict=not arguments.no_strict,
            timing_scale=arguments.timing_scale,
            transcript_directory=arguments.transcript_dir,
            listen_port=arguments.listen_port,
            hold_open_seconds=arguments.hold_open_seconds,
            initial_delay_seconds=arguments.initial_delay_seconds,
            server_frame_patches=server_frame_patches,
            dropped_server_frames=dropped_server_frames,
            post_transcript_server_frames=post_transcript_server_frames,
            post_transcript_start_delay_seconds=(
                arguments.post_transcript_start_delay_seconds
            ),
            post_transcript_frame_delay_seconds=(
                arguments.post_transcript_frame_delay_seconds
            ),
            post_transcript_gap_delays_seconds=tuple(
                arguments.post_transcript_gap_delays_seconds
            ),
            post_transcript_replies=tuple(arguments.reply_after_client_frame),
            client_opcode_replies=client_opcode_replies,
            client_opcode_reply_delays=client_opcode_reply_delays,
            rewrite_channel_transition_world=(
                arguments.rewrite_channel_transition_world
            ),
            keep_world_open=arguments.keep_world_open,
            world_heartbeat_interval_seconds=(
                arguments.world_heartbeat_interval_seconds
            ),
            npc_state_replay_plaintext=npc_state_replay_plaintext,
            player_stat_update_plaintext=player_stat_update_plaintext,
            mob_movement_acknowledgement_policy=(
                mob_movement_acknowledgement_policy
            ),
            runtime_protocol=runtime_protocol,
        )
        runtime_config = {
            "source": "pcap" if arguments.pcap is not None else "transcript",
            "tcp_stream": arguments.tcp_stream,
            "strict": not arguments.no_strict,
            "timing_scale": arguments.timing_scale,
            "hold_open_seconds": arguments.hold_open_seconds,
            "keep_world_open": arguments.keep_world_open,
            "world_heartbeat_interval_seconds": (
                arguments.world_heartbeat_interval_seconds
            ),
            "repeat_final_field_npc_state_update": (
                arguments.repeat_final_field_npc_state_update
            ),
            "rewrite_initial_current_hp": (
                arguments.rewrite_initial_current_hp
            ),
            "emit_current_hp_update": arguments.emit_current_hp_update,
            "reactive_mob_movement_acknowledgements": (
                arguments.reactive_mob_movement_acknowledgements
            ),
            "dropped_server_frame_indices": sorted(dropped_server_frames),
        }
        if arguments.world_heartbeat_interval_seconds is not None:
            runtime_protocol["world_heartbeat"] = {
                "interval_seconds": arguments.world_heartbeat_interval_seconds,
                "probes_sent": 0,
                "responses_observed": 0,
                "pending": 0,
                "last_round_trip_ms": None,
                "max_round_trip_ms": None,
            }
    elif arguments.command == "stub":
        handler = functools.partial(
            stub_connection,
            transcript_directory=arguments.transcript_dir,
            listen_port=arguments.listen_port,
        )
        runtime_config = {"capture_enabled": True}
    else:
        raise ValueError(f"Unknown listener command: {arguments.command}")

    runtime = ServerRuntime(
        mode=handler_name(handler),
        listen_host=arguments.listen_host,
        listen_port=arguments.listen_port,
        config=runtime_config,
        protocol=runtime_protocol,
    )
    await run_listener(
        arguments.listen_host,
        arguments.listen_port,
        handler,
        runtime=runtime,
        http_api_host=arguments.http_api_host,
        http_api_port=arguments.http_api_port,
    )


def main() -> None:
    parser = build_parser()
    arguments = parser.parse_args()
    if arguments.command == "inspect":
        inspect_transcript(arguments.transcript)
        return
    if arguments.command == "compare":
        compare_transcripts(arguments.first, arguments.second)
        return
    if arguments.command in {"analyze-login", "analyze-gameplay"}:
        if arguments.pcap is not None:
            if arguments.tcp_stream is None:
                parser.error("--tcp-stream is required with --pcap")
            transcript = load_pcap_tcp_stream(
                arguments.pcap,
                arguments.tcp_stream,
                tshark=arguments.tshark,
            )
        else:
            if arguments.tcp_stream is not None:
                parser.error("--tcp-stream is only valid with --pcap")
            transcript = Transcript.load(arguments.transcript)
        if arguments.command == "analyze-login":
            analysis = analyze_login_transcript(transcript)
        else:
            analysis = analyze_gameplay_transcript(transcript)
        if arguments.json:
            print(
                analysis.to_json(
                    show_identifiers=arguments.show_identifiers
                )
            )
        else:
            if arguments.command == "analyze-login":
                print(
                    render_login_analysis(
                        analysis,
                        show_identifiers=arguments.show_identifiers,
                        show_packets=arguments.packets,
                    )
                )
            else:
                print(
                    render_gameplay_analysis(
                        analysis,
                        show_identifiers=arguments.show_identifiers,
                        show_packets=arguments.packets,
                        show_events=arguments.events,
                    )
                )
        if arguments.fail_on_invalid and not analysis.valid:
            raise SystemExit(2)
        return
    try:
        asyncio.run(async_main(arguments))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

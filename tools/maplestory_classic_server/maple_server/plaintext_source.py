"""Build a decryptable replay transcript from IL2CPP plaintext JSONL.

The laboratory no longer has ``111.pcapng`` on disk. The checked-in private
packet JSONL still has the exact protocol-300 plaintext, so this module wraps
those packets in a synthetic handshake and Maple AES stream that
``decode_transcript`` can fold.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from .protocol import crypt_payload, encode_frame_header, shuffle_iv
from .transcript import Transcript, TranscriptEvent


DEFAULT_CLIENT_IV = bytes.fromhex("6e3c795a")
DEFAULT_SERVER_IV = bytes.fromhex("885db958")
DEFAULT_CLIENT_VERSION_MASK = 0x0003
DEFAULT_SERVER_VERSION_MASK = 0xFED3
HANDSHAKE_HEX = (
    "1f002c010300330030003000"
    "6e3c795a"
    "885db958"
    "04"
    "2c0100002c01000000000000"
)
PLAINTEXT_SCHEMA = "maple-plaintext-packet/v1"


@dataclass(frozen=True)
class PlaintextPacket:
    tcp_stream: int
    direction: str
    direction_index: int
    opcode: int
    payload: bytes


def load_plaintext_packets(
    path: str | Path, *, tcp_stream: int
) -> tuple[PlaintextPacket, ...]:
    packets: list[PlaintextPacket] = []
    last_index = {"client_to_server": -1, "server_to_client": -1}
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"plaintext JSONL line {line_number} is invalid JSON"
                ) from error
            if not isinstance(record, dict):
                raise ValueError(f"plaintext JSONL line {line_number} is not an object")
            schema = record.get("schema")
            if schema is not None and schema != PLAINTEXT_SCHEMA:
                raise ValueError(
                    f"plaintext JSONL line {line_number} has schema {schema!r}"
                )
            if record.get("tcp_stream") != tcp_stream:
                continue
            direction = record.get("direction")
            if direction not in last_index:
                raise ValueError(
                    f"plaintext JSONL line {line_number} has direction {direction!r}"
                )
            direction_index = record.get("direction_index")
            if type(direction_index) is not int or direction_index < 0:
                raise ValueError(
                    f"plaintext JSONL line {line_number} has an invalid direction index"
                )
            if direction_index <= last_index[direction]:
                raise ValueError(
                    f"plaintext JSONL line {line_number} is not strictly increasing"
                )
            last_index[direction] = direction_index
            payload_hex = record.get("payload_hex")
            if not isinstance(payload_hex, str):
                raise ValueError(
                    f"plaintext JSONL line {line_number} is missing payload_hex"
                )
            try:
                payload = bytes.fromhex(payload_hex)
            except ValueError as error:
                raise ValueError(
                    f"plaintext JSONL line {line_number} has invalid payload_hex"
                ) from error
            expected_length = record.get("length")
            if expected_length is not None and expected_length != len(payload):
                raise ValueError(
                    f"plaintext JSONL line {line_number} length does not match payload"
                )
            digest = record.get("payload_sha256")
            if (
                isinstance(digest, str)
                and digest != hashlib.sha256(payload).hexdigest()
            ):
                raise ValueError(
                    f"plaintext JSONL line {line_number} payload hash does not match"
                )
            opcode = record.get("opcode")
            if type(opcode) is not int or not 0 <= opcode <= 0xFFFF:
                raise ValueError(
                    f"plaintext JSONL line {line_number} has an invalid opcode"
                )
            packets.append(
                PlaintextPacket(
                    tcp_stream=tcp_stream,
                    direction=direction,
                    direction_index=direction_index,
                    opcode=opcode,
                    payload=payload,
                )
            )
    if not packets:
        raise ValueError(f"plaintext JSONL has no packets for tcp stream {tcp_stream}")
    return tuple(packets)


def encode_encrypted_frame(
    payload: bytes, *, iv: bytes, version_mask: int
) -> bytes:
    return encode_frame_header(len(payload), iv, version_mask) + crypt_payload(
        payload, iv
    )


def transcript_from_plaintext_packets(
    packets: tuple[PlaintextPacket, ...],
    *,
    path: str | Path,
    client_iv: bytes = DEFAULT_CLIENT_IV,
    server_iv: bytes = DEFAULT_SERVER_IV,
    client_version_mask: int = DEFAULT_CLIENT_VERSION_MASK,
    server_version_mask: int = DEFAULT_SERVER_VERSION_MASK,
    handshake: bytes | None = None,
    start_timestamp_ns: int = 1_000,
    timestamp_step_ns: int = 1_000_000,
) -> Transcript:
    if handshake is None:
        handshake = bytes.fromhex(HANDSHAKE_HEX)
    iv_by_direction = {
        "client_to_server": client_iv,
        "server_to_client": server_iv,
    }
    mask_by_direction = {
        "client_to_server": client_version_mask,
        "server_to_client": server_version_mask,
    }
    events = [
        TranscriptEvent(
            event="connect",
            timestamp_ns=start_timestamp_ns,
            metadata={
                "source": "plaintext_jsonl",
                "tcp_stream": packets[0].tcp_stream,
                "packet_count": len(packets),
            },
        ),
        TranscriptEvent(
            event="data",
            timestamp_ns=start_timestamp_ns + 1,
            direction="server_to_client",
            data=handshake,
        ),
    ]
    for index, packet in enumerate(packets):
        iv = iv_by_direction[packet.direction]
        events.append(
            TranscriptEvent(
                event="data",
                timestamp_ns=start_timestamp_ns + (index + 2) * timestamp_step_ns,
                direction=packet.direction,
                data=encode_encrypted_frame(
                    packet.payload,
                    iv=iv,
                    version_mask=mask_by_direction[packet.direction],
                ),
            )
        )
        iv_by_direction[packet.direction] = shuffle_iv(iv)
    return Transcript(path=Path(path), events=tuple(events))


def interleave_world_bootstrap(
    packets: tuple[PlaintextPacket, ...],
) -> tuple[PlaintextPacket, ...]:
    """Restore a usable world-session order from direction-grouped JSONL.

    The IL2CPP export writes every client packet, then every server packet.
    Replay/fold need the world-entry request first, the field snapshot next,
    and only then the client's field-load markers.
    """

    if not packets:
        return packets
    clients = [packet for packet in packets if packet.direction == "client_to_server"]
    servers = [packet for packet in packets if packet.direction == "server_to_client"]
    if not clients or not servers:
        return packets
    saw_server = False
    for packet in packets:
        if packet.direction == "server_to_client":
            saw_server = True
        elif saw_server:
            return packets
    return tuple([clients[0], *servers, *clients[1:]])


def transcript_from_plaintext_jsonl(
    path: str | Path, *, tcp_stream: int
) -> Transcript:
    source = Path(path)
    return transcript_from_plaintext_packets(
        interleave_world_bootstrap(
            load_plaintext_packets(source, tcp_stream=tcp_stream)
        ),
        path=source,
    )


def server_plaintexts(packets: tuple[PlaintextPacket, ...]) -> tuple[bytes, ...]:
    return tuple(
        packet.payload
        for packet in packets
        if packet.direction == "server_to_client"
    )

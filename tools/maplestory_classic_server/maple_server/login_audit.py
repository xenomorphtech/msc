from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .gamestate import decode_transcript
from .packets import CharacterListEnvelope, PacketShapeError
from .pcap import (
    PcapError,
    read_pcap_tcp_stream_groups,
    transcript_from_tcp_segments,
)
from .protocol import ProtocolError


@dataclass(frozen=True)
class CharacterListPacketAudit:
    tcp_stream: int
    server_frame_index: int
    plaintext_length: int
    result: int
    character_count: int | None
    ranking_present: tuple[bool, ...]
    exact_round_trip: bool

    def safe_dict(self) -> dict[str, object]:
        return {
            "tcp_stream": self.tcp_stream,
            "server_frame_index": self.server_frame_index,
            "plaintext_length": self.plaintext_length,
            "result": self.result,
            "character_count": self.character_count,
            "ranking_present": list(self.ranking_present),
            "exact_round_trip": self.exact_round_trip,
        }


@dataclass(frozen=True)
class LoginPcapAudit:
    source: str
    server_port: int
    payload_rows: int
    tcp_streams: int
    reconstructed_streams: int
    decoded_streams: int
    reconstruction_failures: int
    decode_failures: int
    invalid_character_list_packets: int
    character_lists: tuple[CharacterListPacketAudit, ...]

    @property
    def observed_character_counts(self) -> tuple[int, ...]:
        return tuple(
            sorted(
                {
                    packet.character_count
                    for packet in self.character_lists
                    if packet.character_count is not None
                }
            )
        )

    @property
    def observed_ranking_present_values(self) -> tuple[bool, ...]:
        return tuple(
            sorted(
                {
                    ranking_present
                    for packet in self.character_lists
                    for ranking_present in packet.ranking_present
                }
            )
        )

    @property
    def has_ranked_or_multi_character_variant(self) -> bool:
        return any(
            (packet.character_count or 0) > 1
            or any(packet.ranking_present)
            for packet in self.character_lists
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "server_port": self.server_port,
            "payload_rows": self.payload_rows,
            "tcp_streams": self.tcp_streams,
            "reconstructed_streams": self.reconstructed_streams,
            "decoded_streams": self.decoded_streams,
            "reconstruction_failures": self.reconstruction_failures,
            "decode_failures": self.decode_failures,
            "invalid_character_list_packets": (
                self.invalid_character_list_packets
            ),
            "character_list_packets": [
                packet.safe_dict() for packet in self.character_lists
            ],
            "observed_character_counts": list(
                self.observed_character_counts
            ),
            "observed_ranking_present_values": list(
                self.observed_ranking_present_values
            ),
            "has_ranked_or_multi_character_variant": (
                self.has_ranked_or_multi_character_variant
            ),
        }


def audit_login_pcap(
    path: str | Path,
    server_port: int,
    *,
    tshark: str = "tshark",
) -> LoginPcapAudit:
    capture_path = Path(path)
    groups = read_pcap_tcp_stream_groups(
        capture_path,
        server_port,
        tshark=tshark,
    )
    payload_rows = sum(len(segments) for _, segments in groups)
    reconstructed_streams = 0
    decoded_streams = 0
    reconstruction_failures = 0
    decode_failures = 0
    invalid_character_list_packets = 0
    character_lists: list[CharacterListPacketAudit] = []

    for tcp_stream, segments in groups:
        try:
            transcript = transcript_from_tcp_segments(
                capture_path,
                tcp_stream,
                segments,
            )
        except PcapError:
            reconstruction_failures += 1
            continue
        reconstructed_streams += 1
        try:
            decoded = decode_transcript(transcript)
        except ProtocolError:
            decode_failures += 1
            continue
        decoded_streams += 1
        for frame in decoded.frames:
            if frame.direction != "server_to_client" or frame.opcode != 4:
                continue
            try:
                envelope = CharacterListEnvelope.parse(frame.plaintext)
                exact_round_trip = envelope.to_bytes() == frame.plaintext
            except PacketShapeError:
                invalid_character_list_packets += 1
                continue
            if not exact_round_trip:
                invalid_character_list_packets += 1
                continue
            character_lists.append(
                CharacterListPacketAudit(
                    tcp_stream=tcp_stream,
                    server_frame_index=frame.direction_index,
                    plaintext_length=len(frame.plaintext),
                    result=envelope.result,
                    character_count=(
                        len(envelope.records) if envelope.result == 0 else None
                    ),
                    ranking_present=tuple(
                        record.ranking is not None
                        for record in envelope.records
                    ),
                    exact_round_trip=exact_round_trip,
                )
            )

    return LoginPcapAudit(
        source=str(capture_path),
        server_port=server_port,
        payload_rows=payload_rows,
        tcp_streams=len(groups),
        reconstructed_streams=reconstructed_streams,
        decoded_streams=decoded_streams,
        reconstruction_failures=reconstruction_failures,
        decode_failures=decode_failures,
        invalid_character_list_packets=invalid_character_list_packets,
        character_lists=tuple(character_lists),
    )


def render_login_pcap_audit(audit: LoginPcapAudit) -> str:
    lines = [
        f"source: {audit.source}",
        f"server_port: {audit.server_port}",
        (
            "scan: "
            f"{audit.payload_rows} payload rows / {audit.tcp_streams} TCP streams"
        ),
        (
            "decode: "
            f"{audit.reconstructed_streams} reconstructed / "
            f"{audit.decoded_streams} decoded / "
            f"{audit.reconstruction_failures} reconstruction failures / "
            f"{audit.decode_failures} decode failures"
        ),
        (
            "character_lists: "
            f"{len(audit.character_lists)} valid / "
            f"{audit.invalid_character_list_packets} invalid"
        ),
    ]
    for packet in audit.character_lists:
        count = (
            "failure"
            if packet.character_count is None
            else str(packet.character_count)
        )
        rankings = ",".join(
            "true" if value else "false"
            for value in packet.ranking_present
        )
        lines.append(
            "  "
            f"stream {packet.tcp_stream} frame {packet.server_frame_index}: "
            f"length={packet.plaintext_length} result={packet.result} "
            f"count={count} rankings=[{rankings}] "
            f"round_trip={'yes' if packet.exact_round_trip else 'no'}"
        )
    lines.extend(
        (
            "observed_character_counts: "
            + ",".join(
                str(value) for value in audit.observed_character_counts
            ),
            "observed_ranking_present_values: "
            + ",".join(
                "true" if value else "false"
                for value in audit.observed_ranking_present_values
            ),
            "has_ranked_or_multi_character_variant: "
            + (
                "yes"
                if audit.has_ranked_or_multi_character_variant
                else "no"
            ),
        )
    )
    return "\n".join(lines)

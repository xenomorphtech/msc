from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
import subprocess

from .protocol import ProtocolError, parse_handshake
from .transcript import Transcript, TranscriptEvent


class PcapError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class TcpEndpoint:
    address: str
    port: int

    def __str__(self) -> str:
        return f"{self.address}:{self.port}"


@dataclass(frozen=True)
class TcpSegment:
    timestamp_ns: int
    source: TcpEndpoint
    destination: TcpEndpoint
    sequence: int
    payload: bytes


def parse_tshark_tcp_segments(output: str) -> tuple[TcpSegment, ...]:
    segments: list[TcpSegment] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 7:
            raise PcapError(
                f"tshark row {line_number} has {len(fields)} fields, expected 7"
            )
        (
            timestamp_text,
            source_address,
            source_port_text,
            destination_address,
            destination_port_text,
            sequence_text,
            payload_text,
        ) = fields
        try:
            timestamp_ns = int(Decimal(timestamp_text) * 1_000_000_000)
            source_port = int(source_port_text)
            destination_port = int(destination_port_text)
            sequence = int(sequence_text)
            payload = bytes.fromhex(payload_text.replace(":", ""))
        except (InvalidOperation, ValueError) as error:
            raise PcapError(f"invalid tshark row {line_number}: {error}") from error
        if not payload:
            continue
        segments.append(
            TcpSegment(
                timestamp_ns=timestamp_ns,
                source=TcpEndpoint(source_address, source_port),
                destination=TcpEndpoint(destination_address, destination_port),
                sequence=sequence,
                payload=payload,
            )
        )
    if not segments:
        raise PcapError("tshark returned no TCP payload segments")
    return tuple(segments)


def parse_tshark_tcp_stream_groups(
    output: str,
) -> tuple[tuple[int, tuple[TcpSegment, ...]], ...]:
    grouped_rows: dict[int, list[str]] = {}
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 8:
            raise PcapError(
                f"tshark row {line_number} has {len(fields)} fields, expected 8"
            )
        try:
            tcp_stream = int(fields[0])
        except ValueError as error:
            raise PcapError(
                f"invalid TCP stream index on tshark row {line_number}: {fields[0]}"
            ) from error
        if tcp_stream < 0:
            raise PcapError(
                f"negative TCP stream index on tshark row {line_number}: {tcp_stream}"
            )
        grouped_rows.setdefault(tcp_stream, []).append("\t".join(fields[1:]))
    if not grouped_rows:
        raise PcapError("tshark returned no TCP payload streams")
    return tuple(
        (
            tcp_stream,
            parse_tshark_tcp_segments("\n".join(rows)),
        )
        for tcp_stream, rows in sorted(grouped_rows.items())
    )


def read_pcap_tcp_segments(
    path: str | Path, tcp_stream: int, *, tshark: str = "tshark"
) -> tuple[TcpSegment, ...]:
    capture_path = Path(path)
    if not capture_path.is_file():
        raise PcapError(f"pcap does not exist: {capture_path}")
    if tcp_stream < 0:
        raise PcapError("TCP stream index cannot be negative")
    command = [
        tshark,
        "-n",
        "-r",
        str(capture_path),
        "-Y",
        f"tcp.stream == {tcp_stream} && tcp.len > 0",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.seq",
        "-e",
        "tcp.payload",
    ]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError as error:
        raise PcapError(f"tshark executable was not found: {tshark}") from error
    except subprocess.TimeoutExpired as error:
        raise PcapError("tshark timed out after 180 seconds") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise PcapError(f"tshark failed with exit code {error.returncode}{suffix}") from error
    return parse_tshark_tcp_segments(completed.stdout)


def read_pcap_tcp_stream_groups(
    path: str | Path,
    server_port: int,
    *,
    tshark: str = "tshark",
) -> tuple[tuple[int, tuple[TcpSegment, ...]], ...]:
    capture_path = Path(path)
    if not capture_path.is_file():
        raise PcapError(f"pcap does not exist: {capture_path}")
    if not 1 <= server_port <= 0xFFFF:
        raise PcapError(f"server port is out of range: {server_port}")
    command = [
        tshark,
        "-n",
        "-r",
        str(capture_path),
        "-Y",
        f"tcp.port == {server_port} && tcp.len > 0",
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
        "-e",
        "tcp.stream",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.seq",
        "-e",
        "tcp.payload",
    ]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError as error:
        raise PcapError(f"tshark executable was not found: {tshark}") from error
    except subprocess.TimeoutExpired as error:
        raise PcapError("tshark timed out after 180 seconds") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise PcapError(
            f"tshark failed with exit code {error.returncode}{suffix}"
        ) from error
    return parse_tshark_tcp_stream_groups(completed.stdout)


def _assemble_source_stream(segments: tuple[TcpSegment, ...]) -> bytes:
    if not segments:
        raise PcapError("cannot assemble an empty TCP source stream")
    ordered = sorted(segments, key=lambda item: (item.sequence, -len(item.payload)))
    cursor = ordered[0].sequence
    assembled = bytearray()
    for segment in ordered:
        end = segment.sequence + len(segment.payload)
        if end <= cursor:
            continue
        if segment.sequence > cursor:
            raise PcapError(
                f"TCP stream has a gap before sequence {segment.sequence} "
                f"(expected {cursor})"
            )
        overlap = cursor - segment.sequence
        assembled.extend(segment.payload[overlap:])
        cursor = end
    return bytes(assembled)


def _maple_handshake_offset(data: bytes) -> int | None:
    """Locate a bounded Maple greeting after an optional transport prelude."""

    maximum_offset = min(max(0, len(data) - 6), 4096)
    for offset in range(maximum_offset + 1):
        try:
            handshake = parse_handshake(data[offset:])
        except ProtocolError:
            continue
        if (
            0 < handshake.version < 10_000
            and 0 < handshake.wire_length <= 256
            and handshake.subversion.isprintable()
            and len(handshake.first_iv) == 4
            and len(handshake.second_iv) == 4
        ):
            return offset
    return None


def identify_maple_endpoints(
    segments: tuple[TcpSegment, ...]
) -> tuple[TcpEndpoint, TcpEndpoint]:
    endpoints = {segment.source for segment in segments} | {
        segment.destination for segment in segments
    }
    if len(endpoints) != 2:
        raise PcapError(
            f"TCP stream has {len(endpoints)} endpoints, expected exactly 2"
        )
    candidates: list[TcpEndpoint] = []
    for endpoint in endpoints:
        source_segments = tuple(
            segment for segment in segments if segment.source == endpoint
        )
        try:
            handshake_offset = _maple_handshake_offset(
                _assemble_source_stream(source_segments)
            )
        except PcapError:
            continue
        if handshake_offset is not None:
            candidates.append(endpoint)
    if len(candidates) != 1:
        raise PcapError(
            f"could not uniquely identify the Maple server endpoint; "
            f"candidates={len(candidates)}"
        )
    server = candidates[0]
    client = next(endpoint for endpoint in endpoints if endpoint != server)
    return client, server


class _ContiguousEmitter:
    def __init__(self, first_sequence: int) -> None:
        self.expected = first_sequence
        self.pending: list[TcpSegment] = []

    def feed(self, segment: TcpSegment) -> tuple[tuple[int, bytes], ...]:
        self.pending.append(segment)
        self.pending.sort(key=lambda item: (item.sequence, -len(item.payload)))
        emitted: list[tuple[int, bytes]] = []
        while self.pending:
            candidate = self.pending[0]
            end = candidate.sequence + len(candidate.payload)
            if end <= self.expected:
                self.pending.pop(0)
                continue
            if candidate.sequence > self.expected:
                break
            self.pending.pop(0)
            start_sequence = self.expected
            overlap = self.expected - candidate.sequence
            data = candidate.payload[overlap:]
            self.expected = end
            emitted.append((start_sequence, data))
        return tuple(emitted)


def transcript_from_tcp_segments(
    path: str | Path,
    tcp_stream: int,
    segments: tuple[TcpSegment, ...],
) -> Transcript:
    if not segments:
        raise PcapError("cannot construct a transcript from no TCP segments")
    client, server = identify_maple_endpoints(segments)
    original_first_sequences = {
        endpoint: min(
            segment.sequence for segment in segments if segment.source == endpoint
        )
        for endpoint in (client, server)
    }
    server_segments = tuple(
        segment for segment in segments if segment.source == server
    )
    server_handshake_offset = _maple_handshake_offset(
        _assemble_source_stream(server_segments)
    )
    if server_handshake_offset is None:
        raise PcapError("identified Maple server has no bounded greeting")
    first_sequences = dict(original_first_sequences)
    if server_handshake_offset:
        server_sequence = first_sequences[server] + server_handshake_offset
        handshake_segment = next(
            (
                segment
                for segment in sorted(
                    server_segments, key=lambda item: item.timestamp_ns
                )
                if segment.sequence
                <= server_sequence
                < segment.sequence + len(segment.payload)
            ),
            None,
        )
        if handshake_segment is None:
            raise PcapError("could not locate the Maple greeting TCP segment")
        client_post_handshake = tuple(
            segment
            for segment in segments
            if segment.source == client
            and segment.timestamp_ns > handshake_segment.timestamp_ns
        )
        if not client_post_handshake:
            raise PcapError("transport prelude has no post-greeting client data")
        first_sequences[server] = server_sequence
        first_sequences[client] = min(
            segment.sequence for segment in client_post_handshake
        )
    emitters = {
        endpoint: _ContiguousEmitter(first_sequences[endpoint])
        for endpoint in (client, server)
    }
    first_timestamp = min(segment.timestamp_ns for segment in segments)
    events: list[TranscriptEvent] = [
        TranscriptEvent(
            event="connect",
            timestamp_ns=first_timestamp - 1,
            metadata={
                "source": "pcap",
                "tcp_stream": tcp_stream,
                "client_endpoint": str(client),
                "server_endpoint": str(server),
                "transport_prelude_bytes": {
                    "client_to_server": (
                        first_sequences[client]
                        - original_first_sequences[client]
                    ),
                    "server_to_client": server_handshake_offset,
                },
            },
        )
    ]
    for segment in sorted(segments, key=lambda item: item.timestamp_ns):
        if (
            segment.sequence + len(segment.payload)
            <= first_sequences[segment.source]
        ):
            continue
        direction = (
            "client_to_server" if segment.source == client else "server_to_client"
        )
        for sequence, data in emitters[segment.source].feed(segment):
            events.append(
                TranscriptEvent(
                    event="data",
                    timestamp_ns=segment.timestamp_ns,
                    direction=direction,
                    data=data,
                    metadata={"tcp_sequence": sequence},
                )
            )
    pending = sum(len(emitter.pending) for emitter in emitters.values())
    if pending:
        raise PcapError(
            f"TCP reassembly ended with {pending} segments behind sequence gaps"
        )
    events.append(
        TranscriptEvent(
            event="close",
            timestamp_ns=max(event.timestamp_ns for event in events) + 1,
        )
    )
    return Transcript(path=Path(path), events=tuple(events))


def load_pcap_tcp_stream(
    path: str | Path, tcp_stream: int, *, tshark: str = "tshark"
) -> Transcript:
    segments = read_pcap_tcp_segments(path, tcp_stream, tshark=tshark)
    return transcript_from_tcp_segments(path, tcp_stream, segments)

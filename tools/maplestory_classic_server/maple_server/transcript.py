from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import time
from typing import IO, Iterable


@dataclass(frozen=True)
class TranscriptEvent:
    event: str
    timestamp_ns: int
    direction: str | None = None
    data: bytes = b""
    metadata: dict[str, object] | None = None


@dataclass(frozen=True)
class Transcript:
    path: Path
    events: tuple[TranscriptEvent, ...]

    @property
    def client_bytes(self) -> bytes:
        return b"".join(
            event.data
            for event in self.events
            if event.event == "data" and event.direction == "client_to_server"
        )

    @property
    def server_bytes(self) -> bytes:
        return b"".join(
            event.data
            for event in self.events
            if event.event == "data" and event.direction == "server_to_client"
        )

    @classmethod
    def load(cls, path: str | Path) -> "Transcript":
        transcript_path = Path(path)
        events: list[TranscriptEvent] = []

        with transcript_path.open(encoding="ascii") as transcript_file:
            for line_number, line in enumerate(transcript_file, start=1):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                    event_type = str(record["event"])
                    timestamp_ns = int(record["timestamp_ns"])
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                    raise ValueError(
                        f"Invalid transcript record at line {line_number}: {error}"
                    ) from error

                direction = record.get("direction")
                if direction is not None and direction not in {
                    "client_to_server",
                    "server_to_client",
                }:
                    raise ValueError(
                        f"Invalid direction at line {line_number}: {direction!r}"
                    )

                encoded_data = record.get("data_base64")
                try:
                    data = (
                        base64.b64decode(encoded_data, validate=True)
                        if encoded_data is not None
                        else b""
                    )
                except (ValueError, TypeError) as error:
                    raise ValueError(
                        f"Invalid base64 at line {line_number}: {error}"
                    ) from error

                metadata = {
                    key: value
                    for key, value in record.items()
                    if key
                    not in {"event", "timestamp_ns", "direction", "data_base64"}
                }
                events.append(
                    TranscriptEvent(
                        event=event_type,
                        timestamp_ns=timestamp_ns,
                        direction=direction,
                        data=data,
                        metadata=metadata or None,
                    )
                )

        return cls(path=transcript_path, events=tuple(events))


class TranscriptWriter:
    def __init__(
        self,
        directory: str | Path,
        *,
        label: str,
        metadata: dict[str, object],
        max_bytes_per_direction: int = 16 * 1024 * 1024,
    ) -> None:
        capture_directory = Path(directory)
        capture_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        safe_label = "".join(
            character if character.isalnum() or character in "-_." else "_"
            for character in label
        )
        self.path = capture_directory / f"{time.time_ns()}_{safe_label}.jsonl"
        self._file: IO[str] = self.path.open("x", encoding="ascii", buffering=1)
        self.path.chmod(0o600)
        self._max_bytes_per_direction = max_bytes_per_direction
        self._captured_bytes = {
            "client_to_server": 0,
            "server_to_client": 0,
        }
        self._closed = False
        self._write_record(
            {
                "event": "connect",
                "timestamp_ns": time.time_ns(),
                **metadata,
            }
        )

    def _write_record(self, record: dict[str, object]) -> None:
        self._file.write(json.dumps(record, separators=(",", ":")) + "\n")

    def data(self, direction: str, data: bytes) -> None:
        if self._closed:
            raise RuntimeError("Cannot append to a closed transcript")
        if direction not in self._captured_bytes:
            raise ValueError(f"Unknown transcript direction: {direction}")

        remaining = self._max_bytes_per_direction - self._captured_bytes[direction]
        if remaining <= 0:
            return

        captured = data[:remaining]
        self._captured_bytes[direction] += len(captured)
        self._write_record(
            {
                "event": "data",
                "timestamp_ns": time.time_ns(),
                "direction": direction,
                "data_base64": base64.b64encode(captured).decode("ascii"),
            }
        )

    def close(self, *, error: str | None = None) -> None:
        if self._closed:
            return
        record: dict[str, object] = {
            "event": "close",
            "timestamp_ns": time.time_ns(),
            "captured_bytes": self._captured_bytes,
        }
        if error:
            record["error"] = error
        self._write_record(record)
        self._closed = True
        self._file.close()

    def __enter__(self) -> "TranscriptWriter":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close(error=str(exc) if exc is not None else None)


def data_events(events: Iterable[TranscriptEvent]) -> Iterable[TranscriptEvent]:
    return (event for event in events if event.event == "data")

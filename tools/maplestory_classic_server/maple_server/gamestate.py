from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import json

from .packets import (
    AccountLoginResponse,
    ChannelTransitionResponse,
    ChannelSelection,
    CharacterListEnvelope,
    CharacterSelection,
    ClientOpcode6RecordSet,
    ClientOpcode31Record,
    ClientStatusMessage,
    HeartbeatProbe,
    HeartbeatResponse,
    PacketShapeError,
    Opcode13Ack,
    Opcode13Envelope,
    ServerTime,
    WorldHandoff,
    WorldListEnd,
    WorldRecord,
    WorldSelection,
)
from .protocol import (
    EncryptedFrame,
    Handshake,
    ProtocolError,
    crypt_payload,
    encode_frame_header,
    parse_encrypted_frames,
    parse_handshake,
    shuffle_iv,
)
from .transcript import Transcript, TranscriptEvent


class LoginPhase(str, Enum):
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    WORLD_SELECTION = "world_selection"
    CHANNEL_SELECTED = "channel_selected"
    CHARACTER_SELECTION = "character_selection"
    CHARACTER_SELECTED = "character_selected"
    HANDOFF_READY = "handoff_ready"


class ShapeCoverage(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    UNKNOWN = "unknown"
    INVALID = "invalid"


@dataclass(frozen=True)
class PlainFrame:
    index: int
    direction_index: int
    timestamp_ns: int
    direction: str
    wire_offset: int
    wire_length: int
    plaintext: bytes = field(repr=False)

    @property
    def opcode(self) -> int | None:
        if len(self.plaintext) < 2:
            return None
        return int.from_bytes(self.plaintext[:2], "little")


@dataclass(frozen=True)
class DecodedSession:
    handshake: Handshake
    client_version_mask: int
    server_version_mask: int
    frames: tuple[PlainFrame, ...]


@dataclass(frozen=True)
class PacketObservation:
    frame_index: int
    direction: str
    direction_index: int
    timestamp_ns: int
    opcode: int | None
    length: int
    wire_offset: int
    wire_length: int
    kind: str
    coverage: ShapeCoverage
    details: dict[str, object] = field(default_factory=dict)
    issues: tuple[str, ...] = ()
    parsed: object | None = field(default=None, repr=False, compare=False)


@dataclass
class LoginGameState:
    phase: LoginPhase = LoginPhase.CONNECTED
    account: AccountLoginResponse | None = field(default=None, repr=False)
    worlds: dict[int, WorldRecord] = field(default_factory=dict)
    world_list_complete: bool = False
    selected_world_id: int | None = None
    channel_transition_stage: int | None = None
    selected_channel_id: int | None = None
    client_address: str | None = None
    character_list: CharacterListEnvelope | None = field(
        default=None, repr=False
    )
    selected_character_id: int | None = field(default=None, repr=False)
    handoff: WorldHandoff | None = None
    heartbeat_probes: int = 0
    heartbeat_responses: int = 0
    matched_heartbeat_responses: int = 0
    unmatched_heartbeat_responses: int = 0
    pending_heartbeat_probes: int = 0
    last_heartbeat_round_trip_ms: float | None = None
    max_heartbeat_round_trip_ms: float | None = None
    client_opcode_6_record_sets: int = 0
    client_opcode_6_entry_count_patterns: dict[str, int] = field(
        default_factory=dict
    )
    client_opcode_6_opaque_values: int = 0
    client_opcode_31_records: int = 0
    client_opcode_31_text_code_unit_patterns: dict[str, int] = field(
        default_factory=dict
    )
    client_opcode_31_opaque_blob_bytes: int = 0


@dataclass(frozen=True)
class LoginAnalysis:
    source: str
    decoded: DecodedSession
    state: LoginGameState
    observations: tuple[PacketObservation, ...]
    issues: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.issues and all(
            observation.coverage != ShapeCoverage.INVALID
            for observation in self.observations
        )

    def safe_dict(self, *, show_identifiers: bool = False) -> dict[str, object]:
        account_id: int | str | None = None
        if self.state.account is not None:
            account_id = (
                self.state.account.account_id
                if show_identifiers
                else "present"
            )
        character_id: int | str | None = None
        if self.state.selected_character_id is not None:
            character_id = (
                self.state.selected_character_id
                if show_identifiers
                else "present"
            )
        handoff: dict[str, object] | None = None
        if self.state.handoff is not None:
            handoff = {
                "result": self.state.handoff.result,
                "address": str(self.state.handoff.address),
                "port": self.state.handoff.port,
                "character_id": (
                    self.state.handoff.character_id
                    if show_identifiers
                    else "present"
                ),
            }
        characters: list[dict[str, object]] = []
        if self.state.character_list is not None:
            characters = [
                {
                    "character_id": (
                        record.snapshot.character_id
                        if show_identifiers
                        else "present"
                    ),
                    "name": (
                        record.snapshot.name
                        if show_identifiers
                        else "present"
                    ),
                    "level": record.snapshot.level,
                    "job_id": record.snapshot.job_id,
                    "strength": record.snapshot.strength,
                    "dexterity": record.snapshot.dexterity,
                    "intelligence": record.snapshot.intelligence,
                    "luck": record.snapshot.luck,
                    "current_hp": record.snapshot.current_hp,
                    "max_hp": record.snapshot.max_hp,
                    "current_mp": record.snapshot.current_mp,
                    "max_mp": record.snapshot.max_mp,
                    "map_id": record.snapshot.map_id,
                    "visible_equipment_count": len(
                        record.appearance.visible_entries
                    ),
                    "masked_equipment_count": len(
                        record.appearance.masked_entries
                    ),
                    "ranking_present": record.ranking is not None,
                }
                for record in self.state.character_list.records
            ]
        return {
            "source": self.source,
            "valid": self.valid,
            "handshake": {
                "version": self.decoded.handshake.version,
                "subversion": self.decoded.handshake.subversion,
                "locale": self.decoded.handshake.locale,
                "wire_length": self.decoded.handshake.wire_length,
                "client_version_mask": self.decoded.client_version_mask,
                "server_version_mask": self.decoded.server_version_mask,
            },
            "state": {
                "phase": self.state.phase.value,
                "account_authenticated": self.state.account is not None,
                "account_id": account_id,
                "world_list_complete": self.state.world_list_complete,
                "worlds": [
                    {
                        "world_id": world.world_id,
                        "name": world.name,
                        "flag": world.flag,
                        "channel_count": len(world.channels),
                        "channel_ids": [
                            channel.channel_id for channel in world.channels
                        ],
                        "event_exp_rate": world.event_exp_rate,
                        "event_drop_rate": world.event_drop_rate,
                    }
                    for world in self.state.worlds.values()
                ],
                "selected_world_id": self.state.selected_world_id,
                "channel_transition_stage": (
                    self.state.channel_transition_stage
                ),
                "selected_channel_id": self.state.selected_channel_id,
                "client_address": self.state.client_address,
                "character_list_received": self.state.character_list is not None,
                "character_count": len(characters),
                "characters": characters,
                "selected_character_id": character_id,
                "handoff": handoff,
                "heartbeat_probes": self.state.heartbeat_probes,
                "heartbeat_responses": self.state.heartbeat_responses,
                "matched_heartbeat_responses": (
                    self.state.matched_heartbeat_responses
                ),
                "unmatched_heartbeat_responses": (
                    self.state.unmatched_heartbeat_responses
                ),
                "pending_heartbeat_probes": (
                    self.state.pending_heartbeat_probes
                ),
                "last_heartbeat_round_trip_ms": (
                    self.state.last_heartbeat_round_trip_ms
                ),
                "max_heartbeat_round_trip_ms": (
                    self.state.max_heartbeat_round_trip_ms
                ),
                "client_opcode_6_record_sets": (
                    self.state.client_opcode_6_record_sets
                ),
                "client_opcode_6_entry_count_patterns": (
                    self.state.client_opcode_6_entry_count_patterns
                ),
                "client_opcode_6_opaque_values": (
                    self.state.client_opcode_6_opaque_values
                ),
                "client_opcode_31_records": (
                    self.state.client_opcode_31_records
                ),
                "client_opcode_31_text_code_unit_patterns": (
                    self.state.client_opcode_31_text_code_unit_patterns
                ),
                "client_opcode_31_opaque_blob_bytes": (
                    self.state.client_opcode_31_opaque_blob_bytes
                ),
            },
            "packets": [
                {
                    "frame_index": observation.frame_index,
                    "direction": observation.direction,
                    "direction_index": observation.direction_index,
                    "timestamp_ns": observation.timestamp_ns,
                    "opcode": observation.opcode,
                    "length": observation.length,
                    "wire_offset": observation.wire_offset,
                    "wire_length": observation.wire_length,
                    "kind": observation.kind,
                    "coverage": observation.coverage.value,
                    "details": observation.details,
                    "issues": list(observation.issues),
                }
                for observation in self.observations
            ],
            "issues": list(self.issues),
            "warnings": list(self.warnings),
        }

    def to_json(self, *, show_identifiers: bool = False) -> str:
        return json.dumps(
            self.safe_dict(show_identifiers=show_identifiers),
            indent=2,
            sort_keys=True,
        )


def _decrypt_direction(
    frames: tuple[EncryptedFrame, ...], initial_iv: bytes
) -> tuple[int, tuple[bytes, ...]]:
    if not frames:
        return 0, ()
    first_word = int.from_bytes(frames[0].header[:2], "little")
    version_mask = first_word ^ int.from_bytes(initial_iv[2:4], "little")
    plaintexts: list[bytes] = []
    iv = initial_iv
    for index, frame in enumerate(frames):
        expected_header = encode_frame_header(
            len(frame.payload), iv, version_mask
        )
        if frame.header != expected_header:
            raise ProtocolError(
                f"frame {index} has a cipher header inconsistent with its "
                "directional IV/version mask"
            )
        plaintexts.append(crypt_payload(frame.payload, iv))
        iv = shuffle_iv(iv)
    return version_mask, tuple(plaintexts)


def _wire_location(
    transcript: Transcript, direction: str, wire_end: int
) -> tuple[int, int]:
    cumulative = 0
    for event_index, event in enumerate(transcript.events):
        if event.event != "data" or event.direction != direction:
            continue
        cumulative += len(event.data)
        if wire_end <= cumulative:
            return event.timestamp_ns, event_index
    raise ProtocolError(
        f"{direction} frame ending at {wire_end} is outside transcript data"
    )


def decode_transcript(transcript: Transcript) -> DecodedSession:
    handshake = parse_handshake(transcript.server_bytes)
    client_encrypted = parse_encrypted_frames(transcript.client_bytes)
    server_encrypted = parse_encrypted_frames(
        transcript.server_bytes, offset=handshake.wire_length
    )
    client_mask, client_plaintexts = _decrypt_direction(
        client_encrypted, handshake.first_iv
    )
    server_mask, server_plaintexts = _decrypt_direction(
        server_encrypted, handshake.second_iv
    )
    pending: list[tuple[int, int, str, int, EncryptedFrame, bytes]] = []
    for direction, frames, plaintexts in (
        ("client_to_server", client_encrypted, client_plaintexts),
        ("server_to_client", server_encrypted, server_plaintexts),
    ):
        for direction_index, (frame, plaintext) in enumerate(
            zip(frames, plaintexts, strict=True)
        ):
            timestamp_ns, event_index = _wire_location(
                transcript,
                direction,
                frame.offset + frame.wire_length,
            )
            pending.append(
                (
                    timestamp_ns,
                    event_index,
                    direction,
                    direction_index,
                    frame,
                    plaintext,
                )
            )
    pending.sort(key=lambda item: (item[0], item[1], item[3]))
    frames = tuple(
        PlainFrame(
            index=index,
            direction_index=direction_index,
            timestamp_ns=timestamp_ns,
            direction=direction,
            wire_offset=encrypted.offset,
            wire_length=encrypted.wire_length,
            plaintext=plaintext,
        )
        for index, (
            timestamp_ns,
            _,
            direction,
            direction_index,
            encrypted,
            plaintext,
        ) in enumerate(pending)
    )
    return DecodedSession(
        handshake=handshake,
        client_version_mask=client_mask,
        server_version_mask=server_mask,
        frames=frames,
    )


def normalize_maple_transcript(transcript: Transcript) -> Transcript:
    """Return handshake/frame-aligned events while preserving wire bytes and order."""
    decoded = decode_transcript(transcript)
    handshake_timestamp, _ = _wire_location(
        transcript,
        "server_to_client",
        decoded.handshake.wire_length,
    )
    connect_metadata: dict[str, object] = {"normalized_maple_frames": True}
    for event in transcript.events:
        if event.event == "connect" and event.metadata:
            connect_metadata.update(event.metadata)
            break
    first_timestamp = min(
        [handshake_timestamp]
        + [frame.timestamp_ns for frame in decoded.frames]
    )
    events: list[TranscriptEvent] = [
        TranscriptEvent(
            event="connect",
            timestamp_ns=first_timestamp - 1,
            metadata=connect_metadata,
        ),
        TranscriptEvent(
            event="data",
            timestamp_ns=handshake_timestamp,
            direction="server_to_client",
            data=transcript.server_bytes[: decoded.handshake.wire_length],
        ),
    ]
    streams = {
        "client_to_server": transcript.client_bytes,
        "server_to_client": transcript.server_bytes,
    }
    for frame in decoded.frames:
        wire = streams[frame.direction][
            frame.wire_offset : frame.wire_offset + frame.wire_length
        ]
        events.append(
            TranscriptEvent(
                event="data",
                timestamp_ns=frame.timestamp_ns,
                direction=frame.direction,
                data=wire,
                metadata={
                    "frame_index": frame.direction_index,
                    "opcode": frame.opcode,
                },
            )
        )
    events.append(
        TranscriptEvent(
            event="close",
            timestamp_ns=max(event.timestamp_ns for event in events) + 1,
        )
    )
    return Transcript(path=transcript.path, events=tuple(events))


class LoginStateFold:
    def __init__(self) -> None:
        self.state = LoginGameState()
        self.issues: list[str] = []
        self.warnings: list[str] = []
        self._pending_heartbeat_probes: deque[int] = deque()

    def _invalid(
        self, frame: PlainFrame, kind: str, error: PacketShapeError
    ) -> PacketObservation:
        return PacketObservation(
            frame_index=frame.index,
            direction=frame.direction,
            direction_index=frame.direction_index,
            timestamp_ns=frame.timestamp_ns,
            opcode=frame.opcode,
            length=len(frame.plaintext),
            wire_offset=frame.wire_offset,
            wire_length=frame.wire_length,
            kind=kind,
            coverage=ShapeCoverage.INVALID,
            issues=(str(error),),
        )

    def _observation(
        self,
        frame: PlainFrame,
        *,
        kind: str,
        coverage: ShapeCoverage,
        parsed: object | None = None,
        details: dict[str, object] | None = None,
        issues: tuple[str, ...] = (),
    ) -> PacketObservation:
        return PacketObservation(
            frame_index=frame.index,
            direction=frame.direction,
            direction_index=frame.direction_index,
            timestamp_ns=frame.timestamp_ns,
            opcode=frame.opcode,
            length=len(frame.plaintext),
            wire_offset=frame.wire_offset,
            wire_length=frame.wire_length,
            kind=kind,
            coverage=coverage,
            parsed=parsed,
            details=details or {},
            issues=issues,
        )

    def consume(self, frame: PlainFrame) -> PacketObservation:
        opcode = frame.opcode
        if opcode is None:
            return self._observation(
                frame,
                kind="short_plaintext",
                coverage=ShapeCoverage.INVALID,
                issues=("plaintext is shorter than the two-byte opcode",),
            )
        try:
            if frame.direction == "server_to_client":
                return self._consume_server(frame, opcode)
            return self._consume_client(frame, opcode)
        except PacketShapeError as error:
            return self._invalid(frame, f"opcode_{opcode}", error)

    def _consume_server(
        self, frame: PlainFrame, opcode: int
    ) -> PacketObservation:
        payload = frame.plaintext
        if opcode == 10:
            probe = HeartbeatProbe.parse(payload)
            self._pending_heartbeat_probes.append(frame.timestamp_ns)
            self.state.heartbeat_probes += 1
            self.state.pending_heartbeat_probes += 1
            return self._observation(
                frame,
                kind="heartbeat_probe",
                coverage=ShapeCoverage.FULL,
                parsed=probe,
                details={
                    "pending_probes": self.state.pending_heartbeat_probes
                },
            )
        if opcode == 13:
            if len(payload) == 3:
                acknowledgment = Opcode13Ack.parse(payload)
                return self._observation(
                    frame,
                    kind="opcode_13_ack",
                    coverage=ShapeCoverage.FULL,
                    parsed=acknowledgment,
                    details={"result": acknowledgment.result},
                )
            message = Opcode13Envelope.parse(payload)
            return self._observation(
                frame,
                kind="opcode_13_envelope",
                coverage=ShapeCoverage.PARTIAL,
                parsed=message,
                details={
                    "message_type": message.message_type,
                    "opaque_bytes": len(message.opaque_payload),
                },
                issues=("opcode-13 envelope payload remains opaque",),
            )
        if opcode == 134:
            server_time = ServerTime.parse(payload)
            return self._observation(
                frame,
                kind="server_time",
                coverage=ShapeCoverage.FULL,
                parsed=server_time,
                details={"ticks": server_time.ticks},
            )
        account_shape_candidate = opcode == 1 or (
            opcode == 0 and len(payload) >= 31 and len(payload) % 2 == 1
        )
        if account_shape_candidate and payload[2] == 0:
            account = AccountLoginResponse.parse(payload)
            if self.state.account is not None:
                self.issues.append("multiple successful account responses observed")
            self.state.account = account
            self.state.phase = LoginPhase.AUTHENTICATED
            return self._observation(
                frame,
                kind="account_login_success",
                coverage=ShapeCoverage.FULL,
                parsed=account,
                details={
                    "result": account.result,
                    "account_id_present": True,
                    "account_name_code_units": len(account.account_name),
                },
            )
        if opcode == 2:
            if len(payload) == 3 and payload[2] == 0xFF:
                ending = WorldListEnd.parse(payload)
                if not self.state.worlds:
                    self.issues.append("world-list sentinel arrived before any world")
                self.state.world_list_complete = True
                self.state.phase = LoginPhase.WORLD_SELECTION
                return self._observation(
                    frame,
                    kind="world_list_end",
                    coverage=ShapeCoverage.FULL,
                    parsed=ending,
                )
            world = WorldRecord.parse(payload)
            existing = self.state.worlds.get(world.world_id)
            if existing is not None and existing != world:
                self.issues.append(
                    f"world {world.world_id} was redefined with a different shape"
                )
            self.state.worlds[world.world_id] = world
            if world.flag not in {1, 2}:
                self.warnings.append(
                    f"world {world.world_id} uses flag {world.flag}; successful "
                    "reference worlds use 1 or 2"
                )
            return self._observation(
                frame,
                kind="world_record",
                coverage=ShapeCoverage.FULL,
                parsed=world,
                details={
                    "world_id": world.world_id,
                    "name": world.name,
                    "flag": world.flag,
                    "event_description": world.event_description,
                    "event_exp_rate": world.event_exp_rate,
                    "event_drop_rate": world.event_drop_rate,
                    "channel_count": len(world.channels),
                    "channels": [
                        {
                            "name": channel.name,
                            "population": channel.population,
                            "world_id": channel.world_id,
                            "channel_id": channel.channel_id,
                            "adult_channel": channel.adult_channel,
                            "unknown": channel.unknown,
                        }
                        for channel in world.channels
                    ],
                    "balloon_count": len(world.balloons),
                    "balloons": [
                        {
                            "x": balloon.x,
                            "y": balloon.y,
                            "message": balloon.message,
                        }
                        for balloon in world.balloons
                    ],
                },
            )
        if opcode == 402:
            transition = ChannelTransitionResponse.parse(payload)
            details: dict[str, object] = {"stage": transition.stage}
            if transition.stage == 0:
                if self.state.channel_transition_stage is not None:
                    self.issues.append(
                        "channel transition stage 0 restarted an active transition"
                    )
                self.state.channel_transition_stage = 0
                details["transition_values"] = list(
                    transition.transition_values or ()
                )
            else:
                if self.state.channel_transition_stage != 0:
                    self.issues.append(
                        "channel transition stage 1 arrived before stage 0"
                    )
                self.state.channel_transition_stage = 1
                details["world_id"] = transition.world_id
                if (
                    self.state.selected_world_id is not None
                    and transition.world_id != self.state.selected_world_id
                ):
                    self.issues.append(
                        f"channel transition world {transition.world_id} does not "
                        f"match selected world {self.state.selected_world_id}"
                    )
            return self._observation(
                frame,
                kind="channel_transition",
                coverage=ShapeCoverage.FULL,
                parsed=transition,
                details=details,
            )
        if opcode == 4:
            character_list = CharacterListEnvelope.parse(payload)
            self.state.character_list = character_list
            if character_list.result == 0:
                self.state.phase = LoginPhase.CHARACTER_SELECTION
            details: dict[str, object] = {
                "result": character_list.result,
                "character_count": len(character_list.records),
            }
            issues: tuple[str, ...] = ()
            coverage = ShapeCoverage.FULL
            if character_list.result != 0 and character_list.failure_payload:
                coverage = ShapeCoverage.PARTIAL
                details["failure_payload_bytes"] = len(
                    character_list.failure_payload
                )
                issues = (
                    "the non-success character-list payload remains opaque",
                )
            elif character_list.result == 0:
                details["characters"] = [
                    {
                        "character_id_present": True,
                        "name_present": bool(record.snapshot.name),
                        "level": record.snapshot.level,
                        "job_id": record.snapshot.job_id,
                        "map_id": record.snapshot.map_id,
                        "visible_equipment_count": len(
                            record.appearance.visible_entries
                        ),
                        "masked_equipment_count": len(
                            record.appearance.masked_entries
                        ),
                        "ranking_present": record.ranking is not None,
                    }
                    for record in character_list.records
                ]
            return self._observation(
                frame,
                kind="character_list",
                coverage=coverage,
                parsed=character_list,
                details=details,
                issues=issues,
            )
        if opcode == 5 and len(payload) == 19:
            handoff = WorldHandoff.parse(payload)
            self.state.handoff = handoff
            if (
                self.state.selected_character_id is not None
                and handoff.character_id != self.state.selected_character_id
            ):
                self.issues.append(
                    "world handoff character id does not match client selection"
                )
            if handoff.result == 0:
                self.state.phase = LoginPhase.HANDOFF_READY
            return self._observation(
                frame,
                kind="world_handoff",
                coverage=ShapeCoverage.FULL,
                parsed=handoff,
                details={
                    "result": handoff.result,
                    "address": str(handoff.address),
                    "port": handoff.port,
                    "character_id_present": True,
                },
            )
        return self._observation(
            frame,
            kind=f"server_opcode_{opcode}",
            coverage=ShapeCoverage.UNKNOWN,
        )

    def _consume_client(
        self, frame: PlainFrame, opcode: int
    ) -> PacketObservation:
        payload = frame.plaintext
        if opcode == 6:
            record_set = ClientOpcode6RecordSet.parse(payload)
            entry_count = str(len(record_set.opaque_entries))
            self.state.client_opcode_6_record_sets += 1
            self.state.client_opcode_6_entry_count_patterns[entry_count] = (
                self.state.client_opcode_6_entry_count_patterns.get(
                    entry_count, 0
                )
                + 1
            )
            self.state.client_opcode_6_opaque_values += len(
                record_set.opaque_entries
            )
            return self._observation(
                frame,
                kind="client_opcode_6_record_set",
                coverage=ShapeCoverage.PARTIAL,
                parsed=record_set,
                details=record_set.safe_dict(),
                issues=(
                    "opcode-6 header and indexed record values remain neutral",
                ),
            )
        if opcode == 31:
            record = ClientOpcode31Record.parse(payload)
            text_pattern = "/".join(
                str(length) for length in record.text_code_units
            )
            self.state.client_opcode_31_records += 1
            self.state.client_opcode_31_text_code_unit_patterns[
                text_pattern
            ] = (
                self.state.client_opcode_31_text_code_unit_patterns.get(
                    text_pattern, 0
                )
                + 1
            )
            self.state.client_opcode_31_opaque_blob_bytes += len(
                record.opaque_blob
            )
            return self._observation(
                frame,
                kind="client_opcode_31_record",
                coverage=ShapeCoverage.PARTIAL,
                parsed=record,
                details=record.safe_dict(),
                issues=(
                    "opcode-31 text, blob contents, and higher-level role "
                    "remain neutral",
                ),
            )
        if opcode == 23:
            response = HeartbeatResponse.parse(payload)
            matched_probe = bool(self._pending_heartbeat_probes)
            round_trip_ms: float | None = None
            if matched_probe:
                probe_timestamp_ns = self._pending_heartbeat_probes.popleft()
                round_trip_ms = (
                    frame.timestamp_ns - probe_timestamp_ns
                ) / 1e6
                self.state.pending_heartbeat_probes -= 1
                self.state.matched_heartbeat_responses += 1
                self.state.last_heartbeat_round_trip_ms = round_trip_ms
                self.state.max_heartbeat_round_trip_ms = max(
                    self.state.max_heartbeat_round_trip_ms or 0.0,
                    round_trip_ms,
                )
            else:
                self.state.unmatched_heartbeat_responses += 1
            self.state.heartbeat_responses += 1
            details: dict[str, object] = {
                "matched_probe": matched_probe,
                "opaque_token_bytes": 8,
            }
            if round_trip_ms is not None:
                details["round_trip_ms"] = round(round_trip_ms, 3)
            return self._observation(
                frame,
                kind="heartbeat_response",
                coverage=ShapeCoverage.PARTIAL,
                parsed=response,
                details=details,
                issues=("heartbeat response token remains opaque",),
            )
        if opcode == 13:
            if len(payload) >= 3 and payload[2] == 15:
                status = ClientStatusMessage.parse(payload)
                return self._observation(
                    frame,
                    kind="client_status_message",
                    coverage=ShapeCoverage.FULL,
                    parsed=status,
                    details={
                        "message_type": status.message_type,
                        "message": status.message,
                    },
                )
            message = Opcode13Envelope.parse(payload)
            return self._observation(
                frame,
                kind="opcode_13_envelope",
                coverage=ShapeCoverage.PARTIAL,
                parsed=message,
                details={
                    "message_type": message.message_type,
                    "opaque_bytes": len(message.opaque_payload),
                },
                issues=("opcode-13 envelope payload remains opaque",),
            )
        if opcode == 4:
            selection = WorldSelection.parse(payload)
            self.state.selected_world_id = selection.world_id
            self.state.channel_transition_stage = None
            if selection.world_id not in self.state.worlds:
                self.issues.append(
                    f"client selected unadvertised world {selection.world_id}"
                )
            return self._observation(
                frame,
                kind="world_selection",
                coverage=ShapeCoverage.FULL,
                parsed=selection,
                details={"world_id": selection.world_id},
            )
        if opcode == 5:
            selection = ChannelSelection.parse(payload)
            if (
                self.state.selected_world_id is not None
                and selection.world_id != self.state.selected_world_id
            ):
                self.issues.append(
                    f"channel selection world {selection.world_id} does not "
                    f"match selected world {self.state.selected_world_id}"
                )
            world = self.state.worlds.get(selection.world_id)
            if world is None:
                self.issues.append(
                    f"client selected a channel in unadvertised world "
                    f"{selection.world_id}"
                )
            elif selection.channel_id not in {
                channel.channel_id for channel in world.channels
            }:
                self.issues.append(
                    f"client selected unadvertised channel "
                    f"{selection.channel_id} in world {selection.world_id}"
                )
            self.state.selected_world_id = selection.world_id
            self.state.selected_channel_id = selection.channel_id
            self.state.client_address = str(selection.client_address)
            self.state.phase = LoginPhase.CHANNEL_SELECTED
            return self._observation(
                frame,
                kind="channel_selection",
                coverage=ShapeCoverage.FULL,
                parsed=selection,
                details={
                    "world_id": selection.world_id,
                    "channel_id": selection.channel_id,
                    "client_address": str(selection.client_address),
                },
            )
        if opcode == 7:
            selection = CharacterSelection.parse(payload)
            character_list = self.state.character_list
            if character_list is None:
                self.issues.append(
                    "client selected a character before receiving a character list"
                )
            elif character_list.result != 0:
                self.issues.append(
                    "client selected a character after a failed character list"
                )
            elif selection.character_id not in {
                record.snapshot.character_id
                for record in character_list.records
            }:
                self.issues.append(
                    "client selected a character not advertised by the server"
                )
            self.state.selected_character_id = selection.character_id
            self.state.phase = LoginPhase.CHARACTER_SELECTED
            return self._observation(
                frame,
                kind="character_selection",
                coverage=ShapeCoverage.FULL,
                parsed=selection,
                details={"character_id_present": True},
            )
        return self._observation(
            frame,
            kind=f"client_opcode_{opcode}",
            coverage=ShapeCoverage.UNKNOWN,
        )


def analyze_login_transcript(transcript: Transcript) -> LoginAnalysis:
    decoded = decode_transcript(transcript)
    fold = LoginStateFold()
    observations = tuple(fold.consume(frame) for frame in decoded.frames)
    return LoginAnalysis(
        source=str(transcript.path),
        decoded=decoded,
        state=fold.state,
        observations=observations,
        issues=tuple(fold.issues),
        warnings=tuple(fold.warnings),
    )


def render_login_analysis(
    analysis: LoginAnalysis,
    *,
    show_identifiers: bool = False,
    show_packets: bool = False,
) -> str:
    report = analysis.safe_dict(show_identifiers=show_identifiers)
    state = report["state"]
    assert isinstance(state, dict)
    packet_counts: dict[str, int] = {}
    for observation in analysis.observations:
        key = f"{observation.kind}:{observation.coverage.value}"
        packet_counts[key] = packet_counts.get(key, 0) + 1
    lines = [
        f"source={analysis.source}",
        f"valid={analysis.valid}",
        (
            f"handshake=version:{analysis.decoded.handshake.version} "
            f"subversion:{analysis.decoded.handshake.subversion!r} "
            f"locale:{analysis.decoded.handshake.locale}"
        ),
        (
            f"cipher_masks=client:{analysis.decoded.client_version_mask:#06x} "
            f"server:{analysis.decoded.server_version_mask:#06x}"
        ),
        f"phase={state['phase']}",
        (
            f"worlds={len(analysis.state.worlds)} "
            f"selected={analysis.state.selected_world_id}/"
            f"{analysis.state.selected_channel_id}"
        ),
        f"character_list_received={state['character_list_received']}",
        f"handoff={state['handoff']}",
        (
            f"heartbeats=probes:{state['heartbeat_probes']} "
            f"responses:{state['heartbeat_responses']} "
            f"matched:{state['matched_heartbeat_responses']} "
            f"unmatched:{state['unmatched_heartbeat_responses']} "
            f"pending:{state['pending_heartbeat_probes']}"
        ),
        (
            "client_opcode_6="
            f"record_sets:{state['client_opcode_6_record_sets']} "
            "entry_counts:"
            f"{state['client_opcode_6_entry_count_patterns']} "
            f"opaque_values:{state['client_opcode_6_opaque_values']}"
        ),
        (
            "client_opcode_31="
            f"records:{state['client_opcode_31_records']} "
            "text_patterns:"
            f"{state['client_opcode_31_text_code_unit_patterns']} "
            f"opaque_blob_bytes:{state['client_opcode_31_opaque_blob_bytes']}"
        ),
        f"packet_shapes={json.dumps(packet_counts, sort_keys=True)}",
    ]
    lines.extend(f"issue={issue}" for issue in analysis.issues)
    lines.extend(f"warning={warning}" for warning in analysis.warnings)
    if show_packets and analysis.observations:
        base_timestamp_ns = analysis.observations[0].timestamp_ns
        previous_timestamp_ns = base_timestamp_ns
        for observation in analysis.observations:
            elapsed_ms = (observation.timestamp_ns - base_timestamp_ns) / 1e6
            delta_ms = (observation.timestamp_ns - previous_timestamp_ns) / 1e6
            previous_timestamp_ns = observation.timestamp_ns
            direction = (
                "C>S"
                if observation.direction == "client_to_server"
                else "S>C"
            )
            details = json.dumps(
                observation.details,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            issues = json.dumps(
                observation.issues,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            lines.append(
                "packet "
                f"frame={observation.frame_index} "
                f"direction={direction} "
                f"direction_frame={observation.direction_index} "
                f"elapsed_ms={elapsed_ms:.3f} delta_ms={delta_ms:.3f} "
                f"wire_offset={observation.wire_offset} "
                f"wire_length={observation.wire_length} "
                f"plaintext_length={observation.length} "
                f"opcode={observation.opcode} kind={observation.kind} "
                f"coverage={observation.coverage.value} details={details} "
                f"issues={issues}"
            )
    return "\n".join(lines)

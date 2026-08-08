from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
import json

from .gamestate import (
    DecodedSession,
    PacketObservation,
    PlainFrame,
    ShapeCoverage,
    decode_transcript,
)
from .packets import (
    FieldLoadStage,
    FieldSnapshotEnvelope,
    HeartbeatAcknowledgement,
    HeartbeatRequest,
    MobMovementAcknowledgement,
    MobMovementSubmission,
    NpcSpawn,
    NpcStateUpdate,
    PacketShapeError,
    WorldBootstrapAcknowledgement,
    WorldEntryRequest,
)
from .transcript import Transcript


class GameplayPhase(str, Enum):
    CONNECTED = "connected"
    ENTRY_REQUESTED = "entry_requested"
    FIELD_LOADING = "field_loading"
    ACTIVE = "active"


@dataclass
class NpcEntity:
    alias: str
    spawn: NpcSpawn = field(repr=False)
    action: int | None = None
    parameter: int | None = None


@dataclass(frozen=True)
class GameplayEvent:
    index: int
    timestamp_ns: int
    frame_index: int
    direction: str
    kind: str
    details: dict[str, object] = field(default_factory=dict)
    identifiers: dict[str, object] = field(
        default_factory=dict, repr=False, compare=False
    )

    def safe_dict(self, *, show_identifiers: bool = False) -> dict[str, object]:
        details = dict(self.details)
        if show_identifiers:
            details.update(self.identifiers)
        return {
            "event_index": self.index,
            "timestamp_ns": self.timestamp_ns,
            "frame_index": self.frame_index,
            "direction": self.direction,
            "kind": self.kind,
            "details": details,
        }


@dataclass
class GameplayGameState:
    phase: GameplayPhase = GameplayPhase.CONNECTED
    field_epoch: int = 0
    field_load_stage: int | None = None
    entry_character_id: int | None = field(default=None, repr=False)
    npcs: dict[int, NpcEntity] = field(default_factory=dict, repr=False)
    packets_by_direction: Counter[str] = field(default_factory=Counter)
    plaintext_bytes_by_direction: Counter[str] = field(default_factory=Counter)
    npc_spawns: int = 0
    npc_state_updates: int = 0
    movement_submissions: int = 0
    movement_acknowledgements: int = 0
    matched_movement_acknowledgements: int = 0
    unmatched_movement_acknowledgements: int = 0
    heartbeat_requests: int = 0
    heartbeat_acknowledgements: int = 0
    bootstrap_acknowledgements: int = 0
    pending_movements: int = 0


@dataclass(frozen=True)
class GameplayAnalysis:
    source: str
    decoded: DecodedSession
    state: GameplayGameState
    observations: tuple[PacketObservation, ...]
    events: tuple[GameplayEvent, ...]
    issues: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.issues and all(
            observation.coverage != ShapeCoverage.INVALID
            for observation in self.observations
        )

    def safe_dict(self, *, show_identifiers: bool = False) -> dict[str, object]:
        npcs: list[dict[str, object]] = []
        for entity in sorted(self.state.npcs.values(), key=lambda item: item.alias):
            spawn = entity.spawn
            record: dict[str, object] = {
                "entity": entity.alias,
                "template_id": spawn.template_id,
                "x": spawn.x,
                "cy": spawn.cy,
                "faces_left": spawn.faces_left,
                "foothold_id": spawn.foothold_id,
                "range_left": spawn.range_left,
                "range_right": spawn.range_right,
                "hidden": spawn.hidden,
                "action": entity.action,
                "parameter": entity.parameter,
            }
            if show_identifiers:
                record["object_id"] = spawn.object_id
            npcs.append(record)
        entry_character_id: int | str | None = None
        if self.state.entry_character_id is not None:
            entry_character_id = (
                self.state.entry_character_id
                if show_identifiers
                else "present"
            )
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
                "field_epoch": self.state.field_epoch,
                "field_load_stage": self.state.field_load_stage,
                "entry_character_id": entry_character_id,
                "active_npc_count": len(self.state.npcs),
                "npcs": npcs,
                "packets_by_direction": dict(self.state.packets_by_direction),
                "plaintext_bytes_by_direction": dict(
                    self.state.plaintext_bytes_by_direction
                ),
                "npc_spawns": self.state.npc_spawns,
                "npc_state_updates": self.state.npc_state_updates,
                "movement_submissions": self.state.movement_submissions,
                "movement_acknowledgements": (
                    self.state.movement_acknowledgements
                ),
                "matched_movement_acknowledgements": (
                    self.state.matched_movement_acknowledgements
                ),
                "unmatched_movement_acknowledgements": (
                    self.state.unmatched_movement_acknowledgements
                ),
                "pending_movements": self.state.pending_movements,
                "heartbeat_requests": self.state.heartbeat_requests,
                "heartbeat_acknowledgements": (
                    self.state.heartbeat_acknowledgements
                ),
                "bootstrap_acknowledgements": (
                    self.state.bootstrap_acknowledgements
                ),
            },
            "events": [
                event.safe_dict(show_identifiers=show_identifiers)
                for event in self.events
            ],
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


class GameplayStateFold:
    def __init__(self) -> None:
        self.state = GameplayGameState()
        self.issues: list[str] = []
        self.warnings: list[str] = []
        self.events: list[GameplayEvent] = []
        self._npc_aliases: dict[int, str] = {}
        self._movement_aliases: dict[int, str] = {}
        self._pending_movements: Counter[tuple[int, int]] = Counter()
        self._unknown_npc_updates: set[tuple[int, int]] = set()
        self._started = False

    def _alias(self, aliases: dict[int, str], object_id: int, prefix: str) -> str:
        alias = aliases.get(object_id)
        if alias is None:
            alias = f"{prefix}:{len(aliases) + 1}"
            aliases[object_id] = alias
        return alias

    def _event(
        self,
        frame: PlainFrame,
        kind: str,
        *,
        details: dict[str, object] | None = None,
        identifiers: dict[str, object] | None = None,
    ) -> None:
        self.events.append(
            GameplayEvent(
                index=len(self.events),
                timestamp_ns=frame.timestamp_ns,
                frame_index=frame.index,
                direction=frame.direction,
                kind=kind,
                details=details or {},
                identifiers=identifiers or {},
            )
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

    def _invalid(
        self, frame: PlainFrame, kind: str, error: PacketShapeError
    ) -> PacketObservation:
        return self._observation(
            frame,
            kind=kind,
            coverage=ShapeCoverage.INVALID,
            issues=(str(error),),
        )

    def consume(self, frame: PlainFrame) -> PacketObservation:
        if not self._started:
            self._started = True
            self._event(frame, "session_started")
        self.state.packets_by_direction[frame.direction] += 1
        self.state.plaintext_bytes_by_direction[frame.direction] += len(
            frame.plaintext
        )
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

    def _consume_client(
        self, frame: PlainFrame, opcode: int
    ) -> PacketObservation:
        payload = frame.plaintext
        if opcode == 8:
            request = WorldEntryRequest.parse(payload)
            if self.state.entry_character_id is not None:
                self.issues.append("multiple world entry requests observed")
            self.state.entry_character_id = request.character_id
            self.state.phase = GameplayPhase.ENTRY_REQUESTED
            self._event(
                frame,
                "world_entry_requested",
                details={"character_id_present": True, "opaque_ticket_bytes": 60},
                identifiers={"character_id": request.character_id},
            )
            return self._observation(
                frame,
                kind="world_entry_request",
                coverage=ShapeCoverage.PARTIAL,
                parsed=request,
                details={"character_id_present": True, "opaque_ticket_bytes": 60},
                issues=("world entry ticket remains opaque",),
            )
        if opcode == 301:
            acknowledgement = WorldBootstrapAcknowledgement.parse(payload)
            self.state.bootstrap_acknowledgements += 1
            self._event(
                frame,
                "world_bootstrap_acknowledged",
                details={"opaque_value_present": True},
            )
            return self._observation(
                frame,
                kind="world_bootstrap_acknowledgement",
                coverage=ShapeCoverage.PARTIAL,
                parsed=acknowledgement,
                details={"opaque_value_present": True},
                issues=("bootstrap acknowledgement value remains opaque",),
            )
        if opcode == 158:
            stage = FieldLoadStage.parse(payload)
            if self.state.field_epoch == 0:
                self.issues.append("field load stage arrived before a field snapshot")
            if stage.stage == 1:
                if self.state.field_load_stage is not None:
                    self.issues.append(
                        "field load stage 1 restarted an active field-load sequence"
                    )
            elif self.state.field_load_stage != 1:
                self.issues.append("field load stage 2 arrived before stage 1")
            self.state.field_load_stage = stage.stage
            self._event(
                frame,
                "field_load_stage_changed",
                details={
                    "field_epoch": self.state.field_epoch,
                    "stage": stage.stage,
                },
            )
            if stage.stage == 2:
                self.state.phase = GameplayPhase.ACTIVE
                self._event(
                    frame,
                    "field_became_active",
                    details={"field_epoch": self.state.field_epoch},
                )
            return self._observation(
                frame,
                kind="field_load_stage",
                coverage=ShapeCoverage.FULL,
                parsed=stage,
                details={
                    "field_epoch": self.state.field_epoch,
                    "stage": stage.stage,
                },
            )
        if opcode == 207:
            movement = MobMovementSubmission.parse(payload)
            alias = self._alias(
                self._movement_aliases, movement.object_id, "mob"
            )
            key = (movement.object_id, movement.sequence)
            self._pending_movements[key] += 1
            self.state.pending_movements += 1
            self.state.movement_submissions += 1
            details = {
                "entity": alias,
                "sequence": movement.sequence,
                "opaque_movement_bytes": len(movement.opaque_movement),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "mob_movement_submitted",
                details=details,
                identifiers={"object_id": movement.object_id},
            )
            return self._observation(
                frame,
                kind="mob_movement_submission",
                coverage=ShapeCoverage.PARTIAL,
                parsed=movement,
                details=details,
                issues=("movement command stream remains opaque",),
            )
        if opcode == 23:
            heartbeat = HeartbeatRequest.parse(payload)
            self.state.heartbeat_requests += 1
            self._event(frame, "heartbeat_requested")
            return self._observation(
                frame,
                kind="heartbeat_request",
                coverage=ShapeCoverage.PARTIAL,
                parsed=heartbeat,
                details={"opaque_token_bytes": 8},
                issues=("heartbeat token remains opaque",),
            )
        return self._observation(
            frame,
            kind=f"client_opcode_{opcode}",
            coverage=ShapeCoverage.UNKNOWN,
        )

    def _consume_server(
        self, frame: PlainFrame, opcode: int
    ) -> PacketObservation:
        payload = frame.plaintext
        if opcode == 157:
            snapshot = FieldSnapshotEnvelope.parse(payload)
            cleared_npcs = len(self.state.npcs)
            if self.state.entry_character_id is None:
                self.warnings.append(
                    "field snapshot arrived without a captured world entry request"
                )
            self.state.field_epoch += 1
            self.state.field_load_stage = None
            self.state.phase = GameplayPhase.FIELD_LOADING
            self.state.npcs.clear()
            self._pending_movements.clear()
            self.state.pending_movements = 0
            details = {
                "field_epoch": self.state.field_epoch,
                "opaque_snapshot_bytes": len(snapshot.opaque_snapshot),
                "cleared_npcs": cleared_npcs,
            }
            self._event(frame, "field_snapshot_received", details=details)
            return self._observation(
                frame,
                kind="field_snapshot",
                coverage=ShapeCoverage.PARTIAL,
                parsed=snapshot,
                details=details,
                issues=("field snapshot body remains opaque",),
            )
        if opcode == 300:
            spawn = NpcSpawn.parse(payload)
            alias = self._alias(self._npc_aliases, spawn.object_id, "npc")
            existing = self.state.npcs.get(spawn.object_id)
            if existing is not None and existing.spawn != spawn:
                self.issues.append(
                    f"{alias} was respawned with a different shape in field "
                    f"epoch {self.state.field_epoch}"
                )
            self.state.npcs[spawn.object_id] = NpcEntity(alias=alias, spawn=spawn)
            self.state.npc_spawns += 1
            details = {
                "entity": alias,
                "template_id": spawn.template_id,
                "x": spawn.x,
                "cy": spawn.cy,
                "faces_left": spawn.faces_left,
                "foothold_id": spawn.foothold_id,
                "range_left": spawn.range_left,
                "range_right": spawn.range_right,
                "hidden": spawn.hidden,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "npc_spawned",
                details=details,
                identifiers={"object_id": spawn.object_id},
            )
            return self._observation(
                frame,
                kind="npc_spawn",
                coverage=ShapeCoverage.FULL,
                parsed=spawn,
                details=details,
            )
        if opcode == 303:
            update = NpcStateUpdate.parse(payload)
            alias = self._alias(self._npc_aliases, update.object_id, "npc")
            entity = self.state.npcs.get(update.object_id)
            known_entity = entity is not None
            if entity is not None:
                entity.action = update.action
                entity.parameter = update.parameter
            else:
                warning_key = (self.state.field_epoch, update.object_id)
                if warning_key not in self._unknown_npc_updates:
                    self._unknown_npc_updates.add(warning_key)
                    self.warnings.append(
                        f"{alias} received a state update without a spawn in field "
                        f"epoch {self.state.field_epoch}"
                    )
            self.state.npc_state_updates += 1
            details = {
                "entity": alias,
                "known_entity": known_entity,
                "action": update.action,
                "parameter": update.parameter,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "npc_state_updated",
                details=details,
                identifiers={"object_id": update.object_id},
            )
            return self._observation(
                frame,
                kind="npc_state_update",
                coverage=ShapeCoverage.FULL,
                parsed=update,
                details=details,
            )
        if opcode == 283:
            acknowledgement = MobMovementAcknowledgement.parse(payload)
            alias = self._alias(
                self._movement_aliases, acknowledgement.object_id, "mob"
            )
            key = (acknowledgement.object_id, acknowledgement.sequence)
            matched = self._pending_movements[key] > 0
            if matched:
                self._pending_movements[key] -= 1
                if self._pending_movements[key] == 0:
                    del self._pending_movements[key]
                self.state.pending_movements -= 1
                self.state.matched_movement_acknowledgements += 1
            else:
                self.state.unmatched_movement_acknowledgements += 1
            self.state.movement_acknowledgements += 1
            details = {
                "entity": alias,
                "sequence": acknowledgement.sequence,
                "matched_submission": matched,
                "opaque_status_bytes": 5,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "mob_movement_acknowledged",
                details=details,
                identifiers={"object_id": acknowledgement.object_id},
            )
            return self._observation(
                frame,
                kind="mob_movement_acknowledgement",
                coverage=ShapeCoverage.PARTIAL,
                parsed=acknowledgement,
                details=details,
                issues=("movement acknowledgement status remains opaque",),
            )
        if opcode == 10:
            heartbeat = HeartbeatAcknowledgement.parse(payload)
            self.state.heartbeat_acknowledgements += 1
            self._event(frame, "heartbeat_acknowledged")
            return self._observation(
                frame,
                kind="heartbeat_acknowledgement",
                coverage=ShapeCoverage.FULL,
                parsed=heartbeat,
            )
        return self._observation(
            frame,
            kind=f"server_opcode_{opcode}",
            coverage=ShapeCoverage.UNKNOWN,
        )

    def finish(self, last_frame: PlainFrame | None) -> None:
        if self.state.unmatched_movement_acknowledgements:
            self.warnings.append(
                f"{self.state.unmatched_movement_acknowledgements} movement "
                "acknowledgements had no pending captured submission"
            )
        if last_frame is not None:
            self._event(
                last_frame,
                "session_ended",
                details={
                    "field_epoch": self.state.field_epoch,
                    "phase": self.state.phase.value,
                    "active_npcs": len(self.state.npcs),
                    "pending_movements": self.state.pending_movements,
                },
            )


def analyze_gameplay_transcript(transcript: Transcript) -> GameplayAnalysis:
    decoded = decode_transcript(transcript)
    fold = GameplayStateFold()
    observations = tuple(fold.consume(frame) for frame in decoded.frames)
    fold.finish(decoded.frames[-1] if decoded.frames else None)
    return GameplayAnalysis(
        source=str(transcript.path),
        decoded=decoded,
        state=fold.state,
        observations=observations,
        events=tuple(fold.events),
        issues=tuple(fold.issues),
        warnings=tuple(fold.warnings),
    )


def render_gameplay_analysis(
    analysis: GameplayAnalysis,
    *,
    show_identifiers: bool = False,
    show_packets: bool = False,
    show_events: bool = False,
) -> str:
    packet_counts = Counter(
        f"{observation.kind}:{observation.coverage.value}"
        for observation in analysis.observations
    )
    event_counts = Counter(event.kind for event in analysis.events)
    state = analysis.state
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
        (
            f"phase={state.phase.value} field_epoch={state.field_epoch} "
            f"field_load_stage={state.field_load_stage}"
        ),
        (
            f"frames=client:{state.packets_by_direction['client_to_server']} "
            f"server:{state.packets_by_direction['server_to_client']}"
        ),
        (
            f"npcs=active:{len(state.npcs)} spawned:{state.npc_spawns} "
            f"state_updates:{state.npc_state_updates}"
        ),
        (
            f"movement=submitted:{state.movement_submissions} "
            f"acknowledged:{state.movement_acknowledgements} "
            f"matched:{state.matched_movement_acknowledgements} "
            f"unmatched:{state.unmatched_movement_acknowledgements} "
            f"pending:{state.pending_movements}"
        ),
        (
            f"heartbeats=requested:{state.heartbeat_requests} "
            f"acknowledged:{state.heartbeat_acknowledgements}"
        ),
        f"packet_shapes={json.dumps(dict(sorted(packet_counts.items())))}",
        f"events={json.dumps(dict(sorted(event_counts.items())))}",
    ]
    lines.extend(f"issue={issue}" for issue in analysis.issues)
    lines.extend(f"warning={warning}" for warning in analysis.warnings)
    if show_events and analysis.events:
        base_timestamp_ns = analysis.events[0].timestamp_ns
        for event in analysis.events:
            safe = event.safe_dict(show_identifiers=show_identifiers)
            details = json.dumps(
                safe["details"],
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            elapsed_ms = (event.timestamp_ns - base_timestamp_ns) / 1e6
            lines.append(
                "event "
                f"index={event.index} frame={event.frame_index} "
                f"elapsed_ms={elapsed_ms:.3f} direction={event.direction} "
                f"kind={event.kind} details={details}"
            )
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
                f"frame={observation.frame_index} direction={direction} "
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

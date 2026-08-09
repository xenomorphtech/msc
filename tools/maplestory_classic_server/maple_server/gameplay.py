from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field, replace
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
    CharacterStatUpdate,
    CompactFieldTransition,
    FieldLoadStage,
    FieldSnapshotEnvelope,
    HeartbeatProbe,
    HeartbeatResponse,
    InitialFieldSnapshot,
    InitialInventoryItem,
    MobControllerChange,
    MobEnterField,
    MobLeaveField,
    MobMovementAcknowledgement,
    MobMovementBroadcast,
    MobMovementSubmission,
    MobSpawnData,
    NpcSpawn,
    NpcStateUpdate,
    PacketShapeError,
    PlayerMovementBroadcast,
    PlayerMovementPath,
    PlayerMovementSubmission,
    WorldBootstrapAcknowledgement,
    WorldEntryRequest,
    WorldSessionTermination,
)
from .transcript import Transcript


class GameplayPhase(str, Enum):
    CONNECTED = "connected"
    ENTRY_REQUESTED = "entry_requested"
    FIELD_LOADING = "field_loading"
    ACTIVE = "active"
    TERMINATED = "terminated"


@dataclass
class NpcEntity:
    alias: str
    spawn: NpcSpawn = field(repr=False)
    action: int | None = None
    parameter: int | None = None


@dataclass
class MobEntity:
    alias: str
    spawn: MobSpawnData = field(repr=False)
    controller_level: int = 0
    x: int = 0
    y: int = 0
    stance: int = 0


@dataclass
class ObservedPlayerEntity:
    alias: str
    x: int
    y: int


@dataclass(frozen=True)
class PendingMobMovement:
    expected_status_flag: int
    template_id: int | None


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
    initial_field_snapshots: int = 0
    compact_field_transitions: int = 0
    transition_sequence: int | None = None
    map_id: int | None = None
    portal_index: int | None = None
    current_hp: int | None = None
    max_hp: int | None = None
    current_mp: int | None = None
    max_mp: int | None = None
    character_level: int | None = None
    job_id: int | None = None
    strength: int | None = None
    dexterity: int | None = None
    intelligence: int | None = None
    luck: int | None = None
    ability_points: int | None = None
    skill_points: int | None = None
    experience: int | None = None
    fame: int | None = None
    mesos: int | None = None
    player_x: int | None = None
    player_y: int | None = None
    inventory_region_bytes: int | None = None
    progression_region_bytes: int | None = None
    inventory_items: dict[str, tuple[InitialInventoryItem, ...]] = field(
        default_factory=dict, repr=False
    )
    skill_levels: dict[int, int] = field(default_factory=dict, repr=False)
    string_property_code_units: dict[int, int] = field(
        default_factory=dict, repr=False
    )
    timestamp_property_keys: tuple[int, ...] = field(default=(), repr=False)
    saved_map_ids: tuple[int, ...] = field(default=(), repr=False)
    extended_property_code_units: dict[int, int] = field(
        default_factory=dict, repr=False
    )
    progression_variant: int | None = None
    server_local_filetime_ticks: int | None = None
    entry_character_id: int | None = field(default=None, repr=False)
    npcs: dict[int, NpcEntity] = field(default_factory=dict, repr=False)
    mobs: dict[int, MobEntity] = field(default_factory=dict, repr=False)
    mob_templates: dict[int, int] = field(default_factory=dict, repr=False)
    observed_players: dict[int, ObservedPlayerEntity] = field(
        default_factory=dict, repr=False
    )
    packets_by_direction: Counter[str] = field(default_factory=Counter)
    plaintext_bytes_by_direction: Counter[str] = field(default_factory=Counter)
    npc_spawns: int = 0
    npc_state_updates: int = 0
    mob_entries: int = 0
    mob_leaves: int = 0
    mob_controller_changes: int = 0
    mob_movement_broadcasts: int = 0
    unknown_mob_leaves: int = 0
    unknown_mob_broadcasts: int = 0
    mob_broadcast_commands: int = 0
    mob_broadcast_commands_by_type: Counter[int] = field(
        default_factory=Counter
    )
    player_movement_submissions: int = 0
    player_movement_commands: int = 0
    player_movement_commands_by_type: Counter[int] = field(
        default_factory=Counter
    )
    remote_player_movement_broadcasts: int = 0
    remote_player_movement_commands: int = 0
    remote_player_movement_commands_by_type: Counter[int] = field(
        default_factory=Counter
    )
    player_stat_updates: int = 0
    player_stat_updates_by_mask: Counter[int] = field(default_factory=Counter)
    player_stat_fields_updated: Counter[str] = field(default_factory=Counter)
    player_stat_request_flags: Counter[int] = field(default_factory=Counter)
    player_stat_zero_mask_updates: int = 0
    movement_submissions: int = 0
    movement_submissions_for_unknown_mobs: int = 0
    movement_submissions_with_unknown_template: int = 0
    movement_commands: int = 0
    movement_commands_by_type: Counter[int] = field(default_factory=Counter)
    movement_acknowledgements: int = 0
    movement_acknowledgements_for_unknown_mobs: int = 0
    movement_acknowledgement_statuses: Counter[
        tuple[int, int, int, int]
    ] = field(
        default_factory=Counter
    )
    movement_acknowledgement_flag_matches: int = 0
    movement_acknowledgement_flag_mismatches: int = 0
    movement_acknowledgement_zero_auxiliary_pairs: int = 0
    movement_acknowledgement_nonzero_auxiliary_pairs: int = 0
    movement_acknowledgements_with_known_template: int = 0
    movement_acknowledgements_with_unknown_template: int = 0
    movement_acknowledgement_values_by_template: dict[int, set[int]] = field(
        default_factory=dict
    )
    movement_acknowledgements_by_template: Counter[int] = field(
        default_factory=Counter
    )
    matched_movement_acknowledgements: int = 0
    unmatched_movement_acknowledgements: int = 0
    heartbeat_probes: int = 0
    heartbeat_responses: int = 0
    matched_heartbeat_responses: int = 0
    unmatched_heartbeat_responses: int = 0
    pending_heartbeat_probes: int = 0
    last_heartbeat_round_trip_ms: float | None = None
    max_heartbeat_round_trip_ms: float | None = None
    bootstrap_acknowledgements: int = 0
    pending_movements: int = 0
    termination_received: bool = False


@dataclass(frozen=True)
class NpcStateReplayPlan:
    update: NpcStateUpdate = field(repr=False)
    entity: str
    field_epoch: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "entity": self.entity,
            "field_epoch": self.field_epoch,
            "action": self.update.action,
            "parameter": self.update.parameter,
            "prediction": {
                "npc_state_updates_delta": 1,
                "events_delta": 1,
                "active_npc_count_delta": 0,
                "phase": "unchanged",
            },
        }


@dataclass(frozen=True)
class InitialPlayerHpReplayPlan:
    server_frame_index: int
    original_current_hp: int
    rewritten_current_hp: int
    max_hp: int
    replacement: InitialFieldSnapshot = field(repr=False)

    def safe_dict(self) -> dict[str, object]:
        return {
            "server_frame_index": self.server_frame_index,
            "original_current_hp": self.original_current_hp,
            "rewritten_current_hp": self.rewritten_current_hp,
            "max_hp": self.max_hp,
            "prediction": {
                "current_hp": self.rewritten_current_hp,
                "max_hp": self.max_hp,
                "map_id": "unchanged",
                "inventory": "unchanged",
                "progression": "unchanged",
                "phase": "unchanged",
            },
        }


@dataclass(frozen=True)
class CurrentHpStatUpdateReplayPlan:
    update: CharacterStatUpdate = field(repr=False)
    original_current_hp: int
    emitted_current_hp: int
    max_hp: int
    field_epoch: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "opcode": self.update.opcode,
            "stat_mask": f"0x{self.update.stat_mask:08x}",
            "request_flag": self.update.request_flag,
            "field_epoch": self.field_epoch,
            "original_current_hp": self.original_current_hp,
            "emitted_current_hp": self.emitted_current_hp,
            "max_hp": self.max_hp,
            "prediction": {
                "current_hp": self.emitted_current_hp,
                "max_hp": self.max_hp,
                "player_stat_updates_delta": 1,
                "events_delta": 1,
                "map_id": "unchanged",
                "inventory": "unchanged",
                "progression": "unchanged",
                "phase": "unchanged",
            },
        }


@dataclass(frozen=True)
class MobMovementAcknowledgementPolicy:
    status_values_by_template: dict[int, int]
    observations_by_template: dict[int, int]
    known_mob_templates: dict[int, int] = field(
        repr=False, compare=False
    )
    active_known_mob_count: int
    field_epoch: int
    matched_pairs: int
    known_template_pairs: int
    unknown_template_pairs: int
    flag_rule_matches: int
    zero_auxiliary_pairs: int
    pending_submissions: int

    def acknowledge(
        self, submission: MobMovementSubmission
    ) -> MobMovementAcknowledgement:
        template_id = self.known_mob_templates.get(submission.object_id)
        if template_id is None:
            raise ValueError(
                "movement submission has no explicit field-local "
                "mob-template state"
            )
        status_value = self.status_values_by_template.get(template_id)
        if status_value is None:
            raise ValueError(
                f"mob template {template_id} has no deterministic captured "
                "acknowledgement value"
            )
        status_flag = int(bool(submission.movement_path.opaque_control[0]))
        return MobMovementAcknowledgement(
            object_id=submission.object_id,
            sequence=submission.sequence,
            status_flag=status_flag,
            status_value=status_value,
            status_auxiliary_1=0,
            status_auxiliary_2=0,
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "field_epoch": self.field_epoch,
            "field_known_mob_count": len(self.known_mob_templates),
            "active_known_mob_count": self.active_known_mob_count,
            "status_values_by_template": [
                {
                    "template_id": template_id,
                    "status_value": status_value,
                    "observations": self.observations_by_template[template_id],
                }
                for template_id, status_value in sorted(
                    self.status_values_by_template.items()
                )
            ],
            "evidence": {
                "matched_pairs": self.matched_pairs,
                "known_template_pairs": self.known_template_pairs,
                "unknown_template_pairs": self.unknown_template_pairs,
                "flag_rule_matches": self.flag_rule_matches,
                "zero_auxiliary_pairs": self.zero_auxiliary_pairs,
                "pending_submissions": self.pending_submissions,
            },
            "prediction": {
                "status_flag": "submission_control_byte_0_nonzero",
                "status_value": "captured_template_value",
                "status_auxiliary_1": 0,
                "status_auxiliary_2": 0,
            },
        }


@dataclass(frozen=True)
class GameplayAnalysis:
    source: str
    decoded: DecodedSession
    state: GameplayGameState
    observations: tuple[PacketObservation, ...]
    events: tuple[GameplayEvent, ...]
    transport_closed: bool
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
        mobs: list[dict[str, object]] = []
        for object_id, entity in sorted(
            self.state.mobs.items(), key=lambda item: item[1].alias
        ):
            record = {
                "entity": entity.alias,
                "template_id": entity.spawn.template_id,
                "controller_level": entity.controller_level,
                "x": entity.x,
                "y": entity.y,
                "stance": entity.stance,
                "foothold_id": entity.spawn.foothold_id,
                "origin_foothold_id": entity.spawn.origin_foothold_id,
                "spawn_effect": entity.spawn.spawn_effect,
            }
            if show_identifiers:
                record["object_id"] = object_id
            mobs.append(record)
        observed_players: list[dict[str, object]] = []
        for object_id, entity in sorted(
            self.state.observed_players.items(), key=lambda item: item[1].alias
        ):
            record = {
                "entity": entity.alias,
                "x": entity.x,
                "y": entity.y,
            }
            if show_identifiers:
                record["object_id"] = object_id
            observed_players.append(record)
        entry_character_id: int | str | None = None
        if self.state.entry_character_id is not None:
            entry_character_id = (
                self.state.entry_character_id
                if show_identifiers
                else "present"
            )
        inventory = {
            name: [
                {
                    "slot": item.slot,
                    "item_id": item.item_id,
                    "record_type": item.record_type,
                    "cash_item": item.cash_item,
                    "quantity": item.quantity,
                }
                for item in items
            ]
            for name, items in self.state.inventory_items.items()
        }
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
                "initial_field_snapshots": self.state.initial_field_snapshots,
                "compact_field_transitions": (
                    self.state.compact_field_transitions
                ),
                "transition_sequence": self.state.transition_sequence,
                "map_id": self.state.map_id,
                "portal_index": self.state.portal_index,
                "current_hp": self.state.current_hp,
                "player": {
                    "level": self.state.character_level,
                    "job_id": self.state.job_id,
                    "strength": self.state.strength,
                    "dexterity": self.state.dexterity,
                    "intelligence": self.state.intelligence,
                    "luck": self.state.luck,
                    "current_hp": self.state.current_hp,
                    "max_hp": self.state.max_hp,
                    "current_mp": self.state.current_mp,
                    "max_mp": self.state.max_mp,
                    "ability_points": self.state.ability_points,
                    "skill_points": self.state.skill_points,
                    "experience": self.state.experience,
                    "fame": self.state.fame,
                    "mesos": self.state.mesos,
                    "x": self.state.player_x,
                    "y": self.state.player_y,
                },
                "inventory": {
                    "region_bytes": self.state.inventory_region_bytes,
                    "item_counts": {
                        name: len(items)
                        for name, items in self.state.inventory_items.items()
                    },
                    "items": inventory,
                },
                "progression": {
                    "region_bytes": self.state.progression_region_bytes,
                    "skill_levels": self.state.skill_levels,
                    "string_property_code_units": (
                        self.state.string_property_code_units
                    ),
                    "timestamp_property_keys": (
                        self.state.timestamp_property_keys
                    ),
                    "saved_map_ids": self.state.saved_map_ids,
                    "extended_property_code_units": (
                        self.state.extended_property_code_units
                    ),
                    "variant": self.state.progression_variant,
                },
                "server_local_filetime_ticks": (
                    self.state.server_local_filetime_ticks
                ),
                "entry_character_id": entry_character_id,
                "observed_remote_player_count": len(
                    self.state.observed_players
                ),
                "observed_remote_players": observed_players,
                "active_npc_count": len(self.state.npcs),
                "npcs": npcs,
                "active_mob_count": len(self.state.mobs),
                "field_known_mob_template_count": len(
                    self.state.mob_templates
                ),
                "controlled_mob_count": sum(
                    entity.controller_level != 0
                    for entity in self.state.mobs.values()
                ),
                "mobs": mobs,
                "packets_by_direction": dict(self.state.packets_by_direction),
                "plaintext_bytes_by_direction": dict(
                    self.state.plaintext_bytes_by_direction
                ),
                "npc_spawns": self.state.npc_spawns,
                "npc_state_updates": self.state.npc_state_updates,
                "mob_entries": self.state.mob_entries,
                "mob_leaves": self.state.mob_leaves,
                "mob_controller_changes": self.state.mob_controller_changes,
                "mob_movement_broadcasts": (
                    self.state.mob_movement_broadcasts
                ),
                "unknown_mob_leaves": self.state.unknown_mob_leaves,
                "unknown_mob_broadcasts": self.state.unknown_mob_broadcasts,
                "mob_broadcast_commands": self.state.mob_broadcast_commands,
                "mob_broadcast_commands_by_type": dict(
                    self.state.mob_broadcast_commands_by_type
                ),
                "player_movement_submissions": (
                    self.state.player_movement_submissions
                ),
                "player_movement_commands": self.state.player_movement_commands,
                "player_movement_commands_by_type": dict(
                    self.state.player_movement_commands_by_type
                ),
                "remote_player_movement_broadcasts": (
                    self.state.remote_player_movement_broadcasts
                ),
                "remote_player_movement_commands": (
                    self.state.remote_player_movement_commands
                ),
                "remote_player_movement_commands_by_type": dict(
                    self.state.remote_player_movement_commands_by_type
                ),
                "player_stat_updates": self.state.player_stat_updates,
                "player_stat_updates_by_mask": {
                    f"0x{mask:08x}": count
                    for mask, count in sorted(
                        self.state.player_stat_updates_by_mask.items()
                    )
                },
                "player_stat_fields_updated": dict(
                    self.state.player_stat_fields_updated
                ),
                "player_stat_request_flags": dict(
                    self.state.player_stat_request_flags
                ),
                "player_stat_zero_mask_updates": (
                    self.state.player_stat_zero_mask_updates
                ),
                "movement_submissions": self.state.movement_submissions,
                "movement_submissions_for_unknown_mobs": (
                    self.state.movement_submissions_for_unknown_mobs
                ),
                "movement_submissions_with_unknown_template": (
                    self.state.movement_submissions_with_unknown_template
                ),
                "movement_commands": self.state.movement_commands,
                "movement_commands_by_type": dict(
                    self.state.movement_commands_by_type
                ),
                "movement_acknowledgements": (
                    self.state.movement_acknowledgements
                ),
                "movement_acknowledgements_for_unknown_mobs": (
                    self.state.movement_acknowledgements_for_unknown_mobs
                ),
                "movement_acknowledgement_statuses": [
                    {
                        "flag": flag,
                        "value": value,
                        "auxiliary_1": auxiliary_1,
                        "auxiliary_2": auxiliary_2,
                        "count": count,
                    }
                    for (
                        flag,
                        value,
                        auxiliary_1,
                        auxiliary_2,
                    ), count in sorted(
                        self.state.movement_acknowledgement_statuses.items()
                    )
                ],
                "movement_acknowledgement_flag_matches": (
                    self.state.movement_acknowledgement_flag_matches
                ),
                "movement_acknowledgement_flag_mismatches": (
                    self.state.movement_acknowledgement_flag_mismatches
                ),
                "movement_acknowledgement_zero_auxiliary_pairs": (
                    self.state.movement_acknowledgement_zero_auxiliary_pairs
                ),
                "movement_acknowledgement_nonzero_auxiliary_pairs": (
                    self.state.movement_acknowledgement_nonzero_auxiliary_pairs
                ),
                "movement_acknowledgements_with_known_template": (
                    self.state.movement_acknowledgements_with_known_template
                ),
                "movement_acknowledgements_with_unknown_template": (
                    self.state.movement_acknowledgements_with_unknown_template
                ),
                "movement_acknowledgement_values_by_template": [
                    {
                        "template_id": template_id,
                        "status_values": sorted(status_values),
                        "count": (
                            self.state.movement_acknowledgements_by_template[
                                template_id
                            ]
                        ),
                    }
                    for template_id, status_values in sorted(
                        self.state.movement_acknowledgement_values_by_template.items()
                    )
                ],
                "matched_movement_acknowledgements": (
                    self.state.matched_movement_acknowledgements
                ),
                "unmatched_movement_acknowledgements": (
                    self.state.unmatched_movement_acknowledgements
                ),
                "pending_movements": self.state.pending_movements,
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
                "bootstrap_acknowledgements": (
                    self.state.bootstrap_acknowledgements
                ),
                "termination_received": self.state.termination_received,
                "transport_closed": self.transport_closed,
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
        self._mob_aliases: dict[int, str] = {}
        self._player_aliases: dict[int, str] = {}
        self._pending_movements: dict[
            tuple[int, int], deque[PendingMobMovement]
        ] = {}
        self._pending_heartbeat_probes: deque[int] = deque()
        self._unknown_npc_updates: set[tuple[int, int]] = set()
        self._started = False

    def _alias(self, aliases: dict[int, str], object_id: int, prefix: str) -> str:
        alias = aliases.get(object_id)
        if alias is None:
            alias = f"{prefix}:{len(aliases) + 1}"
            aliases[object_id] = alias
        return alias

    @staticmethod
    def _mob_spawn_details(spawn: MobSpawnData) -> dict[str, object]:
        return {
            "template_id": spawn.template_id,
            "opaque_status_bytes": len(spawn.opaque_status),
            "x": spawn.x,
            "y": spawn.y,
            "stance": spawn.stance,
            "foothold_id": spawn.foothold_id,
            "origin_foothold_id": spawn.origin_foothold_id,
            "spawn_effect": spawn.spawn_effect,
            "opaque_tail_bytes": len(spawn.opaque_tail),
        }

    @staticmethod
    def _player_movement_details(
        movement: PlayerMovementPath,
    ) -> dict[str, object]:
        details: dict[str, object] = {
            "reference_x": movement.reference_x,
            "reference_y": movement.reference_y,
            "command_count": len(movement.commands),
            "command_types": [
                command.command_type for command in movement.commands
            ],
            "commands": [
                command.safe_dict() for command in movement.commands
            ],
            "opaque_command_payload_bytes": sum(
                len(command.opaque_payload) for command in movement.commands
            ),
        }
        final_position = movement.final_position
        if final_position is not None:
            details["final_x"], details["final_y"] = final_position
        return details

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
        if opcode == 182:
            movement = PlayerMovementSubmission.parse(payload)
            path = movement.movement
            self.state.player_movement_submissions += 1
            self.state.player_movement_commands += len(path.commands)
            self.state.player_movement_commands_by_type.update(
                command.command_type for command in path.commands
            )
            self.state.player_x = movement.path_end_x
            self.state.player_y = movement.path_end_y
            details = {
                "control_value": movement.control_value,
                **self._player_movement_details(path),
                "path_start_x": movement.path_start_x,
                "path_start_y": movement.path_start_y,
                "path_end_x": movement.path_end_x,
                "path_end_y": movement.path_end_y,
                "field_epoch": self.state.field_epoch,
            }
            self._event(frame, "player_movement_submitted", details=details)
            return self._observation(
                frame,
                kind="player_movement_submission",
                coverage=ShapeCoverage.PARTIAL,
                parsed=movement,
                details=details,
                issues=(
                    "player movement control value and type-3 command "
                    "meaning remain opaque",
                ),
            )
        if opcode == 207:
            movement = MobMovementSubmission.parse(payload)
            movement_path = movement.movement_path
            alias = self._alias(
                self._mob_aliases, movement.object_id, "mob"
            )
            key = (movement.object_id, movement.sequence)
            entity = self.state.mobs.get(movement.object_id)
            template_id = self.state.mob_templates.get(movement.object_id)
            expected_status_flag = int(
                bool(movement_path.opaque_control[0])
            )
            self._pending_movements.setdefault(key, deque()).append(
                PendingMobMovement(
                    expected_status_flag=expected_status_flag,
                    template_id=template_id,
                )
            )
            self.state.pending_movements += 1
            self.state.movement_submissions += 1
            self.state.movement_commands += len(movement_path.commands)
            self.state.movement_commands_by_type.update(
                command.command_type for command in movement_path.commands
            )
            if entity is None:
                self.state.movement_submissions_for_unknown_mobs += 1
            if template_id is None:
                self.state.movement_submissions_with_unknown_template += 1
            if entity is not None:
                entity.x = movement_path.path_end_x
                entity.y = movement_path.path_end_y
                entity.stance = movement_path.commands[-1].stance
            details = {
                "entity": alias,
                "known_entity": entity is not None,
                "controller_level": (
                    entity.controller_level if entity is not None else None
                ),
                "known_template": template_id is not None,
                "template_id": template_id,
                "sequence": movement.sequence,
                "predicted_acknowledgement_flag": expected_status_flag,
                "movement_body_bytes": len(movement.opaque_movement),
                "opaque_control_bytes": len(movement_path.opaque_control),
                "reference_x": movement_path.reference_x,
                "reference_y": movement_path.reference_y,
                "command_count": len(movement_path.commands),
                "command_types": [
                    command.command_type for command in movement_path.commands
                ],
                "commands": [
                    command.safe_dict() for command in movement_path.commands
                ],
                "opaque_command_payload_bytes": sum(
                    len(command.opaque_payload)
                    for command in movement_path.commands
                ),
                "path_start_x": movement_path.path_start_x,
                "path_start_y": movement_path.path_start_y,
                "path_end_x": movement_path.path_end_x,
                "path_end_y": movement_path.path_end_y,
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
                issues=(
                    "movement control metadata after byte zero remains opaque",
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
            details = {
                "matched_probe": matched_probe,
                "opaque_token_bytes": 8,
            }
            if round_trip_ms is not None:
                details["round_trip_ms"] = round(round_trip_ms, 3)
            self._event(
                frame, "heartbeat_response_submitted", details=details
            )
            return self._observation(
                frame,
                kind="heartbeat_response",
                coverage=ShapeCoverage.PARTIAL,
                parsed=response,
                details=details,
                issues=("heartbeat response token remains opaque",),
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
        if opcode == 41:
            update = CharacterStatUpdate.parse(payload)
            changes: dict[str, dict[str, int | None]] = {}
            for field_name, current_value in update.values.items():
                previous_value = getattr(self.state, field_name)
                setattr(self.state, field_name, current_value)
                changes[field_name] = {
                    "previous": previous_value,
                    "current": current_value,
                }
                self.state.player_stat_fields_updated[field_name] += 1
            self.state.player_stat_updates += 1
            self.state.player_stat_updates_by_mask[update.stat_mask] += 1
            self.state.player_stat_request_flags[update.request_flag] += 1
            if update.stat_mask == 0:
                self.state.player_stat_zero_mask_updates += 1
            details: dict[str, object] = {
                "request_flag": update.request_flag,
                "stat_mask": f"0x{update.stat_mask:08x}",
                "changes": changes,
                "changed_field_count": len(changes),
                "tail_variant": (
                    "single_zero"
                    if update.opaque_tail == b"\x00"
                    else "double_one"
                ),
                "field_epoch": self.state.field_epoch,
            }
            self._event(frame, "player_stats_updated", details=details)
            issues = [
                "stat update request flag and final marker semantics remain neutral"
            ]
            if update.stat_mask == 0:
                issues.append(
                    "zero-mask single-zero/double-one variant remains opaque"
                )
            return self._observation(
                frame,
                kind="character_stat_update",
                coverage=ShapeCoverage.PARTIAL,
                parsed=update,
                details=details,
                issues=tuple(issues),
            )
        if opcode == 9:
            termination = WorldSessionTermination.parse(payload)
            self.state.termination_received = True
            self.state.phase = GameplayPhase.TERMINATED
            self._event(
                frame,
                "world_session_termination_received",
                details={"opaque_reason_bytes": 7},
            )
            return self._observation(
                frame,
                kind="world_session_termination",
                coverage=ShapeCoverage.PARTIAL,
                parsed=termination,
                details={"opaque_reason_bytes": 7},
                issues=("world-session termination reason remains opaque",),
            )
        if opcode == 157:
            snapshot = FieldSnapshotEnvelope.parse(payload)
            transition = (
                CompactFieldTransition.parse(payload)
                if len(snapshot.opaque_snapshot) == 93
                else None
            )
            initial_snapshot = (
                InitialFieldSnapshot.parse(payload)
                if transition is None and len(payload) >= 112
                else None
            )
            cleared_npcs = len(self.state.npcs)
            cleared_mobs = len(self.state.mobs)
            if self.state.entry_character_id is None:
                self.warnings.append(
                    "field snapshot arrived without a captured world entry request"
                )
            self.state.field_epoch += 1
            self.state.field_load_stage = None
            self.state.phase = GameplayPhase.FIELD_LOADING
            self.state.npcs.clear()
            self.state.mobs.clear()
            self.state.mob_templates.clear()
            self.state.observed_players.clear()
            self.state.player_x = None
            self.state.player_y = None
            self._pending_movements.clear()
            self.state.pending_movements = 0
            details = {
                "field_epoch": self.state.field_epoch,
                "opaque_snapshot_bytes": len(snapshot.opaque_snapshot),
                "cleared_npcs": cleared_npcs,
                "cleared_mobs": cleared_mobs,
                "variant": (
                    "compact_transition"
                    if transition is not None
                    else (
                        "initial_character_snapshot"
                        if initial_snapshot is not None
                        else "opaque_snapshot"
                    )
                ),
            }
            event_identifiers: dict[str, object] = {}
            if initial_snapshot is not None:
                character = initial_snapshot.character
                inventory = initial_snapshot.parse_inventory()
                progression = initial_snapshot.parse_progression()
                self.state.initial_field_snapshots += 1
                self.state.transition_sequence = None
                self.state.map_id = character.map_id
                self.state.portal_index = character.portal_index
                self.state.current_hp = character.current_hp
                self.state.max_hp = character.max_hp
                self.state.current_mp = character.current_mp
                self.state.max_mp = character.max_mp
                self.state.character_level = character.level
                self.state.job_id = character.job_id
                self.state.strength = character.strength
                self.state.dexterity = character.dexterity
                self.state.intelligence = character.intelligence
                self.state.luck = character.luck
                self.state.ability_points = character.ability_points
                self.state.skill_points = character.skill_points
                self.state.experience = character.experience
                self.state.fame = character.fame
                self.state.inventory_region_bytes = (
                    len(initial_snapshot.opaque_tail)
                    - len(inventory.opaque_remainder)
                )
                self.state.progression_region_bytes = len(
                    inventory.opaque_remainder
                )
                self.state.inventory_items = {
                    group.name: group.items for group in inventory.groups
                }
                self.state.skill_levels = dict(progression.skill_levels)
                self.state.string_property_code_units = {
                    key: len(value.encode("utf-16-le")) // 2
                    for key, value in progression.string_properties
                }
                self.state.timestamp_property_keys = tuple(
                    key for key, _ in progression.timestamp_properties
                )
                self.state.saved_map_ids = progression.saved_map_ids
                self.state.extended_property_code_units = {
                    key: len(value.encode("utf-16-le")) // 2
                    for key, value in progression.extended_properties
                }
                self.state.progression_variant = progression.variant
                self.state.server_local_filetime_ticks = (
                    progression.trailer.server_local_filetime_ticks
                )
                if (
                    self.state.entry_character_id is not None
                    and character.character_id != self.state.entry_character_id
                ):
                    self.issues.append(
                        "initial field snapshot character id does not match "
                        "the world entry request"
                    )
                details.update(
                    {
                        "typed_prefix_bytes": initial_snapshot.typed_prefix_bytes,
                        "snapshot_tail_bytes": len(initial_snapshot.opaque_tail),
                        "character_data_flags": character.data_flags,
                        "character_name_code_units": (
                            len(character.name.encode("utf-16-le")) // 2
                        ),
                        "level": character.level,
                        "job_id": character.job_id,
                        "strength": character.strength,
                        "dexterity": character.dexterity,
                        "intelligence": character.intelligence,
                        "luck": character.luck,
                        "current_hp": character.current_hp,
                        "max_hp": character.max_hp,
                        "current_mp": character.current_mp,
                        "max_mp": character.max_mp,
                        "ability_points": character.ability_points,
                        "skill_points": character.skill_points,
                        "experience": character.experience,
                        "fame": character.fame,
                        "map_id": character.map_id,
                        "portal_index": character.portal_index,
                        "inventory_region_bytes": (
                            self.state.inventory_region_bytes
                        ),
                        "progression_region_bytes": (
                            self.state.progression_region_bytes
                        ),
                        "inventory_item_counts": {
                            group.name: len(group.items)
                            for group in inventory.groups
                        },
                        "skill_levels": dict(progression.skill_levels),
                        "string_properties": [
                            {
                                "key": key,
                                "value_code_units": (
                                    len(value.encode("utf-16-le")) // 2
                                ),
                            }
                            for key, value in progression.string_properties
                        ],
                        "timestamp_property_keys": [
                            key for key, _ in progression.timestamp_properties
                        ],
                        "saved_map_ids": list(progression.saved_map_ids),
                        "progression_variant": progression.variant,
                        "extended_properties": [
                            {
                                "key": key,
                                "value_code_units": (
                                    len(value.encode("utf-16-le")) // 2
                                ),
                            }
                            for key, value in progression.extended_properties
                        ],
                        "trailer_text_code_units": [
                            len(value.encode("utf-16-le")) // 2
                            for value in progression.trailer.opaque_texts
                        ],
                        "server_local_filetime_ticks": (
                            progression.trailer.server_local_filetime_ticks
                        ),
                        "unknown_tail_u32": (
                            progression.trailer.unknown_tail_u32
                        ),
                        "inventory_items": {
                            group.name: [
                                {
                                    "slot": item.slot,
                                    "item_id": item.item_id,
                                    "cash_item": item.cash_item,
                                    "quantity": item.quantity,
                                }
                                for item in group.items
                            ]
                            for group in inventory.groups
                        },
                    }
                )
                event_identifiers["character_id"] = character.character_id
            elif transition is None:
                self.state.transition_sequence = None
                self.state.map_id = None
                self.state.portal_index = None
                self.state.current_hp = None
                self.state.server_local_filetime_ticks = None
            else:
                self.state.compact_field_transitions += 1
                self.state.transition_sequence = (
                    transition.transition_sequence
                )
                self.state.map_id = transition.map_id
                self.state.portal_index = transition.portal_index
                self.state.current_hp = transition.current_hp
                self.state.server_local_filetime_ticks = (
                    transition.server_local_filetime_ticks
                )
                if transition.transition_sequence != self.state.field_epoch:
                    self.issues.append(
                        "compact field transition sequence does not match "
                        "the folded field epoch"
                    )
                details.update(
                    {
                        "transition_sequence": transition.transition_sequence,
                        "map_id": transition.map_id,
                        "portal_index": transition.portal_index,
                        "current_hp": transition.current_hp,
                        "opaque_text_character_counts": [
                            len(transition.opaque_text_1),
                            len(transition.opaque_text_2),
                            len(transition.opaque_text_3),
                        ],
                        "constant_u32": transition.constant_u32,
                        "sentinel_filetime_ticks": (
                            transition.sentinel_filetime_ticks
                        ),
                        "server_local_filetime_ticks": (
                            transition.server_local_filetime_ticks
                        ),
                        "unknown_tail_u32": transition.unknown_tail_u32,
                    }
                )
            self._event(
                frame,
                "field_snapshot_received",
                details=details,
                identifiers=event_identifiers,
            )
            return self._observation(
                frame,
                kind=(
                    "compact_field_transition"
                    if transition is not None
                    else (
                        "initial_field_snapshot"
                        if initial_snapshot is not None
                        else "field_snapshot"
                    )
                ),
                coverage=(
                    ShapeCoverage.FULL
                    if transition is not None
                    else ShapeCoverage.PARTIAL
                ),
                parsed=(
                    transition
                    if transition is not None
                    else (
                        initial_snapshot
                        if initial_snapshot is not None
                        else snapshot
                    )
                ),
                details=details,
                issues=(
                    ()
                    if transition is not None
                    else (
                        (
                            "initial field snapshot equipment metadata and "
                            "progression/trailer meanings remain partially opaque",
                        )
                        if initial_snapshot is not None
                        else ("field snapshot body remains opaque",)
                    )
                ),
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
        if opcode == 202:
            broadcast = PlayerMovementBroadcast.parse(payload)
            path = broadcast.movement
            alias = self._alias(
                self._player_aliases, broadcast.object_id, "player"
            )
            existing = self.state.observed_players.get(broadcast.object_id)
            final_position = path.final_position
            if final_position is None:
                final_position = (path.reference_x, path.reference_y)
            self.state.observed_players[broadcast.object_id] = (
                ObservedPlayerEntity(
                    alias=alias,
                    x=final_position[0],
                    y=final_position[1],
                )
            )
            self.state.remote_player_movement_broadcasts += 1
            self.state.remote_player_movement_commands += len(path.commands)
            self.state.remote_player_movement_commands_by_type.update(
                command.command_type for command in path.commands
            )
            details = {
                "entity": alias,
                "previously_observed": existing is not None,
                "control_value": broadcast.control_value,
                **self._player_movement_details(path),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "remote_player_movement_broadcast",
                details=details,
                identifiers={"object_id": broadcast.object_id},
            )
            return self._observation(
                frame,
                kind="player_movement_broadcast",
                coverage=ShapeCoverage.PARTIAL,
                parsed=broadcast,
                details=details,
                issues=(
                    "player movement control value and type-3 command "
                    "meaning remain opaque",
                ),
            )
        if opcode == 279:
            entered = MobEnterField.parse(payload)
            alias = self._alias(self._mob_aliases, entered.object_id, "mob")
            existing = self.state.mobs.get(entered.object_id)
            controller_level = (
                existing.controller_level if existing is not None else 0
            )
            self.state.mobs[entered.object_id] = MobEntity(
                alias=alias,
                spawn=entered.spawn,
                controller_level=controller_level,
                x=entered.spawn.x,
                y=entered.spawn.y,
                stance=entered.spawn.stance,
            )
            self.state.mob_templates[entered.object_id] = (
                entered.spawn.template_id
            )
            self.state.mob_entries += 1
            details = {
                "entity": alias,
                "replaced_existing": existing is not None,
                "controller_level": controller_level,
                "field_epoch": self.state.field_epoch,
                **self._mob_spawn_details(entered.spawn),
            }
            self._event(
                frame,
                "mob_entered_field",
                details=details,
                identifiers={"object_id": entered.object_id},
            )
            return self._observation(
                frame,
                kind="mob_enter_field",
                coverage=ShapeCoverage.PARTIAL,
                parsed=entered,
                details=details,
                issues=("mob temporary status and spawn tail remain opaque",),
            )
        if opcode == 280:
            left = MobLeaveField.parse(payload)
            alias = self._alias(self._mob_aliases, left.object_id, "mob")
            known_entity = self.state.mobs.pop(left.object_id, None) is not None
            if not known_entity:
                self.state.unknown_mob_leaves += 1
            self.state.mob_leaves += 1
            details = {
                "entity": alias,
                "known_entity": known_entity,
                "reason": left.reason,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "mob_left_field",
                details=details,
                identifiers={"object_id": left.object_id},
            )
            return self._observation(
                frame,
                kind="mob_leave_field",
                coverage=ShapeCoverage.FULL,
                parsed=left,
                details=details,
            )
        if opcode == 281:
            change = MobControllerChange.parse(payload)
            alias = self._alias(self._mob_aliases, change.object_id, "mob")
            entity = self.state.mobs.get(change.object_id)
            known_entity = entity is not None
            if change.spawn is not None:
                self.state.mob_templates[change.object_id] = (
                    change.spawn.template_id
                )
                if entity is None:
                    entity = MobEntity(alias=alias, spawn=change.spawn)
                    self.state.mobs[change.object_id] = entity
                else:
                    entity.spawn = change.spawn
                entity.x = change.spawn.x
                entity.y = change.spawn.y
                entity.stance = change.spawn.stance
                entity.controller_level = change.control_level
            elif entity is not None:
                entity.controller_level = 0
            self.state.mob_controller_changes += 1
            details = {
                "entity": alias,
                "known_entity": known_entity,
                "control_level": change.control_level,
                "has_spawn": change.spawn is not None,
                "field_epoch": self.state.field_epoch,
            }
            if change.spawn is not None:
                details.update(self._mob_spawn_details(change.spawn))
            self._event(
                frame,
                "mob_controller_changed",
                details=details,
                identifiers={"object_id": change.object_id},
            )
            issues = (
                ("mob temporary status and spawn tail remain opaque",)
                if change.spawn is not None
                else ()
            )
            return self._observation(
                frame,
                kind="mob_controller_change",
                coverage=(
                    ShapeCoverage.PARTIAL
                    if change.spawn is not None
                    else ShapeCoverage.FULL
                ),
                parsed=change,
                details=details,
                issues=issues,
            )
        if opcode == 282:
            broadcast = MobMovementBroadcast.parse(payload)
            alias = self._alias(self._mob_aliases, broadcast.object_id, "mob")
            entity = self.state.mobs.get(broadcast.object_id)
            if entity is None:
                self.state.unknown_mob_broadcasts += 1
            absolute_positions = [
                command.position
                for command in broadcast.commands
                if command.position is not None
            ]
            if entity is not None:
                if absolute_positions:
                    entity.x, entity.y = absolute_positions[-1]
                else:
                    entity.x = broadcast.reference_x
                    entity.y = broadcast.reference_y
                entity.stance = broadcast.commands[-1].stance
            self.state.mob_movement_broadcasts += 1
            self.state.mob_broadcast_commands += len(broadcast.commands)
            self.state.mob_broadcast_commands_by_type.update(
                command.command_type for command in broadcast.commands
            )
            details = {
                "entity": alias,
                "known_entity": entity is not None,
                "opaque_control_bytes": len(broadcast.opaque_control),
                "reference_x": broadcast.reference_x,
                "reference_y": broadcast.reference_y,
                "command_count": len(broadcast.commands),
                "command_types": [
                    command.command_type for command in broadcast.commands
                ],
                "commands": [
                    command.safe_dict() for command in broadcast.commands
                ],
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "mob_movement_broadcast",
                details=details,
                identifiers={"object_id": broadcast.object_id},
            )
            return self._observation(
                frame,
                kind="mob_movement_broadcast",
                coverage=ShapeCoverage.PARTIAL,
                parsed=broadcast,
                details=details,
                issues=("server mob-movement control metadata remains opaque",),
            )
        if opcode == 283:
            acknowledgement = MobMovementAcknowledgement.parse(payload)
            alias = self._alias(
                self._mob_aliases, acknowledgement.object_id, "mob"
            )
            key = (acknowledgement.object_id, acknowledgement.sequence)
            pending_queue = self._pending_movements.get(key)
            matched = bool(pending_queue)
            pending: PendingMobMovement | None = None
            if matched:
                assert pending_queue is not None
                pending = pending_queue.popleft()
                if not pending_queue:
                    del self._pending_movements[key]
                self.state.pending_movements -= 1
                self.state.matched_movement_acknowledgements += 1
            else:
                self.state.unmatched_movement_acknowledgements += 1
            self.state.movement_acknowledgements += 1
            known_entity = acknowledgement.object_id in self.state.mobs
            if not known_entity:
                self.state.movement_acknowledgements_for_unknown_mobs += 1
            self.state.movement_acknowledgement_statuses[
                (
                    acknowledgement.status_flag,
                    acknowledgement.status_value,
                    acknowledgement.status_auxiliary_1,
                    acknowledgement.status_auxiliary_2,
                )
            ] += 1
            flag_matches_submission: bool | None = None
            if pending is not None:
                flag_matches_submission = (
                    acknowledgement.status_flag
                    == pending.expected_status_flag
                )
                if flag_matches_submission:
                    self.state.movement_acknowledgement_flag_matches += 1
                else:
                    self.state.movement_acknowledgement_flag_mismatches += 1
                    self.issues.append(
                        f"{alias} movement acknowledgement flag did not match "
                        "submission control byte zero"
                    )
                auxiliary_is_zero = (
                    acknowledgement.status_auxiliary_1 == 0
                    and acknowledgement.status_auxiliary_2 == 0
                )
                if auxiliary_is_zero:
                    self.state.movement_acknowledgement_zero_auxiliary_pairs += 1
                else:
                    self.state.movement_acknowledgement_nonzero_auxiliary_pairs += 1
                    self.issues.append(
                        f"{alias} movement acknowledgement auxiliary bytes "
                        "were nonzero"
                    )
                if pending.template_id is None:
                    self.state.movement_acknowledgements_with_unknown_template += 1
                else:
                    self.state.movement_acknowledgements_with_known_template += 1
                    status_values = (
                        self.state.movement_acknowledgement_values_by_template
                        .setdefault(pending.template_id, set())
                    )
                    status_values.add(acknowledgement.status_value)
                    self.state.movement_acknowledgements_by_template[
                        pending.template_id
                    ] += 1
                    if len(status_values) > 1:
                        self.issues.append(
                            f"mob template {pending.template_id} has multiple "
                            "movement acknowledgement values"
                        )
            details = {
                "entity": alias,
                "known_entity": known_entity,
                "sequence": acknowledgement.sequence,
                "matched_submission": matched,
                "submission_template_id": (
                    pending.template_id if pending is not None else None
                ),
                "status_flag_matches_submission_control": (
                    flag_matches_submission
                ),
                "status_flag": acknowledgement.status_flag,
                "status_value": acknowledgement.status_value,
                "status_auxiliary_1": acknowledgement.status_auxiliary_1,
                "status_auxiliary_2": acknowledgement.status_auxiliary_2,
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
                coverage=ShapeCoverage.FULL,
                parsed=acknowledgement,
                details=details,
            )
        if opcode == 10:
            probe = HeartbeatProbe.parse(payload)
            self._pending_heartbeat_probes.append(frame.timestamp_ns)
            self.state.heartbeat_probes += 1
            self.state.pending_heartbeat_probes += 1
            self._event(
                frame,
                "heartbeat_probe_received",
                details={
                    "pending_probes": self.state.pending_heartbeat_probes,
                },
            )
            return self._observation(
                frame,
                kind="heartbeat_probe",
                coverage=ShapeCoverage.FULL,
                parsed=probe,
            )
        return self._observation(
            frame,
            kind=f"server_opcode_{opcode}",
            coverage=ShapeCoverage.UNKNOWN,
        )

    def finish(
        self, last_frame: PlainFrame | None, *, transport_closed: bool
    ) -> None:
        if self.state.unmatched_movement_acknowledgements:
            self.warnings.append(
                f"{self.state.unmatched_movement_acknowledgements} movement "
                "acknowledgements had no pending captured submission"
            )
        if self.state.unmatched_heartbeat_responses:
            self.warnings.append(
                f"{self.state.unmatched_heartbeat_responses} heartbeat "
                "responses had no pending captured server probe"
            )
        if self.state.pending_heartbeat_probes:
            self.warnings.append(
                f"{self.state.pending_heartbeat_probes} server heartbeat "
                "probes had no captured client response"
            )
        if last_frame is not None and transport_closed:
            self._event(
                last_frame,
                "session_ended",
                details={
                    "field_epoch": self.state.field_epoch,
                    "phase": self.state.phase.value,
                    "active_npcs": len(self.state.npcs),
                    "active_mobs": len(self.state.mobs),
                    "pending_movements": self.state.pending_movements,
                    "pending_heartbeat_probes": (
                        self.state.pending_heartbeat_probes
                    ),
                },
            )


def world_session_termination_frame_index(transcript: Transcript) -> int:
    """Return the final server-frame index for one validated termination packet."""

    decoded = decode_transcript(transcript)
    server_frames = tuple(
        frame
        for frame in decoded.frames
        if frame.direction == "server_to_client"
    )
    terminations = tuple(
        frame for frame in server_frames if frame.opcode == 9
    )
    if not terminations:
        raise PacketShapeError(
            "world transcript has no server opcode-9 termination packet"
        )
    if len(terminations) != 1:
        raise PacketShapeError(
            "world transcript has multiple server opcode-9 termination packets"
        )
    termination = terminations[0]
    WorldSessionTermination.parse(termination.plaintext)
    if termination.direction_index != server_frames[-1].direction_index:
        raise PacketShapeError(
            "world-session termination is not the final captured server frame"
        )
    return termination.direction_index


def analyze_gameplay_transcript(transcript: Transcript) -> GameplayAnalysis:
    decoded = decode_transcript(transcript)
    fold = GameplayStateFold()
    observations = tuple(fold.consume(frame) for frame in decoded.frames)
    transport_closed = any(event.event == "close" for event in transcript.events)
    fold.finish(
        decoded.frames[-1] if decoded.frames else None,
        transport_closed=transport_closed,
    )
    return GameplayAnalysis(
        source=str(transcript.path),
        decoded=decoded,
        state=fold.state,
        observations=observations,
        events=tuple(fold.events),
        transport_closed=transport_closed,
        issues=tuple(fold.issues),
        warnings=tuple(fold.warnings),
    )


def derive_mob_movement_acknowledgement_policy(
    transcript: Transcript,
) -> MobMovementAcknowledgementPolicy:
    """Derive only acknowledgement behavior proven by a validated capture."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    state = analysis.state
    if state.matched_movement_acknowledgements == 0:
        raise ValueError(
            "world transcript has no correlated mob movement acknowledgements"
        )
    if (
        state.movement_acknowledgement_flag_matches
        != state.matched_movement_acknowledgements
    ):
        raise ValueError(
            "movement acknowledgement flag rule is not exact in this capture"
        )
    if (
        state.movement_acknowledgement_zero_auxiliary_pairs
        != state.matched_movement_acknowledgements
    ):
        raise ValueError(
            "movement acknowledgement auxiliary bytes are not uniformly zero"
        )
    ambiguous_templates = {
        template_id: sorted(status_values)
        for template_id, status_values in (
            state.movement_acknowledgement_values_by_template.items()
        )
        if len(status_values) != 1
    }
    if ambiguous_templates:
        raise ValueError(
            "movement acknowledgement values are not deterministic for "
            f"templates {ambiguous_templates}"
        )
    status_values_by_template = {
        template_id: next(iter(status_values))
        for template_id, status_values in (
            state.movement_acknowledgement_values_by_template.items()
        )
    }
    if not status_values_by_template:
        raise ValueError(
            "world transcript has no acknowledgements for explicitly known "
            "mob templates"
        )
    return MobMovementAcknowledgementPolicy(
        status_values_by_template=status_values_by_template,
        observations_by_template=dict(
            state.movement_acknowledgements_by_template
        ),
        known_mob_templates=dict(state.mob_templates),
        active_known_mob_count=sum(
            object_id in state.mob_templates for object_id in state.mobs
        ),
        field_epoch=state.field_epoch,
        matched_pairs=state.matched_movement_acknowledgements,
        known_template_pairs=(
            state.movement_acknowledgements_with_known_template
        ),
        unknown_template_pairs=(
            state.movement_acknowledgements_with_unknown_template
        ),
        flag_rule_matches=state.movement_acknowledgement_flag_matches,
        zero_auxiliary_pairs=(
            state.movement_acknowledgement_zero_auxiliary_pairs
        ),
        pending_submissions=state.pending_movements,
    )


def plan_initial_player_hp_rewrite(
    transcript: Transcript,
    current_hp: int,
) -> InitialPlayerHpReplayPlan:
    """Rewrite only the typed current-HP field in the initial snapshot."""
    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    observations = tuple(
        observation
        for observation in analysis.observations
        if observation.kind == "initial_field_snapshot"
    )
    if len(observations) != 1:
        raise ValueError(
            "world transcript must contain exactly one initial field snapshot"
        )
    observation = observations[0]
    snapshot = observation.parsed
    if not isinstance(snapshot, InitialFieldSnapshot):
        raise ValueError("initial field observation has no typed snapshot")
    if not 0 <= current_hp <= snapshot.character.max_hp:
        raise ValueError(
            f"rewritten current HP must be between 0 and "
            f"{snapshot.character.max_hp}"
        )
    replacement = replace(
        snapshot,
        character=replace(snapshot.character, current_hp=current_hp),
    )
    replacement_payload = replacement.to_bytes()
    if len(replacement_payload) != observation.length:
        raise ValueError("initial HP rewrite unexpectedly changed packet length")
    if InitialFieldSnapshot.parse(replacement_payload) != replacement:
        raise ValueError("initial HP rewrite failed packet round-trip validation")
    return InitialPlayerHpReplayPlan(
        server_frame_index=observation.direction_index,
        original_current_hp=snapshot.character.current_hp,
        rewritten_current_hp=current_hp,
        max_hp=snapshot.character.max_hp,
        replacement=replacement,
    )


def plan_current_hp_stat_update(
    transcript: Transcript,
    current_hp: int,
) -> CurrentHpStatUpdateReplayPlan:
    """Generate one typed post-transcript HP update from validated evidence."""
    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    if analysis.state.current_hp is None or analysis.state.max_hp is None:
        raise ValueError("world transcript has no modeled current/max HP state")
    if not 0 <= current_hp <= analysis.state.max_hp:
        raise ValueError(
            f"emitted current HP must be between 0 and {analysis.state.max_hp}"
        )
    update = CharacterStatUpdate(
        request_flag=0,
        stat_mask=CharacterStatUpdate.CURRENT_HP,
        current_hp=current_hp,
    )
    plaintext = update.to_bytes()
    if CharacterStatUpdate.parse(plaintext) != update:
        raise ValueError("generated current-HP stat update failed round-trip")
    return CurrentHpStatUpdateReplayPlan(
        update=update,
        original_current_hp=analysis.state.current_hp,
        emitted_current_hp=current_hp,
        max_hp=analysis.state.max_hp,
        field_epoch=analysis.state.field_epoch,
    )


def plan_final_field_npc_state_replay(
    transcript: Transcript,
) -> NpcStateReplayPlan:
    """Select a fully modeled, known-NPC update from the final field epoch."""
    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    for observation in reversed(analysis.observations):
        if observation.kind != "npc_state_update":
            continue
        if observation.details.get("field_epoch") != analysis.state.field_epoch:
            continue
        if observation.details.get("known_entity") is not True:
            continue
        update = observation.parsed
        if not isinstance(update, NpcStateUpdate):
            continue
        if update.object_id not in analysis.state.npcs:
            continue
        entity = observation.details.get("entity")
        if not isinstance(entity, str):
            continue
        return NpcStateReplayPlan(
            update=update,
            entity=entity,
            field_epoch=analysis.state.field_epoch,
        )
    raise ValueError(
        "world transcript has no modeled known-NPC state update in its final field"
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
    movement_command_types = json.dumps(
        dict(sorted(state.movement_commands_by_type.items()))
    )
    player_movement_command_types = json.dumps(
        dict(sorted(state.player_movement_commands_by_type.items()))
    )
    remote_player_movement_command_types = json.dumps(
        dict(sorted(state.remote_player_movement_commands_by_type.items()))
    )
    player_stat_masks = json.dumps(
        {
            f"0x{mask:08x}": count
            for mask, count in sorted(state.player_stat_updates_by_mask.items())
        }
    )
    player_stat_fields = json.dumps(
        dict(sorted(state.player_stat_fields_updated.items()))
    )
    acknowledgement_template_values = json.dumps(
        {
            template_id: sorted(status_values)
            for template_id, status_values in sorted(
                state.movement_acknowledgement_values_by_template.items()
            )
        }
    )
    inventory_item_counts = json.dumps(
        {
            name: len(items)
            for name, items in state.inventory_items.items()
        },
        sort_keys=True,
    )
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
            f"field_load_stage={state.field_load_stage} "
            f"transport_closed={analysis.transport_closed}"
        ),
        (
            f"field=map_id:{state.map_id} portal_index:{state.portal_index} "
            f"current_hp:{state.current_hp} "
            f"transition_sequence:{state.transition_sequence} "
            f"initial_snapshots:{state.initial_field_snapshots} "
            f"compact_transitions:{state.compact_field_transitions}"
        ),
        (
            f"player=level:{state.character_level} job_id:{state.job_id} "
            f"hp:{state.current_hp}/{state.max_hp} "
            f"mp:{state.current_mp}/{state.max_mp} "
            f"str:{state.strength} dex:{state.dexterity} "
            f"int:{state.intelligence} luk:{state.luck} "
            f"exp:{state.experience} fame:{state.fame} mesos:{state.mesos}"
        ),
        (
            f"player_stat_updates=count:{state.player_stat_updates} "
            f"masks:{player_stat_masks} fields:{player_stat_fields} "
            f"zero_mask:{state.player_stat_zero_mask_updates}"
        ),
        (
            "inventory="
            f"counts:{inventory_item_counts} "
            f"region_bytes:{state.inventory_region_bytes} "
            f"progression_region_bytes:{state.progression_region_bytes}"
        ),
        (
            f"progression=skills:{len(state.skill_levels)} "
            f"string_properties:{len(state.string_property_code_units)} "
            f"timestamp_properties:{len(state.timestamp_property_keys)} "
            f"extended_properties:{len(state.extended_property_code_units)} "
            f"variant:{state.progression_variant}"
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
            f"mobs=active:{len(state.mobs)} entries:{state.mob_entries} "
            f"leaves:{state.mob_leaves} "
            f"controller_changes:{state.mob_controller_changes} "
            f"movement_broadcasts:{state.mob_movement_broadcasts} "
            f"broadcast_commands:{state.mob_broadcast_commands} "
            f"field_known_templates:{len(state.mob_templates)}"
        ),
        (
            f"player_movement=position:{state.player_x},{state.player_y} "
            f"submitted:{state.player_movement_submissions} "
            f"commands:{state.player_movement_commands} "
            f"command_types:{player_movement_command_types} "
            "remote_observed:"
            f"{len(state.observed_players)} "
            "remote_broadcasts:"
            f"{state.remote_player_movement_broadcasts} "
            "remote_commands:"
            f"{state.remote_player_movement_commands} "
            "remote_command_types:"
            f"{remote_player_movement_command_types}"
        ),
        (
            f"movement=submitted:{state.movement_submissions} "
            "unknown_active_mob:"
            f"{state.movement_submissions_for_unknown_mobs} "
            "unknown_template:"
            f"{state.movement_submissions_with_unknown_template} "
            f"commands:{state.movement_commands} "
            f"command_types:{movement_command_types} "
            f"acknowledged:{state.movement_acknowledgements} "
            f"matched:{state.matched_movement_acknowledgements} "
            f"unmatched:{state.unmatched_movement_acknowledgements} "
            f"pending:{state.pending_movements}"
        ),
        (
            "movement_ack_policy="
            f"flag_matches:{state.movement_acknowledgement_flag_matches} "
            f"flag_mismatches:{state.movement_acknowledgement_flag_mismatches} "
            "zero_auxiliary:"
            f"{state.movement_acknowledgement_zero_auxiliary_pairs} "
            "nonzero_auxiliary:"
            f"{state.movement_acknowledgement_nonzero_auxiliary_pairs} "
            "known_template_pairs:"
            f"{state.movement_acknowledgements_with_known_template} "
            "unknown_template_pairs:"
            f"{state.movement_acknowledgements_with_unknown_template} "
            f"template_values:{acknowledgement_template_values}"
        ),
        (
            f"heartbeats=probed:{state.heartbeat_probes} "
            f"responded:{state.heartbeat_responses} "
            f"matched:{state.matched_heartbeat_responses} "
            f"unmatched:{state.unmatched_heartbeat_responses} "
            f"pending:{state.pending_heartbeat_probes} "
            f"last_rtt_ms:{state.last_heartbeat_round_trip_ms} "
            f"max_rtt_ms:{state.max_heartbeat_round_trip_ms}"
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

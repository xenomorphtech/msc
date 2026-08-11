from __future__ import annotations

from bisect import bisect_right
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
    ClientAttackAction,
    ClientFixedOpaqueRecord,
    ClientOpcode43Envelope,
    ClientOpcode66Acknowledgement,
    ClientOpcode75EmptyRecord,
    ClientOpcode101Record,
    ClientOpcode114TextEnvelope,
    ClientOpcode122Envelope,
    ClientOpcode217RecordSet,
    ClientOpcode279TextEnvelope,
    ClientOpcode309Acknowledgement,
    ClientOpcode54AttackAction,
    ClientSkillUseRequest,
    ClientWorldExitRequest,
    ClientWorldExitStatus,
    CompactFieldTransition,
    CompactInitialProgressionSnapshot,
    FieldDropRemoval,
    FieldDropSpawn,
    FixedServerEmptyRecord,
    FixedServerI32Record,
    FixedServerOpcode11Record,
    FixedServerU16PairRecord,
    FixedServerU16Record,
    FixedServerU32PairRecord,
    FixedServerU32Record,
    FixedServerU64Record,
    FixedServerU8Record,
    FieldLoadStage,
    FieldSnapshotEnvelope,
    HeartbeatProbe,
    HeartbeatResponse,
    InitialFieldSnapshot,
    InitialCharacterContextRecord,
    InitialProgressionSnapshot,
    InitialInventoryItem,
    TypedInitialFieldSnapshot,
    VariableServerRecord,
    InventoryChangeSet,
    InventoryModification,
    ItemPickupRequest,
    ItemUseRequest,
    LifeMovementBroadcast,
    LifeMovementSubmission,
    LocalTemporaryStatSetHeader,
    MobControllerChange,
    MobEnterField,
    MobHealthPercentageUpdate,
    MobLeaveField,
    MobMovementAcknowledgement,
    MobMovementBroadcast,
    MobMovementCommand,
    MobMovementSubmission,
    MobSpawnData,
    MobTemporaryStatReset,
    MobTemporaryStatSet,
    NpcLifecycleControl,
    NpcSpawn,
    NpcStateUpdate,
    Opcode13Envelope,
    Opcode13Type1Envelope,
    PacketShapeError,
    PlayerMovementBroadcast,
    PlayerMovementPath,
    PlayerMovementSubmission,
    PickupGainNotice,
    RemotePlayerEnterField,
    RemotePlayerLeaveField,
    RemotePlayerMobValueRecord,
    ServerAttackRelay,
    ServerOpcode43Envelope,
    ServerOpcode69Record,
    ServerOpcode93Record,
    ServerOpcode94Record,
    ServerOpcode137OpaqueTailEnvelope,
    ServerOpcode169TextInstruction,
    ServerOpcode27IntegerLedger,
    ServerOpcode28TextLedger,
    ServerOpcode29TextLedger,
    ServerOpcode135BootstrapLedger,
    ServerOpcode142TextLedger,
    ServerOpcode147BoundsLedger,
    ServerOpcode148Envelope,
    ServerOpcode201Record,
    ServerOpcode205Record,
    ServerOpcode239Envelope,
    ServerOpcode244DialogueInstruction,
    ServerOpcode272Ledger,
    ServerOpcode276BooleanFlag,
    ServerOpcode320PositionedEffectRecord,
    ServerOpcode322PositionedEffectRecord,
    ServerOpcode323PositionedEffectRecord,
    ServerOpcode348TextEnvelope,
    ServerOpcode394TextEnvelope,
    ServerOpcode379Record,
    ServerOpcode425ValueLedger,
    ServerOpcode49Envelope,
    ServerOpcode77Envelope,
    ServerOpcode426Notification,
    ServerU32OpaqueTailEnvelope,
    SkillLevelChangeRequest,
    SkillRecordUpdate,
    SkillRecordUpdateAcknowledgement,
    TutorialUiInstruction,
    WorldBootstrapAcknowledgement,
    WorldEntryRequest,
    WorldSessionTermination,
)
from .transcript import Transcript


# Version-specific info/maxHP values extracted from the official client's WZJS
# mob bundle.  The table is intentionally limited to templates attacked in the
# two repository reference captures; unknown templates remain unpredicted.
REFERENCE_MOB_MAX_HP: dict[int, int] = {
    100_100: 8,
    100_101: 15,
    120_100: 20,
    130_100: 40,
    130_101: 40,
    210_100: 50,
    1_110_100: 250,
    1_130_100: 300,
    1_210_100: 75,
    1_210_102: 80,
    9_300_018: 8,
}


def mob_hp_bounds_for_percentage(
    max_hp: int, health_percentage: int
) -> tuple[int, int]:
    """Return integer HP bounds for the observed floor-percentage byte."""

    if max_hp <= 0:
        raise ValueError("mob max HP must be positive")
    if not 0 <= health_percentage <= 100:
        raise ValueError("mob health percentage must be between 0 and 100")
    lower = (health_percentage * max_hp + 99) // 100
    upper = min(
        max_hp,
        (((health_percentage + 1) * max_hp + 99) // 100) - 1,
    )
    return lower, upper


def predict_mob_health_percentage_range(
    *, max_hp: int, previous_percentage: int, damage: int
) -> tuple[int, int]:
    """Bound the next floor-percentage byte after one submitted hit."""

    if damage < 0:
        raise ValueError("mob damage must not be negative")
    previous_min_hp, previous_max_hp = mob_hp_bounds_for_percentage(
        max_hp, previous_percentage
    )
    remaining_min_hp = max(0, previous_min_hp - damage)
    remaining_max_hp = max(0, previous_max_hp - damage)
    return (
        remaining_min_hp * 100 // max_hp,
        remaining_max_hp * 100 // max_hp,
    )


class GameplayPhase(str, Enum):
    CONNECTED = "connected"
    ENTRY_REQUESTED = "entry_requested"
    FIELD_LOADING = "field_loading"
    ACTIVE = "active"
    EXIT_REQUESTED = "exit_requested"
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
    foothold_id: int = 0
    stance: int = 0
    health_percentage: int | None = None
    max_hp: int | None = None
    health_hp_min: int | None = None
    health_hp_max: int | None = None
    client_attack_submitted_hits: int = 0
    client_attack_submitted_damage: int = 0
    client_attack_submitted_high_bit_markers: int = 0
    attack_relay_hits: int = 0
    attack_relay_damage: int = 0
    attack_relay_high_bit_markers: int = 0
    last_attack_hit_action: int | None = None
    temporary_stats: dict[int, MobTemporaryStatSet] = field(
        default_factory=dict, repr=False
    )


@dataclass
class ObservedPlayerEntity:
    alias: str
    x: int | None
    y: int | None
    level: int | None = None
    name_code_units: int | None = None


@dataclass
class PositionedEffectEntity:
    alias: str
    x: int
    y: int
    last_opcode: int


@dataclass
class FieldDropEntity:
    alias: str
    spawn: FieldDropSpawn = field(repr=False)


@dataclass(frozen=True)
class InventoryItemEntity:
    slot: int
    record_type: int
    item_id: int
    cash_item: bool
    expires_at_ticks: int
    quantity: int | None

    @classmethod
    def from_initial(
        cls, item: InitialInventoryItem
    ) -> "InventoryItemEntity":
        return cls(
            slot=item.slot,
            record_type=item.record_type,
            item_id=item.item_id,
            cash_item=item.cash_item,
            expires_at_ticks=item.expires_at_ticks,
            quantity=item.quantity,
        )


CAPTURED_ITEM_USE_EFFECTS: dict[int, tuple[str, str, int]] = {
    2_000_000: ("current_hp", "max_hp", 50),
    2_000_014: ("current_mp", "max_mp", 80),
}

STACK_INVENTORY_TYPES = {"use": 2, "setup": 3, "etc": 4}


@dataclass
class PendingItemUse:
    request_frame_index: int
    request_timestamp_ns: int
    request: ItemUseRequest
    expected_quantity: int
    effect_field: str | None
    expected_effect_value: int | None
    inventory_confirmed: bool = False


@dataclass
class PendingItemPickup:
    request_frame_index: int
    request_timestamp_ns: int
    request: ItemPickupRequest
    expected_drop_kind: str | None
    expected_value: int | None
    effect: dict[str, object] | None = None
    result_confirmed: bool = False


@dataclass(frozen=True)
class PendingClientAttackHit:
    request_frame_index: int
    request_timestamp_ns: int
    hit_index: int
    damage_values: tuple[int, ...]
    high_bit_markers: tuple[bool, ...]
    attack_relay_hits_at_submission: int


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
    inventory_items: dict[str, tuple[InventoryItemEntity, ...]] = field(
        default_factory=dict, repr=False
    )
    skill_levels: dict[int, int] = field(default_factory=dict, repr=False)
    skill_level_change_requests: int = 0
    skill_level_change_requests_by_skill_id: Counter[int] = field(
        default_factory=Counter
    )
    skill_record_updates: int = 0
    skill_record_update_records: int = 0
    skill_record_updates_by_flags: Counter[str] = field(
        default_factory=Counter
    )
    skill_record_auxiliary_values: Counter[int] = field(
        default_factory=Counter
    )
    skill_record_trailing_values: Counter[int] = field(
        default_factory=Counter
    )
    skill_record_request_matches: int = 0
    skill_record_request_mismatches: int = 0
    skill_record_updates_without_request: int = 0
    pending_skill_level_change_requests: int = 0
    last_skill_record_response_ms: float | None = None
    max_skill_record_response_ms: float | None = None
    skill_record_update_acknowledgements: int = 0
    matched_skill_record_update_acknowledgements: int = 0
    unmatched_skill_record_update_acknowledgements: int = 0
    pending_skill_record_update_acknowledgements: int = 0
    skill_record_acknowledgement_control_values: Counter[int] = field(
        default_factory=Counter
    )
    skill_record_acknowledgement_trailing_values: Counter[int] = field(
        default_factory=Counter
    )
    last_skill_record_acknowledgement_ms: float | None = None
    max_skill_record_acknowledgement_ms: float | None = None
    string_property_code_units: dict[int, int] = field(
        default_factory=dict, repr=False
    )
    timestamp_property_keys: tuple[int, ...] = field(default=(), repr=False)
    saved_map_ids: tuple[int, ...] = field(default=(), repr=False)
    extended_property_code_units: dict[int, int] = field(
        default_factory=dict, repr=False
    )
    progression_variant: int | None = None
    progression_shape: str | None = None
    server_local_filetime_ticks: int | None = None
    entry_character_id: int | None = field(default=None, repr=False)
    npcs: dict[int, NpcEntity] = field(default_factory=dict, repr=False)
    mobs: dict[int, MobEntity] = field(default_factory=dict, repr=False)
    mob_templates: dict[int, int] = field(default_factory=dict, repr=False)
    observed_players: dict[int, ObservedPlayerEntity] = field(
        default_factory=dict, repr=False
    )
    field_drops: dict[int, FieldDropEntity] = field(
        default_factory=dict, repr=False
    )
    packets_by_direction: Counter[str] = field(default_factory=Counter)
    plaintext_bytes_by_direction: Counter[str] = field(default_factory=Counter)
    npc_spawns: int = 0
    npc_lifecycle_spawns: int = 0
    npc_lifecycle_removals: int = 0
    npc_lifecycle_unknown_removals: int = 0
    npc_state_updates: int = 0
    mob_entries: int = 0
    mob_leaves: int = 0
    mob_controller_changes: int = 0
    mob_movement_broadcasts: int = 0
    mob_health_percentage_updates: int = 0
    mob_health_zero_updates: int = 0
    mob_health_increases: int = 0
    mob_health_updates_for_unknown_mobs: int = 0
    mob_temporary_stat_sets: int = 0
    mob_temporary_stat_resets: int = 0
    mob_temporary_stat_sets_for_known_mobs: int = 0
    mob_temporary_stat_sets_for_unknown_mobs: int = 0
    mob_temporary_stat_resets_for_known_mobs: int = 0
    mob_temporary_stat_resets_for_unknown_mobs: int = 0
    mob_temporary_stat_set_refreshes: int = 0
    mob_temporary_stat_resets_with_modeled_set: int = 0
    mob_temporary_stat_resets_without_modeled_set: int = 0
    mob_temporary_stat_attack_relay_matches: int = 0
    mob_temporary_stats_cleared_on_leave: int = 0
    mob_temporary_stats_cleared_on_field_change: int = 0
    mob_temporary_stat_mask_patterns: Counter[str] = field(
        default_factory=Counter
    )
    mob_temporary_stat_source_skills: Counter[int] = field(
        default_factory=Counter
    )
    mob_temporary_stat_source_levels: Counter[int] = field(
        default_factory=Counter
    )
    mob_temporary_stat_duration_values: Counter[int] = field(
        default_factory=Counter
    )
    mob_temporary_stat_set_flags: Counter[int] = field(
        default_factory=Counter
    )
    mob_temporary_stat_reset_flags: Counter[int] = field(
        default_factory=Counter
    )
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
    remote_player_movement_broadcasts_for_known_players: int = 0
    remote_player_movement_broadcasts_for_unknown_players: int = 0
    remote_player_entries: int = 0
    remote_player_refreshes: int = 0
    remote_player_entry_opaque_bytes: int = 0
    remote_player_leaves: int = 0
    remote_player_unknown_leaves: int = 0
    remote_player_mob_value_records: int = 0
    remote_player_mob_values_for_known_players: int = 0
    remote_player_mob_values_for_unknown_players: int = 0
    remote_player_mob_values_with_active_template: int = 0
    remote_player_mob_values_with_inactive_template: int = 0
    remote_player_mob_values: Counter[int] = field(default_factory=Counter)
    remote_player_mob_templates: Counter[int] = field(default_factory=Counter)
    remote_player_mob_value_flags: Counter[int] = field(default_factory=Counter)
    life_movement_submissions: int = 0
    life_movement_submission_commands: int = 0
    life_movement_submission_commands_by_type: Counter[int] = field(
        default_factory=Counter
    )
    life_movement_tail_types: Counter[int] = field(default_factory=Counter)
    life_movement_tail_markers: Counter[int] = field(default_factory=Counter)
    life_movement_broadcasts: int = 0
    life_movement_broadcast_commands: int = 0
    life_movement_broadcast_commands_by_type: Counter[int] = field(
        default_factory=Counter
    )
    life_movement_broadcasts_for_known_players: int = 0
    life_movement_broadcasts_for_unknown_players: int = 0
    player_stat_updates: int = 0
    player_stat_updates_by_mask: Counter[int] = field(default_factory=Counter)
    player_stat_fields_updated: Counter[str] = field(default_factory=Counter)
    player_stat_request_flags: Counter[int] = field(default_factory=Counter)
    player_stat_zero_mask_updates: int = 0
    inventory_change_packets: int = 0
    inventory_modifications: int = 0
    inventory_modifications_by_operation: Counter[str] = field(
        default_factory=Counter
    )
    inventory_update_flags: Counter[int] = field(default_factory=Counter)
    inventory_empty_change_packets: int = 0
    inventory_unknown_slot_modifications: int = 0
    item_use_requests: int = 0
    item_use_requests_by_item: Counter[int] = field(default_factory=Counter)
    item_use_unknown_slots: int = 0
    item_use_item_mismatches: int = 0
    item_use_inventory_matches: int = 0
    item_use_inventory_mismatches: int = 0
    item_use_effect_matches: int = 0
    item_use_effect_mismatches: int = 0
    item_use_policy_rejections: int = 0
    pending_item_uses: int = 0
    item_pickup_requests: int = 0
    item_pickup_base_requests: int = 0
    item_pickup_extended_requests: int = 0
    item_pickup_field_epoch_matches: int = 0
    item_pickup_field_epoch_mismatches: int = 0
    item_pickup_results: int = 0
    item_pickup_results_by_kind: Counter[str] = field(default_factory=Counter)
    item_pickup_effect_matches: int = 0
    item_pickup_effect_mismatches: int = 0
    item_pickup_inferred_mesos_baselines: int = 0
    item_pickup_removal_matches: int = 0
    item_pickup_removal_mismatches: int = 0
    item_pickup_policy_rejections: int = 0
    pending_item_pickups: int = 0
    item_pickup_known_drops: int = 0
    item_pickup_unknown_drops: int = 0
    item_pickup_spawn_result_matches: int = 0
    item_pickup_spawn_result_mismatches: int = 0
    item_pickup_item_effects_by_template: dict[
        int, set[tuple[str, int]]
    ] = field(default_factory=dict, repr=False)
    field_drop_spawn_packets: int = 0
    field_drop_spawns: int = 0
    field_drop_refreshes: int = 0
    field_drop_refresh_mismatches: int = 0
    field_drop_spawns_by_mode: Counter[int] = field(default_factory=Counter)
    field_drop_spawns_by_kind: Counter[str] = field(default_factory=Counter)
    field_drop_spawns_with_known_source_mob: int = 0
    field_drop_spawns_with_unknown_source_mob: int = 0
    field_drop_removals: int = 0
    field_drop_removals_by_reason: Counter[int] = field(default_factory=Counter)
    field_drop_removals_for_known_drop: int = 0
    field_drop_removals_for_unknown_drop: int = 0
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
    opcode_426_notifications: int = 0
    opcode_309_acknowledgements: int = 0
    matched_opcode_309_acknowledgements: int = 0
    unmatched_opcode_309_acknowledgements: int = 0
    pending_opcode_426_notifications: int = 0
    last_opcode_426_round_trip_ms: float | None = None
    max_opcode_426_round_trip_ms: float | None = None
    client_attack_actions: int = 0
    client_attack_actions_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    client_attack_shapes: Counter[str] = field(default_factory=Counter)
    client_attack_targeted_actions: int = 0
    client_attack_untargeted_actions: int = 0
    client_attack_targets_for_active_mobs: int = 0
    client_attack_targets_for_known_mobs: int = 0
    client_attack_targets_for_unknown_mobs: int = 0
    client_attack_damage_actions: int = 0
    client_attack_damage_entries: int = 0
    client_attack_damage_total: int = 0
    client_attack_damage_min: int | None = None
    client_attack_damage_max: int | None = None
    client_attack_damage_high_bit_markers: int = 0
    client_attack_zero_damage_entries: int = 0
    client_attack_health_matches: int = 0
    client_attack_health_predictions: int = 0
    client_attack_health_prediction_matches: int = 0
    client_attack_health_prediction_mismatches: int = 0
    client_attack_health_one_hp_differences: int = 0
    client_attack_predictions_with_relay_hits: int = 0
    client_attack_mismatches_without_relays: int = 0
    client_attack_health_mismatch_damage_deltas: Counter[int] = field(
        default_factory=Counter
    )
    client_attack_health_predictions_by_template: Counter[int] = field(
        default_factory=Counter
    )
    client_attack_effects_cleared: int = 0
    pending_client_attack_effects: int = 0
    last_client_attack_health_response_ms: float | None = None
    max_client_attack_health_response_ms: float | None = None
    server_attack_relays: int = 0
    server_attack_relays_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    server_attack_target_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_attack_hit_counts: Counter[int] = field(default_factory=Counter)
    server_attack_relays_for_known_players: int = 0
    server_attack_relays_for_unknown_players: int = 0
    server_melee_attack_relays: int = 0
    server_melee_attack_short_zero_target_forms: int = 0
    server_melee_attack_tags: Counter[int] = field(default_factory=Counter)
    server_melee_attack_skill_levels: Counter[int] = field(
        default_factory=Counter
    )
    server_melee_attack_unknown_values: Counter[int] = field(
        default_factory=Counter
    )
    server_melee_attack_displays: Counter[int] = field(
        default_factory=Counter
    )
    server_melee_attack_facing_flags: Counter[int] = field(
        default_factory=Counter
    )
    server_melee_attack_speeds: Counter[int] = field(
        default_factory=Counter
    )
    server_melee_attack_mastery_values: Counter[int] = field(
        default_factory=Counter
    )
    server_melee_attack_auxiliary_values: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_relays: int = 0
    server_ranged_attack_tags: Counter[int] = field(default_factory=Counter)
    server_ranged_attack_skill_levels: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_skill_ids: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_unknown_values: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_displays: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_facing_flags: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_speeds: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_mastery_values: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_projectile_ids: Counter[int] = field(
        default_factory=Counter
    )
    server_ranged_attack_positions_for_known_players: int = 0
    server_ranged_attack_position_delta_x_min: int | None = None
    server_ranged_attack_position_delta_x_max: int | None = None
    server_ranged_attack_position_delta_y_min: int | None = None
    server_ranged_attack_position_delta_y_max: int | None = None
    server_attack_target_records: int = 0
    server_attack_zero_object_targets: int = 0
    server_attack_targets_for_active_mobs: int = 0
    server_attack_targets_for_known_mobs: int = 0
    server_attack_targets_for_unknown_mobs: int = 0
    server_attack_hit_actions: Counter[int] = field(default_factory=Counter)
    server_attack_damage_entries: int = 0
    server_attack_damage_total: int = 0
    server_attack_damage_min: int | None = None
    server_attack_damage_max: int | None = None
    server_attack_damage_high_bit_markers: int = 0
    client_opcode_101_packets: int = 0
    client_opcode_101_header_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_101_primary_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_101_flag_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_101_secondary_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_101_tail_values: Counter[int] = field(
        default_factory=Counter
    )
    client_skill_use_requests: int = 0
    client_skill_use_requests_by_skill_id: Counter[int] = field(
        default_factory=Counter
    )
    client_skill_use_level_values: Counter[int] = field(
        default_factory=Counter
    )
    client_skill_use_trailing_values: Counter[int] = field(
        default_factory=Counter
    )
    client_skill_use_known_skills: int = 0
    client_skill_use_unknown_skills: int = 0
    client_skill_use_level_matches: int = 0
    client_skill_use_level_mismatches: int = 0
    client_skill_use_binding_matches: int = 0
    client_skill_use_binding_mismatches: int = 0
    last_client_skill_tick: int | None = None
    client_skill_tick_decreases: int = 0
    local_temporary_stat_sets: int = 0
    local_temporary_stat_zero_masks: int = 0
    local_temporary_stat_nonzero_masks: int = 0
    local_temporary_stat_enabled_bits: int = 0
    local_temporary_stat_mask_patterns: Counter[str] = field(
        default_factory=Counter
    )
    local_temporary_stat_zero_flag_a_values: Counter[int] = field(
        default_factory=Counter
    )
    local_temporary_stat_zero_flag_b_values: Counter[int] = field(
        default_factory=Counter
    )
    local_temporary_stat_zero_trailing_i16_values: Counter[int] = field(
        default_factory=Counter
    )
    local_temporary_stat_opaque_bytes: int = 0
    server_opcode_49_packets: int = 0
    server_opcode_49_by_variant: Counter[int] = field(default_factory=Counter)
    server_opcode_49_by_shape: Counter[str] = field(default_factory=Counter)
    server_opcode_49_text_fields: int = 0
    server_opcode_49_text_code_units: int = 0
    server_opcode_49_opaque_bytes: int = 0
    server_opcode_77_packets: int = 0
    server_opcode_77_by_variant: Counter[int] = field(default_factory=Counter)
    server_opcode_77_text_fields: int = 0
    server_opcode_77_text_code_units: int = 0
    server_opcode_77_opaque_bytes: int = 0
    server_opcode_77_control_patterns: Counter[str] = field(
        default_factory=Counter
    )
    server_opcode_77_terminal_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_13_messages: int = 0
    client_opcode_13_messages_by_type: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_13_opaque_bytes: int = 0
    client_opcode_13_opaque_lengths: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_13_messages: int = 0
    server_opcode_13_messages_by_type: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_13_opaque_bytes: int = 0
    server_opcode_13_opaque_lengths: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_43_packets: int = 0
    client_opcode_43_sequences: Counter[int] = field(default_factory=Counter)
    client_opcode_43_variants: Counter[str] = field(default_factory=Counter)
    client_opcode_43_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_43_opaque_bytes: int = 0
    server_opcode_43_packets: int = 0
    server_opcode_43_message_types: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_43_opaque_bytes: int = 0
    client_opcode_114_packets: int = 0
    client_opcode_114_control_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_114_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_114_redacted_values: int = 0
    client_opcode_122_packets: int = 0
    client_opcode_122_selectors: Counter[int] = field(default_factory=Counter)
    client_opcode_122_shapes: Counter[str] = field(default_factory=Counter)
    client_opcode_122_terminal_sentinels: int = 0
    client_opcode_217_packets: int = 0
    client_opcode_217_compact_packets: int = 0
    client_opcode_217_record_sets: int = 0
    client_opcode_217_records: int = 0
    client_opcode_217_records_by_format: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_217_record_counts: Counter[int] = field(
        default_factory=Counter
    )
    bootstrap_acknowledgements: int = 0
    neutral_server_records: int = 0
    neutral_server_records_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    neutral_server_typed_values: int = 0
    neutral_server_opaque_bytes: int = 0
    tutorial_ui_instructions: int = 0
    tutorial_ui_text_code_units: Counter[int] = field(default_factory=Counter)
    tutorial_ui_value_1: Counter[int] = field(default_factory=Counter)
    tutorial_ui_value_2: Counter[int] = field(default_factory=Counter)
    tutorial_ui_control_values: Counter[int] = field(default_factory=Counter)
    tutorial_ui_extended_instructions: int = 0
    server_opcode_239_packets: int = 0
    server_opcode_239_selectors: Counter[int] = field(default_factory=Counter)
    server_opcode_239_records: int = 0
    server_opcode_239_record_values: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_239_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_239_trailing_values: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_27_packets: int = 0
    server_opcode_27_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_27_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_28_packets: int = 0
    server_opcode_28_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_28_text_1_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_28_text_2_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_29_packets: int = 0
    server_opcode_29_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_29_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_packets: int = 0
    server_opcode_135_section_a_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_section_a_enabled_count: int = 0
    server_opcode_135_section_a_value_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_section_b_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_section_b_enabled_count: int = 0
    server_opcode_135_section_b_pair_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_section_c_pair_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_section_d_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_section_d_group_1_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_135_section_d_group_2_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_142_packets: int = 0
    server_opcode_142_enabled_packets: int = 0
    server_opcode_142_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_142_header_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_142_entry_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_142_flag_1_true_count: int = 0
    server_opcode_142_flag_2_true_count: int = 0
    server_opcode_147_packets: int = 0
    server_opcode_147_value_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_147_rectangle_shapes: Counter[str] = field(
        default_factory=Counter
    )
    server_opcode_272_packets: int = 0
    server_opcode_272_entry_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_272_group_1_count: int = 0
    server_opcode_272_group_2_count: int = 0
    server_opcode_272_flag_1_true_count: int = 0
    server_opcode_272_flag_2_true_count: int = 0
    server_opcode_272_trailer_values: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_425_packets: int = 0
    server_opcode_425_value_counts: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_425_trailer_shapes: Counter[str] = field(
        default_factory=Counter
    )
    instructional_dialogue_requests: int = 0
    instructional_dialogue_value_1: Counter[int] = field(default_factory=Counter)
    instructional_dialogue_value_2: Counter[int] = field(default_factory=Counter)
    instructional_dialogue_value_3: Counter[int] = field(default_factory=Counter)
    positioned_effect_entities: dict[int, PositionedEffectEntity] = field(
        default_factory=dict, repr=False
    )
    positioned_effect_records: int = 0
    positioned_effect_records_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    positioned_effect_new_entities: int = 0
    positioned_effect_updates: int = 0
    positioned_effect_unknown_updates: int = 0
    positioned_effect_control_values: Counter[str] = field(
        default_factory=Counter
    )
    server_opcode_169_packets: int = 0
    server_opcode_169_selectors: Counter[int] = field(default_factory=Counter)
    server_opcode_169_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_348_packets: int = 0
    server_opcode_348_categories: Counter[int] = field(default_factory=Counter)
    server_opcode_348_selectors: Counter[int] = field(default_factory=Counter)
    server_opcode_348_values: Counter[int] = field(default_factory=Counter)
    server_opcode_348_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    server_opcode_348_control_pairs: Counter[str] = field(
        default_factory=Counter
    )
    server_opcode_394_packets: int = 0
    server_opcode_394_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_279_text_packets: int = 0
    client_opcode_279_control_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_279_text_code_units: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_279_changed_code_unit_counts: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_279_changed_span_shapes: Counter[str] = field(
        default_factory=Counter
    )
    correlated_client_opcode_279_packets: int = 0
    uncorrelated_client_opcode_279_packets: int = 0
    client_opcode_279_transform_matches: int = 0
    client_opcode_279_transform_mismatches: int = 0
    pending_server_opcode_394_envelopes: int = 0
    last_opcode_394_279_gap_ms: float | None = None
    max_opcode_394_279_gap_ms: float | None = None
    client_opcode_66_acknowledgements: int = 0
    client_opcode_66_selectors: Counter[int] = field(default_factory=Counter)
    client_opcode_66_status_values: Counter[int] = field(
        default_factory=Counter
    )
    client_opcode_66_shapes: Counter[str] = field(default_factory=Counter)
    client_opcode_66_optional_values: int = 0
    matched_client_opcode_66_acknowledgements: int = 0
    unmatched_client_opcode_66_acknowledgements: int = 0
    pending_server_opcode_348_requests: int = 0
    last_opcode_348_round_trip_ms: float | None = None
    max_opcode_348_round_trip_ms: float | None = None
    fixed_server_records: int = 0
    fixed_server_records_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    initial_character_contexts: int = 0
    variable_server_records: int = 0
    variable_server_records_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    variable_server_variants: Counter[str] = field(default_factory=Counter)
    variable_server_typed_entries: int = 0
    variable_server_typed_values: int = 0
    variable_server_opaque_bytes: int = 0
    keyboard_binding_snapshots: int = 0
    keyboard_binding_selector_counts: Counter[int] = field(
        default_factory=Counter
    )
    keyboard_skill_bindings: dict[int, int] = field(
        default_factory=dict, repr=False
    )
    keyboard_known_skill_bindings: int = 0
    left_ctrl_skill_id: int | None = None
    left_ctrl_skill_known: bool = False
    pending_movements: int = 0
    client_opcode_75_empty_records: int = 0
    client_fixed_opaque_records_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    client_fixed_opaque_bytes_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    client_periodic_report_last_interval_ms: dict[int, float] = field(
        default_factory=dict
    )
    client_periodic_report_min_interval_ms: dict[int, float] = field(
        default_factory=dict
    )
    client_periodic_report_max_interval_ms: dict[int, float] = field(
        default_factory=dict
    )
    world_exit_requests: int = 0
    world_exit_requests_from_active_phase: int = 0
    world_exit_status_packets: int = 0
    world_exit_status_packets_by_opcode: Counter[int] = field(
        default_factory=Counter
    )
    matched_world_exit_terminations: int = 0
    pending_world_exit_requests: int = 0
    last_world_exit_round_trip_ms: float | None = None
    max_world_exit_round_trip_ms: float | None = None
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
class NpcSpawnReplayFrame:
    server_frame_index: int
    entity: str
    field_epoch: int
    spawn: NpcSpawn = field(repr=False)

    def safe_dict(self) -> dict[str, object]:
        return {
            "server_frame_index": self.server_frame_index,
            "entity": self.entity,
            "field_epoch": self.field_epoch,
            "template_id": self.spawn.template_id,
            "x": self.spawn.x,
            "cy": self.spawn.cy,
            "facing_value": self.spawn.facing_value,
            "foothold_id": self.spawn.foothold_id,
            "range_left": self.spawn.range_left,
            "range_right": self.spawn.range_right,
            "hidden": self.spawn.hidden,
        }


@dataclass(frozen=True)
class FieldNpcSpawnReplayPlan:
    frames: tuple[NpcSpawnReplayFrame, ...]

    def safe_dict(self) -> dict[str, object]:
        return {
            "emitter": "typed_npc_spawn",
            "frame_count": len(self.frames),
            "field_epochs": sorted(
                {frame.field_epoch for frame in self.frames}
            ),
            "spawns": [frame.safe_dict() for frame in self.frames],
            "prediction": {
                "npc_spawn_events": len(self.frames),
                "active_npc_state": "capture_equivalent",
                "phase": "unchanged",
            },
        }


FixedServerRecord = (
    FixedServerEmptyRecord
    | FixedServerI32Record
    | FixedServerOpcode11Record
    | FixedServerU16PairRecord
    | FixedServerU16Record
    | FixedServerU32PairRecord
    | FixedServerU32Record
    | FixedServerU64Record
    | FixedServerU8Record
    | InitialCharacterContextRecord
)

NeutralServerRecord = (
    ServerOpcode69Record
    | ServerOpcode93Record
    | ServerOpcode94Record
    | ServerOpcode137OpaqueTailEnvelope
    | ServerOpcode148Envelope
    | ServerOpcode201Record
    | ServerOpcode205Record
    | ServerOpcode276BooleanFlag
    | ServerOpcode379Record
    | ServerU32OpaqueTailEnvelope
)

FIXED_SERVER_OPCODES = frozenset({11, 59}).union(
    FixedServerEmptyRecord.SUPPORTED_OPCODES,
    FixedServerU8Record.SUPPORTED_OPCODES,
    FixedServerU16Record.SUPPORTED_OPCODES,
    FixedServerU16PairRecord.SUPPORTED_OPCODES,
    FixedServerI32Record.SUPPORTED_OPCODES,
    FixedServerU32Record.SUPPORTED_OPCODES,
    FixedServerU32PairRecord.SUPPORTED_OPCODES,
    FixedServerU64Record.SUPPORTED_OPCODES,
)


@dataclass(frozen=True)
class FixedServerReplayFrame:
    server_frame_index: int
    record: FixedServerRecord = field(repr=False)
    kind: str
    details: tuple[tuple[str, object], ...]

    def safe_dict(self) -> dict[str, object]:
        return {
            "server_frame_index": self.server_frame_index,
            "opcode": self.record.opcode,
            "kind": self.kind,
            **dict(self.details),
        }


@dataclass(frozen=True)
class FixedServerReplayPlan:
    frames: tuple[FixedServerReplayFrame, ...]

    def safe_dict(self) -> dict[str, object]:
        return {
            "emitter": "typed_fixed_server_record",
            "frame_count": len(self.frames),
            "opcodes": [frame.record.opcode for frame in self.frames],
            "frames": [frame.safe_dict() for frame in self.frames],
            "prediction": {
                "fixed_server_record_events": len(self.frames),
                "player_state": "unchanged",
                "phase": "unchanged",
            },
        }


@dataclass(frozen=True)
class VariableServerReplayFrame:
    server_frame_index: int
    record: VariableServerRecord = field(repr=False)
    field_epoch: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "server_frame_index": self.server_frame_index,
            "opcode": self.record.opcode,
            "variant": self.record.variant,
            "opaque_tail_length": len(self.record.opaque_tail),
            "entry_count": len(self.record.entries),
            "text_code_units": (
                len(self.record.text.encode("utf-16le")) // 2
                if self.record.text is not None
                else 0
            ),
            "flag": self.record.flag,
            "value_count": len(self.record.values),
            "nonzero_keyboard_selector_count": (
                self.record.nonzero_keyboard_selector_count
            ),
            "skill_binding_count": len(
                self.record.keyboard_skill_bindings
            ),
            "left_ctrl_skill_id": self.record.left_ctrl_skill_id,
            "compact": (
                bool(self.record.variant)
                if self.record.opcode == 385
                else None
            ),
            "field_epoch": self.field_epoch,
        }


@dataclass(frozen=True)
class VariableServerReplayPlan:
    frames: tuple[VariableServerReplayFrame, ...]

    def safe_dict(self) -> dict[str, object]:
        return {
            "emitter": "typed_variable_server_record",
            "frame_count": len(self.frames),
            "frames": [frame.safe_dict() for frame in self.frames],
            "prediction": {
                "variable_server_record_events": len(self.frames),
                "typed_entry_count": sum(
                    len(frame.record.entries) for frame in self.frames
                ),
                "typed_value_count": sum(
                    len(frame.record.values) for frame in self.frames
                ),
                "keyboard_binding_snapshots": sum(
                    frame.record.opcode == 385 and not frame.record.variant
                    for frame in self.frames
                ),
                "final_left_ctrl_skill_id": next(
                    (
                        frame.record.left_ctrl_skill_id
                        for frame in reversed(self.frames)
                        if frame.record.opcode == 385
                        and not frame.record.variant
                    ),
                    None,
                ),
                "opaque_byte_count": sum(
                    len(frame.record.opaque_tail) for frame in self.frames
                ),
                "player_state": "unchanged",
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
    typed_state: TypedInitialFieldSnapshot = field(repr=False)

    def safe_dict(self) -> dict[str, object]:
        return {
            "server_frame_index": self.server_frame_index,
            "original_current_hp": self.original_current_hp,
            "rewritten_current_hp": self.rewritten_current_hp,
            "max_hp": self.max_hp,
            "emitter": "typed_initial_field_snapshot",
            "inventory_group_count": len(self.typed_state.inventory_groups),
            "inventory_item_count": self.typed_state.inventory_item_count,
            "skill_level_count": len(
                self.typed_state.progression.skill_levels
            ),
            "progression_shape": (
                "compact"
                if self.typed_state.marker == 26
                else "keyed_properties"
            ),
            "progression_variant": getattr(
                self.typed_state.progression, "variant", None
            ),
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
class FinalFieldDropPositionReplayPlan:
    server_frame_index: int
    drop_alias: str
    item_id: int
    original_position_x: int
    original_position_y: int
    rewritten_position_x: int
    rewritten_position_y: int
    field_epoch: int
    replacement: FieldDropSpawn = field(repr=False)

    def safe_dict(self) -> dict[str, object]:
        return {
            "server_frame_index": self.server_frame_index,
            "drop": self.drop_alias,
            "item_id": self.item_id,
            "original_position": {
                "x": self.original_position_x,
                "y": self.original_position_y,
            },
            "rewritten_position": {
                "x": self.rewritten_position_x,
                "y": self.rewritten_position_y,
            },
            "field_epoch": self.field_epoch,
            "prediction": {
                "active_field_drop_count_delta": 0,
                "drop_template": "unchanged",
                "drop_ownership": "unchanged",
                "drop_position": "rewritten",
                "inventory": "unchanged",
                "player_position": "unchanged",
                "phase": "unchanged",
            },
        }


@dataclass(frozen=True)
class FinalFieldDropOwnerReplayPlan:
    server_frame_index: int
    drop_alias: str
    item_id: int
    ownership_flag: int
    field_epoch: int
    replacement: FieldDropSpawn = field(repr=False)

    def safe_dict(self) -> dict[str, object]:
        return {
            "server_frame_index": self.server_frame_index,
            "drop": self.drop_alias,
            "item_id": self.item_id,
            "ownership_flag": self.ownership_flag,
            "field_epoch": self.field_epoch,
            "character_identifiers": "redacted",
            "prediction": {
                "active_field_drop_count_delta": 0,
                "drop_template": "unchanged",
                "drop_owner_fields": "match_initial_player",
                "drop_position": "unchanged",
                "inventory": "unchanged_until_pickup",
                "pickup_eligibility": "requires_additional_client_conditions",
                "player_identity": "unchanged",
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
class InventoryQuantityUpdateReplayPlan:
    update: InventoryChangeSet = field(repr=False)
    inventory: str
    slot: int
    item_id: int
    original_quantity: int
    emitted_quantity: int
    field_epoch: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "opcode": self.update.opcode,
            "update_flag": self.update.update_flag,
            "inventory": self.inventory,
            "slot": self.slot,
            "item_id": self.item_id,
            "original_quantity": self.original_quantity,
            "emitted_quantity": self.emitted_quantity,
            "field_epoch": self.field_epoch,
            "prediction": {
                "quantity": self.emitted_quantity,
                "inventory_change_packets_delta": 1,
                "inventory_modifications_delta": 1,
                "inventory_item_count_delta": 0,
                "events_delta": 1,
                "player_stats": "unchanged",
                "map_id": "unchanged",
                "progression": "unchanged",
                "phase": "unchanged",
            },
        }


@dataclass(frozen=True)
class ItemUseResponsePlan:
    request: ItemUseRequest
    inventory_update: InventoryChangeSet = field(repr=False)
    stat_update: CharacterStatUpdate = field(repr=False)
    quantity_before: int
    quantity_after: int
    effect_field: str
    effect_before: int
    effect_after: int
    maximum_effect_value: int

    @property
    def plaintexts(self) -> tuple[bytes, bytes]:
        return self.inventory_update.to_bytes(), self.stat_update.to_bytes()

    def safe_dict(self) -> dict[str, object]:
        return {
            **self.request.safe_dict(),
            "quantity_before": self.quantity_before,
            "quantity_after": self.quantity_after,
            "effect_field": self.effect_field,
            "effect_before": self.effect_before,
            "effect_after": self.effect_after,
            "maximum_effect_value": self.maximum_effect_value,
            "server_opcodes": [
                self.inventory_update.opcode,
                self.stat_update.opcode,
            ],
        }


@dataclass
class ItemUseResponsePolicy:
    use_items: dict[int, InventoryItemEntity] = field(repr=False)
    current_hp: int
    max_hp: int
    current_mp: int
    max_mp: int
    field_epoch: int
    source_item_use_requests: int = 0
    source_inventory_matches: int = 0
    source_effect_matches: int = 0

    def safe_dict(self) -> dict[str, object]:
        return {
            "field_epoch": self.field_epoch,
            "modeled_items": [
                {
                    "item_id": item.item_id,
                    "slot": item.slot,
                    "quantity": item.quantity,
                    "effect_field": CAPTURED_ITEM_USE_EFFECTS.get(
                        item.item_id, (None, None, None)
                    )[0],
                    "effect_amount": CAPTURED_ITEM_USE_EFFECTS.get(
                        item.item_id, (None, None, None)
                    )[2],
                }
                for item in sorted(
                    self.use_items.values(), key=lambda candidate: candidate.slot
                )
                if item.item_id in CAPTURED_ITEM_USE_EFFECTS
            ],
            "current_hp": self.current_hp,
            "max_hp": self.max_hp,
            "current_mp": self.current_mp,
            "max_mp": self.max_mp,
            "source_evidence": {
                "requests": self.source_item_use_requests,
                "inventory_matches": self.source_inventory_matches,
                "effect_matches": self.source_effect_matches,
            },
            "prediction": {
                "inventory_quantity_delta": -1,
                "server_opcodes": [39, 41],
                "stat_effect": "captured_item_template_with_maximum_cap",
            },
        }

    def apply_server_packet(self, plaintext: bytes) -> None:
        if len(plaintext) < 2:
            return
        opcode = int.from_bytes(plaintext[:2], "little")
        if opcode == 39:
            change_set = InventoryChangeSet.parse(plaintext)
            for modification in change_set.modifications:
                if modification.inventory_type != 2:
                    continue
                if modification.operation == InventoryModification.ADD:
                    if modification.item is None:
                        raise PacketShapeError(
                            "item-use policy saw add without an item"
                        )
                    self.use_items[modification.slot] = (
                        InventoryItemEntity.from_initial(modification.item)
                    )
                elif (
                    modification.operation
                    == InventoryModification.UPDATE_QUANTITY
                ):
                    item = self.use_items.get(modification.slot)
                    if item is None:
                        raise ValueError(
                            f"item-use policy has no Use slot "
                            f"{modification.slot}"
                        )
                    self.use_items[modification.slot] = replace(
                        item, quantity=modification.quantity
                    )
                elif modification.operation == InventoryModification.MOVE:
                    item = self.use_items.pop(modification.slot, None)
                    if (
                        item is not None
                        and modification.destination_slot is not None
                    ):
                        destination_item = self.use_items.pop(
                            modification.destination_slot, None
                        )
                        self.use_items[modification.destination_slot] = replace(
                            item, slot=modification.destination_slot
                        )
                        if destination_item is not None:
                            self.use_items[modification.slot] = replace(
                                destination_item, slot=modification.slot
                            )
                else:
                    self.use_items.pop(modification.slot, None)
        elif opcode == 41:
            update = CharacterStatUpdate.parse(plaintext)
            for field_name, value in update.values.items():
                if field_name in {"current_hp", "current_mp"}:
                    setattr(self, field_name, value)

    def respond(self, request: ItemUseRequest) -> ItemUseResponsePlan:
        item = self.use_items.get(request.slot)
        if item is None:
            raise ValueError(
                f"item-use request references unknown Use slot {request.slot}"
            )
        if item.item_id != request.item_id:
            raise ValueError(
                f"item-use request template {request.item_id} does not match "
                f"Use slot {request.slot} template {item.item_id}"
            )
        if item.quantity is None or item.quantity <= 0:
            raise ValueError(
                f"item-use request references empty Use slot {request.slot}"
            )
        if item.quantity == 1:
            raise ValueError(
                "item-use last-item removal response shape is not validated"
            )
        effect = CAPTURED_ITEM_USE_EFFECTS.get(request.item_id)
        if effect is None:
            raise ValueError(
                f"item-use template {request.item_id} has no validated effect"
            )
        effect_field, maximum_field, amount = effect
        effect_before = getattr(self, effect_field)
        maximum_value = getattr(self, maximum_field)
        if effect_before >= maximum_value:
            raise ValueError(
                f"item-use request cannot increase capped {effect_field}"
            )
        effect_after = min(maximum_value, effect_before + amount)
        quantity_after = item.quantity - 1
        inventory_update = InventoryChangeSet(
            update_flag=0,
            modifications=(
                InventoryModification(
                    operation=InventoryModification.UPDATE_QUANTITY,
                    inventory_type=2,
                    slot=request.slot,
                    quantity=quantity_after,
                ),
            ),
        )
        stat_mask = (
            CharacterStatUpdate.CURRENT_HP
            if effect_field == "current_hp"
            else CharacterStatUpdate.CURRENT_MP
        )
        stat_update = CharacterStatUpdate(
            request_flag=1,
            stat_mask=stat_mask,
            **{effect_field: effect_after},
        )
        plan = ItemUseResponsePlan(
            request=request,
            inventory_update=inventory_update,
            stat_update=stat_update,
            quantity_before=item.quantity,
            quantity_after=quantity_after,
            effect_field=effect_field,
            effect_before=effect_before,
            effect_after=effect_after,
            maximum_effect_value=maximum_value,
        )
        for plaintext in plan.plaintexts:
            self.apply_server_packet(plaintext)
        return plan


@dataclass(frozen=True)
class ItemPickupResponsePlan:
    request: ItemPickupRequest = field(repr=False)
    drop_alias: str
    inventory: str
    slot: int
    item_id: int
    quantity_before: int
    quantity_delta: int
    quantity_after: int
    inventory_update: InventoryChangeSet = field(repr=False)
    gain_notice: PickupGainNotice = field(repr=False)
    removal: FieldDropRemoval = field(repr=False)

    @property
    def plaintexts(self) -> tuple[bytes, bytes, bytes]:
        return (
            self.inventory_update.to_bytes(),
            self.gain_notice.to_bytes(),
            self.removal.to_bytes(),
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            **self.request.safe_dict(),
            "drop": self.drop_alias,
            "inventory": self.inventory,
            "slot": self.slot,
            "item_id": self.item_id,
            "quantity_before": self.quantity_before,
            "quantity_delta": self.quantity_delta,
            "quantity_after": self.quantity_after,
            "removal_reason": self.removal.reason,
            "server_opcodes": [
                self.inventory_update.opcode,
                self.gain_notice.opcode,
                self.removal.opcode,
            ],
        }


@dataclass
class ItemPickupResponsePolicy:
    inventory_items: dict[str, dict[int, InventoryItemEntity]] = field(
        repr=False
    )
    active_drops: dict[int, FieldDropEntity] = field(repr=False)
    validated_item_effects: dict[int, tuple[str, int]] = field(repr=False)
    field_epoch: int
    source_item_pickup_requests: int = 0
    source_spawn_result_matches: int = 0
    source_effect_matches: int = 0
    source_removal_matches: int = 0

    def _matching_stack(
        self, drop: FieldDropEntity
    ) -> tuple[str, InventoryItemEntity, int]:
        effect = self.validated_item_effects.get(drop.spawn.value)
        if effect is None:
            raise ValueError(
                f"item template {drop.spawn.value} has no deterministic "
                "captured pickup effect"
            )
        inventory, quantity_delta = effect
        matches = tuple(
            item
            for item in self.inventory_items.get(inventory, {}).values()
            if item.item_id == drop.spawn.value
        )
        if len(matches) != 1:
            raise ValueError(
                f"item template {drop.spawn.value} has {len(matches)} "
                f"matching {inventory} stacks; exactly one is required"
            )
        return inventory, matches[0], quantity_delta

    def safe_dict(self) -> dict[str, object]:
        modeled_drops: list[dict[str, object]] = []
        for entity in sorted(
            self.active_drops.values(), key=lambda candidate: candidate.alias
        ):
            try:
                inventory, item, quantity_delta = self._matching_stack(entity)
            except ValueError:
                continue
            modeled_drops.append(
                {
                    "drop": entity.alias,
                    "kind": entity.spawn.kind_name,
                    "item_id": entity.spawn.value,
                    "inventory": inventory,
                    "slot": item.slot,
                    "quantity": item.quantity,
                    "pickup_quantity": quantity_delta,
                }
            )
        return {
            "field_epoch": self.field_epoch,
            "modeled_drops": modeled_drops,
            "source_evidence": {
                "requests": self.source_item_pickup_requests,
                "spawn_result_matches": self.source_spawn_result_matches,
                "effect_matches": self.source_effect_matches,
                "removal_matches": self.source_removal_matches,
            },
            "prediction": {
                "server_opcodes": [39, 49, 312],
                "inventory_quantity_delta": "captured_template_quantity",
                "gain_notice": "captured_template_kind_and_quantity",
                "field_drop_removal_reason": 5,
                "active_field_drop_count_delta": -1,
            },
        }

    def apply_server_packet(self, plaintext: bytes) -> None:
        if len(plaintext) < 2:
            return
        if int.from_bytes(plaintext[:2], "little") != 39:
            return
        change_set = InventoryChangeSet.parse(plaintext)
        inventory_names = {
            inventory_type: name
            for name, inventory_type in STACK_INVENTORY_TYPES.items()
        }
        for modification in change_set.modifications:
            inventory = inventory_names.get(modification.inventory_type)
            if inventory is None:
                continue
            items = self.inventory_items.setdefault(inventory, {})
            if modification.operation == InventoryModification.ADD:
                if modification.item is None:
                    raise PacketShapeError(
                        "item-pickup policy saw add without an item"
                    )
                added = InventoryItemEntity.from_initial(modification.item)
                items[added.slot] = added
            elif (
                modification.operation
                == InventoryModification.UPDATE_QUANTITY
            ):
                item = items.get(modification.slot)
                if item is None:
                    raise ValueError(
                        f"item-pickup policy has no {inventory} slot "
                        f"{modification.slot}"
                    )
                items[modification.slot] = replace(
                    item, quantity=modification.quantity
                )
            elif modification.operation == InventoryModification.MOVE:
                item = items.pop(modification.slot, None)
                if (
                    item is not None
                    and modification.destination_slot is not None
                ):
                    destination_item = items.pop(
                        modification.destination_slot, None
                    )
                    items[modification.destination_slot] = replace(
                        item, slot=modification.destination_slot
                    )
                    if destination_item is not None:
                        items[modification.slot] = replace(
                            destination_item, slot=modification.slot
                        )
            else:
                items.pop(modification.slot, None)

    def respond(self, request: ItemPickupRequest) -> ItemPickupResponsePlan:
        if request.field_epoch != self.field_epoch:
            raise ValueError(
                f"item-pickup request field epoch {request.field_epoch} does "
                f"not match modeled epoch {self.field_epoch}"
            )
        drop = self.active_drops.get(request.drop_object_id)
        if drop is None:
            raise ValueError("item-pickup request references an unknown active drop")
        if drop.spawn.drop_kind != FieldDropSpawn.ITEM:
            raise ValueError("reactive mesos pickup responses are not modeled")
        if drop.spawn.owner_value_1 != drop.spawn.owner_value_2:
            raise ValueError("active drop has unequal capture-neutral owner values")
        inventory, item, quantity_delta = self._matching_stack(drop)
        if item.quantity is None:
            raise ValueError("item-pickup target stack has no quantity")
        quantity_after = item.quantity + quantity_delta
        if not 1 <= quantity_after <= 0xFFFF:
            raise ValueError("item-pickup target stack cannot accept the item")
        inventory_update = InventoryChangeSet(
            update_flag=0,
            modifications=(
                InventoryModification(
                    operation=InventoryModification.UPDATE_QUANTITY,
                    inventory_type=STACK_INVENTORY_TYPES[inventory],
                    slot=item.slot,
                    quantity=quantity_after,
                ),
            ),
        )
        gain_notice = PickupGainNotice(
            result_flag=0,
            kind=PickupGainNotice.ITEM,
            item_id=drop.spawn.value,
            quantity=quantity_delta,
        )
        removal = FieldDropRemoval(
            reason=5,
            drop_object_id=request.drop_object_id,
            actor_id=drop.spawn.owner_value_1,
            trailing_value=0,
        )
        plan = ItemPickupResponsePlan(
            request=request,
            drop_alias=drop.alias,
            inventory=inventory,
            slot=item.slot,
            item_id=item.item_id,
            quantity_before=item.quantity,
            quantity_delta=quantity_delta,
            quantity_after=quantity_after,
            inventory_update=inventory_update,
            gain_notice=gain_notice,
            removal=removal,
        )
        self.apply_server_packet(inventory_update.to_bytes())
        self.active_drops.pop(request.drop_object_id)
        return plan


@dataclass(frozen=True)
class MobMovementBroadcastPlan:
    broadcast: MobMovementBroadcast = field(repr=False)
    mode: str
    entity: str
    template_id: int
    field_epoch: int
    previous_x: int
    previous_y: int
    previous_foothold_id: int
    previous_stance: int
    target_x: int
    target_y: int
    target_foothold_id: int
    stance: int
    broadcast_evidence: int
    exact_stationary_shape_evidence: int
    source_server_frame_index: int | None
    exact_relative_motion_shape_evidence: int
    matching_displacement_path_evidence: int
    matching_displacement_shape_evidence: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "entity": self.entity,
            "template_id": self.template_id,
            "field_epoch": self.field_epoch,
            "previous": {
                "x": self.previous_x,
                "y": self.previous_y,
                "foothold_id": self.previous_foothold_id,
                "stance": self.previous_stance,
            },
            "predicted": {
                "x": self.target_x,
                "y": self.target_y,
                "foothold_id": self.target_foothold_id,
                "stance": self.stance,
            },
            "packet": {
                "opcode": self.broadcast.opcode,
                "control_prefix": self.broadcast.opaque_control.hex(),
                "reference_x": self.broadcast.reference_x,
                "reference_y": self.broadcast.reference_y,
                "command_count": len(self.broadcast.commands),
                "commands": [
                    command.safe_dict()
                    for command in self.broadcast.commands
                ],
            },
            "evidence": {
                "broadcasts": self.broadcast_evidence,
                "exact_stationary_shape": (
                    self.exact_stationary_shape_evidence
                ),
                "source_server_frame_index": (
                    self.source_server_frame_index
                ),
                "exact_relative_motion_shape": (
                    self.exact_relative_motion_shape_evidence
                ),
                "matching_displacement_paths": (
                    self.matching_displacement_path_evidence
                ),
                "matching_displacement_shapes": (
                    self.matching_displacement_shape_evidence
                ),
            },
        }


@dataclass(frozen=True)
class MobMovementBroadcastSequencePlan:
    steps: tuple[MobMovementBroadcastPlan, ...] = field(repr=False)
    max_steps: int
    usable_displacements: int
    ambiguous_displacements: int
    shortest_sequence_count: int

    @property
    def broadcasts(self) -> tuple[MobMovementBroadcast, ...]:
        return tuple(step.broadcast for step in self.steps)

    def safe_dict(self) -> dict[str, object]:
        first = self.steps[0]
        last = self.steps[-1]
        return {
            "mode": "composed_captured_path",
            "entity": first.entity,
            "template_id": first.template_id,
            "field_epoch": first.field_epoch,
            "previous": {
                "x": first.previous_x,
                "y": first.previous_y,
                "foothold_id": first.previous_foothold_id,
                "stance": first.previous_stance,
            },
            "predicted": {
                "x": last.target_x,
                "y": last.target_y,
                "foothold_id": last.target_foothold_id,
                "stance": last.stance,
            },
            "step_count": len(self.steps),
            "max_steps": self.max_steps,
            "source_server_frame_indices": [
                step.source_server_frame_index for step in self.steps
            ],
            "steps": [
                {
                    "step_index": index,
                    **step.safe_dict(),
                }
                for index, step in enumerate(self.steps, 1)
            ],
            "evidence": {
                "usable_displacements": self.usable_displacements,
                "ambiguous_displacements": self.ambiguous_displacements,
                "shortest_sequence_count": self.shortest_sequence_count,
            },
        }


@dataclass
class MobMovementBroadcastScheduler:
    """Track the sent prefix of one validated mob-movement plan."""

    steps: tuple[MobMovementBroadcastPlan, ...] = field(repr=False)
    baseline_server_frames: tuple[bytes, ...] = field(
        default=(), repr=False
    )
    packets_sent: int = field(default=0, init=False)
    current_x: int = field(init=False)
    current_y: int = field(init=False)
    current_foothold_id: int = field(init=False)
    current_stance: int = field(init=False)

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError("mob movement schedule requires at least one step")
        first = self.steps[0]
        expected_entity = first.entity
        expected_template_id = first.template_id
        expected_field_epoch = first.field_epoch
        expected_object_id = first.broadcast.object_id
        expected_state = (
            first.previous_x,
            first.previous_y,
            first.previous_foothold_id,
            first.previous_stance,
        )
        for step_index, step in enumerate(self.steps, 1):
            if (
                step.entity != expected_entity
                or step.template_id != expected_template_id
                or step.field_epoch != expected_field_epoch
                or step.broadcast.object_id != expected_object_id
            ):
                raise ValueError(
                    f"mob movement schedule step {step_index} changes entity, "
                    "template, field epoch, or object"
                )
            previous_state = (
                step.previous_x,
                step.previous_y,
                step.previous_foothold_id,
                step.previous_stance,
            )
            if previous_state != expected_state:
                raise ValueError(
                    f"mob movement schedule step {step_index} is "
                    f"discontinuous: {previous_state} != {expected_state}"
                )
            expected_state = (
                step.target_x,
                step.target_y,
                step.target_foothold_id,
                step.stance,
            )
        (
            self.current_x,
            self.current_y,
            self.current_foothold_id,
            self.current_stance,
        ) = (
            first.previous_x,
            first.previous_y,
            first.previous_foothold_id,
            first.previous_stance,
        )

    @property
    def plaintexts(self) -> tuple[bytes, ...]:
        return tuple(step.broadcast.to_bytes() for step in self.steps)

    @property
    def packets_remaining(self) -> int:
        return len(self.steps) - self.packets_sent

    @property
    def confirmed_server_frames(self) -> tuple[bytes, ...]:
        """Return only movement steps whose writes completed."""

        return tuple(
            step.broadcast.to_bytes()
            for step in self.steps[: self.packets_sent]
        )

    @property
    def planning_server_frames(self) -> tuple[bytes, ...]:
        """Return the planning baseline plus the confirmed movement prefix."""

        return self.baseline_server_frames + self.confirmed_server_frames

    def confirm_sent(self, plaintext: bytes) -> MobMovementBroadcastPlan:
        """Advance modeled state after the expected packet was drained."""

        if self.packets_sent >= len(self.steps):
            raise ValueError("mob movement schedule is already complete")
        step = self.steps[self.packets_sent]
        expected_plaintext = step.broadcast.to_bytes()
        if plaintext != expected_plaintext:
            raise ValueError(
                "sent mob movement packet does not match the next scheduled "
                f"step {self.packets_sent + 1}"
            )
        current_state = (
            self.current_x,
            self.current_y,
            self.current_foothold_id,
            self.current_stance,
        )
        expected_state = (
            step.previous_x,
            step.previous_y,
            step.previous_foothold_id,
            step.previous_stance,
        )
        if current_state != expected_state:
            raise RuntimeError(
                "mob movement scheduler state diverged from the next step: "
                f"{current_state} != {expected_state}"
            )
        self.current_x = step.target_x
        self.current_y = step.target_y
        self.current_foothold_id = step.target_foothold_id
        self.current_stance = step.stance
        self.packets_sent += 1
        return step

    @staticmethod
    def _step_safe_dict(
        step_index: int, step: MobMovementBroadcastPlan
    ) -> dict[str, object]:
        return {
            "step_index": step_index,
            "source_server_frame_index": step.source_server_frame_index,
            "previous": {
                "x": step.previous_x,
                "y": step.previous_y,
                "foothold_id": step.previous_foothold_id,
                "stance": step.previous_stance,
            },
            "predicted": {
                "x": step.target_x,
                "y": step.target_y,
                "foothold_id": step.target_foothold_id,
                "stance": step.stance,
            },
        }

    def safe_dict(self) -> dict[str, object]:
        first = self.steps[0]
        final = self.steps[-1]
        if self.packets_sent == 0:
            phase = "planned"
        elif self.packets_sent == len(self.steps):
            phase = "complete"
        else:
            phase = "in_progress"
        last_sent_step = (
            self._step_safe_dict(
                self.packets_sent,
                self.steps[self.packets_sent - 1],
            )
            if self.packets_sent
            else None
        )
        next_step = (
            self._step_safe_dict(
                self.packets_sent + 1,
                self.steps[self.packets_sent],
            )
            if self.packets_sent < len(self.steps)
            else None
        )
        return {
            "phase": phase,
            "entity": first.entity,
            "template_id": first.template_id,
            "field_epoch": first.field_epoch,
            "current": {
                "x": self.current_x,
                "y": self.current_y,
                "foothold_id": self.current_foothold_id,
                "stance": self.current_stance,
            },
            "target": {
                "x": final.target_x,
                "y": final.target_y,
                "foothold_id": final.target_foothold_id,
                "stance": final.stance,
            },
            "last_sent_step": last_sent_step,
            "next_step": next_step,
            "confirmed_server_frame_count": len(
                self.confirmed_server_frames
            ),
            "planning_server_frame_count": len(
                self.planning_server_frames
            ),
        }

    def telemetry_dict(self) -> dict[str, object]:
        return {
            "packets_planned": len(self.steps),
            "packets_sent": self.packets_sent,
            "packets_remaining": self.packets_remaining,
            "state": self.safe_dict(),
        }


MAX_MOB_MOVEMENT_FOLLOW_UP_DECISIONS = 8
MAX_PLAYER_MOB_PROXIMITY_RADIUS = 4096


@dataclass(frozen=True)
class MobMovementRelativeDecisionPolicy:
    """Derive bounded follow-up targets from the last confirmed position."""

    decision_count: int
    max_steps: int
    displacement_x: int
    displacement_y: int
    foothold_id: int

    def __post_init__(self) -> None:
        if not 1 <= self.decision_count <= MAX_MOB_MOVEMENT_FOLLOW_UP_DECISIONS:
            raise ValueError(
                "mob movement relative policy decision count must be in 1..8"
            )
        if not 2 <= self.max_steps <= 8:
            raise ValueError(
                "mob movement relative policy max steps must be in 2..8"
            )
        if (self.displacement_x, self.displacement_y) == (0, 0):
            raise ValueError(
                "mob movement relative policy displacement cannot be zero"
            )
        if not 0 <= self.foothold_id <= 0xFFFF:
            raise ValueError(
                "mob movement relative policy foothold must fit in uint16"
            )

    def target_from(
        self, x: int, y: int
    ) -> tuple[int, int, int, int]:
        target_x = x + self.displacement_x
        target_y = y + self.displacement_y
        if not all(
            -0x8000 <= value <= 0x7FFF for value in (target_x, target_y)
        ):
            raise ValueError(
                "mob movement relative policy target exceeds int16"
            )
        return self.max_steps, target_x, target_y, self.foothold_id

    def safe_dict(self) -> dict[str, int]:
        return {
            "decision_count": self.decision_count,
            "max_steps": self.max_steps,
            "displacement_x": self.displacement_x,
            "displacement_y": self.displacement_y,
            "foothold_id": self.foothold_id,
        }


@dataclass
class PlayerMobProximityPredicate:
    """Edge-trigger a decision when a local player enters a mob radius."""

    radius: int
    events_observed: int = field(default=0, init=False)
    entries_observed: int = field(default=0, init=False)
    _was_within_radius: bool | None = field(default=None, init=False)
    _last_observation: dict[str, object] | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        if not 1 <= self.radius <= MAX_PLAYER_MOB_PROXIMITY_RADIUS:
            raise ValueError(
                "player-mob proximity radius must be in 1..4096"
            )

    def observe(
        self,
        *,
        player_x: int,
        player_y: int,
        mob_x: int,
        mob_y: int,
    ) -> bool:
        distance = abs(player_x - mob_x) + abs(player_y - mob_y)
        within_radius = distance <= self.radius
        entered_radius = (
            within_radius and self._was_within_radius is not True
        )
        self.events_observed += 1
        if entered_radius:
            self.entries_observed += 1
        self._was_within_radius = within_radius
        self._last_observation = {
            "player": {"x": player_x, "y": player_y},
            "mob": {"x": mob_x, "y": mob_y},
            "manhattan_distance": distance,
            "within_radius": within_radius,
            "entered_radius": entered_radius,
        }
        return entered_radius

    def safe_dict(self) -> dict[str, object]:
        last_observation = (
            {
                **self._last_observation,
                "player": dict(self._last_observation["player"]),
                "mob": dict(self._last_observation["mob"]),
            }
            if self._last_observation is not None
            else None
        )
        return {
            "radius": self.radius,
            "events_observed": self.events_observed,
            "entries_observed": self.entries_observed,
            "player_was_within_radius": self._was_within_radius,
            "last_observation": last_observation,
        }


@dataclass
class MobMovementBroadcastDecisionQueue:
    """Plan bounded follow-up decisions from transmission-confirmed state."""

    transcript: Transcript = field(repr=False)
    initial_steps: tuple[MobMovementBroadcastPlan, ...] = field(repr=False)
    follow_up_targets: tuple[tuple[int, int, int, int], ...] = field(
        default=(), repr=False
    )
    follow_up_policy: MobMovementRelativeDecisionPolicy | None = None
    evidence_transcript: Transcript | None = field(default=None, repr=False)
    planning_context: MobMovementPlanningContext | None = field(
        default=None, repr=False
    )
    baseline_server_frames: tuple[bytes, ...] = field(
        default=(), repr=False
    )
    max_follow_up_decisions: int = MAX_MOB_MOVEMENT_FOLLOW_UP_DECISIONS
    _active_schedule: MobMovementBroadcastScheduler = field(
        init=False, repr=False
    )
    _planned_follow_ups: list[MobMovementBroadcastSequencePlan] = field(
        default_factory=list, init=False, repr=False
    )
    _next_follow_up_index: int = field(default=0, init=False, repr=False)
    _decisions_completed: int = field(default=0, init=False, repr=False)
    _packets_sent: int = field(default=0, init=False, repr=False)
    _last_sent_step: MobMovementBroadcastPlan | None = field(
        default=None, init=False, repr=False
    )
    _last_sent_decision_index: int | None = field(
        default=None, init=False, repr=False
    )
    _last_sent_step_in_decision: int | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        if self.max_follow_up_decisions < 0:
            raise ValueError(
                "mob movement follow-up decision limit cannot be negative"
            )
        if len(self.follow_up_targets) > self.max_follow_up_decisions:
            raise ValueError(
                "mob movement follow-up decision queue exceeds its "
                f"limit of {self.max_follow_up_decisions}"
            )
        if self.follow_up_targets and self.follow_up_policy is not None:
            raise ValueError(
                "mob movement follow-up targets conflict with a relative "
                "decision policy"
            )
        if (
            self.follow_up_policy is not None
            and self.follow_up_policy.decision_count
            > self.max_follow_up_decisions
        ):
            raise ValueError(
                "mob movement relative policy exceeds the decision queue "
                f"limit of {self.max_follow_up_decisions}"
            )
        for decision_index, target in enumerate(self.follow_up_targets, 2):
            max_steps, _, _, _ = target
            if max_steps not in range(2, 9):
                raise ValueError(
                    f"mob movement decision {decision_index} max_steps "
                    "must be in 2..8"
                )
        self._active_schedule = MobMovementBroadcastScheduler(
            self.initial_steps,
            baseline_server_frames=self.baseline_server_frames,
        )

    @property
    def plaintexts(self) -> tuple[bytes, ...]:
        """Return only the startup-planned packet sequence."""

        return self._active_schedule.plaintexts

    @property
    def next_plaintext(self) -> bytes | None:
        if self._active_schedule.packets_remaining == 0:
            return None
        return self._active_schedule.steps[
            self._active_schedule.packets_sent
        ].broadcast.to_bytes()

    @property
    def decisions_total(self) -> int:
        return 1 + self._follow_up_decision_count

    @property
    def _follow_up_decision_count(self) -> int:
        return (
            self.follow_up_policy.decision_count
            if self.follow_up_policy is not None
            else len(self.follow_up_targets)
        )

    @property
    def decisions_planned(self) -> int:
        return 1 + len(self._planned_follow_ups)

    @property
    def decisions_completed(self) -> int:
        return self._decisions_completed

    @property
    def packets_planned(self) -> int:
        return len(self.initial_steps) + sum(
            len(plan.steps) for plan in self._planned_follow_ups
        )

    @property
    def packets_sent(self) -> int:
        return self._packets_sent

    @property
    def packets_remaining(self) -> int:
        """Return planned packets not yet sent; future decisions stay unplanned."""

        return self.packets_planned - self.packets_sent

    @property
    def complete(self) -> bool:
        return (
            self._decisions_completed == self.decisions_total
            and self._active_schedule.packets_remaining == 0
        )

    @property
    def has_unplanned_decision(self) -> bool:
        return (
            self._active_schedule.packets_remaining == 0
            and self._next_follow_up_index
            < self._follow_up_decision_count
        )

    @property
    def planning_server_frames(self) -> tuple[bytes, ...]:
        return self._active_schedule.planning_server_frames

    @property
    def confirmed_server_frames(self) -> tuple[bytes, ...]:
        return self.planning_server_frames[len(self.baseline_server_frames) :]

    @property
    def active_schedule(self) -> MobMovementBroadcastScheduler:
        return self._active_schedule

    @staticmethod
    def _target_safe_dict(
        decision_index: int, target: tuple[int, int, int, int]
    ) -> dict[str, int]:
        max_steps, target_x, target_y, foothold_id = target
        return {
            "decision_index": decision_index,
            "max_steps": max_steps,
            "x": target_x,
            "y": target_y,
            "foothold_id": foothold_id,
        }

    def confirm_sent(self, plaintext: bytes) -> MobMovementBroadcastPlan:
        """Advance one drained write without planning future decisions."""

        decision_index = self.decisions_planned
        step_in_decision = self._active_schedule.packets_sent + 1
        step = self._active_schedule.confirm_sent(plaintext)
        self._packets_sent += 1
        self._last_sent_step = step
        self._last_sent_decision_index = decision_index
        self._last_sent_step_in_decision = step_in_decision
        if self._active_schedule.packets_remaining:
            return step

        self._decisions_completed += 1
        return step

    def plan_next_decision(self) -> MobMovementBroadcastSequencePlan:
        """Synchronously plan the next target from the confirmed prefix."""

        if not self.has_unplanned_decision:
            raise ValueError(
                "mob movement decision queue has no decision ready to plan"
            )

        planning_server_frames = self._active_schedule.planning_server_frames
        target = (
            self.follow_up_policy.target_from(
                self._active_schedule.current_x,
                self._active_schedule.current_y,
            )
            if self.follow_up_policy is not None
            else self.follow_up_targets[self._next_follow_up_index]
        )
        max_steps, target_x, target_y, foothold_id = target
        next_plan = plan_composed_mob_movement_broadcasts(
            self.transcript,
            post_transcript_server_frames=planning_server_frames,
            evidence_transcript=self.evidence_transcript,
            target_x=target_x,
            target_y=target_y,
            foothold_id=foothold_id,
            max_steps=max_steps,
            planning_context=self.planning_context,
        )
        self._active_schedule = MobMovementBroadcastScheduler(
            next_plan.steps,
            baseline_server_frames=planning_server_frames,
        )
        self._planned_follow_ups.append(next_plan)
        self._next_follow_up_index += 1
        return next_plan

    def safe_dict(self) -> dict[str, object]:
        state = self._active_schedule.safe_dict()
        if self._packets_sent == 0:
            phase = "planned"
        elif self.complete:
            phase = "complete"
        elif self.has_unplanned_decision:
            phase = "planning"
        else:
            phase = "in_progress"
        last_sent_step = None
        if self._last_sent_step is not None:
            last_sent_step = {
                **MobMovementBroadcastScheduler._step_safe_dict(
                    self._packets_sent,
                    self._last_sent_step,
                ),
                "decision_index": self._last_sent_decision_index,
                "step_in_decision": self._last_sent_step_in_decision,
            }
        next_step = None
        if self._active_schedule.packets_remaining:
            next_plan_step = self._active_schedule.steps[
                self._active_schedule.packets_sent
            ]
            next_step = {
                **MobMovementBroadcastScheduler._step_safe_dict(
                    self._packets_sent + 1,
                    next_plan_step,
                ),
                "decision_index": self.decisions_planned,
                "step_in_decision": (
                    self._active_schedule.packets_sent + 1
                ),
            }
        pending_targets = [
            self._target_safe_dict(decision_index, target)
            for decision_index, target in enumerate(
                self.follow_up_targets[self._next_follow_up_index :],
                self.decisions_planned + 1,
            )
        ]
        next_policy_target = (
            self._target_safe_dict(
                self.decisions_planned + 1,
                self.follow_up_policy.target_from(
                    self._active_schedule.current_x,
                    self._active_schedule.current_y,
                ),
            )
            if self.follow_up_policy is not None
            and self.has_unplanned_decision
            else None
        )
        state.update(
            {
                "phase": phase,
                "last_sent_step": last_sent_step,
                "next_step": next_step,
                "confirmed_server_frame_count": self._packets_sent,
                "planning_server_frame_count": len(
                    self.planning_server_frames
                ),
                "decision_queue": {
                    "max_follow_up_decisions": (
                        self.max_follow_up_decisions
                    ),
                    "decisions_total": self.decisions_total,
                    "decisions_planned": self.decisions_planned,
                    "decisions_completed": self.decisions_completed,
                    "decisions_remaining": (
                        self.decisions_total - self.decisions_completed
                    ),
                    "active_decision_index": (
                        self.decisions_planned
                        if self._active_schedule.packets_remaining
                        else None
                    ),
                    "planning_decision_index": (
                        self.decisions_planned + 1
                        if self.has_unplanned_decision
                        else None
                    ),
                    "pending_targets": pending_targets,
                    "relative_policy": (
                        self.follow_up_policy.safe_dict()
                        if self.follow_up_policy is not None
                        else None
                    ),
                    "next_policy_target": next_policy_target,
                },
            }
        )
        return state

    def telemetry_dict(self) -> dict[str, object]:
        return {
            "packets_planned": self.packets_planned,
            "packets_sent": self.packets_sent,
            "packets_remaining": self.packets_remaining,
            "state": self.safe_dict(),
        }


@dataclass(frozen=True)
class MobMovementAcknowledgementPolicy:
    status_values_by_template: dict[int, int]
    observations_by_template: dict[int, int]
    known_mob_templates: dict[int, int] = field(
        repr=False, compare=False
    )
    field_epoch: int
    matched_pairs: int
    known_template_pairs: int
    unknown_template_pairs: int
    flag_rule_matches: int
    zero_auxiliary_pairs: int
    pending_submissions: int
    active_mob_object_ids: set[int] = field(
        default_factory=set, repr=False, compare=False
    )

    @property
    def active_known_mob_count(self) -> int:
        return sum(
            object_id in self.known_mob_templates
            for object_id in self.active_mob_object_ids
        )

    def apply_server_packet(self, plaintext: bytes) -> None:
        if len(plaintext) < 2:
            return
        opcode = int.from_bytes(plaintext[:2], "little")
        spawn: tuple[int, MobSpawnData] | None = None
        if opcode == 279:
            entered = MobEnterField.parse(plaintext)
            spawn = (entered.object_id, entered.spawn)
        elif opcode == 281:
            controller = MobControllerChange.parse(plaintext)
            if controller.spawn is not None:
                spawn = (controller.object_id, controller.spawn)
        elif opcode == 280:
            left = MobLeaveField.parse(plaintext)
            self.active_mob_object_ids.discard(left.object_id)
        if spawn is not None:
            object_id, spawn_data = spawn
            self.known_mob_templates[object_id] = spawn_data.template_id
            self.active_mob_object_ids.add(object_id)

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


@dataclass
class ReactiveMobHealth:
    alias: str
    template_id: int
    current_hp: int
    max_hp: int


@dataclass(frozen=True)
class MobHealthResponsePlan:
    target: str
    template_id: int
    damage_values: tuple[int, ...]
    hp_before: int
    hp_after: int
    health_percentages: tuple[int, ...]
    zero_damage_entries: int
    terminal_hits_skipped: int
    removed: bool
    plaintexts: tuple[bytes, ...] = field(repr=False)

    def safe_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "template_id": self.template_id,
            "damage_values": list(self.damage_values),
            "hp_before": self.hp_before,
            "hp_after": self.hp_after,
            "health_percentages": list(self.health_percentages),
            "zero_damage_entries": self.zero_damage_entries,
            "terminal_hits_skipped": self.terminal_hits_skipped,
            "removed": self.removed,
            "server_opcodes": [
                int.from_bytes(plaintext[:2], "little")
                for plaintext in self.plaintexts
            ],
        }


@dataclass
class MobHealthResponsePolicy:
    mobs: dict[int, ReactiveMobHealth] = field(repr=False)
    field_epoch: int
    source_health_predictions: int = 0
    source_exact_health_predictions: int = 0
    source_one_hp_differences: int = 0

    def _next_alias(self) -> str:
        used = {mob.alias for mob in self.mobs.values()}
        index = 1
        while f"mob:runtime:{index}" in used:
            index += 1
        return f"mob:runtime:{index}"

    def safe_dict(self) -> dict[str, object]:
        return {
            "field_epoch": self.field_epoch,
            "active_mobs": [
                {
                    "entity": mob.alias,
                    "template_id": mob.template_id,
                    "current_hp": mob.current_hp,
                    "max_hp": mob.max_hp,
                    "health_percentage": (
                        mob.current_hp * 100 // mob.max_hp
                    ),
                }
                for mob in sorted(
                    self.mobs.values(), key=lambda candidate: candidate.alias
                )
            ],
            "source_evidence": {
                "health_predictions": self.source_health_predictions,
                "exact_health_predictions": (
                    self.source_exact_health_predictions
                ),
                "one_hp_differences": self.source_one_hp_differences,
            },
            "prediction": {
                "damage_rule": "subtract_each_nonzero_submitted_damage_word",
                "health_percentage_rule": "floor(current_hp*100/max_hp)",
                "zero_damage_rule": "no_response",
                "terminal_rule": "opcode_293_zero_then_opcode_280_reason_1",
            },
        }

    def apply_server_packet(self, plaintext: bytes) -> None:
        if len(plaintext) < 2:
            return
        opcode = int.from_bytes(plaintext[:2], "little")
        if opcode == 279:
            entered = MobEnterField.parse(plaintext)
            max_hp = REFERENCE_MOB_MAX_HP.get(entered.spawn.template_id)
            if max_hp is None:
                self.mobs.pop(entered.object_id, None)
                return
            prior = self.mobs.get(entered.object_id)
            self.mobs[entered.object_id] = ReactiveMobHealth(
                alias=prior.alias if prior is not None else self._next_alias(),
                template_id=entered.spawn.template_id,
                current_hp=max_hp,
                max_hp=max_hp,
            )
        elif opcode == 293:
            update = MobHealthPercentageUpdate.parse(plaintext)
            mob = self.mobs.get(update.object_id)
            if mob is None:
                return
            hp_min, hp_max = mob_hp_bounds_for_percentage(
                mob.max_hp, update.health_percentage
            )
            if hp_min != hp_max:
                raise ValueError(
                    "reactive mob-health policy cannot adopt an ambiguous "
                    "post-transcript HP percentage"
                )
            mob.current_hp = hp_min
        elif opcode == 280:
            left = MobLeaveField.parse(plaintext)
            self.mobs.pop(left.object_id, None)

    def respond(self, request: ClientAttackAction) -> MobHealthResponsePlan:
        target_object_id = request.target_object_id
        if target_object_id is None:
            raise ValueError("client attack has no modeled mob target")
        mob = self.mobs.get(target_object_id)
        if mob is None:
            raise ValueError("client attack target is not an active modeled mob")
        if not request.damage_values:
            raise ValueError("client attack has no decoded damage words")
        if any(request.high_bit_markers):
            raise ValueError("client attack uses an unmodeled damage high bit")

        hp_before = mob.current_hp
        health_updates: list[MobHealthPercentageUpdate] = []
        zero_damage_entries = 0
        terminal_hits_skipped = 0
        for damage in request.damage_values:
            if damage == 0:
                zero_damage_entries += 1
                continue
            if mob.current_hp == 0:
                terminal_hits_skipped += 1
                continue
            mob.current_hp = max(0, mob.current_hp - damage)
            health_updates.append(
                MobHealthPercentageUpdate(
                    object_id=target_object_id,
                    health_percentage=(
                        mob.current_hp * 100 // mob.max_hp
                    ),
                )
            )

        removed = mob.current_hp == 0 and bool(health_updates)
        plaintexts = tuple(update.to_bytes() for update in health_updates)
        if removed:
            plaintexts += (
                MobLeaveField(
                    object_id=target_object_id,
                    reason=1,
                ).to_bytes(),
            )
            del self.mobs[target_object_id]
        return MobHealthResponsePlan(
            target=mob.alias,
            template_id=mob.template_id,
            damage_values=request.damage_values,
            hp_before=hp_before,
            hp_after=mob.current_hp,
            health_percentages=tuple(
                update.health_percentage for update in health_updates
            ),
            zero_damage_entries=zero_damage_entries,
            terminal_hits_skipped=terminal_hits_skipped,
            removed=removed,
            plaintexts=plaintexts,
        )


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
                "facing_value": spawn.facing_value,
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
                "health_percentage": entity.health_percentage,
                "max_hp": entity.max_hp,
                "health_hp_min": entity.health_hp_min,
                "health_hp_max": entity.health_hp_max,
                "client_attack_submitted_hits": (
                    entity.client_attack_submitted_hits
                ),
                "client_attack_submitted_damage": (
                    entity.client_attack_submitted_damage
                ),
                "client_attack_submitted_high_bit_markers": (
                    entity.client_attack_submitted_high_bit_markers
                ),
                "attack_relay_hits": entity.attack_relay_hits,
                "attack_relay_damage": entity.attack_relay_damage,
                "attack_relay_high_bit_markers": (
                    entity.attack_relay_high_bit_markers
                ),
                "last_attack_hit_action": entity.last_attack_hit_action,
                "temporary_stat_bits": sorted(entity.temporary_stats),
                "foothold_id": entity.foothold_id,
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
                "level": entity.level,
                "name_code_units": entity.name_code_units,
            }
            if show_identifiers:
                record["object_id"] = object_id
            observed_players.append(record)
        positioned_effect_entities: list[dict[str, object]] = []
        for primary_value, entity in sorted(
            self.state.positioned_effect_entities.items(),
            key=lambda item: item[1].alias,
        ):
            record = {
                "entity": entity.alias,
                "x": entity.x,
                "y": entity.y,
                "last_opcode": entity.last_opcode,
            }
            if show_identifiers:
                record["primary_value"] = primary_value
            positioned_effect_entities.append(record)
        field_drops: list[dict[str, object]] = []
        for object_id, entity in sorted(
            self.state.field_drops.items(), key=lambda item: item[1].alias
        ):
            spawn = entity.spawn
            record = {"drop": entity.alias, **spawn.safe_dict()}
            if show_identifiers:
                record.update(
                    {
                        "drop_object_id": object_id,
                        "owner_value_1": spawn.owner_value_1,
                        "owner_value_2": spawn.owner_value_2,
                        "source_mob_object_id": spawn.source_mob_object_id,
                    }
                )
            field_drops.append(record)
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
                    "shape": self.state.progression_shape,
                    "skill_levels": self.state.skill_levels,
                    "skill_record_updates": {
                        "requests": self.state.skill_level_change_requests,
                        "requests_by_skill_id": dict(
                            self.state.skill_level_change_requests_by_skill_id
                        ),
                        "updates": self.state.skill_record_updates,
                        "records": self.state.skill_record_update_records,
                        "updates_by_flags": dict(
                            self.state.skill_record_updates_by_flags
                        ),
                        "auxiliary_values": dict(
                            self.state.skill_record_auxiliary_values
                        ),
                        "trailing_values": dict(
                            self.state.skill_record_trailing_values
                        ),
                        "request_matches": (
                            self.state.skill_record_request_matches
                        ),
                        "request_mismatches": (
                            self.state.skill_record_request_mismatches
                        ),
                        "updates_without_request": (
                            self.state.skill_record_updates_without_request
                        ),
                        "pending_requests": (
                            self.state.pending_skill_level_change_requests
                        ),
                        "last_request_response_ms": (
                            None
                            if self.state.last_skill_record_response_ms is None
                            else round(
                                self.state.last_skill_record_response_ms, 3
                            )
                        ),
                        "max_request_response_ms": (
                            None
                            if self.state.max_skill_record_response_ms is None
                            else round(
                                self.state.max_skill_record_response_ms, 3
                            )
                        ),
                        "acknowledgements": (
                            self.state.skill_record_update_acknowledgements
                        ),
                        "matched_acknowledgements": (
                            self.state.matched_skill_record_update_acknowledgements
                        ),
                        "unmatched_acknowledgements": (
                            self.state.unmatched_skill_record_update_acknowledgements
                        ),
                        "pending_acknowledgements": (
                            self.state.pending_skill_record_update_acknowledgements
                        ),
                        "acknowledgement_control_values": dict(
                            self.state.skill_record_acknowledgement_control_values
                        ),
                        "acknowledgement_trailing_values": dict(
                            self.state.skill_record_acknowledgement_trailing_values
                        ),
                        "last_acknowledgement_ms": (
                            None
                            if self.state.last_skill_record_acknowledgement_ms
                            is None
                            else round(
                                self.state.last_skill_record_acknowledgement_ms,
                                3,
                            )
                        ),
                        "max_acknowledgement_ms": (
                            None
                            if self.state.max_skill_record_acknowledgement_ms
                            is None
                            else round(
                                self.state.max_skill_record_acknowledgement_ms,
                                3,
                            )
                        ),
                    },
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
                "positioned_effect_entity_count": len(
                    self.state.positioned_effect_entities
                ),
                "positioned_effect_entities": positioned_effect_entities,
                "active_field_drop_count": len(self.state.field_drops),
                "field_drops": field_drops,
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
                "npc_lifecycle_spawns": self.state.npc_lifecycle_spawns,
                "npc_lifecycle_removals": self.state.npc_lifecycle_removals,
                "npc_lifecycle_unknown_removals": (
                    self.state.npc_lifecycle_unknown_removals
                ),
                "npc_state_updates": self.state.npc_state_updates,
                "mob_entries": self.state.mob_entries,
                "mob_leaves": self.state.mob_leaves,
                "mob_controller_changes": self.state.mob_controller_changes,
                "mob_movement_broadcasts": (
                    self.state.mob_movement_broadcasts
                ),
                "mob_health_percentage_updates": (
                    self.state.mob_health_percentage_updates
                ),
                "mob_health_zero_updates": self.state.mob_health_zero_updates,
                "mob_health_increases": self.state.mob_health_increases,
                "mob_health_updates_for_unknown_mobs": (
                    self.state.mob_health_updates_for_unknown_mobs
                ),
                "mob_temporary_stats": {
                    "active_count": sum(
                        len(entity.temporary_stats)
                        for entity in self.state.mobs.values()
                    ),
                    "set_count": self.state.mob_temporary_stat_sets,
                    "reset_count": self.state.mob_temporary_stat_resets,
                    "sets_for_known_mobs": (
                        self.state.mob_temporary_stat_sets_for_known_mobs
                    ),
                    "sets_for_unknown_mobs": (
                        self.state.mob_temporary_stat_sets_for_unknown_mobs
                    ),
                    "resets_for_known_mobs": (
                        self.state.mob_temporary_stat_resets_for_known_mobs
                    ),
                    "resets_for_unknown_mobs": (
                        self.state.mob_temporary_stat_resets_for_unknown_mobs
                    ),
                    "set_refreshes": (
                        self.state.mob_temporary_stat_set_refreshes
                    ),
                    "resets_with_modeled_set": (
                        self.state.mob_temporary_stat_resets_with_modeled_set
                    ),
                    "resets_without_modeled_set": (
                        self.state.mob_temporary_stat_resets_without_modeled_set
                    ),
                    "attack_relay_matches": (
                        self.state.mob_temporary_stat_attack_relay_matches
                    ),
                    "cleared_on_leave": (
                        self.state.mob_temporary_stats_cleared_on_leave
                    ),
                    "cleared_on_field_change": (
                        self.state.mob_temporary_stats_cleared_on_field_change
                    ),
                    "mask_patterns": dict(
                        self.state.mob_temporary_stat_mask_patterns
                    ),
                    "source_skills": dict(
                        self.state.mob_temporary_stat_source_skills
                    ),
                    "source_levels": dict(
                        self.state.mob_temporary_stat_source_levels
                    ),
                    "duration_values": dict(
                        self.state.mob_temporary_stat_duration_values
                    ),
                    "set_flags": dict(
                        self.state.mob_temporary_stat_set_flags
                    ),
                    "reset_flags": dict(
                        self.state.mob_temporary_stat_reset_flags
                    ),
                },
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
                "remote_player_movement_broadcasts_for_known_players": (
                    self.state.remote_player_movement_broadcasts_for_known_players
                ),
                "remote_player_movement_broadcasts_for_unknown_players": (
                    self.state.remote_player_movement_broadcasts_for_unknown_players
                ),
                "remote_player_entries": self.state.remote_player_entries,
                "remote_player_refreshes": self.state.remote_player_refreshes,
                "remote_player_entry_opaque_bytes": (
                    self.state.remote_player_entry_opaque_bytes
                ),
                "remote_player_leaves": self.state.remote_player_leaves,
                "remote_player_unknown_leaves": (
                    self.state.remote_player_unknown_leaves
                ),
                "remote_player_mob_values": {
                    "packet_count": (
                        self.state.remote_player_mob_value_records
                    ),
                    "known_player_count": (
                        self.state.remote_player_mob_values_for_known_players
                    ),
                    "unknown_player_count": (
                        self.state.remote_player_mob_values_for_unknown_players
                    ),
                    "active_template_count": (
                        self.state.remote_player_mob_values_with_active_template
                    ),
                    "inactive_template_count": (
                        self.state.remote_player_mob_values_with_inactive_template
                    ),
                    "values": dict(self.state.remote_player_mob_values),
                    "mob_templates": dict(
                        self.state.remote_player_mob_templates
                    ),
                    "flags": dict(self.state.remote_player_mob_value_flags),
                },
                "life_movement_submissions": (
                    self.state.life_movement_submissions
                ),
                "life_movement_submission_commands": (
                    self.state.life_movement_submission_commands
                ),
                "life_movement_submission_commands_by_type": dict(
                    self.state.life_movement_submission_commands_by_type
                ),
                "life_movement_tail_types": dict(
                    self.state.life_movement_tail_types
                ),
                "life_movement_tail_markers": dict(
                    self.state.life_movement_tail_markers
                ),
                "life_movement_broadcasts": self.state.life_movement_broadcasts,
                "life_movement_broadcast_commands": (
                    self.state.life_movement_broadcast_commands
                ),
                "life_movement_broadcast_commands_by_type": dict(
                    self.state.life_movement_broadcast_commands_by_type
                ),
                "life_movement_broadcasts_for_known_players": (
                    self.state.life_movement_broadcasts_for_known_players
                ),
                "life_movement_broadcasts_for_unknown_players": (
                    self.state.life_movement_broadcasts_for_unknown_players
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
                "inventory_change_packets": self.state.inventory_change_packets,
                "inventory_modifications": self.state.inventory_modifications,
                "inventory_modifications_by_operation": dict(
                    self.state.inventory_modifications_by_operation
                ),
                "inventory_update_flags": dict(
                    self.state.inventory_update_flags
                ),
                "inventory_empty_change_packets": (
                    self.state.inventory_empty_change_packets
                ),
                "inventory_unknown_slot_modifications": (
                    self.state.inventory_unknown_slot_modifications
                ),
                "item_use_requests": self.state.item_use_requests,
                "item_use_requests_by_item": {
                    str(item_id): count
                    for item_id, count in sorted(
                        self.state.item_use_requests_by_item.items()
                    )
                },
                "item_use_unknown_slots": self.state.item_use_unknown_slots,
                "item_use_item_mismatches": (
                    self.state.item_use_item_mismatches
                ),
                "item_use_inventory_matches": (
                    self.state.item_use_inventory_matches
                ),
                "item_use_inventory_mismatches": (
                    self.state.item_use_inventory_mismatches
                ),
                "item_use_effect_matches": self.state.item_use_effect_matches,
                "item_use_effect_mismatches": (
                    self.state.item_use_effect_mismatches
                ),
                "item_use_policy_rejections": (
                    self.state.item_use_policy_rejections
                ),
                "pending_item_uses": self.state.pending_item_uses,
                "item_pickup_requests": self.state.item_pickup_requests,
                "item_pickup_base_requests": (
                    self.state.item_pickup_base_requests
                ),
                "item_pickup_extended_requests": (
                    self.state.item_pickup_extended_requests
                ),
                "item_pickup_field_epoch_matches": (
                    self.state.item_pickup_field_epoch_matches
                ),
                "item_pickup_field_epoch_mismatches": (
                    self.state.item_pickup_field_epoch_mismatches
                ),
                "item_pickup_results": self.state.item_pickup_results,
                "item_pickup_results_by_kind": dict(
                    self.state.item_pickup_results_by_kind
                ),
                "item_pickup_effect_matches": (
                    self.state.item_pickup_effect_matches
                ),
                "item_pickup_effect_mismatches": (
                    self.state.item_pickup_effect_mismatches
                ),
                "item_pickup_inferred_mesos_baselines": (
                    self.state.item_pickup_inferred_mesos_baselines
                ),
                "item_pickup_removal_matches": (
                    self.state.item_pickup_removal_matches
                ),
                "item_pickup_removal_mismatches": (
                    self.state.item_pickup_removal_mismatches
                ),
                "item_pickup_policy_rejections": (
                    self.state.item_pickup_policy_rejections
                ),
                "pending_item_pickups": self.state.pending_item_pickups,
                "item_pickup_known_drops": self.state.item_pickup_known_drops,
                "item_pickup_unknown_drops": (
                    self.state.item_pickup_unknown_drops
                ),
                "item_pickup_spawn_result_matches": (
                    self.state.item_pickup_spawn_result_matches
                ),
                "item_pickup_spawn_result_mismatches": (
                    self.state.item_pickup_spawn_result_mismatches
                ),
                "item_pickup_item_effects_by_template": {
                    str(item_id): [
                        {
                            "inventory": inventory,
                            "quantity_delta": quantity_delta,
                        }
                        for inventory, quantity_delta in sorted(effects)
                    ]
                    for item_id, effects in sorted(
                        self.state.item_pickup_item_effects_by_template.items()
                    )
                },
                "field_drop_spawn_packets": self.state.field_drop_spawn_packets,
                "field_drop_spawns": self.state.field_drop_spawns,
                "field_drop_refreshes": self.state.field_drop_refreshes,
                "field_drop_refresh_mismatches": (
                    self.state.field_drop_refresh_mismatches
                ),
                "field_drop_spawns_by_mode": dict(
                    self.state.field_drop_spawns_by_mode
                ),
                "field_drop_spawns_by_kind": dict(
                    self.state.field_drop_spawns_by_kind
                ),
                "field_drop_spawns_with_known_source_mob": (
                    self.state.field_drop_spawns_with_known_source_mob
                ),
                "field_drop_spawns_with_unknown_source_mob": (
                    self.state.field_drop_spawns_with_unknown_source_mob
                ),
                "field_drop_removals": self.state.field_drop_removals,
                "field_drop_removals_by_reason": dict(
                    self.state.field_drop_removals_by_reason
                ),
                "field_drop_removals_for_known_drop": (
                    self.state.field_drop_removals_for_known_drop
                ),
                "field_drop_removals_for_unknown_drop": (
                    self.state.field_drop_removals_for_unknown_drop
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
                "opcode_426_notifications": (
                    self.state.opcode_426_notifications
                ),
                "opcode_309_acknowledgements": (
                    self.state.opcode_309_acknowledgements
                ),
                "matched_opcode_309_acknowledgements": (
                    self.state.matched_opcode_309_acknowledgements
                ),
                "unmatched_opcode_309_acknowledgements": (
                    self.state.unmatched_opcode_309_acknowledgements
                ),
                "pending_opcode_426_notifications": (
                    self.state.pending_opcode_426_notifications
                ),
                "last_opcode_426_round_trip_ms": (
                    self.state.last_opcode_426_round_trip_ms
                ),
                "max_opcode_426_round_trip_ms": (
                    self.state.max_opcode_426_round_trip_ms
                ),
                "client_attack_actions": self.state.client_attack_actions,
                "client_attack_actions_by_opcode": dict(
                    self.state.client_attack_actions_by_opcode
                ),
                "client_attack_shapes": dict(
                    self.state.client_attack_shapes
                ),
                "client_attack_targeted_actions": (
                    self.state.client_attack_targeted_actions
                ),
                "client_attack_untargeted_actions": (
                    self.state.client_attack_untargeted_actions
                ),
                "client_attack_targets_for_active_mobs": (
                    self.state.client_attack_targets_for_active_mobs
                ),
                "client_attack_targets_for_known_mobs": (
                    self.state.client_attack_targets_for_known_mobs
                ),
                "client_attack_targets_for_unknown_mobs": (
                    self.state.client_attack_targets_for_unknown_mobs
                ),
                "client_attack_damage_actions": (
                    self.state.client_attack_damage_actions
                ),
                "client_attack_damage_entries": (
                    self.state.client_attack_damage_entries
                ),
                "client_attack_damage_total": (
                    self.state.client_attack_damage_total
                ),
                "client_attack_damage_min": (
                    self.state.client_attack_damage_min
                ),
                "client_attack_damage_max": (
                    self.state.client_attack_damage_max
                ),
                "client_attack_damage_high_bit_markers": (
                    self.state.client_attack_damage_high_bit_markers
                ),
                "client_attack_zero_damage_entries": (
                    self.state.client_attack_zero_damage_entries
                ),
                "client_attack_health_matches": (
                    self.state.client_attack_health_matches
                ),
                "client_attack_health_predictions": (
                    self.state.client_attack_health_predictions
                ),
                "client_attack_health_prediction_matches": (
                    self.state.client_attack_health_prediction_matches
                ),
                "client_attack_health_prediction_mismatches": (
                    self.state.client_attack_health_prediction_mismatches
                ),
                "client_attack_health_prediction_one_hp_differences": (
                    self.state.client_attack_health_one_hp_differences
                ),
                "client_attack_health_predictions_with_relay_hits": (
                    self.state.client_attack_predictions_with_relay_hits
                ),
                "client_attack_health_mismatches_without_relay_hits": (
                    self.state.client_attack_mismatches_without_relays
                ),
                "client_attack_health_mismatch_damage_deltas": dict(
                    sorted(
                        self.state.client_attack_health_mismatch_damage_deltas.items()
                    )
                ),
                "client_attack_health_predictions_by_template": dict(
                    self.state.client_attack_health_predictions_by_template
                ),
                "client_attack_effects_cleared": (
                    self.state.client_attack_effects_cleared
                ),
                "pending_client_attack_effects": (
                    self.state.pending_client_attack_effects
                ),
                "last_client_attack_health_response_ms": (
                    self.state.last_client_attack_health_response_ms
                ),
                "max_client_attack_health_response_ms": (
                    self.state.max_client_attack_health_response_ms
                ),
                "server_attack_relays": self.state.server_attack_relays,
                "server_attack_relays_by_opcode": dict(
                    self.state.server_attack_relays_by_opcode
                ),
                "server_attack_target_counts": dict(
                    self.state.server_attack_target_counts
                ),
                "server_attack_hit_counts": dict(
                    self.state.server_attack_hit_counts
                ),
                "server_attack_relays_for_known_players": (
                    self.state.server_attack_relays_for_known_players
                ),
                "server_attack_relays_for_unknown_players": (
                    self.state.server_attack_relays_for_unknown_players
                ),
                "server_melee_attack_relays": (
                    self.state.server_melee_attack_relays
                ),
                "server_melee_attack_short_zero_target_forms": (
                    self.state.server_melee_attack_short_zero_target_forms
                ),
                "server_melee_attack_tags": dict(
                    self.state.server_melee_attack_tags
                ),
                "server_melee_attack_skill_levels": dict(
                    self.state.server_melee_attack_skill_levels
                ),
                "server_melee_attack_unknown_values": dict(
                    self.state.server_melee_attack_unknown_values
                ),
                "server_melee_attack_displays": dict(
                    self.state.server_melee_attack_displays
                ),
                "server_melee_attack_facing_flags": dict(
                    self.state.server_melee_attack_facing_flags
                ),
                "server_melee_attack_speeds": dict(
                    self.state.server_melee_attack_speeds
                ),
                "server_melee_attack_mastery_values": dict(
                    self.state.server_melee_attack_mastery_values
                ),
                "server_melee_attack_auxiliary_values": dict(
                    self.state.server_melee_attack_auxiliary_values
                ),
                "server_ranged_attack_relays": (
                    self.state.server_ranged_attack_relays
                ),
                "server_ranged_attack_tags": dict(
                    self.state.server_ranged_attack_tags
                ),
                "server_ranged_attack_skill_levels": dict(
                    self.state.server_ranged_attack_skill_levels
                ),
                "server_ranged_attack_skill_ids": dict(
                    self.state.server_ranged_attack_skill_ids
                ),
                "server_ranged_attack_unknown_values": dict(
                    self.state.server_ranged_attack_unknown_values
                ),
                "server_ranged_attack_displays": dict(
                    self.state.server_ranged_attack_displays
                ),
                "server_ranged_attack_facing_flags": dict(
                    self.state.server_ranged_attack_facing_flags
                ),
                "server_ranged_attack_speeds": dict(
                    self.state.server_ranged_attack_speeds
                ),
                "server_ranged_attack_mastery_values": dict(
                    self.state.server_ranged_attack_mastery_values
                ),
                "server_ranged_attack_projectile_ids": dict(
                    self.state.server_ranged_attack_projectile_ids
                ),
                "server_ranged_attack_positions_for_known_players": (
                    self.state.server_ranged_attack_positions_for_known_players
                ),
                "server_ranged_attack_position_delta_x_min": (
                    self.state.server_ranged_attack_position_delta_x_min
                ),
                "server_ranged_attack_position_delta_x_max": (
                    self.state.server_ranged_attack_position_delta_x_max
                ),
                "server_ranged_attack_position_delta_y_min": (
                    self.state.server_ranged_attack_position_delta_y_min
                ),
                "server_ranged_attack_position_delta_y_max": (
                    self.state.server_ranged_attack_position_delta_y_max
                ),
                "server_attack_target_records": (
                    self.state.server_attack_target_records
                ),
                "server_attack_zero_object_targets": (
                    self.state.server_attack_zero_object_targets
                ),
                "server_attack_targets_for_active_mobs": (
                    self.state.server_attack_targets_for_active_mobs
                ),
                "server_attack_targets_for_known_mobs": (
                    self.state.server_attack_targets_for_known_mobs
                ),
                "server_attack_targets_for_unknown_mobs": (
                    self.state.server_attack_targets_for_unknown_mobs
                ),
                "server_attack_hit_actions": dict(
                    self.state.server_attack_hit_actions
                ),
                "server_attack_damage_entries": (
                    self.state.server_attack_damage_entries
                ),
                "server_attack_damage_total": (
                    self.state.server_attack_damage_total
                ),
                "server_attack_damage_min": (
                    self.state.server_attack_damage_min
                ),
                "server_attack_damage_max": (
                    self.state.server_attack_damage_max
                ),
                "server_attack_damage_high_bit_markers": (
                    self.state.server_attack_damage_high_bit_markers
                ),
                "client_opcode_101_packets": (
                    self.state.client_opcode_101_packets
                ),
                "client_opcode_101_header_values": dict(
                    self.state.client_opcode_101_header_values
                ),
                "client_opcode_101_primary_values": dict(
                    self.state.client_opcode_101_primary_values
                ),
                "client_opcode_101_flag_values": dict(
                    self.state.client_opcode_101_flag_values
                ),
                "client_opcode_101_secondary_values": dict(
                    self.state.client_opcode_101_secondary_values
                ),
                "client_opcode_101_tail_values": dict(
                    self.state.client_opcode_101_tail_values
                ),
                "client_skill_uses": {
                    "request_count": self.state.client_skill_use_requests,
                    "requests_by_skill_id": dict(
                        self.state.client_skill_use_requests_by_skill_id
                    ),
                    "skill_level_values": dict(
                        self.state.client_skill_use_level_values
                    ),
                    "trailing_values": dict(
                        self.state.client_skill_use_trailing_values
                    ),
                    "known_skills": self.state.client_skill_use_known_skills,
                    "unknown_skills": (
                        self.state.client_skill_use_unknown_skills
                    ),
                    "level_matches": (
                        self.state.client_skill_use_level_matches
                    ),
                    "level_mismatches": (
                        self.state.client_skill_use_level_mismatches
                    ),
                    "binding_matches": (
                        self.state.client_skill_use_binding_matches
                    ),
                    "binding_mismatches": (
                        self.state.client_skill_use_binding_mismatches
                    ),
                    "last_client_tick": self.state.last_client_skill_tick,
                    "tick_decreases": self.state.client_skill_tick_decreases,
                },
                "local_temporary_stat_sets": {
                    "packet_count": self.state.local_temporary_stat_sets,
                    "zero_mask_packets": (
                        self.state.local_temporary_stat_zero_masks
                    ),
                    "nonzero_mask_packets": (
                        self.state.local_temporary_stat_nonzero_masks
                    ),
                    "enabled_bit_count": (
                        self.state.local_temporary_stat_enabled_bits
                    ),
                    "mask_patterns": dict(
                        self.state.local_temporary_stat_mask_patterns
                    ),
                    "zero_mask_flag_a_values": dict(
                        self.state.local_temporary_stat_zero_flag_a_values
                    ),
                    "zero_mask_flag_b_values": dict(
                        self.state.local_temporary_stat_zero_flag_b_values
                    ),
                    "zero_mask_trailing_i16_values": dict(
                        self.state.local_temporary_stat_zero_trailing_i16_values
                    ),
                    "opaque_bytes": (
                        self.state.local_temporary_stat_opaque_bytes
                    ),
                },
                "server_opcode_49": {
                    "packet_count": self.state.server_opcode_49_packets,
                    "packets_by_variant": dict(
                        self.state.server_opcode_49_by_variant
                    ),
                    "packets_by_shape": dict(
                        self.state.server_opcode_49_by_shape
                    ),
                    "text_field_count": (
                        self.state.server_opcode_49_text_fields
                    ),
                    "text_code_units": (
                        self.state.server_opcode_49_text_code_units
                    ),
                    "opaque_bytes": self.state.server_opcode_49_opaque_bytes,
                },
                "server_opcode_77": {
                    "packet_count": self.state.server_opcode_77_packets,
                    "packets_by_variant": dict(
                        self.state.server_opcode_77_by_variant
                    ),
                    "text_field_count": (
                        self.state.server_opcode_77_text_fields
                    ),
                    "text_code_units": (
                        self.state.server_opcode_77_text_code_units
                    ),
                    "opaque_bytes": self.state.server_opcode_77_opaque_bytes,
                    "control_patterns": dict(
                        self.state.server_opcode_77_control_patterns
                    ),
                    "terminal_u32_values": dict(
                        self.state.server_opcode_77_terminal_values
                    ),
                },
                "client_opcode_13_messages": (
                    self.state.client_opcode_13_messages
                ),
                "client_opcode_13_messages_by_type": dict(
                    self.state.client_opcode_13_messages_by_type
                ),
                "client_opcode_13_opaque_bytes": (
                    self.state.client_opcode_13_opaque_bytes
                ),
                "client_opcode_13_opaque_lengths": dict(
                    self.state.client_opcode_13_opaque_lengths
                ),
                "server_opcode_13": {
                    "message_count": self.state.server_opcode_13_messages,
                    "messages_by_type": dict(
                        self.state.server_opcode_13_messages_by_type
                    ),
                    "opaque_bytes": self.state.server_opcode_13_opaque_bytes,
                    "opaque_lengths": dict(
                        self.state.server_opcode_13_opaque_lengths
                    ),
                    "body_redacted": True,
                },
                "client_opcode_43": {
                    "packet_count": self.state.client_opcode_43_packets,
                    "sequences": dict(self.state.client_opcode_43_sequences),
                    "variants": dict(self.state.client_opcode_43_variants),
                    "text_code_units": dict(
                        self.state.client_opcode_43_text_code_units
                    ),
                    "opaque_bytes": self.state.client_opcode_43_opaque_bytes,
                },
                "server_opcode_43": {
                    "packet_count": self.state.server_opcode_43_packets,
                    "message_types": dict(
                        self.state.server_opcode_43_message_types
                    ),
                    "opaque_bytes": self.state.server_opcode_43_opaque_bytes,
                },
                "client_opcode_114": {
                    "packet_count": self.state.client_opcode_114_packets,
                    "control_values": dict(
                        self.state.client_opcode_114_control_values
                    ),
                    "text_code_units": dict(
                        self.state.client_opcode_114_text_code_units
                    ),
                    "redacted_value_count": (
                        self.state.client_opcode_114_redacted_values
                    ),
                },
                "client_opcode_122": {
                    "packet_count": self.state.client_opcode_122_packets,
                    "selectors": dict(self.state.client_opcode_122_selectors),
                    "shapes": dict(self.state.client_opcode_122_shapes),
                    "terminal_sentinel_count": (
                        self.state.client_opcode_122_terminal_sentinels
                    ),
                },
                "client_opcode_217_packets": (
                    self.state.client_opcode_217_packets
                ),
                "client_opcode_217_compact_packets": (
                    self.state.client_opcode_217_compact_packets
                ),
                "client_opcode_217_record_sets": (
                    self.state.client_opcode_217_record_sets
                ),
                "client_opcode_217_records": (
                    self.state.client_opcode_217_records
                ),
                "client_opcode_217_records_by_format": dict(
                    self.state.client_opcode_217_records_by_format
                ),
                "client_opcode_217_record_counts": dict(
                    self.state.client_opcode_217_record_counts
                ),
                "bootstrap_acknowledgements": (
                    self.state.bootstrap_acknowledgements
                ),
                "neutral_server_records": {
                    "packet_count": self.state.neutral_server_records,
                    "packets_by_opcode": dict(
                        self.state.neutral_server_records_by_opcode
                    ),
                    "typed_value_count": (
                        self.state.neutral_server_typed_values
                    ),
                    "opaque_bytes": self.state.neutral_server_opaque_bytes,
                },
                "tutorial_ui_instructions": {
                    "packet_count": self.state.tutorial_ui_instructions,
                    "text_code_units": dict(
                        self.state.tutorial_ui_text_code_units
                    ),
                    "value_1": dict(self.state.tutorial_ui_value_1),
                    "value_2": dict(self.state.tutorial_ui_value_2),
                    "control_values": dict(
                        self.state.tutorial_ui_control_values
                    ),
                    "extended_packet_count": (
                        self.state.tutorial_ui_extended_instructions
                    ),
                },
                "instructional_dialogue_requests": {
                    "packet_count": self.state.instructional_dialogue_requests,
                    "opcode": 244,
                    "selector": 8,
                    "value_1": dict(self.state.instructional_dialogue_value_1),
                    "value_2": dict(self.state.instructional_dialogue_value_2),
                    "value_3": dict(self.state.instructional_dialogue_value_3),
                },
                "server_opcode_239": {
                    "packet_count": self.state.server_opcode_239_packets,
                    "selectors": dict(self.state.server_opcode_239_selectors),
                    "record_count": self.state.server_opcode_239_records,
                    "record_values": dict(
                        self.state.server_opcode_239_record_values
                    ),
                    "text_code_units": dict(
                        self.state.server_opcode_239_text_code_units
                    ),
                    "trailing_values": dict(
                        self.state.server_opcode_239_trailing_values
                    ),
                },
                "server_opcode_27": {
                    "packet_count": self.state.server_opcode_27_packets,
                    "entry_counts": dict(
                        self.state.server_opcode_27_entry_counts
                    ),
                    "text_code_units": dict(
                        self.state.server_opcode_27_text_code_units
                    ),
                },
                "server_opcode_28": {
                    "packet_count": self.state.server_opcode_28_packets,
                    "entry_counts": dict(
                        self.state.server_opcode_28_entry_counts
                    ),
                    "text_1_code_units": dict(
                        self.state.server_opcode_28_text_1_code_units
                    ),
                    "text_2_code_units": dict(
                        self.state.server_opcode_28_text_2_code_units
                    ),
                },
                "server_opcode_29": {
                    "packet_count": self.state.server_opcode_29_packets,
                    "entry_counts": dict(
                        self.state.server_opcode_29_entry_counts
                    ),
                    "text_code_units": dict(
                        self.state.server_opcode_29_text_code_units
                    ),
                },
                "server_opcode_135": {
                    "packet_count": self.state.server_opcode_135_packets,
                    "section_a_entry_counts": dict(
                        self.state.server_opcode_135_section_a_entry_counts
                    ),
                    "section_a_enabled_count": (
                        self.state.server_opcode_135_section_a_enabled_count
                    ),
                    "section_a_value_counts": dict(
                        self.state.server_opcode_135_section_a_value_counts
                    ),
                    "section_b_entry_counts": dict(
                        self.state.server_opcode_135_section_b_entry_counts
                    ),
                    "section_b_enabled_count": (
                        self.state.server_opcode_135_section_b_enabled_count
                    ),
                    "section_b_pair_counts": dict(
                        self.state.server_opcode_135_section_b_pair_counts
                    ),
                    "section_c_pair_counts": dict(
                        self.state.server_opcode_135_section_c_pair_counts
                    ),
                    "section_d_entry_counts": dict(
                        self.state.server_opcode_135_section_d_entry_counts
                    ),
                    "section_d_group_1_counts": dict(
                        self.state.server_opcode_135_section_d_group_1_counts
                    ),
                    "section_d_group_2_counts": dict(
                        self.state.server_opcode_135_section_d_group_2_counts
                    ),
                },
                "server_opcode_142": {
                    "packet_count": self.state.server_opcode_142_packets,
                    "enabled_packet_count": (
                        self.state.server_opcode_142_enabled_packets
                    ),
                    "entry_counts": dict(
                        self.state.server_opcode_142_entry_counts
                    ),
                    "header_text_code_units": dict(
                        self.state.server_opcode_142_header_text_code_units
                    ),
                    "entry_text_code_units": dict(
                        self.state.server_opcode_142_entry_text_code_units
                    ),
                    "flag_1_true_count": (
                        self.state.server_opcode_142_flag_1_true_count
                    ),
                    "flag_2_true_count": (
                        self.state.server_opcode_142_flag_2_true_count
                    ),
                },
                "server_opcode_147": {
                    "packet_count": self.state.server_opcode_147_packets,
                    "value_counts": dict(
                        self.state.server_opcode_147_value_counts
                    ),
                    "rectangle_shapes": dict(
                        self.state.server_opcode_147_rectangle_shapes
                    ),
                },
                "server_opcode_425": {
                    "packet_count": self.state.server_opcode_425_packets,
                    "value_counts": dict(
                        self.state.server_opcode_425_value_counts
                    ),
                    "trailer_shapes": dict(
                        self.state.server_opcode_425_trailer_shapes
                    ),
                },
                "server_opcode_272": {
                    "packet_count": self.state.server_opcode_272_packets,
                    "entry_counts": dict(
                        self.state.server_opcode_272_entry_counts
                    ),
                    "group_1_count": (
                        self.state.server_opcode_272_group_1_count
                    ),
                    "group_2_count": (
                        self.state.server_opcode_272_group_2_count
                    ),
                    "flag_1_true_count": (
                        self.state.server_opcode_272_flag_1_true_count
                    ),
                    "flag_2_true_count": (
                        self.state.server_opcode_272_flag_2_true_count
                    ),
                    "trailer_values": dict(
                        self.state.server_opcode_272_trailer_values
                    ),
                },
                "positioned_effect_records": {
                    "packet_count": self.state.positioned_effect_records,
                    "by_opcode": dict(
                        self.state.positioned_effect_records_by_opcode
                    ),
                    "new_entity_count": (
                        self.state.positioned_effect_new_entities
                    ),
                    "update_count": self.state.positioned_effect_updates,
                    "unknown_update_count": (
                        self.state.positioned_effect_unknown_updates
                    ),
                    "control_values": dict(
                        self.state.positioned_effect_control_values
                    ),
                },
                "server_opcode_169": {
                    "packet_count": self.state.server_opcode_169_packets,
                    "selectors": dict(self.state.server_opcode_169_selectors),
                    "text_code_units": dict(
                        self.state.server_opcode_169_text_code_units
                    ),
                },
                "server_opcode_348": {
                    "packet_count": self.state.server_opcode_348_packets,
                    "categories": dict(
                        self.state.server_opcode_348_categories
                    ),
                    "selectors": dict(self.state.server_opcode_348_selectors),
                    "values": dict(self.state.server_opcode_348_values),
                    "text_code_units": dict(
                        self.state.server_opcode_348_text_code_units
                    ),
                    "control_pairs": dict(
                        self.state.server_opcode_348_control_pairs
                    ),
                },
                "opcode_394_279": {
                    "server_packet_count": self.state.server_opcode_394_packets,
                    "server_text_code_units": dict(
                        self.state.server_opcode_394_text_code_units
                    ),
                    "client_packet_count": (
                        self.state.client_opcode_279_text_packets
                    ),
                    "client_control_values": dict(
                        self.state.client_opcode_279_control_values
                    ),
                    "client_text_code_units": dict(
                        self.state.client_opcode_279_text_code_units
                    ),
                    "changed_code_unit_counts": dict(
                        self.state.client_opcode_279_changed_code_unit_counts
                    ),
                    "changed_span_shapes": dict(
                        self.state.client_opcode_279_changed_span_shapes
                    ),
                    "correlated_pair_count": (
                        self.state.correlated_client_opcode_279_packets
                    ),
                    "uncorrelated_client_packet_count": (
                        self.state.uncorrelated_client_opcode_279_packets
                    ),
                    "captured_transform_matches": (
                        self.state.client_opcode_279_transform_matches
                    ),
                    "captured_transform_mismatches": (
                        self.state.client_opcode_279_transform_mismatches
                    ),
                    "pending_server_envelope_count": (
                        self.state.pending_server_opcode_394_envelopes
                    ),
                    "last_observed_gap_ms": (
                        None
                        if self.state.last_opcode_394_279_gap_ms is None
                        else round(self.state.last_opcode_394_279_gap_ms, 3)
                    ),
                    "max_observed_gap_ms": (
                        None
                        if self.state.max_opcode_394_279_gap_ms is None
                        else round(self.state.max_opcode_394_279_gap_ms, 3)
                    ),
                    "text_redacted": True,
                },
                "client_opcode_66": {
                    "packet_count": (
                        self.state.client_opcode_66_acknowledgements
                    ),
                    "selectors": dict(
                        self.state.client_opcode_66_selectors
                    ),
                    "status_values": dict(
                        self.state.client_opcode_66_status_values
                    ),
                    "shapes": dict(self.state.client_opcode_66_shapes),
                    "optional_value_count": (
                        self.state.client_opcode_66_optional_values
                    ),
                    "matched_request_count": (
                        self.state.matched_client_opcode_66_acknowledgements
                    ),
                    "unmatched_request_count": (
                        self.state.unmatched_client_opcode_66_acknowledgements
                    ),
                    "pending_request_count": (
                        self.state.pending_server_opcode_348_requests
                    ),
                    "last_round_trip_ms": (
                        None
                        if self.state.last_opcode_348_round_trip_ms is None
                        else round(
                            self.state.last_opcode_348_round_trip_ms, 3
                        )
                    ),
                    "max_round_trip_ms": (
                        None
                        if self.state.max_opcode_348_round_trip_ms is None
                        else round(self.state.max_opcode_348_round_trip_ms, 3)
                    ),
                },
                "fixed_server_records": (
                    self.state.fixed_server_records
                ),
                "fixed_server_records_by_opcode": dict(
                    self.state.fixed_server_records_by_opcode
                ),
                "initial_character_contexts": (
                    self.state.initial_character_contexts
                ),
                "variable_server_records": self.state.variable_server_records,
                "variable_server_records_by_opcode": dict(
                    self.state.variable_server_records_by_opcode
                ),
                "variable_server_variants": dict(
                    self.state.variable_server_variants
                ),
                "variable_server_typed_entries": (
                    self.state.variable_server_typed_entries
                ),
                "variable_server_typed_values": (
                    self.state.variable_server_typed_values
                ),
                "variable_server_opaque_bytes": (
                    self.state.variable_server_opaque_bytes
                ),
                "keyboard_bindings": {
                    "snapshot_count": self.state.keyboard_binding_snapshots,
                    "key_code_space": "linux_evdev",
                    "validated_key_codes": {
                        "left_ctrl": VariableServerRecord.LEFT_CTRL_KEY_CODE,
                    },
                    "selector_counts": dict(
                        self.state.keyboard_binding_selector_counts
                    ),
                    "skill_bindings": dict(
                        self.state.keyboard_skill_bindings
                    ),
                    "known_skill_binding_count": (
                        self.state.keyboard_known_skill_bindings
                    ),
                    "left_ctrl_skill_id": self.state.left_ctrl_skill_id,
                    "left_ctrl_skill_known": (
                        self.state.left_ctrl_skill_known
                    ),
                },
                "client_fixed_opaque_records": {
                    "packets_by_opcode": dict(
                        self.state.client_fixed_opaque_records_by_opcode
                    ),
                    "opaque_bytes_by_opcode": dict(
                        self.state.client_fixed_opaque_bytes_by_opcode
                    ),
                    "periodic_last_interval_ms": {
                        opcode: round(interval, 3)
                        for opcode, interval in (
                            self.state.client_periodic_report_last_interval_ms.items()
                        )
                    },
                    "periodic_min_interval_ms": {
                        opcode: round(interval, 3)
                        for opcode, interval in (
                            self.state.client_periodic_report_min_interval_ms.items()
                        )
                    },
                    "periodic_max_interval_ms": {
                        opcode: round(interval, 3)
                        for opcode, interval in (
                            self.state.client_periodic_report_max_interval_ms.items()
                        )
                    },
                    "bodies_redacted": True,
                },
                "world_exit": {
                    "bootstrap_marker_count": (
                        self.state.client_opcode_75_empty_records
                    ),
                    "request_count": self.state.world_exit_requests,
                    "requests_from_active_phase": (
                        self.state.world_exit_requests_from_active_phase
                    ),
                    "status_packet_count": (
                        self.state.world_exit_status_packets
                    ),
                    "status_packets_by_opcode": dict(
                        self.state.world_exit_status_packets_by_opcode
                    ),
                    "status_values_redacted": (
                        self.state.world_exit_status_packets
                    ),
                    "matched_termination_count": (
                        self.state.matched_world_exit_terminations
                    ),
                    "pending_request_count": (
                        self.state.pending_world_exit_requests
                    ),
                    "last_round_trip_ms": (
                        None
                        if self.state.last_world_exit_round_trip_ms is None
                        else round(self.state.last_world_exit_round_trip_ms, 3)
                    ),
                    "max_round_trip_ms": (
                        None
                        if self.state.max_world_exit_round_trip_ms is None
                        else round(self.state.max_world_exit_round_trip_ms, 3)
                    ),
                },
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
        self._drop_aliases: dict[int, str] = {}
        self._positioned_effect_aliases: dict[int, str] = {}
        self._pending_movements: dict[
            tuple[int, int], deque[PendingMobMovement]
        ] = {}
        self._pending_heartbeat_probes: deque[int] = deque()
        self._pending_opcode_426_notifications: deque[int] = deque()
        self._pending_server_opcode_348: dict[int, deque[int]] = {}
        self._pending_server_opcode_394: deque[tuple[int, str]] = deque()
        self._pending_world_exit_requests: deque[int] = deque()
        self._last_client_periodic_report_timestamp_ns: dict[int, int] = {}
        self._pending_skill_level_changes: deque[
            tuple[int, int, SkillLevelChangeRequest]
        ] = deque()
        self._pending_skill_record_acknowledgements: deque[
            tuple[int, int]
        ] = deque()
        self._pending_item_uses: deque[PendingItemUse] = deque()
        self._pending_item_pickups: deque[PendingItemPickup] = deque()
        self._pending_client_attacks: dict[
            int, deque[PendingClientAttackHit]
        ] = {}
        self._last_client_skill_use: (
            tuple[int, int, ClientSkillUseRequest] | None
        ) = None
        self._last_server_attack_relay: (
            tuple[PlainFrame, ServerAttackRelay] | None
        ) = None
        self._unknown_npc_updates: set[tuple[int, int]] = set()
        self._started = False

    def _alias(self, aliases: dict[int, str], object_id: int, prefix: str) -> str:
        alias = aliases.get(object_id)
        if alias is None:
            alias = f"{prefix}:{len(aliases) + 1}"
            aliases[object_id] = alias
        return alias

    def _attach_item_pickup_effect(
        self, frame: PlainFrame, effect: dict[str, object]
    ) -> PendingItemPickup | None:
        pending = next(
            (
                candidate
                for candidate in self._pending_item_pickups
                if candidate.effect is None and not candidate.result_confirmed
            ),
            None,
        )
        if pending is None:
            return None
        pending.effect = {
            **effect,
            "request_frame": pending.request_frame_index,
            "response_ms": round(
                (frame.timestamp_ns - pending.request_timestamp_ns) / 1e6,
                3,
            ),
        }
        return pending

    def apply_runtime_event(self, event: GameplayEvent) -> None:
        """Fold explicit policy rejections into pending request accounting."""

        if event.kind == "item_use_request_rejected":
            if not isinstance(event.details.get("reason"), str):
                self.issues.append(
                    "runtime item-use rejection reason must be a string"
                )
                return
            request_fields = {
                name: event.details.get(name)
                for name in ("client_tick", "slot", "item_id")
            }
            pending = next(
                (
                    candidate
                    for candidate in self._pending_item_uses
                    if event.timestamp_ns >= candidate.request_timestamp_ns
                    and candidate.request.safe_dict() == request_fields
                ),
                None,
            )
            if pending is None:
                observed_request = any(
                    candidate.kind == "item_use_requested"
                    and event.timestamp_ns >= candidate.timestamp_ns
                    and all(
                        candidate.details.get(name) == value
                        for name, value in request_fields.items()
                    )
                    for candidate in self.events
                )
                if not observed_request:
                    self.issues.append(
                        "runtime item-use rejection had no matching observed "
                        "request"
                    )
                    return
            else:
                self._pending_item_uses.remove(pending)
                self.state.pending_item_uses -= 1
            self.state.item_use_policy_rejections += 1
            return
        if event.kind == "item_pickup_request_rejected":
            if not isinstance(event.details.get("reason"), str):
                self.issues.append(
                    "runtime item-pickup rejection reason must be a string"
                )
                return
            request_fields = {
                name: event.details.get(name)
                for name in (
                    "control_value",
                    "field_epoch",
                    "client_tick",
                    "position_x",
                    "position_y",
                    "item_validation_token_present",
                    "optional_proof_bytes",
                )
            }
            pending = next(
                (
                    candidate
                    for candidate in self._pending_item_pickups
                    if event.timestamp_ns >= candidate.request_timestamp_ns
                    and candidate.request.safe_dict() == request_fields
                ),
                None,
            )
            if pending is None:
                self.issues.append(
                    "runtime item-pickup rejection had no matching pending "
                    "request"
                )
                return
            self._pending_item_pickups.remove(pending)
            self.state.pending_item_pickups -= 1
            self.state.item_pickup_policy_rejections += 1

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

    def _fold_client_attack(
        self,
        frame: PlainFrame,
        action: ClientAttackAction | ClientOpcode54AttackAction,
    ) -> PacketObservation:
        target_object_id = action.target_object_id
        self.state.client_attack_actions += 1
        self.state.client_attack_actions_by_opcode[action.opcode] += 1
        if isinstance(action, ClientAttackAction):
            shape = f"{action.opcode}:variant={action.variant}"
        else:
            shape = f"54:flags={action.flag_1}:{action.flag_2}"
        self.state.client_attack_shapes[shape] += 1

        details: dict[str, object] = {
            **action.safe_dict(),
            "opcode": action.opcode,
            "shape": shape,
            "field_epoch": self.state.field_epoch,
        }
        damage_values = (
            action.damage_values
            if isinstance(action, ClientAttackAction)
            else ()
        )
        high_bit_markers = (
            action.high_bit_markers
            if isinstance(action, ClientAttackAction)
            else ()
        )
        if damage_values:
            self.state.client_attack_damage_entries += len(damage_values)
            self.state.client_attack_damage_total += sum(damage_values)
            self.state.client_attack_damage_high_bit_markers += sum(
                high_bit_markers
            )
            packet_min = min(damage_values)
            packet_max = max(damage_values)
            self.state.client_attack_damage_min = (
                packet_min
                if self.state.client_attack_damage_min is None
                else min(self.state.client_attack_damage_min, packet_min)
            )
            self.state.client_attack_damage_max = (
                packet_max
                if self.state.client_attack_damage_max is None
                else max(self.state.client_attack_damage_max, packet_max)
            )
        identifiers: dict[str, object] = {}
        if target_object_id is None:
            self.state.client_attack_untargeted_actions += 1
        else:
            self.state.client_attack_targeted_actions += 1
            target_alias = self._alias(
                self._mob_aliases, target_object_id, "mob"
            )
            active_target = target_object_id in self.state.mobs
            known_target = target_object_id in self.state.mob_templates
            if active_target:
                self.state.client_attack_targets_for_active_mobs += 1
            if known_target:
                self.state.client_attack_targets_for_known_mobs += 1
            else:
                self.state.client_attack_targets_for_unknown_mobs += 1
            zero_damage_entries = 0
            target_entity = self.state.mobs.get(target_object_id)
            if isinstance(action, ClientAttackAction):
                self.state.client_attack_damage_actions += 1
                pending = self._pending_client_attacks.setdefault(
                    target_object_id, deque()
                )
                pending_hits = tuple(
                    PendingClientAttackHit(
                        request_frame_index=frame.index,
                        request_timestamp_ns=frame.timestamp_ns,
                        hit_index=hit_index,
                        damage_values=damage_values,
                        high_bit_markers=high_bit_markers,
                        attack_relay_hits_at_submission=(
                            target_entity.attack_relay_hits
                            if target_entity is not None
                            else 0
                        ),
                    )
                    for hit_index, damage in enumerate(damage_values)
                    if damage != 0
                )
                pending.extend(pending_hits)
                zero_damage_entries = len(damage_values) - len(pending_hits)
                self.state.client_attack_zero_damage_entries += (
                    zero_damage_entries
                )
                self.state.pending_client_attack_effects += len(pending_hits)
                if target_entity is not None:
                    target_entity.client_attack_submitted_hits += len(
                        damage_values
                    )
                    target_entity.client_attack_submitted_damage += sum(
                        damage_values
                    )
                    target_entity.client_attack_submitted_high_bit_markers += (
                        sum(high_bit_markers)
                    )
            details.update(
                {
                    "target": target_alias,
                    "active_target": active_target,
                    "known_target": known_target,
                    "pending_health_effects_for_target": len(
                        self._pending_client_attacks.get(
                            target_object_id, ()
                        )
                    ),
                    "zero_damage_entries": zero_damage_entries,
                }
            )
            identifiers["target_object_id"] = target_object_id

        self._event(
            frame,
            "client_attack_submitted",
            details=details,
            identifiers=identifiers,
        )
        return self._observation(
            frame,
            kind="client_attack_action",
            coverage=ShapeCoverage.PARTIAL,
            parsed=action,
            details=details,
            issues=(
                (
                    "attack target and damage-array roles are "
                    "capture-correlated; control, value, and opaque target "
                    "prefix/tail roles remain uninterpreted"
                    if isinstance(action, ClientAttackAction)
                    else "attack target role is capture-correlated; control, "
                    "value, and opaque body roles remain uninterpreted"
                ),
            ),
        )

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
            entry_details = {
                "character_id_present": True,
                "entry_value_present": True,
                "opaque_ticket_bytes": len(request.opaque_ticket),
            }
            self._event(
                frame,
                "world_entry_requested",
                details=entry_details,
                identifiers={"character_id": request.character_id},
            )
            return self._observation(
                frame,
                kind="world_entry_request",
                coverage=ShapeCoverage.PARTIAL,
                parsed=request,
                details=entry_details,
                issues=("world entry value and ticket tail remain opaque",),
            )
        if opcode == 75:
            marker = ClientOpcode75EmptyRecord.parse(payload)
            self.state.client_opcode_75_empty_records += 1
            details = {
                "field_epoch": self.state.field_epoch,
                "phase": self.state.phase.value,
            }
            self._event(
                frame,
                "client_opcode_75_empty_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_75_empty_record",
                coverage=ShapeCoverage.FULL,
                parsed=marker,
                details=details,
            )
        if opcode in {100, 307, 308, 310, 311}:
            record = ClientFixedOpaqueRecord.parse(payload)
            body_length = len(record.opaque_body)
            self.state.client_fixed_opaque_records_by_opcode[opcode] += 1
            self.state.client_fixed_opaque_bytes_by_opcode[opcode] += body_length
            interval_ms: float | None = None
            if opcode in {308, 311}:
                previous_timestamp_ns = (
                    self._last_client_periodic_report_timestamp_ns.get(opcode)
                )
                self._last_client_periodic_report_timestamp_ns[opcode] = (
                    frame.timestamp_ns
                )
                if previous_timestamp_ns is not None:
                    interval_ms = (
                        frame.timestamp_ns - previous_timestamp_ns
                    ) / 1e6
                    self.state.client_periodic_report_last_interval_ms[
                        opcode
                    ] = interval_ms
                    self.state.client_periodic_report_min_interval_ms[
                        opcode
                    ] = min(
                        self.state.client_periodic_report_min_interval_ms.get(
                            opcode, interval_ms
                        ),
                        interval_ms,
                    )
                    self.state.client_periodic_report_max_interval_ms[
                        opcode
                    ] = max(
                        self.state.client_periodic_report_max_interval_ms.get(
                            opcode, interval_ms
                        ),
                        interval_ms,
                    )
            details: dict[str, object] = {
                **record.safe_dict(),
                "field_epoch": self.state.field_epoch,
                "phase": self.state.phase.value,
            }
            if interval_ms is not None:
                details["interval_ms"] = round(interval_ms, 3)
            event_kind = (
                "client_periodic_report_submitted"
                if opcode in {308, 311}
                else "client_fixed_record_submitted"
            )
            self._event(frame, event_kind, details=details)
            return self._observation(
                frame,
                kind="client_fixed_opaque_record",
                coverage=ShapeCoverage.PARTIAL,
                parsed=record,
                details=details,
                issues=(
                    f"client opcode-{opcode} fixed body remains opaque",
                ),
            )
        if opcode == 241:
            request = ClientWorldExitRequest.parse(payload)
            phase_before = self.state.phase
            self._pending_world_exit_requests.append(frame.timestamp_ns)
            self.state.world_exit_requests += 1
            self.state.pending_world_exit_requests += 1
            if phase_before == GameplayPhase.ACTIVE:
                self.state.world_exit_requests_from_active_phase += 1
            self.state.phase = GameplayPhase.EXIT_REQUESTED
            details = {
                "field_epoch": self.state.field_epoch,
                "phase_before": phase_before.value,
                "pending_requests": self.state.pending_world_exit_requests,
            }
            self._event(frame, "world_exit_requested", details=details)
            return self._observation(
                frame,
                kind="client_world_exit_request",
                coverage=ShapeCoverage.FULL,
                parsed=request,
                details=details,
            )
        if opcode in {45, 46}:
            status = ClientWorldExitStatus.parse(payload)
            self.state.world_exit_status_packets += 1
            self.state.world_exit_status_packets_by_opcode[opcode] += 1
            details = {
                **status.safe_dict(),
                "correlated_exit_request": bool(
                    self._pending_world_exit_requests
                ),
                "pending_requests": self.state.pending_world_exit_requests,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "world_exit_status_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_world_exit_status",
                coverage=ShapeCoverage.FULL,
                parsed=status,
                details=details,
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
            stage_details = {
                "field_epoch": self.state.field_epoch,
                "stage": stage.stage,
                "opaque_tail_bytes": len(stage.opaque_tail),
            }
            if stage.stage == 0:
                self._event(
                    frame,
                    "field_load_stage_observed",
                    details=stage_details,
                )
                return self._observation(
                    frame,
                    kind="field_load_stage",
                    coverage=ShapeCoverage.PARTIAL,
                    parsed=stage,
                    details=stage_details,
                    issues=(
                        "field-load stage-0 extended variant semantics remain opaque",
                    ),
                )
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
                details=stage_details,
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
                details=stage_details,
            )
        if opcode == 80:
            request = ItemUseRequest.parse(payload)
            self.state.item_use_requests += 1
            self.state.item_use_requests_by_item[request.item_id] += 1
            item = next(
                (
                    item
                    for item in self.state.inventory_items.get("use", ())
                    if item.slot == request.slot
                ),
                None,
            )
            known_slot = item is not None
            item_matches = item is not None and item.item_id == request.item_id
            details: dict[str, object] = {
                **request.safe_dict(),
                "known_slot": known_slot,
                "item_matches_slot": item_matches,
                "field_epoch": self.state.field_epoch,
            }
            if item is None:
                self.state.item_use_unknown_slots += 1
                self.warnings.append(
                    f"item-use request referenced unknown Use slot {request.slot}"
                )
            elif not item_matches:
                self.state.item_use_item_mismatches += 1
                self.warnings.append(
                    f"item-use request template {request.item_id} did not match "
                    f"Use slot {request.slot} template {item.item_id}"
                )
            elif item.quantity is None or item.quantity <= 0:
                self.state.item_use_inventory_mismatches += 1
                self.warnings.append(
                    f"item-use request referenced non-consumable or empty "
                    f"Use slot {request.slot}"
                )
            else:
                expected_quantity = item.quantity - 1
                details["quantity_before"] = item.quantity
                details["predicted_quantity"] = expected_quantity
                effect = CAPTURED_ITEM_USE_EFFECTS.get(request.item_id)
                effect_field = None
                expected_effect_value = None
                if effect is not None:
                    effect_field, maximum_field, amount = effect
                    current_value = getattr(self.state, effect_field)
                    maximum_value = getattr(self.state, maximum_field)
                    details["predicted_effect_field"] = effect_field
                    details["predicted_effect_amount"] = amount
                    if current_value is not None and maximum_value is not None:
                        expected_effect_value = min(
                            maximum_value, current_value + amount
                        )
                        details["effect_before"] = current_value
                        details["predicted_effect_value"] = (
                            expected_effect_value
                        )
                self._pending_item_uses.append(
                    PendingItemUse(
                        request_frame_index=frame.index,
                        request_timestamp_ns=frame.timestamp_ns,
                        request=request,
                        expected_quantity=expected_quantity,
                        effect_field=effect_field,
                        expected_effect_value=expected_effect_value,
                    )
                )
                self.state.pending_item_uses += 1
            self._event(frame, "item_use_requested", details=details)
            return self._observation(
                frame,
                kind="item_use_request",
                coverage=ShapeCoverage.PARTIAL,
                parsed=request,
                details=details,
                issues=(
                    "client tick semantics and item effects beyond the two "
                    "captured potion templates remain neutral",
                ),
            )
        if opcode == 185:
            request = ItemPickupRequest.parse(payload)
            alias = self._alias(
                self._drop_aliases, request.drop_object_id, "drop"
            )
            drop = self.state.field_drops.get(request.drop_object_id)
            if drop is None:
                self.state.item_pickup_unknown_drops += 1
            else:
                self.state.item_pickup_known_drops += 1
            epoch_matches = request.field_epoch == self.state.field_epoch
            self.state.item_pickup_requests += 1
            if request.optional_proof:
                self.state.item_pickup_extended_requests += 1
            else:
                self.state.item_pickup_base_requests += 1
            if epoch_matches:
                self.state.item_pickup_field_epoch_matches += 1
            else:
                self.state.item_pickup_field_epoch_mismatches += 1
                self.warnings.append(
                    f"item-pickup request field epoch {request.field_epoch} "
                    f"did not match folded epoch {self.state.field_epoch}"
                )
            self._pending_item_pickups.append(
                PendingItemPickup(
                    request_frame_index=frame.index,
                    request_timestamp_ns=frame.timestamp_ns,
                    request=request,
                    expected_drop_kind=(
                        drop.spawn.kind_name if drop is not None else None
                    ),
                    expected_value=(
                        drop.spawn.value if drop is not None else None
                    ),
                )
            )
            self.state.pending_item_pickups += 1
            details: dict[str, object] = {
                **request.safe_dict(),
                "drop": alias,
                "known_drop": drop is not None,
                "field_epoch_matches": epoch_matches,
            }
            if drop is not None:
                details["predicted_result_kind"] = drop.spawn.kind_name
                if drop.spawn.drop_kind == FieldDropSpawn.ITEM:
                    details["predicted_item_id"] = drop.spawn.value
                else:
                    details["predicted_mesos_amount"] = drop.spawn.value
            self._event(
                frame,
                "item_pickup_requested",
                details=details,
                identifiers={"drop_object_id": request.drop_object_id},
            )
            return self._observation(
                frame,
                kind="item_pickup_request",
                coverage=ShapeCoverage.PARTIAL,
                parsed=request,
                details=details,
                issues=(
                    "pickup control, validation token, and optional proof "
                    "semantics remain neutral",
                ),
            )
        if opcode == 47:
            submission = LifeMovementSubmission.parse(payload)
            path = submission.movement
            self.state.life_movement_submissions += 1
            self.state.life_movement_submission_commands += len(path.commands)
            self.state.life_movement_submission_commands_by_type.update(
                command.command_type for command in path.commands
            )
            self.state.life_movement_tail_types[submission.tail_type] += 1
            self.state.life_movement_tail_markers[submission.tail_marker] += 1
            details = {
                "local_object_index": submission.local_object_index,
                "client_token_present": True,
                "control_value": submission.control_value,
                **path.safe_dict(),
                "tail_type": submission.tail_type,
                "opaque_tail_state_bytes": len(submission.opaque_tail_state),
                "tail_marker": submission.tail_marker,
                "path_start_x": submission.path_start_x,
                "path_start_y": submission.path_start_y,
                "path_end_x": submission.path_end_x,
                "path_end_y": submission.path_end_y,
                "field_epoch": self.state.field_epoch,
            }
            self._event(frame, "life_movement_submitted", details=details)
            return self._observation(
                frame,
                kind="life_movement_submission",
                coverage=ShapeCoverage.PARTIAL,
                parsed=submission,
                details=details,
                issues=(
                    "life movement command payload and control/tail roles "
                    "remain opaque",
                ),
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
        if opcode == 293:
            acknowledgement = SkillRecordUpdateAcknowledgement.parse(payload)
            matched_update = bool(
                self._pending_skill_record_acknowledgements
            )
            update_frame: int | None = None
            round_trip_ms: float | None = None
            if matched_update:
                update_frame, update_timestamp_ns = (
                    self._pending_skill_record_acknowledgements.popleft()
                )
                round_trip_ms = (
                    frame.timestamp_ns - update_timestamp_ns
                ) / 1e6
                self.state.pending_skill_record_update_acknowledgements -= 1
                self.state.matched_skill_record_update_acknowledgements += 1
                self.state.last_skill_record_acknowledgement_ms = round_trip_ms
                self.state.max_skill_record_acknowledgement_ms = max(
                    self.state.max_skill_record_acknowledgement_ms or 0.0,
                    round_trip_ms,
                )
            else:
                self.state.unmatched_skill_record_update_acknowledgements += 1
            self.state.skill_record_update_acknowledgements += 1
            self.state.skill_record_acknowledgement_control_values[
                acknowledgement.control_value
            ] += 1
            self.state.skill_record_acknowledgement_trailing_values[
                acknowledgement.trailing_value
            ] += 1
            details: dict[str, object] = {
                **acknowledgement.safe_dict(),
                "matched_update": matched_update,
                "update_frame": update_frame,
                "pending_updates": (
                    self.state.pending_skill_record_update_acknowledgements
                ),
                "field_epoch": self.state.field_epoch,
            }
            if round_trip_ms is not None:
                details["round_trip_ms"] = round(round_trip_ms, 3)
            self._event(
                frame,
                "skill_record_update_acknowledged",
                details=details,
            )
            return self._observation(
                frame,
                kind="skill_record_update_acknowledgement",
                coverage=ShapeCoverage.FULL,
                parsed=acknowledgement,
                details=details,
            )
        if opcode == 279:
            envelope = ClientOpcode279TextEnvelope.parse(payload)
            correlated_server_envelope = bool(self._pending_server_opcode_394)
            observed_gap_ms: float | None = None
            changed_indices: tuple[int, ...] = ()
            same_text_length: bool | None = None
            captured_transform_match: bool | None = None
            changed_span = "uncorrelated"
            if correlated_server_envelope:
                server_timestamp_ns, server_text = (
                    self._pending_server_opcode_394.popleft()
                )
                self.state.pending_server_opcode_394_envelopes -= 1
                self.state.correlated_client_opcode_279_packets += 1
                observed_gap_ms = (
                    frame.timestamp_ns - server_timestamp_ns
                ) / 1e6
                self.state.last_opcode_394_279_gap_ms = observed_gap_ms
                self.state.max_opcode_394_279_gap_ms = max(
                    self.state.max_opcode_394_279_gap_ms or 0.0,
                    observed_gap_ms,
                )
                server_code_units = len(server_text.encode("utf-16le")) // 2
                same_text_length = (
                    server_code_units == envelope.text_code_units
                )
                changed_indices = envelope.changed_code_unit_indices(
                    server_text
                )
                contiguous = bool(changed_indices) and changed_indices == tuple(
                    range(changed_indices[0], changed_indices[-1] + 1)
                )
                if contiguous:
                    changed_span = f"{changed_indices[0]}:{changed_indices[-1]}"
                elif not changed_indices:
                    changed_span = "none"
                else:
                    changed_span = "noncontiguous"
                captured_transform_match = (
                    same_text_length
                    and changed_indices == (10, 11, 12, 13, 14)
                )
                if captured_transform_match:
                    self.state.client_opcode_279_transform_matches += 1
                else:
                    self.state.client_opcode_279_transform_mismatches += 1
            else:
                self.state.uncorrelated_client_opcode_279_packets += 1
            self.state.client_opcode_279_text_packets += 1
            self.state.client_opcode_279_control_values[
                envelope.control_value
            ] += 1
            self.state.client_opcode_279_text_code_units[
                envelope.text_code_units
            ] += 1
            self.state.client_opcode_279_changed_code_unit_counts[
                len(changed_indices)
            ] += 1
            self.state.client_opcode_279_changed_span_shapes[changed_span] += 1
            details: dict[str, object] = {
                **envelope.safe_dict(),
                "correlated_server_envelope": correlated_server_envelope,
                "same_text_length": same_text_length,
                "changed_code_unit_count": len(changed_indices),
                "changed_span": changed_span,
                "captured_transform_match": captured_transform_match,
                "pending_server_envelopes": (
                    self.state.pending_server_opcode_394_envelopes
                ),
                "field_epoch": self.state.field_epoch,
            }
            if observed_gap_ms is not None:
                details["observed_gap_ms"] = round(observed_gap_ms, 3)
            self._event(
                frame,
                "client_opcode_279_text_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_279_text_envelope",
                coverage=ShapeCoverage.FULL,
                parsed=envelope,
                details=details,
            )
        if opcode == 309:
            acknowledgement = ClientOpcode309Acknowledgement.parse(payload)
            matched_notification = bool(
                self._pending_opcode_426_notifications
            )
            round_trip_ms: float | None = None
            if matched_notification:
                notification_timestamp_ns = (
                    self._pending_opcode_426_notifications.popleft()
                )
                round_trip_ms = (
                    frame.timestamp_ns - notification_timestamp_ns
                ) / 1e6
                self.state.pending_opcode_426_notifications -= 1
                self.state.matched_opcode_309_acknowledgements += 1
                self.state.last_opcode_426_round_trip_ms = round_trip_ms
                self.state.max_opcode_426_round_trip_ms = max(
                    self.state.max_opcode_426_round_trip_ms or 0.0,
                    round_trip_ms,
                )
            else:
                self.state.unmatched_opcode_309_acknowledgements += 1
            self.state.opcode_309_acknowledgements += 1
            details: dict[str, object] = {
                "matched_notification": matched_notification,
                "pending_notifications": (
                    self.state.pending_opcode_426_notifications
                ),
                "field_epoch": self.state.field_epoch,
            }
            if round_trip_ms is not None:
                details["round_trip_ms"] = round(round_trip_ms, 3)
            self._event(
                frame,
                "opcode_309_acknowledgement_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="opcode_309_acknowledgement",
                coverage=ShapeCoverage.FULL,
                parsed=acknowledgement,
                details=details,
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
        if opcode in {50, 52}:
            return self._fold_client_attack(
                frame, ClientAttackAction.parse(payload)
            )
        if opcode == 54:
            return self._fold_client_attack(
                frame, ClientOpcode54AttackAction.parse(payload)
            )
        if opcode == 103:
            request = SkillLevelChangeRequest.parse(payload)
            previous_request = (
                self._pending_skill_level_changes[-1][2]
                if self._pending_skill_level_changes
                else None
            )
            tick_delta = (
                None
                if previous_request is None
                else (request.client_tick - previous_request.client_tick)
                & 0xFFFF_FFFF
            )
            modeled_level = self.state.skill_levels.get(request.skill_id)
            self._pending_skill_level_changes.append(
                (frame.index, frame.timestamp_ns, request)
            )
            self.state.skill_level_change_requests += 1
            self.state.skill_level_change_requests_by_skill_id[
                request.skill_id
            ] += 1
            self.state.pending_skill_level_change_requests += 1
            details = {
                **request.safe_dict(),
                "modeled_level_before": modeled_level,
                "skill_known_before": modeled_level is not None,
                "client_tick_delta": tick_delta,
                "pending_requests": (
                    self.state.pending_skill_level_change_requests
                ),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "skill_level_change_requested",
                details=details,
            )
            return self._observation(
                frame,
                kind="skill_level_change_request",
                coverage=ShapeCoverage.FULL,
                parsed=request,
                details=details,
            )
        if opcode == 104:
            request = ClientSkillUseRequest.parse(payload)
            modeled_skill_level = self.state.skill_levels.get(
                request.skill_id
            )
            bound_key_codes = sorted(
                key_code
                for key_code, skill_id in (
                    self.state.keyboard_skill_bindings.items()
                )
                if skill_id == request.skill_id
            )
            previous_tick = self.state.last_client_skill_tick
            tick_delta = (
                None
                if previous_tick is None
                else (request.client_tick - previous_tick) & 0xFFFF_FFFF
            )
            skill_known = modeled_skill_level is not None
            level_matches = (
                None
                if modeled_skill_level is None
                else request.skill_level == modeled_skill_level
            )
            binding_matches = bool(bound_key_codes)
            self.state.client_skill_use_requests += 1
            self.state.client_skill_use_requests_by_skill_id[
                request.skill_id
            ] += 1
            self.state.client_skill_use_level_values[
                request.skill_level
            ] += 1
            self.state.client_skill_use_trailing_values[
                request.trailing_value
            ] += 1
            if skill_known:
                self.state.client_skill_use_known_skills += 1
                if level_matches:
                    self.state.client_skill_use_level_matches += 1
                else:
                    self.state.client_skill_use_level_mismatches += 1
            else:
                self.state.client_skill_use_unknown_skills += 1
            if binding_matches:
                self.state.client_skill_use_binding_matches += 1
            else:
                self.state.client_skill_use_binding_mismatches += 1
            if (
                previous_tick is not None
                and request.client_tick < previous_tick
            ):
                self.state.client_skill_tick_decreases += 1
            self.state.last_client_skill_tick = request.client_tick
            self._last_client_skill_use = (
                frame.index,
                frame.timestamp_ns,
                request,
            )
            details = {
                **request.safe_dict(),
                "field_epoch": self.state.field_epoch,
                "modeled_skill_level": modeled_skill_level,
                "skill_known": skill_known,
                "skill_level_matches_model": level_matches,
                "bound_key_codes": bound_key_codes,
                "binding_matches_model": binding_matches,
                "client_tick_delta": tick_delta,
            }
            self._event(
                frame,
                "client_skill_use_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_skill_use_request",
                coverage=ShapeCoverage.FULL,
                parsed=request,
                details=details,
            )
        if opcode == 101:
            record = ClientOpcode101Record.parse(payload)
            self.state.client_opcode_101_packets += 1
            self.state.client_opcode_101_header_values[
                record.header_value
            ] += 1
            self.state.client_opcode_101_primary_values[
                record.primary_value
            ] += 1
            self.state.client_opcode_101_flag_values[
                record.flag_value
            ] += 1
            self.state.client_opcode_101_secondary_values[
                record.secondary_value
            ] += 1
            self.state.client_opcode_101_tail_values[
                record.tail_value
            ] += 1
            details = {
                **record.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "client_opcode_101_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_101_record",
                coverage=ShapeCoverage.PARTIAL,
                parsed=record,
                details=details,
                issues=("client opcode-101 field roles remain neutral",),
            )
        if opcode == 13 and len(payload) >= 3:
            message_type = payload[2]
            if message_type == 1:
                message = Opcode13Type1Envelope.parse(payload)
            elif message_type in {6, 13}:
                message = Opcode13Envelope.parse(payload)
            else:
                return self._observation(
                    frame,
                    kind=f"client_opcode_{opcode}",
                    coverage=ShapeCoverage.UNKNOWN,
                )
            opaque_bytes = len(message.opaque_payload)
            self.state.client_opcode_13_messages += 1
            self.state.client_opcode_13_messages_by_type[message_type] += 1
            self.state.client_opcode_13_opaque_bytes += opaque_bytes
            self.state.client_opcode_13_opaque_lengths[opaque_bytes] += 1
            details = {
                "message_type": message_type,
                "opaque_payload_bytes": opaque_bytes,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "client_opcode_13_message_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_13_message",
                coverage=ShapeCoverage.PARTIAL,
                parsed=message,
                details=details,
                issues=("client opcode-13 payload remains opaque",),
            )
        if opcode == 43:
            envelope = ClientOpcode43Envelope.parse(payload)
            self.state.client_opcode_43_packets += 1
            self.state.client_opcode_43_sequences[envelope.sequence] += 1
            self.state.client_opcode_43_variants[envelope.variant] += 1
            self.state.client_opcode_43_text_code_units[
                envelope.text_code_units
            ] += 1
            self.state.client_opcode_43_opaque_bytes += (
                envelope.opaque_byte_count
            )
            details = {
                **envelope.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "client_opcode_43_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_43_envelope",
                coverage=ShapeCoverage.PARTIAL,
                parsed=envelope,
                details=details,
                issues=(
                    "client opcode-43 identifier, text, opaque bytes, and "
                    "higher-level purpose remain semantically unresolved",
                ),
            )
        if opcode == 66:
            acknowledgement = ClientOpcode66Acknowledgement.parse(payload)
            pending = self._pending_server_opcode_348.get(
                acknowledgement.selector
            )
            matched_request = bool(pending)
            round_trip_ms: float | None = None
            if pending:
                request_timestamp_ns = pending.popleft()
                round_trip_ms = (
                    frame.timestamp_ns - request_timestamp_ns
                ) / 1e6
                self.state.pending_server_opcode_348_requests -= 1
                self.state.matched_client_opcode_66_acknowledgements += 1
                self.state.last_opcode_348_round_trip_ms = round_trip_ms
                self.state.max_opcode_348_round_trip_ms = max(
                    self.state.max_opcode_348_round_trip_ms or 0.0,
                    round_trip_ms,
                )
                if not pending:
                    self._pending_server_opcode_348.pop(
                        acknowledgement.selector, None
                    )
            else:
                self.state.unmatched_client_opcode_66_acknowledgements += 1
            self.state.client_opcode_66_acknowledgements += 1
            self.state.client_opcode_66_selectors[
                acknowledgement.selector
            ] += 1
            self.state.client_opcode_66_status_values[
                acknowledgement.status_value
            ] += 1
            self.state.client_opcode_66_shapes[acknowledgement.shape] += 1
            if acknowledgement.optional_value is not None:
                self.state.client_opcode_66_optional_values += 1
            details: dict[str, object] = {
                **acknowledgement.safe_dict(),
                "matched_request": matched_request,
                "pending_requests": (
                    self.state.pending_server_opcode_348_requests
                ),
                "field_epoch": self.state.field_epoch,
            }
            if round_trip_ms is not None:
                details["round_trip_ms"] = round(round_trip_ms, 3)
            self._event(
                frame,
                "server_opcode_348_acknowledged",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_66_acknowledgement",
                coverage=ShapeCoverage.FULL,
                parsed=acknowledgement,
                details=details,
            )
        if opcode == 114:
            envelope = ClientOpcode114TextEnvelope.parse(payload)
            self.state.client_opcode_114_packets += 1
            self.state.client_opcode_114_control_values[
                envelope.control_value
            ] += 1
            self.state.client_opcode_114_text_code_units[
                envelope.text_code_units
            ] += 1
            self.state.client_opcode_114_redacted_values += 1
            details = {
                **envelope.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "client_opcode_114_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_114_text_envelope",
                coverage=ShapeCoverage.PARTIAL,
                parsed=envelope,
                details=details,
                issues=(
                    "client opcode-114 text, trailing value, and "
                    "higher-level purpose remain semantically unresolved",
                ),
            )
        if opcode == 122 and ClientOpcode122Envelope.is_captured_shape(payload):
            envelope = ClientOpcode122Envelope.parse(payload)
            self.state.client_opcode_122_packets += 1
            self.state.client_opcode_122_selectors[envelope.selector] += 1
            self.state.client_opcode_122_shapes[envelope.shape] += 1
            if envelope.terminal_sentinel_present:
                self.state.client_opcode_122_terminal_sentinels += 1
            details = {
                **envelope.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "client_opcode_122_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_122_envelope",
                coverage=ShapeCoverage.FULL,
                parsed=envelope,
                details=details,
            )
        if opcode == 217:
            record_set = ClientOpcode217RecordSet.parse(payload)
            self.state.client_opcode_217_packets += 1
            if record_set.record_format is None:
                self.state.client_opcode_217_compact_packets += 1
            else:
                self.state.client_opcode_217_record_sets += 1
                self.state.client_opcode_217_records += record_set.record_count
                self.state.client_opcode_217_records_by_format[
                    record_set.record_format
                ] += record_set.record_count
                self.state.client_opcode_217_record_counts[
                    record_set.record_count
                ] += 1
            details = {
                **record_set.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "client_opcode_217_submitted",
                details=details,
            )
            return self._observation(
                frame,
                kind="client_opcode_217_record_set",
                coverage=ShapeCoverage.PARTIAL,
                parsed=record_set,
                details=details,
                issues=(
                    "client opcode-217 prefix, records, trailer, and effect "
                    "semantics remain opaque",
                ),
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
        if opcode == 43:
            envelope = ServerOpcode43Envelope.parse(payload)
            self.state.server_opcode_43_packets += 1
            self.state.server_opcode_43_message_types[
                envelope.message_type
            ] += 1
            self.state.server_opcode_43_opaque_bytes += len(
                envelope.opaque_body
            )
            details = {
                **envelope.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_43_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_43_envelope",
                coverage=ShapeCoverage.PARTIAL,
                parsed=envelope,
                details=details,
                issues=(
                    "server opcode-43 body and higher-level purpose remain "
                    "semantically unresolved",
                ),
            )
        if opcode == 39:
            change_set = InventoryChangeSet.parse(payload)
            modification_details: list[dict[str, object]] = []
            pickup_effect_candidates: list[dict[str, object]] = []
            applied_modifications = 0
            self.state.inventory_change_packets += 1
            self.state.inventory_update_flags[change_set.update_flag] += 1
            if not change_set.modifications:
                self.state.inventory_empty_change_packets += 1
            for modification in change_set.modifications:
                operation_name = InventoryModification.OPERATION_NAMES[
                    modification.operation
                ]
                inventory_name = InventoryModification.INVENTORY_NAMES[
                    modification.inventory_type
                ]
                self.state.inventory_modifications += 1
                self.state.inventory_modifications_by_operation[
                    operation_name
                ] += 1
                items = list(self.state.inventory_items.get(inventory_name, ()))
                existing_index = next(
                    (
                        index
                        for index, item in enumerate(items)
                        if item.slot == modification.slot
                    ),
                    None,
                )
                existing = (
                    items[existing_index]
                    if existing_index is not None
                    else None
                )
                details = modification.safe_dict()
                details["known_slot"] = existing is not None
                if modification.operation == InventoryModification.ADD:
                    if modification.item is None:
                        raise PacketShapeError(
                            "inventory add observation has no parsed item"
                        )
                    added = InventoryItemEntity.from_initial(modification.item)
                    details["replaced_existing_slot"] = existing is not None
                    if existing_index is None:
                        items.append(added)
                    else:
                        items[existing_index] = added
                    if added.quantity is not None and added.quantity > 0:
                        pickup_effect_candidates.append(
                            {
                                "kind": "item",
                                "inventory": inventory_name,
                                "slot": added.slot,
                                "item_id": added.item_id,
                                "quantity_delta": added.quantity,
                                "previous_quantity": (
                                    existing.quantity
                                    if existing is not None
                                    else None
                                ),
                                "current_quantity": added.quantity,
                            }
                        )
                    applied_modifications += 1
                elif (
                    modification.operation
                    == InventoryModification.UPDATE_QUANTITY
                ):
                    if existing_index is None or existing is None:
                        self.state.inventory_unknown_slot_modifications += 1
                        self.warnings.append(
                            f"inventory quantity update referenced unknown "
                            f"{inventory_name} slot {modification.slot}"
                        )
                    else:
                        details["item_id"] = existing.item_id
                        details["previous_quantity"] = existing.quantity
                        if existing.quantity is not None:
                            quantity_delta = (
                                modification.quantity - existing.quantity
                            )
                            if quantity_delta > 0:
                                pickup_effect_candidates.append(
                                    {
                                        "kind": "item",
                                        "inventory": inventory_name,
                                        "slot": modification.slot,
                                        "item_id": existing.item_id,
                                        "quantity_delta": quantity_delta,
                                        "previous_quantity": existing.quantity,
                                        "current_quantity": (
                                            modification.quantity
                                        ),
                                    }
                                )
                        pending_item_use = next(
                            (
                                pending
                                for pending in self._pending_item_uses
                                if not pending.inventory_confirmed
                                and pending.request.slot == modification.slot
                                and pending.request.item_id == existing.item_id
                            ),
                            None,
                        )
                        if pending_item_use is not None:
                            quantity_matches = (
                                modification.quantity
                                == pending_item_use.expected_quantity
                            )
                            details["item_use_request_frame"] = (
                                pending_item_use.request_frame_index
                            )
                            details["item_use_response_ms"] = round(
                                (
                                    frame.timestamp_ns
                                    - pending_item_use.request_timestamp_ns
                                )
                                / 1e6,
                                3,
                            )
                            details["item_use_quantity_matches"] = (
                                quantity_matches
                            )
                            if quantity_matches:
                                self.state.item_use_inventory_matches += 1
                            else:
                                self.state.item_use_inventory_mismatches += 1
                                self.warnings.append(
                                    f"item-use response for Use slot "
                                    f"{modification.slot} set quantity "
                                    f"{modification.quantity}, expected "
                                    f"{pending_item_use.expected_quantity}"
                                )
                            pending_item_use.inventory_confirmed = True
                            if (
                                pending_item_use.effect_field is None
                                or pending_item_use.expected_effect_value is None
                            ):
                                self._pending_item_uses.remove(pending_item_use)
                                self.state.pending_item_uses -= 1
                        items[existing_index] = replace(
                            existing, quantity=modification.quantity
                        )
                        applied_modifications += 1
                elif modification.operation == InventoryModification.MOVE:
                    destination_slot = modification.destination_slot
                    if (
                        existing is None
                        or existing_index is None
                        or destination_slot is None
                    ):
                        self.state.inventory_unknown_slot_modifications += 1
                        self.warnings.append(
                            f"inventory move referenced unknown "
                            f"{inventory_name} slot {modification.slot}"
                        )
                    else:
                        destination_existing = next(
                            (
                                item
                                for item in items
                                if item.slot == destination_slot
                            ),
                            None,
                        )
                        details["item_id"] = existing.item_id
                        details["destination_known"] = (
                            destination_existing is not None
                        )
                        items = [
                            item
                            for item in items
                            if item.slot
                            not in {modification.slot, destination_slot}
                        ]
                        items.append(replace(existing, slot=destination_slot))
                        if destination_existing is not None:
                            items.append(
                                replace(
                                    destination_existing,
                                    slot=modification.slot,
                                )
                            )
                        applied_modifications += 1
                else:
                    if existing_index is None or existing is None:
                        self.state.inventory_unknown_slot_modifications += 1
                        self.warnings.append(
                            f"inventory remove referenced unknown "
                            f"{inventory_name} slot {modification.slot}"
                        )
                    else:
                        details["removed_item_id"] = existing.item_id
                        details["removed_quantity"] = existing.quantity
                        items.pop(existing_index)
                        applied_modifications += 1
                self.state.inventory_items[inventory_name] = tuple(
                    sorted(items, key=lambda item: item.slot)
                )
                modification_details.append(details)
            item_pickup_effect: dict[str, object] | None = None
            if len(pickup_effect_candidates) == 1:
                pending_item_pickup = self._attach_item_pickup_effect(
                    frame, pickup_effect_candidates[0]
                )
                if pending_item_pickup is not None:
                    item_pickup_effect = pending_item_pickup.effect
            details = {
                "update_flag": change_set.update_flag,
                "modification_count": len(change_set.modifications),
                "applied_modifications": applied_modifications,
                "modifications": modification_details,
                "field_epoch": self.state.field_epoch,
            }
            if item_pickup_effect is not None:
                details["item_pickup_effect"] = item_pickup_effect
            self._event(frame, "inventory_change_set_received", details=details)
            return self._observation(
                frame,
                kind="inventory_change_set",
                coverage=ShapeCoverage.PARTIAL,
                parsed=change_set,
                details=details,
                issues=(
                    "inventory update flag and extended item metadata roles "
                    "remain neutral",
                ),
            )
        if opcode == 42:
            header = LocalTemporaryStatSetHeader.parse(payload)
            mask_pattern = ":".join(
                f"{word:08x}" for word in header.mask_words
            )
            enabled_bit_count = len(header.enabled_bit_indices)
            self.state.local_temporary_stat_sets += 1
            self.state.local_temporary_stat_enabled_bits += enabled_bit_count
            self.state.local_temporary_stat_mask_patterns[mask_pattern] += 1
            self.state.local_temporary_stat_opaque_bytes += len(
                header.opaque_tail
            )
            if header.zero_mask:
                self.state.local_temporary_stat_zero_masks += 1
                if header.zero_mask_flag_a is None:
                    raise PacketShapeError(
                        "decoded zero-mask temporary stat header has no flag A"
                    )
                if header.zero_mask_flag_b is None:
                    raise PacketShapeError(
                        "decoded zero-mask temporary stat header has no flag B"
                    )
                if header.zero_mask_trailing_i16 is None:
                    raise PacketShapeError(
                        "decoded zero-mask temporary stat header has no trailing i16"
                    )
                self.state.local_temporary_stat_zero_flag_a_values[
                    header.zero_mask_flag_a
                ] += 1
                self.state.local_temporary_stat_zero_flag_b_values[
                    header.zero_mask_flag_b
                ] += 1
                self.state.local_temporary_stat_zero_trailing_i16_values[
                    header.zero_mask_trailing_i16
                ] += 1
            else:
                self.state.local_temporary_stat_nonzero_masks += 1
            preceding_skill_candidate: dict[str, object] | None = None
            if self._last_client_skill_use is not None:
                request_frame, request_timestamp_ns, request = (
                    self._last_client_skill_use
                )
                preceding_skill_candidate = {
                    "request_frame": request_frame,
                    "skill_id": request.skill_id,
                    "skill_level": request.skill_level,
                    "response_ms": round(
                        (frame.timestamp_ns - request_timestamp_ns) / 1e6, 3
                    ),
                    "causal_role_proven": False,
                }
            details = {
                **header.safe_dict(),
                "field_epoch": self.state.field_epoch,
                "mask_pattern": mask_pattern,
                "modeled_state_change": (
                    "none" if header.zero_mask else "unknown"
                ),
                "preceding_skill_candidate": preceding_skill_candidate,
                "network_progression_proven": False,
            }
            self._event(
                frame,
                "local_temporary_stat_set_received",
                details=details,
            )
            issues = (
                (
                    "zero-mask suffix is structurally decoded, but its semantic "
                    "roles and safe client progression remain unproven"
                )
                if header.zero_mask and not header.opaque_tail
                else (
                    "zero-mask suffix is structurally decoded, but trailing "
                    "bytes remain opaque"
                )
                if header.zero_mask
                else (
                    "nonzero temporary-stat entry records and suffix remain "
                    "opaque"
                )
            )
            return self._observation(
                frame,
                kind="local_temporary_stat_set_header",
                coverage=ShapeCoverage.PARTIAL,
                parsed=header,
                details=details,
                issues=(issues,),
            )
        if opcode == 77:
            envelope = ServerOpcode77Envelope.parse(payload)
            control_pattern = (
                bytes(envelope.control_bytes).hex()
                if envelope.control_bytes
                else "none"
            )
            text_code_unit_counts = envelope.text_code_unit_counts
            self.state.server_opcode_77_packets += 1
            self.state.server_opcode_77_by_variant[envelope.variant] += 1
            self.state.server_opcode_77_text_fields += len(
                text_code_unit_counts
            )
            self.state.server_opcode_77_text_code_units += sum(
                text_code_unit_counts
            )
            self.state.server_opcode_77_opaque_bytes += len(
                envelope.opaque_tail
            )
            self.state.server_opcode_77_control_patterns[
                f"{envelope.variant}:{control_pattern}"
            ] += 1
            if envelope.terminal_u32 is not None:
                self.state.server_opcode_77_terminal_values[
                    envelope.terminal_u32
                ] += 1
            details = {
                **envelope.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_77_received",
                details=details,
            )
            partial = (
                envelope.variant
                not in ServerOpcode77Envelope.FULLY_BOUNDED_VARIANTS
            )
            return self._observation(
                frame,
                kind="server_opcode_77_envelope",
                coverage=(
                    ShapeCoverage.PARTIAL if partial else ShapeCoverage.FULL
                ),
                parsed=envelope,
                details=details,
                issues=(
                    (
                        f"variant {envelope.variant} retains "
                        f"{len(envelope.opaque_tail)} opaque bytes"
                    ),
                )
                if partial
                else (),
            )
        if opcode == 46:
            update = SkillRecordUpdate.parse(payload)
            record_changes: list[dict[str, int | None]] = []
            for record in update.records:
                previous_level = self.state.skill_levels.get(record.skill_id)
                self.state.skill_levels[record.skill_id] = record.level
                record_changes.append(
                    {
                        "skill_id": record.skill_id,
                        "previous_level": previous_level,
                        "current_level": record.level,
                        "level_delta": (
                            None
                            if previous_level is None
                            else record.level - previous_level
                        ),
                        "auxiliary_value": record.auxiliary_value,
                    }
                )
                self.state.skill_record_auxiliary_values[
                    record.auxiliary_value
                ] += 1

            request_frame: int | None = None
            requested_skill_id: int | None = None
            request_matches: bool | None = None
            request_response_ms: float | None = None
            if update.records:
                if self._pending_skill_level_changes:
                    request_frame, request_timestamp_ns, request = (
                        self._pending_skill_level_changes.popleft()
                    )
                    self.state.pending_skill_level_change_requests -= 1
                    requested_skill_id = request.skill_id
                    request_matches = any(
                        record.skill_id == request.skill_id
                        for record in update.records
                    )
                    request_response_ms = (
                        frame.timestamp_ns - request_timestamp_ns
                    ) / 1e6
                    self.state.last_skill_record_response_ms = (
                        request_response_ms
                    )
                    self.state.max_skill_record_response_ms = max(
                        self.state.max_skill_record_response_ms or 0.0,
                        request_response_ms,
                    )
                    if request_matches:
                        self.state.skill_record_request_matches += 1
                    else:
                        self.state.skill_record_request_mismatches += 1
                        self.warnings.append(
                            "skill record update did not contain the skill id "
                            "from the next pending level-change request"
                        )
                else:
                    self.state.skill_record_updates_without_request += 1

            self._pending_skill_record_acknowledgements.append(
                (frame.index, frame.timestamp_ns)
            )
            self.state.skill_record_updates += 1
            self.state.skill_record_update_records += len(update.records)
            self.state.skill_record_updates_by_flags[
                f"{int(update.flag_a)}:{int(update.flag_b)}"
            ] += 1
            self.state.skill_record_trailing_values[
                update.trailing_value
            ] += 1
            self.state.pending_skill_record_update_acknowledgements += 1
            details: dict[str, object] = {
                **update.safe_dict(),
                "record_changes": record_changes,
                "request_frame": request_frame,
                "requested_skill_id": requested_skill_id,
                "request_matches": request_matches,
                "pending_requests": (
                    self.state.pending_skill_level_change_requests
                ),
                "pending_acknowledgements": (
                    self.state.pending_skill_record_update_acknowledgements
                ),
                "field_epoch": self.state.field_epoch,
            }
            if request_response_ms is not None:
                details["request_response_ms"] = round(
                    request_response_ms, 3
                )
            self._event(frame, "skill_records_updated", details=details)
            return self._observation(
                frame,
                kind="skill_record_update",
                coverage=ShapeCoverage.FULL,
                parsed=update,
                details=details,
            )
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
            item_use_effect: dict[str, object] | None = None
            pending_item_use = next(
                (
                    pending
                    for pending in self._pending_item_uses
                    if pending.inventory_confirmed
                    and pending.effect_field in update.values
                ),
                None,
            )
            if pending_item_use is not None:
                effect_field = pending_item_use.effect_field
                if effect_field is None:
                    raise PacketShapeError(
                        "confirmed item-use effect has no modeled stat field"
                    )
                actual_value = update.values[effect_field]
                effect_matches = (
                    actual_value == pending_item_use.expected_effect_value
                )
                item_use_effect = {
                    "request_frame": pending_item_use.request_frame_index,
                    "item_id": pending_item_use.request.item_id,
                    "slot": pending_item_use.request.slot,
                    "field": effect_field,
                    "expected": pending_item_use.expected_effect_value,
                    "actual": actual_value,
                    "matches": effect_matches,
                    "response_ms": round(
                        (
                            frame.timestamp_ns
                            - pending_item_use.request_timestamp_ns
                        )
                        / 1e6,
                        3,
                    ),
                }
                if effect_matches:
                    self.state.item_use_effect_matches += 1
                else:
                    self.state.item_use_effect_mismatches += 1
                    self.warnings.append(
                        f"item-use response for template "
                        f"{pending_item_use.request.item_id} set "
                        f"{effect_field} to {actual_value}, expected "
                        f"{pending_item_use.expected_effect_value}"
                    )
                self._pending_item_uses.remove(pending_item_use)
                self.state.pending_item_uses -= 1
            item_pickup_effect: dict[str, object] | None = None
            if set(changes) == {"mesos"}:
                previous_mesos = changes["mesos"]["previous"]
                current_mesos = changes["mesos"]["current"]
                if current_mesos is not None:
                    mesos_delta = (
                        None
                        if previous_mesos is None
                        else current_mesos - previous_mesos
                    )
                    if mesos_delta is None or mesos_delta > 0:
                        pending_item_pickup = self._attach_item_pickup_effect(
                            frame,
                            {
                                "kind": "mesos",
                                "amount_delta": mesos_delta,
                                "previous_mesos": previous_mesos,
                                "current_mesos": current_mesos,
                                "baseline_known": previous_mesos is not None,
                            },
                        )
                        if pending_item_pickup is not None:
                            item_pickup_effect = pending_item_pickup.effect
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
            if item_use_effect is not None:
                details["item_use_effect"] = item_use_effect
            if item_pickup_effect is not None:
                details["item_pickup_effect"] = item_pickup_effect
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
        if opcode == 49 and len(payload) > 2 and payload[2] == 0:
            notice = PickupGainNotice.parse(payload)
            pending = next(
                (
                    candidate
                    for candidate in self._pending_item_pickups
                    if not candidate.result_confirmed
                ),
                None,
            )
            self.state.item_pickup_results += 1
            self.state.item_pickup_results_by_kind[notice.kind_name] += 1
            result_matches = False
            details: dict[str, object] = {
                **notice.safe_dict(),
                "matched_request": pending is not None,
                "field_epoch": self.state.field_epoch,
            }
            identifiers: dict[str, object] = {}
            if pending is not None:
                effect = pending.effect
                if notice.kind == PickupGainNotice.ITEM:
                    result_matches = (
                        notice.result_flag == 0
                        and effect is not None
                        and effect.get("kind") == "item"
                        and effect.get("item_id") == notice.item_id
                        and effect.get("quantity_delta") == notice.quantity
                    )
                elif notice.kind == PickupGainNotice.MESOS:
                    if (
                        effect is not None
                        and effect.get("kind") == "mesos"
                        and not effect.get("baseline_known")
                        and notice.mesos_amount is not None
                    ):
                        current_mesos = effect.get("current_mesos")
                        result_matches = (
                            notice.result_flag == 0
                            and isinstance(current_mesos, int)
                            and current_mesos >= notice.mesos_amount
                        )
                        if result_matches:
                            effect["amount_delta"] = notice.mesos_amount
                            effect["inferred_previous_mesos"] = (
                                current_mesos - notice.mesos_amount
                            )
                            self.state.item_pickup_inferred_mesos_baselines += 1
                    else:
                        result_matches = (
                            notice.result_flag == 0
                            and effect is not None
                            and effect.get("kind") == "mesos"
                            and effect.get("amount_delta")
                            == notice.mesos_amount
                        )
                else:
                    result_matches = notice.result_flag == 0 and effect is None
                if notice.kind == PickupGainNotice.ITEM:
                    spawn_matches_notice = (
                        pending.expected_drop_kind == "item"
                        and pending.expected_value == notice.item_id
                    )
                elif notice.kind == PickupGainNotice.MESOS:
                    spawn_matches_notice = (
                        pending.expected_drop_kind == "mesos"
                        and pending.expected_value == notice.mesos_amount
                    )
                else:
                    spawn_matches_notice = (
                        pending.expected_drop_kind == "item"
                        and pending.expected_value == notice.special_value
                    )
                if spawn_matches_notice:
                    self.state.item_pickup_spawn_result_matches += 1
                else:
                    self.state.item_pickup_spawn_result_mismatches += 1
                if (
                    result_matches
                    and spawn_matches_notice
                    and notice.kind == PickupGainNotice.ITEM
                    and notice.item_id is not None
                    and effect is not None
                    and isinstance(effect.get("inventory"), str)
                    and isinstance(effect.get("quantity_delta"), int)
                ):
                    self.state.item_pickup_item_effects_by_template.setdefault(
                        notice.item_id, set()
                    ).add(
                        (
                            effect["inventory"],
                            effect["quantity_delta"],
                        )
                    )
                pending.result_confirmed = True
                alias = self._alias(
                    self._drop_aliases,
                    pending.request.drop_object_id,
                    "drop",
                )
                details.update(
                    {
                        "drop": alias,
                        "request_frame": pending.request_frame_index,
                        "effect": effect,
                        "effect_matches_notice": result_matches,
                        "spawn_matches_notice": spawn_matches_notice,
                        "response_ms": round(
                            (
                                frame.timestamp_ns
                                - pending.request_timestamp_ns
                            )
                            / 1e6,
                            3,
                        ),
                    }
                )
                identifiers["drop_object_id"] = (
                    pending.request.drop_object_id
                )
            if result_matches:
                self.state.item_pickup_effect_matches += 1
            else:
                self.state.item_pickup_effect_mismatches += 1
                self.warnings.append(
                    f"pickup {notice.kind_name} notice did not match the "
                    "next pending request effect"
                )
            self._event(
                frame,
                "item_pickup_result_received",
                details=details,
                identifiers=identifiers,
            )
            return self._observation(
                frame,
                kind="pickup_gain_notice",
                coverage=ShapeCoverage.PARTIAL,
                parsed=notice,
                details=details,
                issues=(
                    "pickup result flag, mesos subtype/tail, and special-value "
                    "semantics remain neutral",
                ),
            )
        if opcode == 49:
            envelope = ServerOpcode49Envelope.parse(payload)
            self.state.server_opcode_49_packets += 1
            self.state.server_opcode_49_by_variant[envelope.variant] += 1
            self.state.server_opcode_49_by_shape[envelope.shape_name] += 1
            if envelope.text_code_unit_count is not None:
                self.state.server_opcode_49_text_fields += 1
                self.state.server_opcode_49_text_code_units += (
                    envelope.text_code_unit_count
                )
            self.state.server_opcode_49_opaque_bytes += len(
                envelope.opaque_tail
            )
            details = {
                **envelope.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_49_received",
                details=details,
            )
            partial = not envelope.fully_bounded
            return self._observation(
                frame,
                kind="server_opcode_49_envelope",
                coverage=(
                    ShapeCoverage.PARTIAL if partial else ShapeCoverage.FULL
                ),
                parsed=envelope,
                details=details,
                issues=(
                    (
                        f"variant {envelope.variant} retains "
                        f"{len(envelope.opaque_tail)} opaque bytes"
                    ),
                )
                if partial
                else (),
            )
        if opcode == 311:
            spawn = FieldDropSpawn.parse(payload)
            alias = self._alias(
                self._drop_aliases, spawn.drop_object_id, "drop"
            )
            existing = self.state.field_drops.get(spawn.drop_object_id)
            refresh_matches = (
                existing is not None
                and replace(
                    existing.spawn,
                    spawn_mode=spawn.spawn_mode,
                )
                == spawn
            )
            self.state.field_drop_spawn_packets += 1
            self.state.field_drop_spawns_by_mode[spawn.spawn_mode] += 1
            if existing is None:
                self.state.field_drop_spawns += 1
                self.state.field_drop_spawns_by_kind[spawn.kind_name] += 1
                event_kind = "field_drop_spawned"
            else:
                self.state.field_drop_refreshes += 1
                event_kind = "field_drop_refreshed"
                if not refresh_matches:
                    self.state.field_drop_refresh_mismatches += 1
                    self.warnings.append(
                        f"field-drop refresh for {alias} changed fields beyond "
                        "the spawn mode"
                    )
            source_mob_alias: str | None = None
            source_mob_known: bool | None = None
            if spawn.source_mob_object_id:
                source_mob_alias = self._alias(
                    self._mob_aliases,
                    spawn.source_mob_object_id,
                    "mob",
                )
                source_mob_known = (
                    spawn.source_mob_object_id in self.state.mob_templates
                )
                if source_mob_known:
                    self.state.field_drop_spawns_with_known_source_mob += 1
                else:
                    self.state.field_drop_spawns_with_unknown_source_mob += 1
            self.state.field_drops[spawn.drop_object_id] = FieldDropEntity(
                alias=alias,
                spawn=spawn,
            )
            details: dict[str, object] = {
                **spawn.safe_dict(),
                "drop": alias,
                "new_drop": existing is None,
                "refresh_matches_prior": refresh_matches,
                "source_mob": source_mob_alias,
                "source_mob_known": source_mob_known,
                "field_epoch": self.state.field_epoch,
            }
            identifiers: dict[str, object] = {
                "drop_object_id": spawn.drop_object_id,
                "owner_value_1": spawn.owner_value_1,
                "owner_value_2": spawn.owner_value_2,
            }
            if spawn.source_mob_object_id:
                identifiers["source_mob_object_id"] = (
                    spawn.source_mob_object_id
                )
            self._event(
                frame,
                event_kind,
                details=details,
                identifiers=identifiers,
            )
            return self._observation(
                frame,
                kind="field_drop_spawn",
                coverage=ShapeCoverage.PARTIAL,
                parsed=spawn,
                details=details,
                issues=(
                    "drop spawn-mode, ownership values/flag, expiration, and "
                    "final-flag roles remain neutral",
                ),
            )
        if opcode == 312 and len(payload) in {7, 11, 15}:
            removal = FieldDropRemoval.parse(payload)
            alias = self._alias(
                self._drop_aliases, removal.drop_object_id, "drop"
            )
            actor_alias = (
                self._alias(self._player_aliases, removal.actor_id, "player")
                if removal.actor_id is not None
                else None
            )
            active_drop = self.state.field_drops.pop(
                removal.drop_object_id, None
            )
            pending = next(
                (
                    candidate
                    for candidate in self._pending_item_pickups
                    if candidate.request.drop_object_id
                    == removal.drop_object_id
                ),
                None,
            )
            self.state.field_drop_removals += 1
            self.state.field_drop_removals_by_reason[removal.reason] += 1
            if active_drop is None:
                self.state.field_drop_removals_for_unknown_drop += 1
            else:
                self.state.field_drop_removals_for_known_drop += 1
            details: dict[str, object] = {
                **removal.safe_dict(),
                "drop": alias,
                "actor": actor_alias,
                "known_active_drop": active_drop is not None,
                "matched_pickup_request": pending is not None,
                "field_epoch": self.state.field_epoch,
            }
            identifiers: dict[str, object] = {
                "drop_object_id": removal.drop_object_id
            }
            if removal.actor_id is not None:
                identifiers["actor_id"] = removal.actor_id
            if pending is not None:
                removal_matches = (
                    pending.result_confirmed
                    and removal.reason == 5
                )
                details.update(
                    {
                        "request_frame": pending.request_frame_index,
                        "result_confirmed": pending.result_confirmed,
                        "pickup_removal_matches": removal_matches,
                        "response_ms": round(
                            (
                                frame.timestamp_ns
                                - pending.request_timestamp_ns
                            )
                            / 1e6,
                            3,
                        ),
                    }
                )
                if removal_matches:
                    self.state.item_pickup_removal_matches += 1
                else:
                    self.state.item_pickup_removal_mismatches += 1
                    self.warnings.append(
                        f"field removal for {alias} did not complete its "
                        "pending pickup result chain"
                    )
                self._pending_item_pickups.remove(pending)
                self.state.pending_item_pickups -= 1
            self._event(
                frame,
                "field_drop_removed",
                details=details,
                identifiers=identifiers,
            )
            return self._observation(
                frame,
                kind="field_drop_removal",
                coverage=ShapeCoverage.PARTIAL,
                parsed=removal,
                details=details,
                issues=(
                    "drop-removal reason, actor role, and trailing value "
                    "semantics remain neutral",
                ),
            )
        if opcode == 9:
            termination = WorldSessionTermination.parse(payload)
            correlated_exit_request = bool(self._pending_world_exit_requests)
            round_trip_ms: float | None = None
            if correlated_exit_request:
                request_timestamp_ns = self._pending_world_exit_requests.popleft()
                self.state.pending_world_exit_requests -= 1
                self.state.matched_world_exit_terminations += 1
                round_trip_ms = (
                    frame.timestamp_ns - request_timestamp_ns
                ) / 1e6
                self.state.last_world_exit_round_trip_ms = round_trip_ms
                self.state.max_world_exit_round_trip_ms = max(
                    self.state.max_world_exit_round_trip_ms or 0.0,
                    round_trip_ms,
                )
            self.state.termination_received = True
            self.state.phase = GameplayPhase.TERMINATED
            details: dict[str, object] = {
                "opaque_reason_bytes": 7,
                "correlated_exit_request": correlated_exit_request,
                "pending_exit_requests": self.state.pending_world_exit_requests,
            }
            if round_trip_ms is not None:
                details["round_trip_ms"] = round(round_trip_ms, 3)
            self._event(
                frame,
                "world_session_termination_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="world_session_termination",
                coverage=ShapeCoverage.PARTIAL,
                parsed=termination,
                details=details,
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
            typed_initial_snapshot = (
                TypedInitialFieldSnapshot.parse(payload)
                if initial_snapshot is not None
                else None
            )
            cleared_npcs = len(self.state.npcs)
            cleared_mobs = len(self.state.mobs)
            cleared_mob_temporary_stats = sum(
                len(entity.temporary_stats)
                for entity in self.state.mobs.values()
            )
            cleared_players = len(self.state.observed_players)
            cleared_drops = len(self.state.field_drops)
            cleared_positioned_effects = len(
                self.state.positioned_effect_entities
            )
            if self.state.entry_character_id is None:
                self.warnings.append(
                    "field snapshot arrived without a captured world entry request"
                )
            self.state.field_epoch += 1
            self.state.field_load_stage = None
            self.state.phase = GameplayPhase.FIELD_LOADING
            self.state.mob_temporary_stats_cleared_on_field_change += (
                cleared_mob_temporary_stats
            )
            self.state.npcs.clear()
            self.state.mobs.clear()
            self.state.mob_templates.clear()
            self.state.observed_players.clear()
            self.state.field_drops.clear()
            self.state.positioned_effect_entities.clear()
            self.state.player_x = None
            self.state.player_y = None
            self._drop_aliases.clear()
            self._pending_movements.clear()
            self.state.pending_movements = 0
            self._pending_item_uses.clear()
            self.state.pending_item_uses = 0
            self._pending_item_pickups.clear()
            self.state.pending_item_pickups = 0
            cleared_client_attack_effects = sum(
                len(pending)
                for pending in self._pending_client_attacks.values()
            )
            self._pending_client_attacks.clear()
            self._last_server_attack_relay = None
            self.state.pending_client_attack_effects = 0
            self.state.client_attack_effects_cleared += (
                cleared_client_attack_effects
            )
            details = {
                "field_epoch": self.state.field_epoch,
                "opaque_snapshot_bytes": len(snapshot.opaque_snapshot),
                "cleared_npcs": cleared_npcs,
                "cleared_mobs": cleared_mobs,
                "cleared_mob_temporary_stats": (
                    cleared_mob_temporary_stats
                ),
                "cleared_players": cleared_players,
                "cleared_drops": cleared_drops,
                "cleared_positioned_effects": cleared_positioned_effects,
                "cleared_client_attack_effects": (
                    cleared_client_attack_effects
                ),
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
                assert typed_initial_snapshot is not None
                progression = typed_initial_snapshot.progression
                progression_shape = (
                    "compact"
                    if isinstance(
                        progression, CompactInitialProgressionSnapshot
                    )
                    else "keyed_properties"
                )
                progression_variant = (
                    progression.variant
                    if isinstance(progression, InitialProgressionSnapshot)
                    else None
                )
                extended_properties = (
                    progression.extended_properties
                    if isinstance(progression, InitialProgressionSnapshot)
                    else ()
                )
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
                    group.name: tuple(
                        InventoryItemEntity.from_initial(item)
                        for item in group.items
                    )
                    for group in inventory.groups
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
                    for key, value in extended_properties
                }
                self.state.progression_variant = progression_variant
                self.state.progression_shape = progression_shape
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
                        "snapshot_marker": initial_snapshot.marker,
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
                        "progression_typed": True,
                        "progression_shape": progression_shape,
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
                details.update(
                    {
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
                                key
                                for key, _ in progression.timestamp_properties
                            ],
                            "saved_map_ids": list(progression.saved_map_ids),
                            "progression_variant": progression_variant,
                            "extended_properties": [
                                {
                                    "key": key,
                                    "value_code_units": (
                                        len(value.encode("utf-16-le")) // 2
                                    ),
                                }
                                for key, value in extended_properties
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
                    }
                )
                if isinstance(
                    progression, CompactInitialProgressionSnapshot
                ):
                    details["compact_variant_header_hex"] = (
                        progression.opaque_variant_header.hex()
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
                        typed_initial_snapshot
                        if typed_initial_snapshot is not None
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
                            "neutral progression/trailer roles remain "
                            "partially opaque",
                        )
                        if typed_initial_snapshot is not None
                        else ("field snapshot body remains opaque",)
                    )
                ),
            )
        if opcode in {156, 385}:
            variable_record = VariableServerRecord.parse(payload)
            variant_key = f"{opcode}:{variable_record.variant}"
            self.state.variable_server_records += 1
            self.state.variable_server_records_by_opcode[opcode] += 1
            self.state.variable_server_variants[variant_key] += 1
            self.state.variable_server_typed_entries += len(
                variable_record.entries
            )
            self.state.variable_server_typed_values += len(
                variable_record.values
            )
            self.state.variable_server_opaque_bytes += len(
                variable_record.opaque_tail
            )
            if opcode == 385 and not variable_record.variant:
                self.state.keyboard_binding_snapshots += 1
                self.state.keyboard_binding_selector_counts = Counter(
                    entry.selector for entry in variable_record.entries
                )
                self.state.keyboard_skill_bindings = (
                    variable_record.keyboard_skill_bindings
                )
                self.state.keyboard_known_skill_bindings = sum(
                    skill_id in self.state.skill_levels
                    for skill_id in self.state.keyboard_skill_bindings.values()
                )
                self.state.left_ctrl_skill_id = (
                    variable_record.left_ctrl_skill_id
                )
                self.state.left_ctrl_skill_known = (
                    self.state.left_ctrl_skill_id in self.state.skill_levels
                    if self.state.left_ctrl_skill_id is not None
                    else False
                )
            details = {
                "opcode": opcode,
                "variant": variable_record.variant,
                "opaque_tail_length": len(variable_record.opaque_tail),
                "entry_count": len(variable_record.entries),
                "text_code_units": (
                    len(variable_record.text.encode("utf-16le")) // 2
                    if variable_record.text is not None
                    else 0
                ),
                "flag": variable_record.flag,
                "value_count": len(variable_record.values),
                "nonzero_keyboard_selector_count": (
                    variable_record.nonzero_keyboard_selector_count
                ),
                "skill_binding_count": len(
                    variable_record.keyboard_skill_bindings
                ),
                "known_skill_binding_count": (
                    self.state.keyboard_known_skill_bindings
                    if opcode == 385 and not variable_record.variant
                    else 0
                ),
                "left_ctrl_skill_id": variable_record.left_ctrl_skill_id,
                "left_ctrl_skill_known": (
                    self.state.left_ctrl_skill_known
                    if opcode == 385 and not variable_record.variant
                    else False
                ),
                "field_epoch": self.state.field_epoch,
            }
            if opcode == 385:
                details["compact"] = bool(variable_record.variant)
            self._event(
                frame,
                "variable_server_record_received",
                details=details,
            )
            if opcode == 385 and not variable_record.variant:
                self._event(
                    frame,
                    "keyboard_bindings_loaded",
                    details=details,
                )
            return self._observation(
                frame,
                kind="variable_server_record",
                coverage=(
                    ShapeCoverage.FULL
                    if not variable_record.opaque_tail
                    else ShapeCoverage.PARTIAL
                ),
                parsed=variable_record,
                details=details,
            )
        if opcode == 247:
            instruction = TutorialUiInstruction.parse(payload)
            details = {
                **instruction.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self.state.tutorial_ui_instructions += 1
            self.state.tutorial_ui_text_code_units[
                instruction.text_code_units
            ] += 1
            self.state.tutorial_ui_value_1[instruction.value_1] += 1
            self.state.tutorial_ui_value_2[instruction.value_2] += 1
            self.state.tutorial_ui_control_values[
                instruction.control_value
            ] += 1
            if instruction.extended_values is not None:
                self.state.tutorial_ui_extended_instructions += 1
            self._event(
                frame,
                "tutorial_ui_instruction_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="tutorial_ui_instruction",
                coverage=ShapeCoverage.FULL,
                parsed=instruction,
                details=details,
            )
        if opcode == 13 and len(payload) >= 3:
            message_type = payload[2]
            if message_type not in {7, 12, 14}:
                return self._observation(
                    frame,
                    kind="server_opcode_13",
                    coverage=ShapeCoverage.UNKNOWN,
                )
            message = Opcode13Envelope.parse(payload)
            opaque_bytes = len(message.opaque_payload)
            self.state.server_opcode_13_messages += 1
            self.state.server_opcode_13_messages_by_type[message_type] += 1
            self.state.server_opcode_13_opaque_bytes += opaque_bytes
            self.state.server_opcode_13_opaque_lengths[opaque_bytes] += 1
            details = {
                "message_type": message_type,
                "opaque_payload_bytes": opaque_bytes,
                "body_redacted": True,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_13_message_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_13_envelope",
                coverage=ShapeCoverage.PARTIAL,
                parsed=message,
                details=details,
                issues=("server opcode-13 payload remains opaque",),
            )
        if opcode == 27:
            ledger_27 = ServerOpcode27IntegerLedger.parse(payload)
            self.state.server_opcode_27_packets += 1
            self.state.server_opcode_27_entry_counts[
                len(ledger_27.entries)
            ] += 1
            self.state.server_opcode_27_text_code_units[
                ledger_27.text_code_units
            ] += 1
            details = {
                **ledger_27.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_27_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_27_integer_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger_27,
                details=details,
            )
        if opcode == 28:
            ledger_28 = ServerOpcode28TextLedger.parse(payload)
            self.state.server_opcode_28_packets += 1
            self.state.server_opcode_28_entry_counts[
                len(ledger_28.entries)
            ] += 1
            self.state.server_opcode_28_text_1_code_units[
                ledger_28.text_1_code_units
            ] += 1
            self.state.server_opcode_28_text_2_code_units[
                ledger_28.text_2_code_units
            ] += 1
            details = {
                **ledger_28.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_28_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_28_text_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger_28,
                details=details,
            )
        if opcode == 29:
            ledger_29 = ServerOpcode29TextLedger.parse(payload)
            self.state.server_opcode_29_packets += 1
            self.state.server_opcode_29_entry_counts[
                len(ledger_29.entries)
            ] += 1
            self.state.server_opcode_29_text_code_units[
                ledger_29.text_code_units
            ] += 1
            details = {
                **ledger_29.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_29_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_29_text_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger_29,
                details=details,
            )
        if opcode == 135:
            ledger_135 = ServerOpcode135BootstrapLedger.parse(payload)
            self.state.server_opcode_135_packets += 1
            self.state.server_opcode_135_section_a_entry_counts[
                len(ledger_135.section_a)
            ] += 1
            self.state.server_opcode_135_section_a_enabled_count += sum(
                entry.enabled for entry in ledger_135.section_a
            )
            self.state.server_opcode_135_section_a_value_counts[
                ledger_135.section_a_value_count
            ] += 1
            self.state.server_opcode_135_section_b_entry_counts[
                len(ledger_135.section_b)
            ] += 1
            self.state.server_opcode_135_section_b_enabled_count += sum(
                entry.enabled for entry in ledger_135.section_b
            )
            self.state.server_opcode_135_section_b_pair_counts[
                ledger_135.section_b_pair_count
            ] += 1
            self.state.server_opcode_135_section_c_pair_counts[
                len(ledger_135.section_c_pairs)
            ] += 1
            self.state.server_opcode_135_section_d_entry_counts[
                len(ledger_135.section_d)
            ] += 1
            self.state.server_opcode_135_section_d_group_1_counts[
                ledger_135.section_d_group_1_count
            ] += 1
            self.state.server_opcode_135_section_d_group_2_counts[
                ledger_135.section_d_group_2_count
            ] += 1
            details = {
                **ledger_135.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_135_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_135_bootstrap_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger_135,
                details=details,
            )
        if opcode == 142:
            ledger_142 = ServerOpcode142TextLedger.parse(payload)
            self.state.server_opcode_142_packets += 1
            self.state.server_opcode_142_enabled_packets += int(
                ledger_142.enabled
            )
            self.state.server_opcode_142_entry_counts[
                len(ledger_142.entries)
            ] += 1
            self.state.server_opcode_142_header_text_code_units[
                ledger_142.header_text_code_units
            ] += 1
            self.state.server_opcode_142_entry_text_code_units[
                ledger_142.entry_text_code_units
            ] += 1
            self.state.server_opcode_142_flag_1_true_count += sum(
                entry.flag_1 for entry in ledger_142.entries
            )
            self.state.server_opcode_142_flag_2_true_count += sum(
                entry.flag_2 for entry in ledger_142.entries
            )
            details = {
                **ledger_142.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_142_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_142_text_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger_142,
                details=details,
            )
        if opcode == 147:
            ledger = ServerOpcode147BoundsLedger.parse(payload)
            rectangle_shape = (
                f"{ledger.rectangle_1}:{ledger.rectangle_2}"
            )
            self.state.server_opcode_147_packets += 1
            self.state.server_opcode_147_value_counts[len(ledger.values)] += 1
            self.state.server_opcode_147_rectangle_shapes[
                rectangle_shape
            ] += 1
            details = {
                **ledger.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "field_bounds_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_147_bounds_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger,
                details=details,
            )
        if opcode == 272:
            ledger_272 = ServerOpcode272Ledger.parse(payload)
            self.state.server_opcode_272_packets += 1
            self.state.server_opcode_272_entry_counts[
                len(ledger_272.entries)
            ] += 1
            self.state.server_opcode_272_group_1_count += (
                ledger_272.group_1_count
            )
            self.state.server_opcode_272_group_2_count += (
                ledger_272.group_2_count
            )
            self.state.server_opcode_272_flag_1_true_count += sum(
                entry.flag_1 for entry in ledger_272.entries
            )
            self.state.server_opcode_272_flag_2_true_count += sum(
                entry.flag_2 for entry in ledger_272.entries
            )
            self.state.server_opcode_272_trailer_values[
                ledger_272.trailer_value
            ] += 1
            details = {
                **ledger_272.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "field_configuration_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_272_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger_272,
                details=details,
            )
        if opcode == 425:
            ledger_425 = ServerOpcode425ValueLedger.parse(payload)
            trailer_shape = str(ledger_425.trailer)
            self.state.server_opcode_425_packets += 1
            self.state.server_opcode_425_value_counts[
                len(ledger_425.values)
            ] += 1
            self.state.server_opcode_425_trailer_shapes[trailer_shape] += 1
            details = {
                **ledger_425.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_425_ledger_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_425_value_ledger",
                coverage=ShapeCoverage.FULL,
                parsed=ledger_425,
                details=details,
            )
        if (
            opcode == 239
            and len(payload) >= 3
            and payload[2]
            in {
                ServerOpcode239Envelope.RECORD_SELECTOR,
                *ServerOpcode239Envelope.EMPTY_SELECTORS,
                ServerOpcode239Envelope.TEXT_SELECTOR,
            }
        ):
            record = ServerOpcode239Envelope.parse(payload)
            self.state.server_opcode_239_packets += 1
            self.state.server_opcode_239_selectors[record.selector] += 1
            self.state.server_opcode_239_records += len(record.records)
            self.state.server_opcode_239_record_values.update(
                member.value for member in record.records
            )
            if record.text is not None:
                self.state.server_opcode_239_text_code_units[
                    record.text_code_units
                ] += 1
            if record.trailing_value is not None:
                self.state.server_opcode_239_trailing_values[
                    record.trailing_value
                ] += 1
            details = {
                **record.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_239_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_239_envelope",
                coverage=ShapeCoverage.FULL,
                parsed=record,
                details=details,
            )
        if opcode == 244 and len(payload) == 15 and payload[2] == 8:
            record = ServerOpcode244DialogueInstruction.parse(payload)
            details = {
                **record.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self.state.instructional_dialogue_requests += 1
            self.state.instructional_dialogue_value_1[record.value_1] += 1
            self.state.instructional_dialogue_value_2[record.value_2] += 1
            self.state.instructional_dialogue_value_3[record.value_3] += 1
            self._event(
                frame,
                "instructional_dialogue_requested",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_244_dialogue_instruction",
                coverage=ShapeCoverage.FULL,
                parsed=record,
                details=details,
            )
        if opcode in {320, 322, 323}:
            if opcode == 320:
                effect_record = ServerOpcode320PositionedEffectRecord.parse(payload)
            elif opcode == 322:
                effect_record = ServerOpcode322PositionedEffectRecord.parse(payload)
            else:
                effect_record = ServerOpcode323PositionedEffectRecord.parse(payload)
            primary_value = effect_record.primary_value
            existing = self.state.positioned_effect_entities.get(primary_value)
            new_entity = existing is None
            if existing is None:
                alias = self._alias(
                    self._positioned_effect_aliases,
                    primary_value,
                    "effect",
                )
                existing = PositionedEffectEntity(
                    alias=alias,
                    x=effect_record.x,
                    y=effect_record.y,
                    last_opcode=opcode,
                )
                self.state.positioned_effect_entities[primary_value] = existing
                self.state.positioned_effect_new_entities += 1
                if opcode == 323:
                    self.state.positioned_effect_unknown_updates += 1
            else:
                existing.x = effect_record.x
                existing.y = effect_record.y
                existing.last_opcode = opcode
                self.state.positioned_effect_updates += 1
            self.state.positioned_effect_records += 1
            self.state.positioned_effect_records_by_opcode[opcode] += 1
            self.state.positioned_effect_control_values[
                f"{opcode}:{effect_record.control_value}"
            ] += 1
            details = {
                "entity": existing.alias,
                **effect_record.safe_dict(),
                "new_entity": new_entity,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "positioned_effect_observed",
                details=details,
                identifiers={"primary_value": primary_value},
            )
            return self._observation(
                frame,
                kind="positioned_effect_record",
                coverage=ShapeCoverage.FULL,
                parsed=effect_record,
                details=details,
            )
        if opcode == 169:
            instruction = ServerOpcode169TextInstruction.parse(payload)
            self.state.server_opcode_169_packets += 1
            self.state.server_opcode_169_selectors[instruction.selector] += 1
            self.state.server_opcode_169_text_code_units[
                instruction.text_code_units
            ] += 1
            details = {
                **instruction.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_169_text_instruction_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_169_text_instruction",
                coverage=ShapeCoverage.FULL,
                parsed=instruction,
                details=details,
            )
        if (
            opcode == 348
            and len(payload) >= 8
            and payload[7]
            in {
                ServerOpcode348TextEnvelope.EXTENDED_SELECTOR,
                *ServerOpcode348TextEnvelope.SIMPLE_SELECTORS,
            }
        ):
            envelope = ServerOpcode348TextEnvelope.parse(payload)
            pending = self._pending_server_opcode_348.setdefault(
                envelope.selector, deque()
            )
            pending.append(frame.timestamp_ns)
            self.state.pending_server_opcode_348_requests += 1
            self.state.server_opcode_348_packets += 1
            self.state.server_opcode_348_categories[envelope.category] += 1
            self.state.server_opcode_348_selectors[envelope.selector] += 1
            self.state.server_opcode_348_values[envelope.value] += 1
            self.state.server_opcode_348_text_code_units[
                envelope.text_code_units
            ] += 1
            if envelope.control_1 is not None:
                control_pair = f"{envelope.control_1}:{envelope.control_2}"
                self.state.server_opcode_348_control_pairs[control_pair] += 1
            details = {
                **envelope.safe_dict(),
                "pending_acknowledgements": (
                    self.state.pending_server_opcode_348_requests
                ),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_348_received",
                details=details,
                identifiers={"primary_value": envelope.primary_value},
            )
            return self._observation(
                frame,
                kind="server_opcode_348_text_envelope",
                coverage=ShapeCoverage.FULL,
                parsed=envelope,
                details=details,
            )
        if opcode == 394:
            envelope = ServerOpcode394TextEnvelope.parse(payload)
            self._pending_server_opcode_394.append(
                (frame.timestamp_ns, envelope.text)
            )
            self.state.server_opcode_394_packets += 1
            self.state.server_opcode_394_text_code_units[
                envelope.text_code_units
            ] += 1
            self.state.pending_server_opcode_394_envelopes += 1
            details = {
                **envelope.safe_dict(),
                "pending_client_envelopes": (
                    self.state.pending_server_opcode_394_envelopes
                ),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "server_opcode_394_text_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="server_opcode_394_text_envelope",
                coverage=ShapeCoverage.FULL,
                parsed=envelope,
                details=details,
            )
        if opcode in {
            69,
            93,
            94,
            137,
            148,
            201,
            205,
            228,
            230,
            231,
            232,
            234,
            235,
            276,
            379,
        }:
            if opcode in ServerU32OpaqueTailEnvelope.CAPTURED_TAIL_LENGTHS:
                neutral_record: NeutralServerRecord = (
                    ServerU32OpaqueTailEnvelope.parse(payload)
                )
            elif opcode == 69:
                neutral_record = ServerOpcode69Record.parse(payload)
            elif opcode == 93:
                neutral_record = ServerOpcode93Record.parse(payload)
            elif opcode == 94:
                neutral_record = ServerOpcode94Record.parse(payload)
            elif opcode == 137:
                neutral_record = ServerOpcode137OpaqueTailEnvelope.parse(
                    payload
                )
            elif opcode == 148:
                neutral_record = ServerOpcode148Envelope.parse(payload)
            elif opcode == 201:
                neutral_record = ServerOpcode201Record.parse(payload)
            elif opcode == 205:
                neutral_record = ServerOpcode205Record.parse(payload)
            elif opcode == 276:
                neutral_record = ServerOpcode276BooleanFlag.parse(payload)
            else:
                neutral_record = ServerOpcode379Record.parse(payload)
            details: dict[str, object] = {
                "opcode": opcode,
                **neutral_record.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            typed_value_count = int(details["typed_value_count"])
            opaque_tail_length = int(details["opaque_tail_length"])
            self.state.neutral_server_records += 1
            self.state.neutral_server_records_by_opcode[opcode] += 1
            self.state.neutral_server_typed_values += typed_value_count
            self.state.neutral_server_opaque_bytes += opaque_tail_length
            self._event(
                frame,
                "neutral_server_record_received",
                details=details,
            )
            partial = opcode in {
                69,
                137,
                201,
                *ServerU32OpaqueTailEnvelope.CAPTURED_TAIL_LENGTHS,
            } or (
                isinstance(neutral_record, ServerOpcode148Envelope)
                and not neutral_record.fully_bounded
            )
            return self._observation(
                frame,
                kind="neutral_server_record",
                coverage=(
                    ShapeCoverage.PARTIAL if partial else ShapeCoverage.FULL
                ),
                parsed=neutral_record,
                details=details,
                issues=(
                    (
                        f"opcode {opcode} retains {opaque_tail_length} "
                        "capture-bounded opaque bytes"
                    ),
                )
                if partial
                else (),
            )
        if opcode in FIXED_SERVER_OPCODES:
            if opcode in FixedServerEmptyRecord.SUPPORTED_OPCODES:
                fixed_record: FixedServerRecord = (
                    FixedServerEmptyRecord.parse(payload)
                )
                details: dict[str, object] = {"shape": "empty"}
            elif opcode in FixedServerU8Record.SUPPORTED_OPCODES:
                fixed_record = FixedServerU8Record.parse(payload)
                details = {
                    "shape": "uint8",
                    "value": fixed_record.value,
                }
            elif opcode in FixedServerU16Record.SUPPORTED_OPCODES:
                fixed_record = FixedServerU16Record.parse(payload)
                details = {
                    "shape": "uint16",
                    "value": fixed_record.value,
                }
            elif opcode in FixedServerI32Record.SUPPORTED_OPCODES:
                fixed_record = FixedServerI32Record.parse(payload)
                details = {
                    "shape": "int32",
                    "value": fixed_record.value,
                }
            elif opcode in FixedServerU32Record.SUPPORTED_OPCODES:
                fixed_record = FixedServerU32Record.parse(payload)
                details = {
                    "shape": "uint32",
                    "value": fixed_record.value,
                }
            elif opcode in FixedServerU16PairRecord.SUPPORTED_OPCODES:
                fixed_record = FixedServerU16PairRecord.parse(payload)
                details = {
                    "shape": "uint16_pair",
                    "values": [
                        fixed_record.value_1,
                        fixed_record.value_2,
                    ],
                }
            elif opcode in FixedServerU32PairRecord.SUPPORTED_OPCODES:
                fixed_record = FixedServerU32PairRecord.parse(payload)
                details = {
                    "shape": "uint32_pair",
                    "values": [
                        fixed_record.value_1,
                        fixed_record.value_2,
                    ],
                }
            elif opcode in FixedServerU64Record.SUPPORTED_OPCODES:
                fixed_record = FixedServerU64Record.parse(payload)
                details = {
                    "shape": "uint64",
                    "value": fixed_record.value,
                }
            elif opcode == 11:
                fixed_record = FixedServerOpcode11Record.parse(payload)
                details = {
                    "shape": "reserved_uint32_uint8",
                    "reserved_values_zero": True,
                }
            else:
                fixed_record = InitialCharacterContextRecord.parse(payload)
                character_matches = (
                    self.state.entry_character_id == fixed_record.character_id
                )
                details = {
                    "shape": "character_context",
                    "context_flag": fixed_record.context_flag,
                    "reserved_values_zero": True,
                    "entry_character_match": character_matches,
                }
                self.state.initial_character_contexts += 1
                if not character_matches:
                    self.issues.append(
                        "initial character context id does not match the world "
                        "entry request"
                    )
            details["field_epoch"] = self.state.field_epoch
            self.state.fixed_server_records += 1
            self.state.fixed_server_records_by_opcode[opcode] += 1
            kind = (
                "initial_character_context"
                if isinstance(
                    fixed_record, InitialCharacterContextRecord
                )
                else "fixed_server_record"
            )
            identifiers = (
                {"character_id": fixed_record.character_id}
                if isinstance(
                    fixed_record, InitialCharacterContextRecord
                )
                else {}
            )
            event_details = {"opcode": opcode, **details}
            self._event(
                frame,
                f"{kind}_received",
                details=event_details,
                identifiers=identifiers,
            )
            return self._observation(
                frame,
                kind=kind,
                coverage=ShapeCoverage.FULL,
                parsed=fixed_record,
                details=event_details,
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
                "facing_value": spawn.facing_value,
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
        if opcode == 302 and (
            (len(payload) == 23 and payload[2] == NpcLifecycleControl.SPAWN)
            or (len(payload) == 7 and payload[2] == NpcLifecycleControl.REMOVE)
        ):
            lifecycle = NpcLifecycleControl.parse(payload)
            alias = self._alias(
                self._npc_aliases, lifecycle.object_id, "npc"
            )
            if lifecycle.spawn is not None:
                spawn = lifecycle.spawn
                existing = self.state.npcs.get(lifecycle.object_id)
                if existing is not None and existing.spawn != spawn:
                    self.issues.append(
                        f"{alias} received opcode-302 spawn with a different "
                        f"shape in field epoch {self.state.field_epoch}"
                    )
                self.state.npcs[lifecycle.object_id] = NpcEntity(
                    alias=alias, spawn=spawn
                )
                self.state.npc_spawns += 1
                self.state.npc_lifecycle_spawns += 1
                details = {
                    "entity": alias,
                    "control_value": lifecycle.control_value,
                    "template_id": spawn.template_id,
                    "x": spawn.x,
                    "cy": spawn.cy,
                    "facing_value": spawn.facing_value,
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
                    identifiers={"object_id": lifecycle.object_id},
                )
                return self._observation(
                    frame,
                    kind="npc_lifecycle_spawn",
                    coverage=ShapeCoverage.FULL,
                    parsed=lifecycle,
                    details=details,
                )
            existing = self.state.npcs.pop(lifecycle.object_id, None)
            known_npc = existing is not None
            self.state.npc_lifecycle_removals += 1
            if not known_npc:
                self.state.npc_lifecycle_unknown_removals += 1
            details = {
                "entity": alias,
                "control_value": lifecycle.control_value,
                "known_npc": known_npc,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "npc_removed",
                details=details,
                identifiers={"object_id": lifecycle.object_id},
            )
            return self._observation(
                frame,
                kind="npc_lifecycle_removal",
                coverage=ShapeCoverage.FULL,
                parsed=lifecycle,
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
                "opaque_tail_bytes": len(update.opaque_tail),
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
                coverage=(
                    ShapeCoverage.PARTIAL
                    if update.opaque_tail
                    else ShapeCoverage.FULL
                ),
                parsed=update,
                details=details,
                issues=(
                    ("NPC state-update tail remains opaque",)
                    if update.opaque_tail
                    else ()
                ),
            )
        if opcode == 189:
            entered = RemotePlayerEnterField.parse(payload)
            alias = self._alias(
                self._player_aliases, entered.object_id, "player"
            )
            existing = self.state.observed_players.get(entered.object_id)
            self.state.observed_players[entered.object_id] = (
                ObservedPlayerEntity(
                    alias=alias,
                    x=existing.x if existing is not None else None,
                    y=existing.y if existing is not None else None,
                    level=entered.level,
                    name_code_units=entered.name_code_units,
                )
            )
            self.state.remote_player_entries += 1
            self.state.remote_player_entry_opaque_bytes += len(
                entered.opaque_body
            )
            if existing is not None:
                self.state.remote_player_refreshes += 1
            details = {
                "entity": alias,
                "level": entered.level,
                "name_code_units": entered.name_code_units,
                "opaque_body_bytes": len(entered.opaque_body),
                "previously_observed": existing is not None,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "remote_player_entered_field",
                details=details,
                identifiers={"object_id": entered.object_id},
            )
            return self._observation(
                frame,
                kind="remote_player_enter_field",
                coverage=ShapeCoverage.PARTIAL,
                parsed=entered,
                details=details,
                issues=(
                    "remote-player entry body remains version-specific and "
                    "opaque",
                ),
            )
        if opcode == 190:
            left = RemotePlayerLeaveField.parse(payload)
            existing = self.state.observed_players.pop(left.object_id, None)
            alias = (
                existing.alias
                if existing is not None
                else self._alias(
                    self._player_aliases, left.object_id, "player"
                )
            )
            self.state.remote_player_leaves += 1
            if existing is None:
                self.state.remote_player_unknown_leaves += 1
            details = {
                "entity": alias,
                "known_player": existing is not None,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "remote_player_left_field",
                details=details,
                identifiers={"object_id": left.object_id},
            )
            return self._observation(
                frame,
                kind="remote_player_leave_field",
                coverage=ShapeCoverage.FULL,
                parsed=left,
                details=details,
            )
        if opcode == 224:
            record = RemotePlayerMobValueRecord.parse(payload)
            alias = self._alias(
                self._player_aliases, record.object_id, "player"
            )
            known_player = record.object_id in self.state.observed_players
            active_template_count = sum(
                entity.spawn.template_id == record.mob_template_id
                for entity in self.state.mobs.values()
            )
            self.state.remote_player_mob_value_records += 1
            if known_player:
                self.state.remote_player_mob_values_for_known_players += 1
            else:
                self.state.remote_player_mob_values_for_unknown_players += 1
            if active_template_count:
                self.state.remote_player_mob_values_with_active_template += 1
            else:
                self.state.remote_player_mob_values_with_inactive_template += 1
            self.state.remote_player_mob_values[record.value] += 1
            self.state.remote_player_mob_templates[record.mob_template_id] += 1
            self.state.remote_player_mob_value_flags[record.flag] += 1
            details = {
                **record.safe_dict(),
                "entity": alias,
                "known_player": known_player,
                "active_mob_template_count": active_template_count,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "remote_player_mob_value_received",
                details=details,
                identifiers={"object_id": record.object_id},
            )
            return self._observation(
                frame,
                kind="remote_player_mob_value_record",
                coverage=ShapeCoverage.FULL,
                parsed=record,
                details=details,
            )
        if opcode == 217:
            broadcast = LifeMovementBroadcast.parse(payload)
            path = broadcast.movement
            alias = self._alias(
                self._player_aliases, broadcast.object_id, "player"
            )
            known_player = broadcast.object_id in self.state.observed_players
            self.state.life_movement_broadcasts += 1
            self.state.life_movement_broadcast_commands += len(path.commands)
            self.state.life_movement_broadcast_commands_by_type.update(
                command.command_type for command in path.commands
            )
            if known_player:
                self.state.life_movement_broadcasts_for_known_players += 1
            else:
                self.state.life_movement_broadcasts_for_unknown_players += 1
            details = {
                "entity": alias,
                "known_player": known_player,
                **path.safe_dict(),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "life_movement_broadcast_received",
                details=details,
                identifiers={"object_id": broadcast.object_id},
            )
            return self._observation(
                frame,
                kind="life_movement_broadcast",
                coverage=ShapeCoverage.PARTIAL,
                parsed=broadcast,
                details=details,
                issues=("life movement command payload roles remain opaque",),
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
                    level=existing.level if existing is not None else None,
                    name_code_units=(
                        existing.name_code_units
                        if existing is not None
                        else None
                    ),
                )
            )
            self.state.remote_player_movement_broadcasts += 1
            if existing is None:
                self.state.remote_player_movement_broadcasts_for_unknown_players += 1
            else:
                self.state.remote_player_movement_broadcasts_for_known_players += 1
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
            cleared_client_attack_effects = len(
                self._pending_client_attacks.pop(entered.object_id, ())
            )
            self.state.pending_client_attack_effects -= (
                cleared_client_attack_effects
            )
            self.state.client_attack_effects_cleared += (
                cleared_client_attack_effects
            )
            controller_level = (
                existing.controller_level if existing is not None else 0
            )
            self.state.mobs[entered.object_id] = MobEntity(
                alias=alias,
                spawn=entered.spawn,
                controller_level=controller_level,
                x=entered.spawn.x,
                y=entered.spawn.y,
                foothold_id=entered.spawn.foothold_id,
                stance=entered.spawn.stance,
                max_hp=REFERENCE_MOB_MAX_HP.get(entered.spawn.template_id),
            )
            self.state.mob_templates[entered.object_id] = (
                entered.spawn.template_id
            )
            self.state.mob_entries += 1
            details = {
                "entity": alias,
                "replaced_existing": existing is not None,
                "cleared_client_attack_effects": (
                    cleared_client_attack_effects
                ),
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
            removed_entity = self.state.mobs.pop(left.object_id, None)
            known_entity = removed_entity is not None
            cleared_temporary_stats = (
                len(removed_entity.temporary_stats)
                if removed_entity is not None
                else 0
            )
            self.state.mob_temporary_stats_cleared_on_leave += (
                cleared_temporary_stats
            )
            cleared_client_attack_effects = len(
                self._pending_client_attacks.pop(left.object_id, ())
            )
            self.state.pending_client_attack_effects -= (
                cleared_client_attack_effects
            )
            self.state.client_attack_effects_cleared += (
                cleared_client_attack_effects
            )
            if not known_entity:
                self.state.unknown_mob_leaves += 1
            self.state.mob_leaves += 1
            details = {
                "entity": alias,
                "known_entity": known_entity,
                "reason": left.reason,
                "cleared_temporary_stats": cleared_temporary_stats,
                "cleared_client_attack_effects": (
                    cleared_client_attack_effects
                ),
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
                entity.foothold_id = change.spawn.foothold_id
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
            previous = (
                {
                    "x": entity.x,
                    "y": entity.y,
                    "foothold_id": entity.foothold_id,
                    "stance": entity.stance,
                }
                if entity is not None
                else None
            )
            if entity is None:
                self.state.unknown_mob_broadcasts += 1
            absolute_commands = [
                command
                for command in broadcast.commands
                if command.position is not None
            ]
            if entity is not None:
                if absolute_commands:
                    final_command = absolute_commands[-1]
                    entity.x, entity.y = final_command.position or (
                        entity.x,
                        entity.y,
                    )
                    final_foothold = final_command.foothold_id
                    if final_foothold is not None:
                        entity.foothold_id = final_foothold
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
                "previous": previous,
                "result": (
                    {
                        "x": entity.x,
                        "y": entity.y,
                        "foothold_id": entity.foothold_id,
                        "stance": entity.stance,
                    }
                    if entity is not None
                    else None
                ),
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
        if opcode in {218, 219}:
            relay = ServerAttackRelay.parse(payload)
            actor_alias = self._alias(
                self._player_aliases, relay.object_id, "player"
            )
            actor_entity = self.state.observed_players.get(relay.object_id)
            known_actor = actor_entity is not None
            self.state.server_attack_relays += 1
            self.state.server_attack_relays_by_opcode[relay.opcode] += 1
            self.state.server_attack_target_counts[relay.target_count] += 1
            self.state.server_attack_hit_counts[relay.hit_count] += 1
            if known_actor:
                self.state.server_attack_relays_for_known_players += 1
            else:
                self.state.server_attack_relays_for_unknown_players += 1
            melee_metadata = relay.melee_metadata
            if melee_metadata is not None:
                self.state.server_melee_attack_relays += 1
                if melee_metadata.short_zero_target_form:
                    self.state.server_melee_attack_short_zero_target_forms += 1
                self.state.server_melee_attack_tags[
                    melee_metadata.relay_tag
                ] += 1
                self.state.server_melee_attack_skill_levels[
                    melee_metadata.skill_level
                ] += 1
                self.state.server_melee_attack_unknown_values[
                    melee_metadata.unknown_value
                ] += 1
                self.state.server_melee_attack_displays[
                    melee_metadata.display
                ] += 1
                self.state.server_melee_attack_facing_flags[
                    melee_metadata.facing_flags
                ] += 1
                self.state.server_melee_attack_speeds[
                    melee_metadata.attack_speed
                ] += 1
                if melee_metadata.mastery is not None:
                    self.state.server_melee_attack_mastery_values[
                        melee_metadata.mastery
                    ] += 1
                if melee_metadata.auxiliary_value is not None:
                    self.state.server_melee_attack_auxiliary_values[
                        melee_metadata.auxiliary_value
                    ] += 1
            ranged_details: dict[str, object] = {}
            ranged_metadata = relay.ranged_metadata
            if ranged_metadata is not None:
                self.state.server_ranged_attack_relays += 1
                self.state.server_ranged_attack_tags[
                    ranged_metadata.relay_tag
                ] += 1
                self.state.server_ranged_attack_skill_levels[
                    ranged_metadata.skill_level
                ] += 1
                if ranged_metadata.skill_id is not None:
                    self.state.server_ranged_attack_skill_ids[
                        ranged_metadata.skill_id
                    ] += 1
                self.state.server_ranged_attack_unknown_values[
                    ranged_metadata.unknown_value
                ] += 1
                self.state.server_ranged_attack_displays[
                    ranged_metadata.display
                ] += 1
                self.state.server_ranged_attack_facing_flags[
                    ranged_metadata.facing_flags
                ] += 1
                self.state.server_ranged_attack_speeds[
                    ranged_metadata.attack_speed
                ] += 1
                self.state.server_ranged_attack_mastery_values[
                    ranged_metadata.mastery
                ] += 1
                self.state.server_ranged_attack_projectile_ids[
                    ranged_metadata.projectile_id
                ] += 1
                if (
                    actor_entity is not None
                    and actor_entity.x is not None
                    and actor_entity.y is not None
                ):
                    delta_x = ranged_metadata.position_x - actor_entity.x
                    delta_y = ranged_metadata.position_y - actor_entity.y
                    self.state.server_ranged_attack_positions_for_known_players += 1
                    self.state.server_ranged_attack_position_delta_x_min = min(
                        self.state.server_ranged_attack_position_delta_x_min
                        if self.state.server_ranged_attack_position_delta_x_min
                        is not None
                        else delta_x,
                        delta_x,
                    )
                    self.state.server_ranged_attack_position_delta_x_max = max(
                        self.state.server_ranged_attack_position_delta_x_max
                        if self.state.server_ranged_attack_position_delta_x_max
                        is not None
                        else delta_x,
                        delta_x,
                    )
                    self.state.server_ranged_attack_position_delta_y_min = min(
                        self.state.server_ranged_attack_position_delta_y_min
                        if self.state.server_ranged_attack_position_delta_y_min
                        is not None
                        else delta_y,
                        delta_y,
                    )
                    self.state.server_ranged_attack_position_delta_y_max = max(
                        self.state.server_ranged_attack_position_delta_y_max
                        if self.state.server_ranged_attack_position_delta_y_max
                        is not None
                        else delta_y,
                        delta_y,
                    )
                    ranged_details = {
                        "actor_position_x": actor_entity.x,
                        "actor_position_y": actor_entity.y,
                        "position_delta_x": delta_x,
                        "position_delta_y": delta_y,
                    }
            target_details: list[dict[str, object]] = []
            target_object_ids: list[int] = []
            for target in relay.targets:
                self.state.server_attack_target_records += 1
                self.state.server_attack_hit_actions[target.hit_action] += 1
                damage_values = target.damage_values
                self.state.server_attack_damage_entries += len(damage_values)
                self.state.server_attack_damage_total += sum(damage_values)
                self.state.server_attack_damage_high_bit_markers += sum(
                    target.high_bit_markers
                )
                if damage_values:
                    target_min = min(damage_values)
                    target_max = max(damage_values)
                    self.state.server_attack_damage_min = min(
                        self.state.server_attack_damage_min
                        if self.state.server_attack_damage_min is not None
                        else target_min,
                        target_min,
                    )
                    self.state.server_attack_damage_max = max(
                        self.state.server_attack_damage_max
                        if self.state.server_attack_damage_max is not None
                        else target_max,
                        target_max,
                    )
                target_detail: dict[str, object] = target.safe_dict()
                if target.object_id == 0:
                    self.state.server_attack_zero_object_targets += 1
                    target_detail.update(
                        {
                            "target": None,
                            "active_target": False,
                            "known_target": False,
                        }
                    )
                else:
                    target_alias = self._alias(
                        self._mob_aliases, target.object_id, "mob"
                    )
                    target_entity = self.state.mobs.get(target.object_id)
                    active_target = target_entity is not None
                    known_target = target.object_id in self.state.mob_templates
                    if target_entity is not None:
                        self.state.server_attack_targets_for_active_mobs += 1
                        target_entity.attack_relay_hits += len(damage_values)
                        target_entity.attack_relay_damage += sum(damage_values)
                        target_entity.attack_relay_high_bit_markers += sum(
                            target.high_bit_markers
                        )
                        target_entity.last_attack_hit_action = target.hit_action
                    if known_target:
                        self.state.server_attack_targets_for_known_mobs += 1
                    else:
                        self.state.server_attack_targets_for_unknown_mobs += 1
                    target_detail.update(
                        {
                            "target": target_alias,
                            "active_target": active_target,
                            "known_target": known_target,
                        }
                    )
                    target_object_ids.append(target.object_id)
                target_details.append(target_detail)
            details = {
                **relay.safe_dict(),
                "opcode": relay.opcode,
                "actor": actor_alias,
                "known_actor": known_actor,
                "targets": target_details,
                "field_epoch": self.state.field_epoch,
                **ranged_details,
            }
            identifiers: dict[str, object] = {"object_id": relay.object_id}
            if target_object_ids:
                identifiers["target_object_ids"] = target_object_ids
            self._last_server_attack_relay = (frame, relay)
            self._event(
                frame,
                "server_attack_relay_received",
                details=details,
                identifiers=identifiers,
            )
            return self._observation(
                frame,
                kind="server_attack_relay",
                coverage=ShapeCoverage.PARTIAL,
                parsed=relay,
                details=details,
                issues=(
                    (
                        "target/damage arrays are capture-bounded; ranged "
                        "relay tag/unknown byte and damage high-bit marker "
                        "roles remain uninterpreted"
                        if relay.opcode == 219
                        else "target/damage arrays are capture-bounded; "
                        "melee relay tag/unknown/auxiliary roles and damage "
                        "high-bit marker remain uninterpreted"
                    ),
                ),
            )
        if opcode == 285 and MobTemporaryStatSet.is_captured_shape(payload):
            record = MobTemporaryStatSet.parse(payload)
            alias = self._alias(self._mob_aliases, record.object_id, "mob")
            entity = self.state.mobs.get(record.object_id)
            known_entity = entity is not None
            refreshed_status_count = 0
            if entity is not None:
                refreshed_status_count = sum(
                    bit_index in entity.temporary_stats
                    for bit_index in record.enabled_bit_indices
                )
                for bit_index in record.enabled_bit_indices:
                    entity.temporary_stats[bit_index] = record

            self.state.mob_temporary_stat_sets += 1
            if known_entity:
                self.state.mob_temporary_stat_sets_for_known_mobs += 1
            else:
                self.state.mob_temporary_stat_sets_for_unknown_mobs += 1
            if refreshed_status_count:
                self.state.mob_temporary_stat_set_refreshes += 1
            self.state.mob_temporary_stat_mask_patterns[
                record.mask_pattern
            ] += 1
            self.state.mob_temporary_stat_source_skills[
                record.source_skill_id
            ] += 1
            self.state.mob_temporary_stat_source_levels[
                record.source_level
            ] += 1
            self.state.mob_temporary_stat_duration_values[
                record.duration_value
            ] += 1
            self.state.mob_temporary_stat_set_flags[record.flag] += 1

            preceding_relay: dict[str, object] | None = None
            relay_matches = False
            if self._last_server_attack_relay is not None:
                relay_frame, relay = self._last_server_attack_relay
                metadata = relay.ranged_metadata
                direction_gap = frame.direction_index - relay_frame.direction_index
                target_matches = any(
                    target.object_id == record.object_id
                    for target in relay.targets
                )
                skill_matches = (
                    metadata is not None
                    and metadata.skill_id == record.source_skill_id
                )
                relay_matches = (
                    0 < direction_gap <= 2
                    and target_matches
                    and skill_matches
                )
                preceding_relay = {
                    "frame_index": relay_frame.index,
                    "server_direction_gap": direction_gap,
                    "response_ms": round(
                        (frame.timestamp_ns - relay_frame.timestamp_ns) / 1e6,
                        3,
                    ),
                    "opcode": relay.opcode,
                    "target_matches": target_matches,
                    "source_skill_matches": skill_matches,
                    "matches": relay_matches,
                }
            if relay_matches:
                self.state.mob_temporary_stat_attack_relay_matches += 1

            details = {
                **record.safe_dict(),
                "entity": alias,
                "known_entity": known_entity,
                "template_id": (
                    entity.spawn.template_id if entity is not None else None
                ),
                "refreshed_status_count": refreshed_status_count,
                "active_status_count": (
                    len(entity.temporary_stats) if entity is not None else 0
                ),
                "preceding_attack_relay": preceding_relay,
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "mob_temporary_stat_set_received",
                details=details,
                identifiers={"object_id": record.object_id},
            )
            return self._observation(
                frame,
                kind="mob_temporary_stat_set",
                coverage=ShapeCoverage.FULL,
                parsed=record,
                details=details,
            )
        if opcode == 286 and MobTemporaryStatReset.is_captured_shape(payload):
            record = MobTemporaryStatReset.parse(payload)
            alias = self._alias(self._mob_aliases, record.object_id, "mob")
            entity = self.state.mobs.get(record.object_id)
            known_entity = entity is not None
            reset_status_count = 0
            if entity is not None:
                for bit_index in record.enabled_bit_indices:
                    if entity.temporary_stats.pop(bit_index, None) is not None:
                        reset_status_count += 1

            self.state.mob_temporary_stat_resets += 1
            if known_entity:
                self.state.mob_temporary_stat_resets_for_known_mobs += 1
            else:
                self.state.mob_temporary_stat_resets_for_unknown_mobs += 1
            if reset_status_count:
                self.state.mob_temporary_stat_resets_with_modeled_set += 1
            else:
                self.state.mob_temporary_stat_resets_without_modeled_set += 1
            self.state.mob_temporary_stat_mask_patterns[
                record.mask_pattern
            ] += 1
            self.state.mob_temporary_stat_reset_flags[record.flag] += 1

            details = {
                **record.safe_dict(),
                "entity": alias,
                "known_entity": known_entity,
                "template_id": (
                    entity.spawn.template_id if entity is not None else None
                ),
                "reset_status_count": reset_status_count,
                "active_status_count": (
                    len(entity.temporary_stats) if entity is not None else 0
                ),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "mob_temporary_stat_reset_received",
                details=details,
                identifiers={"object_id": record.object_id},
            )
            return self._observation(
                frame,
                kind="mob_temporary_stat_reset",
                coverage=ShapeCoverage.FULL,
                parsed=record,
                details=details,
            )
        if opcode == 293:
            update = MobHealthPercentageUpdate.parse(payload)
            alias = self._alias(self._mob_aliases, update.object_id, "mob")
            entity = self.state.mobs.get(update.object_id)
            previous_percentage = (
                entity.health_percentage if entity is not None else None
            )
            if entity is None:
                self.state.mob_health_updates_for_unknown_mobs += 1
                self.warnings.append(
                    f"{alias} received a health percentage without an "
                    "active spawn"
                )
            else:
                if (
                    previous_percentage is not None
                    and update.health_percentage > previous_percentage
                ):
                    self.state.mob_health_increases += 1
                entity.health_percentage = update.health_percentage
                if entity.max_hp is not None:
                    (
                        entity.health_hp_min,
                        entity.health_hp_max,
                    ) = mob_hp_bounds_for_percentage(
                        entity.max_hp, update.health_percentage
                    )
            self.state.mob_health_percentage_updates += 1
            if update.health_percentage == 0:
                self.state.mob_health_zero_updates += 1
            pending_queue = self._pending_client_attacks.get(update.object_id)
            pending_hit = pending_queue.popleft() if pending_queue else None
            if pending_queue is not None and not pending_queue:
                del self._pending_client_attacks[update.object_id]
            correlation_details: dict[str, object] = {
                "matched_client_attack": pending_hit is not None,
            }
            if pending_hit is not None:
                self.state.pending_client_attack_effects -= 1
                self.state.client_attack_health_matches += 1
                response_ms = round(
                    (
                        frame.timestamp_ns
                        - pending_hit.request_timestamp_ns
                    )
                    / 1e6,
                    3,
                )
                self.state.last_client_attack_health_response_ms = response_ms
                self.state.max_client_attack_health_response_ms = max(
                    self.state.max_client_attack_health_response_ms or 0.0,
                    response_ms,
                )
                submitted_damage = pending_hit.damage_values[
                    pending_hit.hit_index
                ]
                submitted_high_bit_marker = pending_hit.high_bit_markers[
                    pending_hit.hit_index
                ]
                intervening_relay_hits = (
                    max(
                        0,
                        entity.attack_relay_hits
                        - pending_hit.attack_relay_hits_at_submission,
                    )
                    if entity is not None
                    else None
                )
                correlation_details.update(
                    {
                        "client_attack_frame": (
                            pending_hit.request_frame_index
                        ),
                        "client_attack_response_ms": response_ms,
                        "submitted_hit_index": pending_hit.hit_index,
                        "submitted_hit_count": len(
                            pending_hit.damage_values
                        ),
                        "submitted_damage": submitted_damage,
                        "submitted_high_bit_marker": (
                            submitted_high_bit_marker
                        ),
                        "submitted_damage_values": list(
                            pending_hit.damage_values
                        ),
                        "submitted_damage_total": sum(
                            pending_hit.damage_values
                        ),
                        "submitted_high_bit_markers": list(
                            pending_hit.high_bit_markers
                        ),
                        "remaining_health_effects_for_target": len(
                            pending_queue or ()
                        ),
                        "intervening_attack_relay_hits": (
                            intervening_relay_hits
                        ),
                    }
                )
                if (
                    entity is not None
                    and entity.max_hp is not None
                    and previous_percentage is not None
                ):
                    expected_min, expected_max = (
                        predict_mob_health_percentage_range(
                            max_hp=entity.max_hp,
                            previous_percentage=previous_percentage,
                            damage=submitted_damage,
                        )
                    )
                    previous_min_hp, previous_max_hp = (
                        mob_hp_bounds_for_percentage(
                            entity.max_hp, previous_percentage
                        )
                    )
                    predicted_min_hp = max(
                        0, previous_min_hp - submitted_damage
                    )
                    predicted_max_hp = max(
                        0, previous_max_hp - submitted_damage
                    )
                    assert entity.health_hp_min is not None
                    assert entity.health_hp_max is not None
                    inferred_damage_min = max(
                        0, previous_min_hp - entity.health_hp_max
                    )
                    inferred_damage_max = max(
                        0, previous_max_hp - entity.health_hp_min
                    )
                    inferred_delta_min = (
                        inferred_damage_min - submitted_damage
                    )
                    inferred_delta_max = (
                        inferred_damage_max - submitted_damage
                    )
                    prediction_matches = (
                        expected_min
                        <= update.health_percentage
                        <= expected_max
                    )
                    if entity.health_hp_max is None:
                        hp_delta = None
                    elif entity.health_hp_max < predicted_min_hp:
                        hp_delta = entity.health_hp_max - predicted_min_hp
                    elif entity.health_hp_min > predicted_max_hp:
                        hp_delta = entity.health_hp_min - predicted_max_hp
                    else:
                        hp_delta = 0
                    combat_state = self.state
                    combat_state.client_attack_health_predictions += 1
                    if intervening_relay_hits:
                        combat_state.client_attack_predictions_with_relay_hits += 1
                    combat_state.client_attack_health_predictions_by_template[
                        entity.spawn.template_id
                    ] += 1
                    if prediction_matches:
                        combat_state.client_attack_health_prediction_matches += 1
                    else:
                        combat_state.client_attack_health_prediction_mismatches += 1
                        if intervening_relay_hits == 0:
                            combat_state.client_attack_mismatches_without_relays += 1
                        if hp_delta is not None and abs(hp_delta) == 1:
                            combat_state.client_attack_health_one_hp_differences += 1
                        if inferred_delta_min == inferred_delta_max:
                            combat_state.client_attack_health_mismatch_damage_deltas[
                                inferred_delta_min
                            ] += 1
                    correlation_details.update(
                        {
                            "mob_max_hp": entity.max_hp,
                            "predicted_hp_min": predicted_min_hp,
                            "predicted_hp_max": predicted_max_hp,
                            "predicted_health_percentage_min": expected_min,
                            "predicted_health_percentage_max": expected_max,
                            "health_prediction_matches": prediction_matches,
                            "health_prediction_hp_delta": hp_delta,
                            "inferred_authoritative_damage_min": (
                                inferred_damage_min
                            ),
                            "inferred_authoritative_damage_max": (
                                inferred_damage_max
                            ),
                            "authoritative_minus_submitted_damage_min": (
                                inferred_delta_min
                            ),
                            "authoritative_minus_submitted_damage_max": (
                                inferred_delta_max
                            ),
                        }
                    )
            details = {
                "entity": alias,
                "known_entity": entity is not None,
                "previous_percentage": previous_percentage,
                "health_percentage": update.health_percentage,
                "field_epoch": self.state.field_epoch,
                **correlation_details,
            }
            if entity is not None:
                details.update(
                    {
                        "template_id": entity.spawn.template_id,
                        "mob_max_hp": entity.max_hp,
                        "health_hp_min": entity.health_hp_min,
                        "health_hp_max": entity.health_hp_max,
                    }
                )
            self._event(
                frame,
                "mob_health_percentage_updated",
                details=details,
                identifiers={"object_id": update.object_id},
            )
            return self._observation(
                frame,
                kind="mob_health_percentage_update",
                coverage=ShapeCoverage.FULL,
                parsed=update,
                details=details,
            )
        if opcode == 426:
            notification = ServerOpcode426Notification.parse(payload)
            self._pending_opcode_426_notifications.append(frame.timestamp_ns)
            self.state.opcode_426_notifications += 1
            self.state.pending_opcode_426_notifications += 1
            details = {
                "pending_notifications": (
                    self.state.pending_opcode_426_notifications
                ),
                "field_epoch": self.state.field_epoch,
            }
            self._event(
                frame,
                "opcode_426_notification_received",
                details=details,
            )
            return self._observation(
                frame,
                kind="opcode_426_notification",
                coverage=ShapeCoverage.FULL,
                parsed=notification,
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
        accounted_client_damage_entries = (
            self.state.client_attack_zero_damage_entries
            + self.state.client_attack_health_matches
            + self.state.client_attack_effects_cleared
            + self.state.pending_client_attack_effects
        )
        if (
            accounted_client_damage_entries
            != self.state.client_attack_damage_entries
        ):
            self.issues.append(
                "client attack hit accounting mismatch: "
                f"decoded {self.state.client_attack_damage_entries}, "
                f"accounted {accounted_client_damage_entries}"
            )
        if self.state.client_attack_health_prediction_mismatches:
            one_hp_differences = (
                self.state.client_attack_health_one_hp_differences
            )
            without_relay_hits = (
                self.state.client_attack_mismatches_without_relays
            )
            damage_deltas = dict(
                sorted(
                    self.state.client_attack_health_mismatch_damage_deltas.items()
                )
            )
            self.warnings.append(
                f"{self.state.client_attack_health_prediction_mismatches} "
                "client attack hit/HP-percentage correlations disagreed with "
                "the reference mob max-HP model; "
                f"{one_hp_differences} differed by exactly one HP, "
                f"{without_relay_hits} had no intervening modeled relay hit, "
                "and exact inferred authoritative-minus-submitted damage "
                f"deltas were {damage_deltas}"
            )
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
        if self.state.unmatched_opcode_309_acknowledgements:
            self.warnings.append(
                f"{self.state.unmatched_opcode_309_acknowledgements} opcode-309 "
                "acknowledgements had no pending server opcode-426 notification"
            )
        if self.state.pending_opcode_426_notifications:
            self.warnings.append(
                f"{self.state.pending_opcode_426_notifications} server "
                "opcode-426 notifications had no captured client "
                "opcode-309 acknowledgement"
            )
        if self.state.unmatched_client_opcode_66_acknowledgements:
            self.warnings.append(
                f"{self.state.unmatched_client_opcode_66_acknowledgements} "
                "client opcode-66 acknowledgements had no pending "
                "same-selector server opcode-348 request"
            )
        if self.state.pending_server_opcode_348_requests:
            self.warnings.append(
                f"{self.state.pending_server_opcode_348_requests} server "
                "opcode-348 requests had no captured client opcode-66 "
                "acknowledgement"
            )
        if self.state.uncorrelated_client_opcode_279_packets:
            self.warnings.append(
                f"{self.state.uncorrelated_client_opcode_279_packets} client "
                "opcode-279 text envelopes had no preceding unmatched server "
                "opcode-394 envelope"
            )
        if self.state.pending_server_opcode_394_envelopes:
            self.warnings.append(
                f"{self.state.pending_server_opcode_394_envelopes} server "
                "opcode-394 text envelopes had no later captured client "
                "opcode-279 envelope"
            )
        if self.state.client_opcode_279_transform_mismatches:
            self.warnings.append(
                f"{self.state.client_opcode_279_transform_mismatches} correlated "
                "opcode-394/279 text pairs did not match the captured five-code-"
                "unit transformation"
            )
        if self.state.pending_world_exit_requests:
            self.warnings.append(
                f"{self.state.pending_world_exit_requests} client world-exit "
                "requests had no captured terminal server opcode-9 packet"
            )
        if self.state.pending_skill_level_change_requests:
            self.warnings.append(
                f"{self.state.pending_skill_level_change_requests} skill "
                "level-change requests had no captured record update"
            )
        if self.state.unmatched_skill_record_update_acknowledgements:
            self.warnings.append(
                f"{self.state.unmatched_skill_record_update_acknowledgements} "
                "skill-record acknowledgements had no pending server update"
            )
        if self.state.pending_skill_record_update_acknowledgements:
            self.warnings.append(
                f"{self.state.pending_skill_record_update_acknowledgements} "
                "server skill-record updates had no captured client "
                "acknowledgement"
            )
        if self.state.pending_item_uses:
            self.warnings.append(
                f"{self.state.pending_item_uses} item-use requests had no "
                "complete captured inventory/effect response"
            )
        if self.state.pending_item_pickups:
            self.warnings.append(
                f"{self.state.pending_item_pickups} item-pickup requests had no "
                "complete captured effect/result/removal chain"
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
                    "active_field_drops": len(self.state.field_drops),
                    "pending_movements": self.state.pending_movements,
                    "pending_heartbeat_probes": (
                        self.state.pending_heartbeat_probes
                    ),
                    "pending_opcode_426_notifications": (
                        self.state.pending_opcode_426_notifications
                    ),
                    "pending_server_opcode_394_envelopes": (
                        self.state.pending_server_opcode_394_envelopes
                    ),
                    "pending_world_exit_requests": (
                        self.state.pending_world_exit_requests
                    ),
                    "pending_skill_level_change_requests": (
                        self.state.pending_skill_level_change_requests
                    ),
                    "pending_skill_record_update_acknowledgements": (
                        self.state.pending_skill_record_update_acknowledgements
                    ),
                    "pending_item_uses": self.state.pending_item_uses,
                    "pending_item_pickups": self.state.pending_item_pickups,
                    "pending_client_attack_effects": (
                        self.state.pending_client_attack_effects
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


def _runtime_gameplay_events(
    transcript: Transcript,
    frames: tuple[PlainFrame, ...],
    issues: list[str],
) -> tuple[GameplayEvent, ...]:
    frame_timestamps = [frame.timestamp_ns for frame in frames]
    runtime_events: list[GameplayEvent] = []
    for transcript_event in transcript.events:
        if transcript_event.event != "runtime_event":
            continue
        metadata = transcript_event.metadata or {}
        kind = metadata.get("kind")
        details = metadata.get("details", {})
        if (
            not isinstance(kind, str)
            or not kind
            or not kind.replace("_", "").isalnum()
        ):
            issues.append(
                "runtime transcript event kind must contain only letters, "
                "digits, and underscores"
            )
            continue
        if not isinstance(details, dict):
            issues.append(
                f"runtime transcript event {kind!r} details are not an object"
            )
            continue
        try:
            json.dumps(details)
        except (TypeError, ValueError):
            issues.append(
                f"runtime transcript event {kind!r} details are not JSON-safe"
            )
            continue
        preceding_position = (
            bisect_right(frame_timestamps, transcript_event.timestamp_ns) - 1
        )
        frame_index = (
            frames[preceding_position].index
            if preceding_position >= 0
            else -1
        )
        runtime_events.append(
            GameplayEvent(
                index=0,
                timestamp_ns=transcript_event.timestamp_ns,
                frame_index=frame_index,
                direction="runtime",
                kind=kind,
                details=dict(details),
            )
        )
    return tuple(runtime_events)


def analyze_gameplay_transcript(transcript: Transcript) -> GameplayAnalysis:
    decoded = decode_transcript(transcript)
    fold = GameplayStateFold()
    observations = tuple(fold.consume(frame) for frame in decoded.frames)
    transport_closed = any(event.event == "close" for event in transcript.events)
    runtime_events = _runtime_gameplay_events(
        transcript, decoded.frames, fold.issues
    )
    for runtime_event in runtime_events:
        fold.apply_runtime_event(runtime_event)
    fold.finish(
        decoded.frames[-1] if decoded.frames else None,
        transport_closed=transport_closed,
    )
    events = [
        *fold.events,
        *runtime_events,
    ]
    dropped_runtime_events = 0
    for transcript_event in transcript.events:
        if transcript_event.event != "close":
            continue
        close_metadata = transcript_event.metadata or {}
        for count_name in (
            "runtime_events_written",
            "runtime_events_dropped",
        ):
            count = close_metadata.get(count_name, 0)
            if type(count) is not int or count < 0:
                fold.issues.append(
                    f"transcript close {count_name} must be a "
                    "non-negative integer"
                )
                continue
            if count_name == "runtime_events_dropped":
                dropped_runtime_events += count
    if dropped_runtime_events:
        fold.warnings.append(
            f"transcript dropped {dropped_runtime_events} runtime event "
            "annotations after reaching its bound"
        )
    events.sort(key=lambda event: event.timestamp_ns)
    indexed_events = tuple(
        replace(event, index=index) for index, event in enumerate(events)
    )
    return GameplayAnalysis(
        source=str(transcript.path),
        decoded=decoded,
        state=fold.state,
        observations=observations,
        events=indexed_events,
        transport_closed=transport_closed,
        issues=tuple(fold.issues),
        warnings=tuple(fold.warnings),
    )


def derive_item_use_response_policy(
    transcript: Transcript,
) -> ItemUseResponsePolicy:
    """Build mutable potion-response state from one validated world replay."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    state = analysis.state
    if (
        state.item_use_inventory_mismatches
        or state.item_use_effect_mismatches
        or state.item_use_unknown_slots
        or state.item_use_item_mismatches
        or state.pending_item_uses
    ):
        raise ValueError(
            "world transcript has unresolved item-use request correlations"
        )
    stats = (state.current_hp, state.max_hp, state.current_mp, state.max_mp)
    if any(value is None for value in stats):
        raise ValueError("world transcript has incomplete HP/MP state")
    use_items = {
        item.slot: item
        for item in state.inventory_items.get("use", ())
    }
    if not any(
        item.item_id in CAPTURED_ITEM_USE_EFFECTS
        for item in use_items.values()
    ):
        raise ValueError(
            "world transcript has no Use item with a validated potion effect"
        )
    current_hp, max_hp, current_mp, max_mp = stats
    assert current_hp is not None
    assert max_hp is not None
    assert current_mp is not None
    assert max_mp is not None
    return ItemUseResponsePolicy(
        use_items=use_items,
        current_hp=current_hp,
        max_hp=max_hp,
        current_mp=current_mp,
        max_mp=max_mp,
        field_epoch=state.field_epoch,
        source_item_use_requests=state.item_use_requests,
        source_inventory_matches=state.item_use_inventory_matches,
        source_effect_matches=state.item_use_effect_matches,
    )


def derive_item_pickup_response_policy(
    transcript: Transcript,
    *,
    evidence_transcript: Transcript | None = None,
) -> ItemPickupResponsePolicy:
    """Build a conservative pickup responder from replay and capture evidence."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    evidence = (
        analysis
        if evidence_transcript is None or evidence_transcript is transcript
        else analyze_gameplay_transcript(evidence_transcript)
    )
    if not evidence.valid:
        raise ValueError("item-pickup evidence failed packet/state validation")
    evidence_state = evidence.state
    if (
        evidence_state.item_pickup_effect_mismatches
        or evidence_state.item_pickup_spawn_result_mismatches
        or evidence_state.item_pickup_removal_mismatches
        or evidence_state.item_pickup_unknown_drops
        or evidence_state.pending_item_pickups
    ):
        raise ValueError(
            "item-pickup evidence has unresolved request/response correlations"
        )
    ambiguous_effects = {
        item_id: sorted(effects)
        for item_id, effects in (
            evidence_state.item_pickup_item_effects_by_template.items()
        )
        if len(effects) != 1
    }
    if ambiguous_effects:
        raise ValueError(
            "item-pickup effects are not deterministic for templates "
            f"{ambiguous_effects}"
        )
    validated_item_effects = {
        item_id: next(iter(effects))
        for item_id, effects in (
            evidence_state.item_pickup_item_effects_by_template.items()
        )
    }
    if not validated_item_effects:
        raise ValueError("item-pickup evidence has no validated item effects")
    inventory_items = {
        inventory: {item.slot: item for item in items}
        for inventory, items in analysis.state.inventory_items.items()
        if inventory in STACK_INVENTORY_TYPES
    }
    eligible_drops: dict[int, FieldDropEntity] = {}
    for object_id, entity in analysis.state.field_drops.items():
        spawn = entity.spawn
        effect = validated_item_effects.get(spawn.value)
        if (
            spawn.drop_kind != FieldDropSpawn.ITEM
            or effect is None
            or spawn.owner_value_1 != spawn.owner_value_2
        ):
            continue
        inventory, quantity_delta = effect
        if quantity_delta <= 0:
            continue
        matching_stacks = tuple(
            item
            for item in inventory_items.get(inventory, {}).values()
            if item.item_id == spawn.value
            and item.quantity is not None
            and item.quantity + quantity_delta <= 0xFFFF
        )
        if len(matching_stacks) == 1:
            eligible_drops[object_id] = entity
    if not eligible_drops:
        raise ValueError(
            "world transcript has no active item drop with a uniquely modeled "
            "captured inventory effect"
        )
    return ItemPickupResponsePolicy(
        inventory_items=inventory_items,
        active_drops=eligible_drops,
        validated_item_effects=validated_item_effects,
        field_epoch=analysis.state.field_epoch,
        source_item_pickup_requests=evidence_state.item_pickup_requests,
        source_spawn_result_matches=(
            evidence_state.item_pickup_spawn_result_matches
        ),
        source_effect_matches=evidence_state.item_pickup_effect_matches,
        source_removal_matches=evidence_state.item_pickup_removal_matches,
    )


@dataclass(frozen=True)
class _CapturedMobMovementPath:
    server_frame_index: int
    template_id: int | None
    broadcast: MobMovementBroadcast = field(repr=False)
    relative_motion_shape: tuple[object, ...] | None
    displacement: tuple[int, int] | None


MOB_MOVEMENT_CONTROL_PREFIX = bytes.fromhex("0000ff00000000")


def _relative_mob_motion_shape(
    broadcast: MobMovementBroadcast,
) -> tuple[object, ...] | None:
    if any(command.position is None for command in broadcast.commands):
        return None
    relative_positions = tuple(
        (
            command.position[0] - broadcast.reference_x,
            command.position[1] - broadcast.reference_y,
        )
        for command in broadcast.commands
    )
    motion = tuple(
        (
            command.command_type,
            command.velocity,
            command.stance,
            command.duration_ms,
        )
        for command in broadcast.commands
    )
    return relative_positions, motion


def _captured_mob_movement_paths(
    analysis: GameplayAnalysis,
) -> tuple[_CapturedMobMovementPath, ...]:
    known_templates: dict[int, int] = {}
    paths: list[_CapturedMobMovementPath] = []
    for frame in analysis.decoded.frames:
        if frame.direction != "server_to_client" or len(frame.plaintext) < 2:
            continue
        opcode = int.from_bytes(frame.plaintext[:2], "little")
        if opcode == 157:
            known_templates.clear()
        elif opcode == 279:
            entered = MobEnterField.parse(frame.plaintext)
            known_templates[entered.object_id] = entered.spawn.template_id
        elif opcode == 281:
            controller = MobControllerChange.parse(frame.plaintext)
            if controller.spawn is not None:
                known_templates[controller.object_id] = (
                    controller.spawn.template_id
                )
        elif opcode == 280:
            left = MobLeaveField.parse(frame.plaintext)
            known_templates.pop(left.object_id, None)
        elif opcode == 282:
            broadcast = MobMovementBroadcast.parse(frame.plaintext)
            endpoint = broadcast.commands[-1].position
            displacement = (
                (
                    endpoint[0] - broadcast.reference_x,
                    endpoint[1] - broadcast.reference_y,
                )
                if endpoint is not None
                else None
            )
            paths.append(
                _CapturedMobMovementPath(
                    server_frame_index=frame.direction_index,
                    template_id=known_templates.get(broadcast.object_id),
                    broadcast=broadcast,
                    relative_motion_shape=(
                        _relative_mob_motion_shape(broadcast)
                    ),
                    displacement=displacement,
                )
            )
    return tuple(paths)


@dataclass(frozen=True)
class MobMovementPlanningContext:
    """Validated immutable replay/evidence inputs reused across decisions."""

    analysis: GameplayAnalysis = field(repr=False)
    evidence_analysis: GameplayAnalysis = field(repr=False)
    captured_paths: tuple[_CapturedMobMovementPath, ...] = field(repr=False)
    evidence_broadcasts: tuple[MobMovementBroadcast, ...] = field(
        repr=False
    )
    stationary_shape_counts: tuple[tuple[int, int], ...]

    def stationary_shape_count(self, stance: int) -> int:
        return dict(self.stationary_shape_counts).get(stance, 0)

    def safe_dict(self) -> dict[str, object]:
        return {
            "replay_frame_count": len(self.analysis.decoded.frames),
            "evidence_frame_count": len(
                self.evidence_analysis.decoded.frames
            ),
            "evidence_broadcast_count": len(self.evidence_broadcasts),
            "captured_path_count": len(self.captured_paths),
            "stationary_shape_counts": {
                str(stance): count
                for stance, count in self.stationary_shape_counts
            },
        }


def build_mob_movement_planning_context(
    transcript: Transcript,
    evidence_transcript: Transcript | None = None,
) -> MobMovementPlanningContext:
    """Fold replay and evidence transcripts once for repeated planning."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    evidence_analysis = (
        analysis
        if evidence_transcript is None
        else analyze_gameplay_transcript(evidence_transcript)
    )
    if not evidence_analysis.valid:
        raise ValueError(
            "mob-movement broadcast evidence transcript failed packet/state "
            "validation"
        )
    evidence_broadcasts = tuple(
        observation.parsed
        for observation in evidence_analysis.observations
        if isinstance(observation.parsed, MobMovementBroadcast)
    )
    stationary_shape_counts: Counter[int] = Counter()
    for broadcast in evidence_broadcasts:
        if broadcast.opaque_control != MOB_MOVEMENT_CONTROL_PREFIX:
            continue
        if len(broadcast.commands) != 1:
            continue
        command = broadcast.commands[0]
        if (
            command.command_type == 0
            and command.position
            == (broadcast.reference_x, broadcast.reference_y)
            and command.velocity == (0, 0)
            and command.duration_ms == 1_080
        ):
            stationary_shape_counts[command.stance] += 1
    return MobMovementPlanningContext(
        analysis=analysis,
        evidence_analysis=evidence_analysis,
        captured_paths=_captured_mob_movement_paths(evidence_analysis),
        evidence_broadcasts=evidence_broadcasts,
        stationary_shape_counts=tuple(sorted(stationary_shape_counts.items())),
    )


def _active_mobs_after_server_frames(
    analysis: GameplayAnalysis,
    server_frames: tuple[bytes, ...],
) -> dict[int, tuple[str, int, int, int, int, int]]:
    active_mobs: dict[int, tuple[str, int, int, int, int, int]] = {
        object_id: (
            mob.alias,
            mob.spawn.template_id,
            mob.x,
            mob.y,
            mob.foothold_id,
            mob.stance,
        )
        for object_id, mob in analysis.state.mobs.items()
    }
    runtime_aliases: dict[int, str] = {}

    def adopt_spawn(object_id: int, spawn: MobSpawnData) -> None:
        if object_id in active_mobs:
            entity = active_mobs[object_id][0]
        else:
            entity = runtime_aliases.setdefault(
                object_id, f"mob:runtime:{len(runtime_aliases) + 1}"
            )
        active_mobs[object_id] = (
            entity,
            spawn.template_id,
            spawn.x,
            spawn.y,
            spawn.foothold_id,
            spawn.stance,
        )

    for plaintext in server_frames:
        if len(plaintext) < 2:
            continue
        opcode = int.from_bytes(plaintext[:2], "little")
        if opcode == 279:
            entered = MobEnterField.parse(plaintext)
            adopt_spawn(entered.object_id, entered.spawn)
        elif opcode == 281:
            controller = MobControllerChange.parse(plaintext)
            if controller.spawn is not None:
                adopt_spawn(controller.object_id, controller.spawn)
        elif opcode == 280:
            left = MobLeaveField.parse(plaintext)
            active_mobs.pop(left.object_id, None)
        elif opcode == 282:
            broadcast = MobMovementBroadcast.parse(plaintext)
            current = active_mobs.get(broadcast.object_id)
            if current is None:
                continue
            (
                entity,
                template_id,
                current_x,
                current_y,
                current_foothold,
                current_stance,
            ) = current
            absolute_commands = tuple(
                command
                for command in broadcast.commands
                if command.position is not None
            )
            if absolute_commands:
                final_command = absolute_commands[-1]
                current_x, current_y = final_command.position or (
                    current_x,
                    current_y,
                )
                if final_command.foothold_id is not None:
                    current_foothold = final_command.foothold_id
                current_stance = final_command.stance
            else:
                current_x = broadcast.reference_x
                current_y = broadcast.reference_y
            active_mobs[broadcast.object_id] = (
                entity,
                template_id,
                current_x,
                current_y,
                current_foothold,
                current_stance,
            )
    return active_mobs


def plan_mob_movement_broadcast(
    transcript: Transcript,
    *,
    post_transcript_server_frames: tuple[bytes, ...] = (),
    evidence_transcript: Transcript | None = None,
    target_x: int,
    target_y: int,
    foothold_id: int,
    stance: int = 4,
    path_evidence_server_frame_index: int | None = None,
    auto_select_captured_path: bool = False,
    planning_context: MobMovementPlanningContext | None = None,
) -> MobMovementBroadcastPlan:
    """Plan one captured stationary or translated path broadcast."""

    if not all(-0x8000 <= value <= 0x7FFF for value in (target_x, target_y)):
        raise ValueError("mob movement target coordinates must fit in int16")
    if not 0 <= foothold_id <= 0xFFFF:
        raise ValueError("mob movement target foothold must fit in uint16")
    if not 0 <= stance <= 0xFF:
        raise ValueError("mob movement target stance must fit in uint8")
    if (
        path_evidence_server_frame_index is not None
        and path_evidence_server_frame_index < 0
    ):
        raise ValueError("mob movement path evidence frame cannot be negative")
    if (
        auto_select_captured_path
        and path_evidence_server_frame_index is not None
    ):
        raise ValueError(
            "automatic mob movement path selection conflicts with an exact "
            "evidence frame"
        )
    path_requested = (
        auto_select_captured_path
        or path_evidence_server_frame_index is not None
    )

    context = planning_context or build_mob_movement_planning_context(
        transcript, evidence_transcript
    )
    analysis = context.analysis
    control_prefix = MOB_MOVEMENT_CONTROL_PREFIX
    evidence_broadcasts = context.evidence_broadcasts
    exact_stationary_shape_evidence = context.stationary_shape_count(stance)
    if not path_requested and exact_stationary_shape_evidence == 0:
        raise ValueError(
            "movement evidence has no exact stationary opcode-282 shape for "
            f"stance {stance}"
        )

    active_mobs = _active_mobs_after_server_frames(
        analysis, post_transcript_server_frames
    )

    if len(active_mobs) != 1:
        raise ValueError(
            "mob movement broadcast planning requires exactly one active "
            f"modeled mob, found {len(active_mobs)}"
        )
    object_id, (
        entity,
        template_id,
        previous_x,
        previous_y,
        previous_foothold_id,
        previous_stance,
    ) = next(iter(active_mobs.items()))
    mode = "stationary"
    source_server_frame_index = None
    exact_relative_motion_shape_evidence = 0
    matching_displacement_path_evidence = 0
    matching_displacement_shape_evidence = 0
    if not path_requested:
        broadcast = MobMovementBroadcast(
            object_id=object_id,
            opaque_control=control_prefix,
            reference_x=target_x,
            reference_y=target_y,
            commands=(
                MobMovementCommand.absolute(
                    position_x=target_x,
                    position_y=target_y,
                    velocity_x=0,
                    velocity_y=0,
                    foothold_id=foothold_id,
                    stance=stance,
                    duration_ms=1_080,
                ),
            ),
        )
    else:
        path_evidence_candidates = context.captured_paths

        desired_displacement = (
            target_x - previous_x,
            target_y - previous_y,
        )
        matching_displacement_paths: list[_CapturedMobMovementPath] = []
        matching_displacement_shapes: set[tuple[object, ...]] = set()
        for candidate in path_evidence_candidates:
            if (
                candidate.template_id != template_id
                or candidate.broadcast.opaque_control != control_prefix
                or len(candidate.broadcast.commands) < 2
                or any(
                    command.command_type != 0
                    for command in candidate.broadcast.commands
                )
            ):
                continue
            if (
                candidate.relative_motion_shape is None
                or candidate.displacement != desired_displacement
            ):
                continue
            matching_displacement_paths.append(candidate)
            matching_displacement_shapes.add(
                candidate.relative_motion_shape
            )
        matching_displacement_path_evidence = len(
            matching_displacement_paths
        )
        matching_displacement_shape_evidence = len(
            matching_displacement_shapes
        )

        if auto_select_captured_path:
            if not matching_displacement_paths:
                raise ValueError(
                    "movement evidence has no multi-command path for active "
                    f"template {template_id} and displacement "
                    f"{desired_displacement}"
                )
            if len(matching_displacement_shapes) != 1:
                raise ValueError(
                    "movement evidence has ambiguous relative motion shapes "
                    f"for displacement {desired_displacement}: "
                    f"{len(matching_displacement_shapes)}"
                )
            selected_path = matching_displacement_paths[0]
            mode = "auto_selected_captured_path"
        else:
            selected_candidates = tuple(
                candidate
                for candidate in path_evidence_candidates
                if candidate.server_frame_index
                == path_evidence_server_frame_index
            )
            if len(selected_candidates) != 1:
                raise ValueError(
                    "mob movement path evidence server frame was not found"
                )
            selected_path = selected_candidates[0]
        source_server_frame_index = selected_path.server_frame_index
        source_template_id = selected_path.template_id
        source_broadcast = selected_path.broadcast
        if source_template_id != template_id:
            raise ValueError(
                "mob movement path evidence template does not match the "
                f"active mob: {source_template_id} != {template_id}"
            )
        if source_broadcast.opaque_control != control_prefix:
            raise ValueError(
                "mob movement path evidence does not use the dominant "
                "captured control prefix"
            )
        if len(source_broadcast.commands) < 2:
            raise ValueError(
                "mob movement path evidence must contain multiple commands"
            )
        if any(
            command.command_type != 0
            for command in source_broadcast.commands
        ):
            raise ValueError(
                "mob movement path evidence must contain only absolute "
                "commands"
            )
        source_endpoint = source_broadcast.commands[-1].position
        if source_endpoint is None:
            raise ValueError("mob movement path evidence has no endpoint")
        translate_x = target_x - source_endpoint[0]
        translate_y = target_y - source_endpoint[1]
        reference_x = source_broadcast.reference_x + translate_x
        reference_y = source_broadcast.reference_y + translate_y
        if (previous_x, previous_y) != (reference_x, reference_y):
            raise ValueError(
                "active mob position does not match the translated path "
                f"reference: {(previous_x, previous_y)} != "
                f"{(reference_x, reference_y)}"
            )
        if previous_foothold_id != foothold_id:
            raise ValueError(
                "active mob foothold does not match the translated path "
                f"foothold: {previous_foothold_id} != {foothold_id}"
            )
        translated_commands: list[MobMovementCommand] = []
        for source_command in source_broadcast.commands:
            source_position = source_command.position
            if source_position is None:
                raise ValueError(
                    "mob movement path evidence contains a relative command"
                )
            position_x = source_position[0] + translate_x
            position_y = source_position[1] + translate_y
            if not all(
                -0x8000 <= value <= 0x7FFF
                for value in (position_x, position_y)
            ):
                raise ValueError(
                    "translated mob movement command position exceeds int16"
                )
            velocity_x, velocity_y = source_command.velocity
            translated_commands.append(
                MobMovementCommand.absolute(
                    position_x=position_x,
                    position_y=position_y,
                    velocity_x=velocity_x,
                    velocity_y=velocity_y,
                    foothold_id=foothold_id,
                    stance=source_command.stance,
                    duration_ms=source_command.duration_ms,
                )
            )
        if not all(
            -0x8000 <= value <= 0x7FFF
            for value in (reference_x, reference_y)
        ):
            raise ValueError("translated mob movement reference exceeds int16")
        source_shape = selected_path.relative_motion_shape
        if source_shape is None:
            raise ValueError(
                "mob movement path evidence contains a relative command"
            )
        for evidence_path in path_evidence_candidates:
            if (
                evidence_path.template_id != template_id
                or evidence_path.broadcast.opaque_control != control_prefix
            ):
                continue
            if evidence_path.relative_motion_shape == source_shape:
                exact_relative_motion_shape_evidence += 1
        if exact_relative_motion_shape_evidence == 0:
            raise ValueError(
                "mob movement relative motion shape has no exact evidence"
            )
        stance = translated_commands[-1].stance
        if not auto_select_captured_path:
            mode = "translated_captured_path"
        broadcast = MobMovementBroadcast(
            object_id=object_id,
            opaque_control=source_broadcast.opaque_control,
            reference_x=reference_x,
            reference_y=reference_y,
            commands=tuple(translated_commands),
        )
    broadcast.to_bytes()
    return MobMovementBroadcastPlan(
        broadcast=broadcast,
        mode=mode,
        entity=entity,
        template_id=template_id,
        field_epoch=analysis.state.field_epoch,
        previous_x=previous_x,
        previous_y=previous_y,
        previous_foothold_id=previous_foothold_id,
        previous_stance=previous_stance,
        target_x=target_x,
        target_y=target_y,
        target_foothold_id=foothold_id,
        stance=stance,
        broadcast_evidence=len(evidence_broadcasts),
        exact_stationary_shape_evidence=exact_stationary_shape_evidence,
        source_server_frame_index=source_server_frame_index,
        exact_relative_motion_shape_evidence=(
            exact_relative_motion_shape_evidence
        ),
        matching_displacement_path_evidence=(
            matching_displacement_path_evidence
        ),
        matching_displacement_shape_evidence=(
            matching_displacement_shape_evidence
        ),
    )


def plan_composed_mob_movement_broadcasts(
    transcript: Transcript,
    *,
    post_transcript_server_frames: tuple[bytes, ...] = (),
    evidence_transcript: Transcript | None = None,
    target_x: int,
    target_y: int,
    foothold_id: int,
    max_steps: int = 4,
    planning_context: MobMovementPlanningContext | None = None,
) -> MobMovementBroadcastSequencePlan:
    """Compose a unique shortest sequence of captured movement paths."""

    if not 2 <= max_steps <= 8:
        raise ValueError("composed mob movement max steps must be in 2..8")
    if not all(-0x8000 <= value <= 0x7FFF for value in (target_x, target_y)):
        raise ValueError("mob movement target coordinates must fit in int16")
    if not 0 <= foothold_id <= 0xFFFF:
        raise ValueError("mob movement target foothold must fit in uint16")

    context = planning_context or build_mob_movement_planning_context(
        transcript, evidence_transcript
    )
    analysis = context.analysis
    active_mobs = _active_mobs_after_server_frames(
        analysis, post_transcript_server_frames
    )
    if len(active_mobs) != 1:
        raise ValueError(
            "composed mob movement planning requires exactly one active "
            f"modeled mob, found {len(active_mobs)}"
        )
    _, (
        _,
        template_id,
        previous_x,
        previous_y,
        previous_foothold_id,
        _,
    ) = next(iter(active_mobs.items()))
    if previous_foothold_id != foothold_id:
        raise ValueError(
            "active mob foothold does not match the composed path foothold: "
            f"{previous_foothold_id} != {foothold_id}"
        )
    desired_displacement = (
        target_x - previous_x,
        target_y - previous_y,
    )
    if desired_displacement == (0, 0):
        raise ValueError("composed mob movement target equals current position")

    control_prefix = MOB_MOVEMENT_CONTROL_PREFIX
    grouped_paths: dict[
        tuple[int, int],
        dict[tuple[object, ...], list[_CapturedMobMovementPath]],
    ] = {}
    for path in context.captured_paths:
        if (
            path.template_id != template_id
            or path.broadcast.opaque_control != control_prefix
            or len(path.broadcast.commands) < 2
            or path.relative_motion_shape is None
            or path.displacement is None
            or path.displacement == (0, 0)
            or any(
                command.command_type != 0
                for command in path.broadcast.commands
            )
        ):
            continue
        grouped_paths.setdefault(path.displacement, {}).setdefault(
            path.relative_motion_shape, []
        ).append(path)
    usable_paths: dict[tuple[int, int], _CapturedMobMovementPath] = {}
    ambiguous_displacements = 0
    for displacement, shapes in grouped_paths.items():
        if len(shapes) != 1:
            ambiguous_displacements += 1
            continue
        repeated_paths = next(iter(shapes.values()))
        usable_paths[displacement] = min(
            repeated_paths,
            key=lambda path: path.server_frame_index,
        )
    if not usable_paths:
        raise ValueError(
            f"movement evidence has no unique path shapes for template "
            f"{template_id}"
        )

    target_offset = desired_displacement
    frontier: dict[
        tuple[int, int],
        list[tuple[tuple[int, int], ...]],
    ] = {(0, 0): [()]}
    selected_sequences: list[tuple[tuple[int, int], ...]] | None = None
    ordered_displacements = tuple(sorted(usable_paths))
    for _ in range(max_steps):
        next_frontier: dict[
            tuple[int, int],
            list[tuple[tuple[int, int], ...]],
        ] = {}
        for position, sequences in frontier.items():
            distance_before = (
                abs(target_offset[0] - position[0])
                + abs(target_offset[1] - position[1])
            )
            for displacement in ordered_displacements:
                next_position = (
                    position[0] + displacement[0],
                    position[1] + displacement[1],
                )
                distance_after = (
                    abs(target_offset[0] - next_position[0])
                    + abs(target_offset[1] - next_position[1])
                )
                if distance_after >= distance_before:
                    continue
                absolute_position = (
                    previous_x + next_position[0],
                    previous_y + next_position[1],
                )
                if not all(
                    -0x8000 <= value <= 0x7FFF
                    for value in absolute_position
                ):
                    continue
                destination_sequences = next_frontier.setdefault(
                    next_position, []
                )
                for sequence in sequences:
                    candidate_sequence = sequence + (displacement,)
                    if candidate_sequence in destination_sequences:
                        continue
                    if len(destination_sequences) < 2:
                        destination_sequences.append(candidate_sequence)
        if len(next_frontier) > 4_096:
            raise ValueError(
                "composed mob movement search exceeded 4096 states"
            )
        if target_offset in next_frontier:
            selected_sequences = next_frontier[target_offset]
            break
        frontier = next_frontier
        if not frontier:
            break
    if selected_sequences is None:
        raise ValueError(
            "movement evidence has no monotonic composed path to displacement "
            f"{desired_displacement} within {max_steps} steps"
        )
    if len(selected_sequences) != 1:
        raise ValueError(
            "movement evidence has ambiguous shortest composed paths to "
            f"displacement {desired_displacement}"
        )
    selected_displacements = selected_sequences[0]
    if len(selected_displacements) < 2:
        raise ValueError(
            "movement evidence has a direct path; use automatic single-path "
            "emission"
        )

    planned_frames = list(post_transcript_server_frames)
    steps: list[MobMovementBroadcastPlan] = []
    current_x = previous_x
    current_y = previous_y
    for displacement in selected_displacements:
        current_x += displacement[0]
        current_y += displacement[1]
        source = usable_paths[displacement]
        step = plan_mob_movement_broadcast(
            transcript,
            post_transcript_server_frames=tuple(planned_frames),
            evidence_transcript=evidence_transcript,
            target_x=current_x,
            target_y=current_y,
            foothold_id=foothold_id,
            path_evidence_server_frame_index=source.server_frame_index,
            planning_context=context,
        )
        steps.append(step)
        planned_frames.append(step.broadcast.to_bytes())
    if (current_x, current_y) != (target_x, target_y):
        raise ValueError("composed mob movement did not reach its target")
    return MobMovementBroadcastSequencePlan(
        steps=tuple(steps),
        max_steps=max_steps,
        usable_displacements=len(usable_paths),
        ambiguous_displacements=ambiguous_displacements,
        shortest_sequence_count=len(selected_sequences),
    )


def derive_mob_movement_acknowledgement_policy(
    transcript: Transcript,
    *,
    evidence_transcript: Transcript | None = None,
) -> MobMovementAcknowledgementPolicy:
    """Derive only acknowledgement behavior proven by a validated capture."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    evidence_analysis = (
        analysis
        if evidence_transcript is None
        else analyze_gameplay_transcript(evidence_transcript)
    )
    if not evidence_analysis.valid:
        raise ValueError(
            "movement-acknowledgement evidence transcript failed packet/state "
            "validation"
        )
    state = analysis.state
    evidence_state = evidence_analysis.state
    if evidence_state.matched_movement_acknowledgements == 0:
        raise ValueError(
            "movement evidence has no correlated mob movement acknowledgements"
        )
    if (
        evidence_state.movement_acknowledgement_flag_matches
        != evidence_state.matched_movement_acknowledgements
    ):
        raise ValueError(
            "movement acknowledgement flag rule is not exact in this capture"
        )
    if (
        evidence_state.movement_acknowledgement_zero_auxiliary_pairs
        != evidence_state.matched_movement_acknowledgements
    ):
        raise ValueError(
            "movement acknowledgement auxiliary bytes are not uniformly zero"
        )
    ambiguous_templates = {
        template_id: sorted(status_values)
        for template_id, status_values in (
            evidence_state.movement_acknowledgement_values_by_template.items()
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
            evidence_state.movement_acknowledgement_values_by_template.items()
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
            evidence_state.movement_acknowledgements_by_template
        ),
        known_mob_templates=dict(state.mob_templates),
        active_mob_object_ids=set(state.mobs),
        field_epoch=state.field_epoch,
        matched_pairs=evidence_state.matched_movement_acknowledgements,
        known_template_pairs=(
            evidence_state.movement_acknowledgements_with_known_template
        ),
        unknown_template_pairs=(
            evidence_state.movement_acknowledgements_with_unknown_template
        ),
        flag_rule_matches=(
            evidence_state.movement_acknowledgement_flag_matches
        ),
        zero_auxiliary_pairs=(
            evidence_state.movement_acknowledgement_zero_auxiliary_pairs
        ),
        pending_submissions=evidence_state.pending_movements,
    )


def derive_mob_health_response_policy(
    transcript: Transcript,
) -> MobHealthResponsePolicy:
    """Build exact custom-server mob HP state from a validated world replay."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    state = analysis.state
    mismatches = state.client_attack_health_prediction_mismatches
    if state.client_attack_health_one_hp_differences != mismatches:
        raise ValueError(
            "world transcript has combat HP differences larger than one HP"
        )
    if state.client_attack_mismatches_without_relays != mismatches:
        raise ValueError(
            "world transcript has combat HP mismatches with an intervening "
            "modeled attack-relay hit"
        )
    if any(
        delta not in {-1, 1}
        for delta in state.client_attack_health_mismatch_damage_deltas
    ):
        raise ValueError(
            "world transcript has an unsupported authoritative damage delta"
        )

    mobs: dict[int, ReactiveMobHealth] = {}
    for object_id, entity in state.mobs.items():
        if entity.max_hp is None:
            continue
        if entity.health_percentage is None:
            current_hp = entity.max_hp
        else:
            if (
                entity.health_hp_min is None
                or entity.health_hp_max is None
            ):
                raise ValueError(
                    f"{entity.alias} has no integer HP bounds"
                )
            if entity.health_hp_min != entity.health_hp_max:
                raise ValueError(
                    f"{entity.alias} has ambiguous final integer HP bounds"
                )
            current_hp = entity.health_hp_min
        mobs[object_id] = ReactiveMobHealth(
            alias=entity.alias,
            template_id=entity.spawn.template_id,
            current_hp=current_hp,
            max_hp=entity.max_hp,
        )
    return MobHealthResponsePolicy(
        mobs=mobs,
        field_epoch=state.field_epoch,
        source_health_predictions=(
            state.client_attack_health_predictions
        ),
        source_exact_health_predictions=(
            state.client_attack_health_prediction_matches
        ),
        source_one_hp_differences=(
            state.client_attack_health_one_hp_differences
        ),
    )


def plan_final_field_drop_position_rewrite(
    transcript: Transcript,
    position_x: int,
    position_y: int,
) -> FinalFieldDropPositionReplayPlan:
    """Move one typed final field-load drop without changing its identity."""

    for name, value in (("x", position_x), ("y", position_y)):
        if not -0x8000 <= value <= 0x7FFF:
            raise ValueError(f"rewritten drop position {name} must fit in i16")
    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    active_drops = tuple(analysis.state.field_drops.items())
    if len(active_drops) != 1:
        raise ValueError(
            "world transcript final field must contain exactly one active drop"
        )
    drop_object_id, entity = active_drops[0]
    spawn = entity.spawn
    if (
        spawn.spawn_mode != FieldDropSpawn.FIELD_LOAD_MODE
        or spawn.drop_kind != FieldDropSpawn.ITEM
    ):
        raise ValueError(
            "final active drop must use the captured field-load item variant"
        )
    observation = next(
        (
            candidate
            for candidate in reversed(analysis.observations)
            if isinstance(candidate.parsed, FieldDropSpawn)
            and candidate.parsed.drop_object_id == drop_object_id
        ),
        None,
    )
    if observation is None:
        raise ValueError("final active drop has no typed spawn observation")
    replacement = replace(
        spawn,
        position_x=position_x,
        position_y=position_y,
    )
    payload = replacement.to_bytes()
    if len(payload) != observation.length:
        raise ValueError("drop position rewrite unexpectedly changed packet length")
    if FieldDropSpawn.parse(payload) != replacement:
        raise ValueError("drop position rewrite failed packet round-trip validation")
    return FinalFieldDropPositionReplayPlan(
        server_frame_index=observation.direction_index,
        drop_alias=entity.alias,
        item_id=spawn.value,
        original_position_x=spawn.position_x,
        original_position_y=spawn.position_y,
        rewritten_position_x=position_x,
        rewritten_position_y=position_y,
        field_epoch=analysis.state.field_epoch,
        replacement=replacement,
    )


def plan_final_field_drop_owner_to_player_rewrite(
    transcript: Transcript,
) -> FinalFieldDropOwnerReplayPlan:
    """Make the sole final field-load item drop belong to the typed player."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    snapshot_observations = tuple(
        observation
        for observation in analysis.observations
        if isinstance(
            observation.parsed,
            (InitialFieldSnapshot, TypedInitialFieldSnapshot),
        )
    )
    if len(snapshot_observations) != 1:
        raise ValueError(
            "world transcript must contain exactly one initial field snapshot"
        )
    player_character_id = (
        snapshot_observations[0].parsed.character.character_id
    )
    if analysis.state.entry_character_id != player_character_id:
        raise ValueError(
            "initial player character id does not match the world entry request"
        )

    active_drops = tuple(analysis.state.field_drops.items())
    if len(active_drops) != 1:
        raise ValueError(
            "world transcript final field must contain exactly one active drop"
        )
    drop_object_id, entity = active_drops[0]
    spawn = entity.spawn
    if (
        spawn.spawn_mode != FieldDropSpawn.FIELD_LOAD_MODE
        or spawn.drop_kind != FieldDropSpawn.ITEM
    ):
        raise ValueError(
            "final active drop must use the captured field-load item variant"
        )
    if spawn.owner_value_1 != spawn.owner_value_2:
        raise ValueError("final active drop owner values must match")
    if spawn.ownership_flag != 0:
        raise ValueError(
            "final active drop must use the capture-validated ownership flag"
        )
    if spawn.owner_value_1 == player_character_id:
        raise ValueError("final active drop already belongs to the initial player")
    observation = next(
        (
            candidate
            for candidate in reversed(analysis.observations)
            if isinstance(candidate.parsed, FieldDropSpawn)
            and candidate.parsed.drop_object_id == drop_object_id
        ),
        None,
    )
    if observation is None:
        raise ValueError("final active drop has no typed spawn observation")
    replacement = replace(
        spawn,
        owner_value_1=player_character_id,
        owner_value_2=player_character_id,
    )
    payload = replacement.to_bytes()
    if len(payload) != observation.length:
        raise ValueError("drop owner rewrite unexpectedly changed packet length")
    if FieldDropSpawn.parse(payload) != replacement:
        raise ValueError("drop owner rewrite failed packet round-trip validation")
    return FinalFieldDropOwnerReplayPlan(
        server_frame_index=observation.direction_index,
        drop_alias=entity.alias,
        item_id=spawn.value,
        ownership_flag=spawn.ownership_flag,
        field_epoch=analysis.state.field_epoch,
        replacement=replacement,
    )


def plan_initial_field_snapshot_replay(
    transcript: Transcript,
    current_hp: int | None = None,
) -> InitialPlayerHpReplayPlan:
    """Materialize and optionally mutate the complete typed initial snapshot."""
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
    if isinstance(snapshot, TypedInitialFieldSnapshot):
        typed_state = snapshot
        envelope = snapshot.to_snapshot()
    elif isinstance(snapshot, InitialFieldSnapshot):
        envelope = snapshot
        typed_state = TypedInitialFieldSnapshot.parse(snapshot.to_bytes())
    else:
        raise ValueError("initial field observation has no typed snapshot")
    emitted_current_hp = (
        typed_state.character.current_hp
        if current_hp is None
        else current_hp
    )
    if not 0 <= emitted_current_hp <= typed_state.character.max_hp:
        raise ValueError(
            f"rewritten current HP must be between 0 and "
            f"{typed_state.character.max_hp}"
        )
    typed_replacement = replace(
        typed_state,
        character=replace(
            typed_state.character,
            current_hp=emitted_current_hp,
        ),
    )
    replacement_payload = typed_replacement.to_bytes()
    if len(replacement_payload) != observation.length:
        raise ValueError(
            "typed initial field emitter unexpectedly changed packet length"
        )
    if current_hp is None and replacement_payload != envelope.to_bytes():
        raise ValueError(
            "typed initial field emitter changed the unmodified snapshot"
        )
    if (
        TypedInitialFieldSnapshot.parse(replacement_payload)
        != typed_replacement
    ):
        raise ValueError(
            "typed initial field emitter failed nested-state round-trip validation"
        )
    replacement = typed_replacement.to_snapshot()
    if InitialFieldSnapshot.parse(replacement_payload) != replacement:
        raise ValueError(
            "typed initial field emitter failed envelope round-trip validation"
        )
    return InitialPlayerHpReplayPlan(
        server_frame_index=observation.direction_index,
        original_current_hp=typed_state.character.current_hp,
        rewritten_current_hp=emitted_current_hp,
        max_hp=typed_state.character.max_hp,
        replacement=replacement,
        typed_state=typed_replacement,
    )


def plan_initial_player_hp_rewrite(
    transcript: Transcript,
    current_hp: int,
) -> InitialPlayerHpReplayPlan:
    """Compatibility wrapper for a current-HP typed snapshot mutation."""
    return plan_initial_field_snapshot_replay(transcript, current_hp)


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


def plan_inventory_quantity_update(
    transcript: Transcript,
    inventory: str,
    slot: int,
    quantity: int,
) -> InventoryQuantityUpdateReplayPlan:
    """Generate one typed stack-quantity update for an existing item."""
    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    inventory_type = STACK_INVENTORY_TYPES.get(inventory)
    if inventory_type is None:
        raise ValueError("inventory quantity update requires use, setup, or etc")
    if not 1 <= slot <= 0x7FFF:
        raise ValueError("inventory slot must be between 1 and 32767")
    if not 1 <= quantity <= 0xFFFF:
        raise ValueError("inventory quantity must be between 1 and 65535")
    item = next(
        (
            item
            for item in analysis.state.inventory_items.get(inventory, ())
            if item.slot == slot
        ),
        None,
    )
    if item is None:
        raise ValueError(f"modeled {inventory} inventory has no slot {slot}")
    if item.quantity is None:
        raise ValueError(f"modeled {inventory} slot {slot} is not stackable")
    update = InventoryChangeSet(
        update_flag=0,
        modifications=(
            InventoryModification(
                operation=InventoryModification.UPDATE_QUANTITY,
                inventory_type=inventory_type,
                slot=slot,
                quantity=quantity,
            ),
        ),
    )
    plaintext = update.to_bytes()
    if InventoryChangeSet.parse(plaintext) != update:
        raise ValueError("generated inventory quantity update failed round-trip")
    return InventoryQuantityUpdateReplayPlan(
        update=update,
        inventory=inventory,
        slot=slot,
        item_id=item.item_id,
        original_quantity=item.quantity,
        emitted_quantity=quantity,
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


def plan_field_npc_spawn_replay(
    transcript: Transcript,
) -> FieldNpcSpawnReplayPlan:
    """Materialize every fully typed NPC spawn for state-based frame replay."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    frames: list[NpcSpawnReplayFrame] = []
    for observation in analysis.observations:
        if observation.kind != "npc_spawn":
            continue
        spawn = observation.parsed
        entity = observation.details.get("entity")
        field_epoch = observation.details.get("field_epoch")
        if not isinstance(spawn, NpcSpawn):
            raise ValueError("NPC spawn observation has no typed packet")
        if not isinstance(entity, str) or not isinstance(field_epoch, int):
            raise ValueError(
                "NPC spawn observation has incomplete folded state"
            )
        payload = spawn.to_bytes()
        if len(payload) != observation.length:
            raise ValueError("typed NPC spawn emitter changed packet length")
        if NpcSpawn.parse(payload) != spawn:
            raise ValueError(
                "typed NPC spawn emitter failed round-trip validation"
            )
        frames.append(
            NpcSpawnReplayFrame(
                server_frame_index=observation.direction_index,
                entity=entity,
                field_epoch=field_epoch,
                spawn=spawn,
            )
        )
    if not frames:
        raise ValueError("world transcript has no typed NPC spawn frames")
    frame_indices = [frame.server_frame_index for frame in frames]
    if len(frame_indices) != len(set(frame_indices)):
        raise ValueError(
            "typed NPC spawn frames contain duplicate server indices"
        )
    return FieldNpcSpawnReplayPlan(frames=tuple(frames))


def plan_fixed_server_record_replay(
    transcript: Transcript,
) -> FixedServerReplayPlan:
    """Materialize every capture-validated fixed-width neutral server record."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    record_types = (
        FixedServerEmptyRecord,
        FixedServerI32Record,
        FixedServerOpcode11Record,
        FixedServerU16PairRecord,
        FixedServerU16Record,
        FixedServerU32PairRecord,
        FixedServerU32Record,
        FixedServerU64Record,
        FixedServerU8Record,
        InitialCharacterContextRecord,
    )
    frames: list[FixedServerReplayFrame] = []
    for observation in analysis.observations:
        if observation.kind not in {
            "fixed_server_record",
            "initial_character_context",
        }:
            continue
        record = observation.parsed
        if not isinstance(record, record_types):
            raise ValueError(
                "fixed-server observation has no typed record"
            )
        payload = record.to_bytes()
        if len(payload) != observation.length:
            raise ValueError(
                "typed fixed-server emitter changed packet length"
            )
        if type(record).parse(payload) != record:
            raise ValueError(
                "typed fixed-server emitter failed round-trip validation"
            )
        frames.append(
            FixedServerReplayFrame(
                server_frame_index=observation.direction_index,
                record=record,
                kind=observation.kind,
                details=tuple(sorted(observation.details.items())),
            )
        )
    if not frames:
        raise ValueError("world transcript has no typed fixed-server frames")
    frame_indices = [frame.server_frame_index for frame in frames]
    if len(frame_indices) != len(set(frame_indices)):
        raise ValueError(
            "typed fixed-server frames contain duplicate server indices"
        )
    return FixedServerReplayPlan(frames=tuple(frames))


def plan_variable_server_record_replay(
    transcript: Transcript,
) -> VariableServerReplayPlan:
    """Materialize every capture-bounded opcode-156/385 variant record."""

    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("world transcript failed packet/state validation")
    frames: list[VariableServerReplayFrame] = []
    for observation in analysis.observations:
        if observation.kind != "variable_server_record":
            continue
        record = observation.parsed
        if not isinstance(record, VariableServerRecord):
            raise ValueError(
                "variable-server observation has no typed record"
            )
        payload = record.to_bytes()
        if len(payload) != observation.length:
            raise ValueError(
                "typed variable-server emitter changed packet length"
            )
        if VariableServerRecord.parse(payload) != record:
            raise ValueError(
                "typed variable-server emitter failed round-trip validation"
            )
        frames.append(
            VariableServerReplayFrame(
                server_frame_index=observation.direction_index,
                record=record,
                field_epoch=int(observation.details["field_epoch"]),
            )
        )
    if not frames:
        raise ValueError("world transcript has no variable-server frames")
    frame_indices = [frame.server_frame_index for frame in frames]
    if len(frame_indices) != len(set(frame_indices)):
        raise ValueError(
            "typed variable-server frames contain duplicate server indices"
        )
    return VariableServerReplayPlan(frames=tuple(frames))


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
    life_movement_submission_command_types = json.dumps(
        dict(sorted(state.life_movement_submission_commands_by_type.items()))
    )
    life_movement_broadcast_command_types = json.dumps(
        dict(sorted(state.life_movement_broadcast_commands_by_type.items()))
    )
    life_movement_tail_types = json.dumps(
        dict(sorted(state.life_movement_tail_types.items()))
    )
    life_movement_tail_markers = json.dumps(
        dict(sorted(state.life_movement_tail_markers.items()))
    )
    client_opcode_13_message_types = json.dumps(
        dict(sorted(state.client_opcode_13_messages_by_type.items()))
    )
    client_opcode_13_opaque_lengths = json.dumps(
        dict(sorted(state.client_opcode_13_opaque_lengths.items()))
    )
    server_opcode_13_message_types = json.dumps(
        dict(sorted(state.server_opcode_13_messages_by_type.items()))
    )
    server_opcode_13_opaque_lengths = json.dumps(
        dict(sorted(state.server_opcode_13_opaque_lengths.items()))
    )
    client_attack_opcodes = json.dumps(
        dict(sorted(state.client_attack_actions_by_opcode.items()))
    )
    client_attack_shapes = json.dumps(
        dict(sorted(state.client_attack_shapes.items()))
    )
    client_attack_mismatch_damage_deltas = json.dumps(
        dict(
            sorted(
                state.client_attack_health_mismatch_damage_deltas.items()
            )
        )
    )
    server_attack_opcodes = json.dumps(
        dict(sorted(state.server_attack_relays_by_opcode.items()))
    )
    server_attack_target_counts = json.dumps(
        dict(sorted(state.server_attack_target_counts.items()))
    )
    server_attack_hit_counts = json.dumps(
        dict(sorted(state.server_attack_hit_counts.items()))
    )
    server_attack_hit_actions = json.dumps(
        dict(sorted(state.server_attack_hit_actions.items()))
    )
    server_melee_attack_tags = json.dumps(
        dict(sorted(state.server_melee_attack_tags.items()))
    )
    server_melee_attack_displays = json.dumps(
        dict(sorted(state.server_melee_attack_displays.items()))
    )
    server_ranged_attack_skill_levels = json.dumps(
        dict(sorted(state.server_ranged_attack_skill_levels.items()))
    )
    server_ranged_attack_skill_ids = json.dumps(
        dict(sorted(state.server_ranged_attack_skill_ids.items()))
    )
    server_ranged_attack_projectile_ids = json.dumps(
        dict(sorted(state.server_ranged_attack_projectile_ids.items()))
    )
    client_opcode_101_header_values = json.dumps(
        dict(sorted(state.client_opcode_101_header_values.items()))
    )
    client_opcode_101_primary_values = json.dumps(
        dict(sorted(state.client_opcode_101_primary_values.items()))
    )
    client_opcode_101_flag_values = json.dumps(
        dict(sorted(state.client_opcode_101_flag_values.items()))
    )
    client_opcode_101_secondary_values = json.dumps(
        dict(sorted(state.client_opcode_101_secondary_values.items()))
    )
    client_opcode_101_tail_values = json.dumps(
        dict(sorted(state.client_opcode_101_tail_values.items()))
    )
    client_skill_use_requests_by_skill_id = json.dumps(
        dict(sorted(state.client_skill_use_requests_by_skill_id.items()))
    )
    client_skill_use_level_values = json.dumps(
        dict(sorted(state.client_skill_use_level_values.items()))
    )
    client_skill_use_trailing_values = json.dumps(
        dict(sorted(state.client_skill_use_trailing_values.items()))
    )
    local_temporary_stat_mask_patterns = json.dumps(
        dict(sorted(state.local_temporary_stat_mask_patterns.items()))
    )
    server_opcode_49_variants = json.dumps(
        dict(sorted(state.server_opcode_49_by_variant.items()))
    )
    server_opcode_49_shapes = json.dumps(
        dict(sorted(state.server_opcode_49_by_shape.items()))
    )
    server_opcode_77_variants = json.dumps(
        dict(sorted(state.server_opcode_77_by_variant.items()))
    )
    server_opcode_77_control_patterns = json.dumps(
        dict(sorted(state.server_opcode_77_control_patterns.items()))
    )
    client_opcode_217_record_formats = json.dumps(
        dict(sorted(state.client_opcode_217_records_by_format.items()))
    )
    client_opcode_217_record_counts = json.dumps(
        dict(sorted(state.client_opcode_217_record_counts.items()))
    )
    neutral_server_record_opcodes = json.dumps(
        dict(sorted(state.neutral_server_records_by_opcode.items()))
    )
    tutorial_ui_text_code_units = json.dumps(
        dict(sorted(state.tutorial_ui_text_code_units.items()))
    )
    tutorial_ui_value_1 = json.dumps(
        dict(sorted(state.tutorial_ui_value_1.items()))
    )
    tutorial_ui_value_2 = json.dumps(
        dict(sorted(state.tutorial_ui_value_2.items()))
    )
    tutorial_ui_control_values = json.dumps(
        dict(sorted(state.tutorial_ui_control_values.items()))
    )
    positioned_effect_opcodes = json.dumps(
        dict(sorted(state.positioned_effect_records_by_opcode.items()))
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
    inventory_modification_operations = json.dumps(
        dict(sorted(state.inventory_modifications_by_operation.items()))
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
            f"progression_region_bytes:{state.progression_region_bytes} "
            f"change_packets:{state.inventory_change_packets} "
            f"modifications:{state.inventory_modifications} "
            f"operations:{inventory_modification_operations} "
            f"empty_packets:{state.inventory_empty_change_packets} "
            f"unknown_slots:{state.inventory_unknown_slot_modifications}"
        ),
        (
            f"item_use=requests:{state.item_use_requests} "
            f"inventory_matches:{state.item_use_inventory_matches} "
            f"inventory_mismatches:{state.item_use_inventory_mismatches} "
            f"effect_matches:{state.item_use_effect_matches} "
            f"effect_mismatches:{state.item_use_effect_mismatches} "
            f"policy_rejections:{state.item_use_policy_rejections} "
            f"unknown_slots:{state.item_use_unknown_slots} "
            f"item_mismatches:{state.item_use_item_mismatches} "
            f"pending:{state.pending_item_uses}"
        ),
        (
            f"item_pickup=requests:{state.item_pickup_requests} "
            f"base:{state.item_pickup_base_requests} "
            f"extended:{state.item_pickup_extended_requests} "
            f"epoch_matches:{state.item_pickup_field_epoch_matches} "
            f"epoch_mismatches:{state.item_pickup_field_epoch_mismatches} "
            f"known_drops:{state.item_pickup_known_drops} "
            f"unknown_drops:{state.item_pickup_unknown_drops} "
            f"results:{state.item_pickup_results} "
            "spawn_result_matches:"
            f"{state.item_pickup_spawn_result_matches} "
            "spawn_result_mismatches:"
            f"{state.item_pickup_spawn_result_mismatches} "
            f"effect_matches:{state.item_pickup_effect_matches} "
            f"effect_mismatches:{state.item_pickup_effect_mismatches} "
            "inferred_mesos_baselines:"
            f"{state.item_pickup_inferred_mesos_baselines} "
            f"removal_matches:{state.item_pickup_removal_matches} "
            f"removal_mismatches:{state.item_pickup_removal_mismatches} "
            f"policy_rejections:{state.item_pickup_policy_rejections} "
            f"field_removals:{state.field_drop_removals} "
            f"pending:{state.pending_item_pickups}"
        ),
        (
            f"field_drops=active:{len(state.field_drops)} "
            f"packets:{state.field_drop_spawn_packets} "
            f"spawned:{state.field_drop_spawns} "
            f"refreshed:{state.field_drop_refreshes} "
            f"refresh_mismatches:{state.field_drop_refresh_mismatches} "
            "known_source_mob:"
            f"{state.field_drop_spawns_with_known_source_mob} "
            "unknown_source_mob:"
            f"{state.field_drop_spawns_with_unknown_source_mob} "
            f"removed_known:{state.field_drop_removals_for_known_drop} "
            f"removed_unknown:{state.field_drop_removals_for_unknown_drop}"
        ),
        (
            f"progression=shape:{state.progression_shape} "
            f"skills:{len(state.skill_levels)} "
            f"string_properties:{len(state.string_property_code_units)} "
            f"timestamp_properties:{len(state.timestamp_property_keys)} "
            f"extended_properties:{len(state.extended_property_code_units)} "
            f"variant:{state.progression_variant}"
        ),
        (
            "skill_records="
            f"requests:{state.skill_level_change_requests} "
            f"updates:{state.skill_record_updates} "
            f"records:{state.skill_record_update_records} "
            f"request_matches:{state.skill_record_request_matches} "
            f"request_mismatches:{state.skill_record_request_mismatches} "
            f"updates_without_request:{state.skill_record_updates_without_request} "
            f"pending_requests:{state.pending_skill_level_change_requests} "
            "acknowledgements:"
            f"{state.skill_record_update_acknowledgements} "
            "matched_acknowledgements:"
            f"{state.matched_skill_record_update_acknowledgements} "
            "unmatched_acknowledgements:"
            f"{state.unmatched_skill_record_update_acknowledgements} "
            "pending_acknowledgements:"
            f"{state.pending_skill_record_update_acknowledgements}"
        ),
        (
            f"fixed_server_records=count:{state.fixed_server_records} "
            f"by_opcode:{dict(state.fixed_server_records_by_opcode)} "
            f"character_contexts:{state.initial_character_contexts}"
        ),
        (
            f"variable_server_records=count:{state.variable_server_records} "
            f"by_opcode:{dict(state.variable_server_records_by_opcode)} "
            f"variants:{dict(state.variable_server_variants)} "
            f"typed_entries:{state.variable_server_typed_entries} "
            f"typed_values:{state.variable_server_typed_values} "
            f"opaque_bytes:{state.variable_server_opaque_bytes}"
        ),
        (
            f"keyboard_bindings=snapshots:{state.keyboard_binding_snapshots} "
            f"selectors:{dict(state.keyboard_binding_selector_counts)} "
            f"skills:{dict(state.keyboard_skill_bindings)} "
            f"known_skills:{state.keyboard_known_skill_bindings} "
            f"left_ctrl_skill:{state.left_ctrl_skill_id}"
        ),
        (
            f"frames=client:{state.packets_by_direction['client_to_server']} "
            f"server:{state.packets_by_direction['server_to_client']}"
        ),
        (
            f"npcs=active:{len(state.npcs)} spawned:{state.npc_spawns} "
            f"lifecycle_spawns:{state.npc_lifecycle_spawns} "
            f"lifecycle_removals:{state.npc_lifecycle_removals} "
            "lifecycle_unknown_removals:"
            f"{state.npc_lifecycle_unknown_removals} "
            f"state_updates:{state.npc_state_updates}"
        ),
        (
            f"mobs=active:{len(state.mobs)} entries:{state.mob_entries} "
            f"leaves:{state.mob_leaves} "
            f"controller_changes:{state.mob_controller_changes} "
            f"movement_broadcasts:{state.mob_movement_broadcasts} "
            f"broadcast_commands:{state.mob_broadcast_commands} "
            f"health_updates:{state.mob_health_percentage_updates} "
            f"health_zero:{state.mob_health_zero_updates} "
            f"health_increases:{state.mob_health_increases} "
            "health_unknown_active_mob:"
            f"{state.mob_health_updates_for_unknown_mobs} "
            f"field_known_templates:{len(state.mob_templates)}"
        ),
        (
            "mob_temporary_stats=active:"
            f"{sum(len(entity.temporary_stats) for entity in state.mobs.values())} "
            f"sets:{state.mob_temporary_stat_sets} "
            f"resets:{state.mob_temporary_stat_resets} "
            "sets_known:"
            f"{state.mob_temporary_stat_sets_for_known_mobs} "
            "sets_unknown:"
            f"{state.mob_temporary_stat_sets_for_unknown_mobs} "
            "resets_known:"
            f"{state.mob_temporary_stat_resets_for_known_mobs} "
            "resets_unknown:"
            f"{state.mob_temporary_stat_resets_for_unknown_mobs} "
            f"refreshes:{state.mob_temporary_stat_set_refreshes} "
            "resets_with_modeled_set:"
            f"{state.mob_temporary_stat_resets_with_modeled_set} "
            "resets_without_modeled_set:"
            f"{state.mob_temporary_stat_resets_without_modeled_set} "
            "attack_relay_matches:"
            f"{state.mob_temporary_stat_attack_relay_matches} "
            "cleared_on_leave:"
            f"{state.mob_temporary_stats_cleared_on_leave} "
            "cleared_on_field_change:"
            f"{state.mob_temporary_stats_cleared_on_field_change} "
            "masks:"
            f"{dict(sorted(state.mob_temporary_stat_mask_patterns.items()))} "
            "source_skills:"
            f"{dict(sorted(state.mob_temporary_stat_source_skills.items()))} "
            "source_levels:"
            f"{dict(sorted(state.mob_temporary_stat_source_levels.items()))} "
            "duration_values:"
            f"{dict(sorted(state.mob_temporary_stat_duration_values.items()))} "
            "set_flags:"
            f"{dict(sorted(state.mob_temporary_stat_set_flags.items()))} "
            "reset_flags:"
            f"{dict(sorted(state.mob_temporary_stat_reset_flags.items()))}"
        ),
        (
            f"player_movement=position:{state.player_x},{state.player_y} "
            f"submitted:{state.player_movement_submissions} "
            f"commands:{state.player_movement_commands} "
            f"command_types:{player_movement_command_types} "
            "remote_observed:"
            f"{len(state.observed_players)} "
            f"remote_entries:{state.remote_player_entries} "
            f"remote_refreshes:{state.remote_player_refreshes} "
            f"remote_leaves:{state.remote_player_leaves} "
            f"remote_unknown_leaves:{state.remote_player_unknown_leaves} "
            "remote_entry_opaque_bytes:"
            f"{state.remote_player_entry_opaque_bytes} "
            "remote_broadcasts:"
            f"{state.remote_player_movement_broadcasts} "
            "remote_known_broadcasts:"
            f"{state.remote_player_movement_broadcasts_for_known_players} "
            "remote_unknown_broadcasts:"
            f"{state.remote_player_movement_broadcasts_for_unknown_players} "
            "remote_commands:"
            f"{state.remote_player_movement_commands} "
            "remote_command_types:"
            f"{remote_player_movement_command_types}"
        ),
        (
            "remote_player_mob_values="
            f"packets:{state.remote_player_mob_value_records} "
            f"known_players:{state.remote_player_mob_values_for_known_players} "
            f"unknown_players:{state.remote_player_mob_values_for_unknown_players} "
            "active_templates:"
            f"{state.remote_player_mob_values_with_active_template} "
            "inactive_templates:"
            f"{state.remote_player_mob_values_with_inactive_template} "
            f"values:{dict(sorted(state.remote_player_mob_values.items()))} "
            "mob_templates:"
            f"{dict(sorted(state.remote_player_mob_templates.items()))} "
            f"flags:{dict(sorted(state.remote_player_mob_value_flags.items()))}"
        ),
        (
            f"life_movement=submitted:{state.life_movement_submissions} "
            f"submission_commands:{state.life_movement_submission_commands} "
            "submission_command_types:"
            f"{life_movement_submission_command_types} "
            f"tail_types:{life_movement_tail_types} "
            f"tail_markers:{life_movement_tail_markers} "
            f"broadcasts:{state.life_movement_broadcasts} "
            f"broadcast_commands:{state.life_movement_broadcast_commands} "
            "broadcast_command_types:"
            f"{life_movement_broadcast_command_types} "
            "known_players:"
            f"{state.life_movement_broadcasts_for_known_players} "
            "unknown_players:"
            f"{state.life_movement_broadcasts_for_unknown_players}"
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
        (
            f"opcode_426_309=notified:{state.opcode_426_notifications} "
            f"acknowledged:{state.opcode_309_acknowledgements} "
            f"matched:{state.matched_opcode_309_acknowledgements} "
            f"unmatched:{state.unmatched_opcode_309_acknowledgements} "
            f"pending:{state.pending_opcode_426_notifications} "
            f"last_rtt_ms:{state.last_opcode_426_round_trip_ms} "
            f"max_rtt_ms:{state.max_opcode_426_round_trip_ms}"
        ),
        (
            f"combat=client_actions:{state.client_attack_actions} "
            f"client_opcodes:{client_attack_opcodes} "
            f"client_shapes:{client_attack_shapes} "
            f"targeted:{state.client_attack_targeted_actions} "
            f"untargeted:{state.client_attack_untargeted_actions} "
            "active_mob_targets:"
            f"{state.client_attack_targets_for_active_mobs} "
            "known_mob_targets:"
            f"{state.client_attack_targets_for_known_mobs} "
            "unknown_mob_targets:"
            f"{state.client_attack_targets_for_unknown_mobs} "
            "client_damage_entries:"
            f"{state.client_attack_damage_entries} "
            "client_damage_actions:"
            f"{state.client_attack_damage_actions} "
            f"client_damage_total:{state.client_attack_damage_total} "
            "client_damage_range:"
            f"{state.client_attack_damage_min}.."
            f"{state.client_attack_damage_max} "
            "client_damage_high_bits:"
            f"{state.client_attack_damage_high_bit_markers} "
            "client_zero_damage_entries:"
            f"{state.client_attack_zero_damage_entries} "
            "client_health_matches:"
            f"{state.client_attack_health_matches} "
            "client_health_predictions:"
            f"{state.client_attack_health_predictions} "
            "client_health_prediction_matches:"
            f"{state.client_attack_health_prediction_matches} "
            "client_health_prediction_mismatches:"
            f"{state.client_attack_health_prediction_mismatches} "
            "client_health_prediction_one_hp_differences:"
            f"{state.client_attack_health_one_hp_differences} "
            "client_health_predictions_with_relay_hits:"
            f"{state.client_attack_predictions_with_relay_hits} "
            "client_health_mismatches_without_relay_hits:"
            f"{state.client_attack_mismatches_without_relays} "
            "client_health_mismatch_damage_deltas:"
            f"{client_attack_mismatch_damage_deltas} "
            "cleared_client_effects:"
            f"{state.client_attack_effects_cleared} "
            "pending_client_effects:"
            f"{state.pending_client_attack_effects} "
            "client_health_rtt_ms:"
            f"{state.last_client_attack_health_response_ms}.."
            f"{state.max_client_attack_health_response_ms} "
            f"server_relays:{state.server_attack_relays} "
            f"server_opcodes:{server_attack_opcodes} "
            f"target_counts:{server_attack_target_counts} "
            f"hit_counts:{server_attack_hit_counts} "
            "known_player_relays:"
            f"{state.server_attack_relays_for_known_players} "
            "unknown_player_relays:"
            f"{state.server_attack_relays_for_unknown_players} "
            f"melee_relays:{state.server_melee_attack_relays} "
            "melee_short_zero_targets:"
            f"{state.server_melee_attack_short_zero_target_forms} "
            f"melee_tags:{server_melee_attack_tags} "
            f"melee_displays:{server_melee_attack_displays} "
            f"ranged_relays:{state.server_ranged_attack_relays} "
            f"ranged_skill_levels:{server_ranged_attack_skill_levels} "
            f"ranged_skill_ids:{server_ranged_attack_skill_ids} "
            f"ranged_projectiles:{server_ranged_attack_projectile_ids} "
            "ranged_known_position_samples:"
            f"{state.server_ranged_attack_positions_for_known_players} "
            "ranged_position_delta_x:"
            f"{state.server_ranged_attack_position_delta_x_min}.."
            f"{state.server_ranged_attack_position_delta_x_max} "
            "ranged_position_delta_y:"
            f"{state.server_ranged_attack_position_delta_y_min}.."
            f"{state.server_ranged_attack_position_delta_y_max} "
            f"target_records:{state.server_attack_target_records} "
            f"zero_object_targets:{state.server_attack_zero_object_targets} "
            "active_relay_targets:"
            f"{state.server_attack_targets_for_active_mobs} "
            "known_relay_targets:"
            f"{state.server_attack_targets_for_known_mobs} "
            "unknown_relay_targets:"
            f"{state.server_attack_targets_for_unknown_mobs} "
            f"hit_actions:{server_attack_hit_actions} "
            f"damage_entries:{state.server_attack_damage_entries} "
            f"damage_total:{state.server_attack_damage_total} "
            f"damage_range:{state.server_attack_damage_min}.."
            f"{state.server_attack_damage_max} "
            "damage_high_bits:"
            f"{state.server_attack_damage_high_bit_markers}"
        ),
        (
            f"client_opcode_101=packets:{state.client_opcode_101_packets} "
            f"header_values:{client_opcode_101_header_values} "
            f"primary_values:{client_opcode_101_primary_values} "
            f"flag_values:{client_opcode_101_flag_values} "
            f"secondary_values:{client_opcode_101_secondary_values} "
            f"tail_values:{client_opcode_101_tail_values}"
        ),
        (
            f"client_skill_uses=requests:{state.client_skill_use_requests} "
            f"by_skill:{client_skill_use_requests_by_skill_id} "
            f"levels:{client_skill_use_level_values} "
            f"trailing_values:{client_skill_use_trailing_values} "
            f"known:{state.client_skill_use_known_skills} "
            f"unknown:{state.client_skill_use_unknown_skills} "
            f"level_matches:{state.client_skill_use_level_matches} "
            f"level_mismatches:{state.client_skill_use_level_mismatches} "
            f"binding_matches:{state.client_skill_use_binding_matches} "
            f"binding_mismatches:{state.client_skill_use_binding_mismatches} "
            f"last_tick:{state.last_client_skill_tick} "
            f"tick_decreases:{state.client_skill_tick_decreases}"
        ),
        (
            "local_temporary_stat_sets="
            f"packets:{state.local_temporary_stat_sets} "
            f"zero_masks:{state.local_temporary_stat_zero_masks} "
            f"nonzero_masks:{state.local_temporary_stat_nonzero_masks} "
            f"enabled_bits:{state.local_temporary_stat_enabled_bits} "
            f"mask_patterns:{local_temporary_stat_mask_patterns} "
            f"opaque_bytes:{state.local_temporary_stat_opaque_bytes}"
        ),
        (
            "server_opcode_49="
            f"packets:{state.server_opcode_49_packets} "
            f"variants:{server_opcode_49_variants} "
            f"shapes:{server_opcode_49_shapes} "
            f"text_fields:{state.server_opcode_49_text_fields} "
            f"text_code_units:{state.server_opcode_49_text_code_units} "
            f"opaque_bytes:{state.server_opcode_49_opaque_bytes}"
        ),
        (
            "server_opcode_77="
            f"packets:{state.server_opcode_77_packets} "
            f"variants:{server_opcode_77_variants} "
            f"text_fields:{state.server_opcode_77_text_fields} "
            f"text_code_units:{state.server_opcode_77_text_code_units} "
            f"control_patterns:{server_opcode_77_control_patterns} "
            f"opaque_bytes:{state.server_opcode_77_opaque_bytes}"
        ),
        (
            f"client_opcode_13=messages:{state.client_opcode_13_messages} "
            f"message_types:{client_opcode_13_message_types} "
            f"opaque_lengths:{client_opcode_13_opaque_lengths} "
            f"opaque_bytes:{state.client_opcode_13_opaque_bytes}"
        ),
        (
            f"server_opcode_13=messages:{state.server_opcode_13_messages} "
            f"message_types:{server_opcode_13_message_types} "
            f"opaque_lengths:{server_opcode_13_opaque_lengths} "
            f"opaque_bytes:{state.server_opcode_13_opaque_bytes}"
        ),
        (
            "neutral_server_records="
            f"packets:{state.neutral_server_records} "
            f"opcodes:{neutral_server_record_opcodes} "
            f"typed_values:{state.neutral_server_typed_values} "
            f"opaque_bytes:{state.neutral_server_opaque_bytes}"
        ),
        (
            "tutorial_ui_instructions="
            f"packets:{state.tutorial_ui_instructions} "
            f"text_code_units:{tutorial_ui_text_code_units} "
            f"value_1:{tutorial_ui_value_1} "
            f"value_2:{tutorial_ui_value_2} "
            f"controls:{tutorial_ui_control_values} "
            f"extended:{state.tutorial_ui_extended_instructions}"
        ),
        (
            "server_opcode_27="
            f"packets:{state.server_opcode_27_packets} "
            "entry_counts:"
            f"{dict(sorted(state.server_opcode_27_entry_counts.items()))} "
            "text_code_units:"
            f"{dict(sorted(state.server_opcode_27_text_code_units.items()))}"
        ),
        (
            "server_opcode_28="
            f"packets:{state.server_opcode_28_packets} "
            "entry_counts:"
            f"{dict(sorted(state.server_opcode_28_entry_counts.items()))} "
            "text_1_code_units:"
            f"{dict(sorted(state.server_opcode_28_text_1_code_units.items()))} "
            "text_2_code_units:"
            f"{dict(sorted(state.server_opcode_28_text_2_code_units.items()))}"
        ),
        (
            "server_opcode_29="
            f"packets:{state.server_opcode_29_packets} "
            "entry_counts:"
            f"{dict(sorted(state.server_opcode_29_entry_counts.items()))} "
            "text_code_units:"
            f"{dict(sorted(state.server_opcode_29_text_code_units.items()))}"
        ),
        (
            "server_opcode_135="
            f"packets:{state.server_opcode_135_packets} "
            "section_a_entries:"
            f"{dict(sorted(state.server_opcode_135_section_a_entry_counts.items()))} "
            "section_a_values:"
            f"{dict(sorted(state.server_opcode_135_section_a_value_counts.items()))} "
            "section_b_entries:"
            f"{dict(sorted(state.server_opcode_135_section_b_entry_counts.items()))} "
            "section_b_pairs:"
            f"{dict(sorted(state.server_opcode_135_section_b_pair_counts.items()))} "
            "section_c_pairs:"
            f"{dict(sorted(state.server_opcode_135_section_c_pair_counts.items()))} "
            "section_d_entries:"
            f"{dict(sorted(state.server_opcode_135_section_d_entry_counts.items()))} "
            "section_d_group_1:"
            f"{dict(sorted(state.server_opcode_135_section_d_group_1_counts.items()))} "
            "section_d_group_2:"
            f"{dict(sorted(state.server_opcode_135_section_d_group_2_counts.items()))}"
        ),
        (
            "server_opcode_142="
            f"packets:{state.server_opcode_142_packets} "
            f"enabled:{state.server_opcode_142_enabled_packets} "
            "entry_counts:"
            f"{dict(sorted(state.server_opcode_142_entry_counts.items()))} "
            "header_text_code_units:"
            f"{dict(sorted(state.server_opcode_142_header_text_code_units.items()))} "
            "entry_text_code_units:"
            f"{dict(sorted(state.server_opcode_142_entry_text_code_units.items()))} "
            f"flag_1_true:{state.server_opcode_142_flag_1_true_count} "
            f"flag_2_true:{state.server_opcode_142_flag_2_true_count}"
        ),
        (
            "server_opcode_147="
            f"packets:{state.server_opcode_147_packets} "
            "value_counts:"
            f"{dict(sorted(state.server_opcode_147_value_counts.items()))} "
            "rectangle_shapes:"
            f"{dict(sorted(state.server_opcode_147_rectangle_shapes.items()))}"
        ),
        (
            "server_opcode_272="
            f"packets:{state.server_opcode_272_packets} "
            "entry_counts:"
            f"{dict(sorted(state.server_opcode_272_entry_counts.items()))} "
            f"group_1:{state.server_opcode_272_group_1_count} "
            f"group_2:{state.server_opcode_272_group_2_count} "
            f"flag_1_true:{state.server_opcode_272_flag_1_true_count} "
            f"flag_2_true:{state.server_opcode_272_flag_2_true_count} "
            "trailer_values:"
            f"{dict(sorted(state.server_opcode_272_trailer_values.items()))}"
        ),
        (
            "server_opcode_425="
            f"packets:{state.server_opcode_425_packets} "
            "value_counts:"
            f"{dict(sorted(state.server_opcode_425_value_counts.items()))} "
            "trailer_shapes:"
            f"{dict(sorted(state.server_opcode_425_trailer_shapes.items()))}"
        ),
        (
            "server_opcode_239="
            f"packets:{state.server_opcode_239_packets} "
            "selectors:"
            f"{dict(sorted(state.server_opcode_239_selectors.items()))} "
            f"records:{state.server_opcode_239_records} "
            "record_values:"
            f"{dict(sorted(state.server_opcode_239_record_values.items()))} "
            "text_code_units:"
            f"{dict(sorted(state.server_opcode_239_text_code_units.items()))} "
            "trailing_values:"
            f"{dict(sorted(state.server_opcode_239_trailing_values.items()))}"
        ),
        (
            "instructional_dialogue_requests="
            f"packets:{state.instructional_dialogue_requests} "
            f"value_1:{dict(sorted(state.instructional_dialogue_value_1.items()))} "
            f"value_2:{dict(sorted(state.instructional_dialogue_value_2.items()))} "
            f"value_3:{dict(sorted(state.instructional_dialogue_value_3.items()))}"
        ),
        (
            "positioned_effect_records="
            f"packets:{state.positioned_effect_records} "
            f"opcodes:{positioned_effect_opcodes} "
            f"active:{len(state.positioned_effect_entities)} "
            f"new:{state.positioned_effect_new_entities} "
            f"updates:{state.positioned_effect_updates} "
            f"unknown_updates:{state.positioned_effect_unknown_updates} "
            f"controls:{dict(sorted(state.positioned_effect_control_values.items()))}"
        ),
        (
            "server_opcode_169="
            f"packets:{state.server_opcode_169_packets} "
            f"selectors:{dict(sorted(state.server_opcode_169_selectors.items()))} "
            "text_code_units:"
            f"{dict(sorted(state.server_opcode_169_text_code_units.items()))}"
        ),
        (
            "server_opcode_348="
            f"packets:{state.server_opcode_348_packets} "
            f"categories:{dict(sorted(state.server_opcode_348_categories.items()))} "
            f"selectors:{dict(sorted(state.server_opcode_348_selectors.items()))} "
            f"values:{dict(sorted(state.server_opcode_348_values.items()))} "
            "text_code_units:"
            f"{dict(sorted(state.server_opcode_348_text_code_units.items()))} "
            "control_pairs:"
            f"{dict(sorted(state.server_opcode_348_control_pairs.items()))}"
        ),
        (
            "client_fixed_opaque_records="
            "packets:"
            f"{dict(sorted(state.client_fixed_opaque_records_by_opcode.items()))} "
            "opaque_bytes:"
            f"{dict(sorted(state.client_fixed_opaque_bytes_by_opcode.items()))} "
            "periodic_last_ms:"
            f"{dict(sorted(state.client_periodic_report_last_interval_ms.items()))} "
            "periodic_min_ms:"
            f"{dict(sorted(state.client_periodic_report_min_interval_ms.items()))} "
            "periodic_max_ms:"
            f"{dict(sorted(state.client_periodic_report_max_interval_ms.items()))}"
        ),
        (
            "world_exit="
            f"bootstrap_markers:{state.client_opcode_75_empty_records} "
            f"requests:{state.world_exit_requests} "
            "active_requests:"
            f"{state.world_exit_requests_from_active_phase} "
            f"statuses:{state.world_exit_status_packets} "
            "status_opcodes:"
            f"{dict(sorted(state.world_exit_status_packets_by_opcode.items()))} "
            f"matched:{state.matched_world_exit_terminations} "
            f"pending:{state.pending_world_exit_requests} "
            f"last_rtt_ms:{state.last_world_exit_round_trip_ms} "
            f"max_rtt_ms:{state.max_world_exit_round_trip_ms}"
        ),
        (
            "opcode_394_279="
            f"server:{state.server_opcode_394_packets} "
            "server_text_code_units:"
            f"{dict(sorted(state.server_opcode_394_text_code_units.items()))} "
            f"client:{state.client_opcode_279_text_packets} "
            "controls:"
            f"{dict(sorted(state.client_opcode_279_control_values.items()))} "
            "client_text_code_units:"
            f"{dict(sorted(state.client_opcode_279_text_code_units.items()))} "
            "changed_counts:"
            f"{dict(sorted(state.client_opcode_279_changed_code_unit_counts.items()))} "
            "changed_spans:"
            f"{dict(sorted(state.client_opcode_279_changed_span_shapes.items()))} "
            f"correlated:{state.correlated_client_opcode_279_packets} "
            f"uncorrelated:{state.uncorrelated_client_opcode_279_packets} "
            f"transform_matches:{state.client_opcode_279_transform_matches} "
            "transform_mismatches:"
            f"{state.client_opcode_279_transform_mismatches} "
            f"pending:{state.pending_server_opcode_394_envelopes} "
            f"last_gap_ms:{state.last_opcode_394_279_gap_ms} "
            f"max_gap_ms:{state.max_opcode_394_279_gap_ms}"
        ),
        (
            "client_opcode_66="
            f"packets:{state.client_opcode_66_acknowledgements} "
            f"selectors:{dict(sorted(state.client_opcode_66_selectors.items()))} "
            "status_values:"
            f"{dict(sorted(state.client_opcode_66_status_values.items()))} "
            f"shapes:{dict(sorted(state.client_opcode_66_shapes.items()))} "
            f"optional_values:{state.client_opcode_66_optional_values} "
            "matched:"
            f"{state.matched_client_opcode_66_acknowledgements} "
            "unmatched:"
            f"{state.unmatched_client_opcode_66_acknowledgements} "
            f"pending:{state.pending_server_opcode_348_requests} "
            f"last_rtt_ms:{state.last_opcode_348_round_trip_ms} "
            f"max_rtt_ms:{state.max_opcode_348_round_trip_ms}"
        ),
        (
            f"client_opcode_43=packets:{state.client_opcode_43_packets} "
            f"sequences:{dict(sorted(state.client_opcode_43_sequences.items()))} "
            f"variants:{dict(sorted(state.client_opcode_43_variants.items()))} "
            "text_code_units:"
            f"{dict(sorted(state.client_opcode_43_text_code_units.items()))} "
            f"opaque_bytes:{state.client_opcode_43_opaque_bytes}"
        ),
        (
            f"server_opcode_43=packets:{state.server_opcode_43_packets} "
            "message_types:"
            f"{dict(sorted(state.server_opcode_43_message_types.items()))} "
            f"opaque_bytes:{state.server_opcode_43_opaque_bytes}"
        ),
        (
            f"client_opcode_114=packets:{state.client_opcode_114_packets} "
            "control_values:"
            f"{dict(sorted(state.client_opcode_114_control_values.items()))} "
            "text_code_units:"
            f"{dict(sorted(state.client_opcode_114_text_code_units.items()))} "
            f"redacted_values:{state.client_opcode_114_redacted_values}"
        ),
        (
            f"client_opcode_122=packets:{state.client_opcode_122_packets} "
            f"selectors:{dict(sorted(state.client_opcode_122_selectors.items()))} "
            f"shapes:{dict(sorted(state.client_opcode_122_shapes.items()))} "
            "terminal_sentinels:"
            f"{state.client_opcode_122_terminal_sentinels}"
        ),
        (
            f"client_opcode_217=packets:{state.client_opcode_217_packets} "
            f"compact:{state.client_opcode_217_compact_packets} "
            f"record_sets:{state.client_opcode_217_record_sets} "
            f"records:{state.client_opcode_217_records} "
            f"records_by_format:{client_opcode_217_record_formats} "
            f"record_counts:{client_opcode_217_record_counts}"
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

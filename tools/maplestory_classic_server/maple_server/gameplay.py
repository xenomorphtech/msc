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
    FieldDropRemoval,
    FieldDropSpawn,
    FieldLoadStage,
    FieldSnapshotEnvelope,
    HeartbeatProbe,
    HeartbeatResponse,
    InitialFieldSnapshot,
    InitialInventoryItem,
    InventoryChangeSet,
    InventoryModification,
    ItemPickupRequest,
    ItemUseRequest,
    MobControllerChange,
    MobEnterField,
    MobHealthPercentageUpdate,
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
    PickupGainNotice,
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
    health_percentage: int | None = None


@dataclass
class ObservedPlayerEntity:
    alias: str
    x: int
    y: int


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
    field_drops: dict[int, FieldDropEntity] = field(
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
    mob_health_percentage_updates: int = 0
    mob_health_zero_updates: int = 0
    mob_health_increases: int = 0
    mob_health_updates_for_unknown_mobs: int = 0
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
        self._drop_aliases: dict[int, str] = {}
        self._pending_movements: dict[
            tuple[int, int], deque[PendingMobMovement]
        ] = {}
        self._pending_heartbeat_probes: deque[int] = deque()
        self._pending_item_uses: deque[PendingItemUse] = deque()
        self._pending_item_pickups: deque[PendingItemPickup] = deque()
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
        if opcode == 49 and len(payload) in {8, 12, 15}:
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
            cleared_drops = len(self.state.field_drops)
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
            self.state.field_drops.clear()
            self.state.player_x = None
            self.state.player_y = None
            self._drop_aliases.clear()
            self._pending_movements.clear()
            self.state.pending_movements = 0
            self._pending_item_uses.clear()
            self.state.pending_item_uses = 0
            self._pending_item_pickups.clear()
            self.state.pending_item_pickups = 0
            details = {
                "field_epoch": self.state.field_epoch,
                "opaque_snapshot_bytes": len(snapshot.opaque_snapshot),
                "cleared_npcs": cleared_npcs,
                "cleared_mobs": cleared_mobs,
                "cleared_drops": cleared_drops,
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
                progression = (
                    initial_snapshot.parse_progression()
                    if initial_snapshot.marker == 23
                    else None
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
                if progression is not None:
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
                else:
                    self.state.skill_levels = {}
                    self.state.string_property_code_units = {}
                    self.state.timestamp_property_keys = ()
                    self.state.saved_map_ids = ()
                    self.state.extended_property_code_units = {}
                    self.state.progression_variant = None
                    self.state.server_local_filetime_ticks = None
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
                        "progression_typed": progression is not None,
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
                if progression is not None:
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
                            (
                                "initial field snapshot marker-26 progression "
                                "region remains opaque"
                                if initial_snapshot.marker == 26
                                else "initial field snapshot equipment metadata "
                                "and progression/trailer meanings remain "
                                "partially opaque"
                            ),
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
            self.state.mob_health_percentage_updates += 1
            if update.health_percentage == 0:
                self.state.mob_health_zero_updates += 1
            details = {
                "entity": alias,
                "known_entity": entity is not None,
                "previous_percentage": previous_percentage,
                "health_percentage": update.health_percentage,
                "field_epoch": self.state.field_epoch,
            }
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
                    "pending_item_uses": self.state.pending_item_uses,
                    "pending_item_pickups": self.state.pending_item_pickups,
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
        if isinstance(observation.parsed, InitialFieldSnapshot)
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
            f"health_updates:{state.mob_health_percentage_updates} "
            f"health_zero:{state.mob_health_zero_updates} "
            f"health_increases:{state.mob_health_increases} "
            "health_unknown_active_mob:"
            f"{state.mob_health_updates_for_unknown_mobs} "
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

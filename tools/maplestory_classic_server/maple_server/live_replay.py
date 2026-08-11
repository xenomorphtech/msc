from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
from ipaddress import ip_address
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .gameplay import (
    CurrentHpStatUpdateReplayPlan,
    GameplayAnalysis,
    analyze_gameplay_transcript,
    plan_current_hp_stat_update,
)
from .gamestate import decode_transcript
from .packets import (
    FieldDropRemoval,
    FieldDropSpawn,
    InventoryChangeSet,
    InventoryModification,
    MobEnterField,
    MobControllerChange,
    MobLeaveField,
    MobTemporaryStatReset,
    MobTemporaryStatSet,
    PickupGainNotice,
    SkillRecordEntry,
    SkillRecordUpdate,
)
from .pcap import load_pcap_tcp_stream
from .transcript import Transcript


DEFAULT_PACKET_API_URL = "http://127.0.0.1:12858/api/v1/server-packets"


@dataclass(frozen=True)
class CurrentHpLiveReplayResult:
    plan: CurrentHpStatUpdateReplayPlan = field(repr=False)
    api_response: dict[str, object]
    observed_packet: dict[str, object]
    observed_current_hp: int
    observed_player_stat_updates_delta: int
    polls: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "accepted": True,
            "operation": "current_hp",
            "plan": self.plan.safe_dict(),
            "api": self.api_response,
            "verification": {
                "matched": True,
                "polls": self.polls,
                "observed_current_hp": self.observed_current_hp,
                "observed_player_stat_updates_delta": (
                    self.observed_player_stat_updates_delta
                ),
                "observed_packet": self.observed_packet,
                "checks": {
                    "typed_packet_observed": True,
                    "current_hp_matches": True,
                    "max_hp_unchanged": True,
                    "phase_unchanged": True,
                    "field_epoch_unchanged": True,
                    "map_id_unchanged": True,
                    "inventory_unchanged": True,
                    "progression_unchanged": True,
                    "player_stat_updates_delta_matches": True,
                },
            },
        }


@dataclass(frozen=True)
class ItemPickupLiveReplayPlan:
    drop_spawn: FieldDropSpawn = field(repr=False)
    drop_refresh: FieldDropSpawn = field(repr=False)
    controller_release: MobControllerChange = field(repr=False)
    inventory_update: InventoryChangeSet = field(repr=False)
    gain_notice: PickupGainNotice = field(repr=False)
    cleanup: FieldDropRemoval = field(repr=False)
    inventory: str
    slot: int
    item_id: int
    quantity_before: int
    quantity_delta: int
    quantity_after: int
    player_x: int
    player_y: int
    player_position_source: str
    folded_trailer_x: int
    folded_trailer_y: int
    source_offset_x: int
    source_offset_y: int
    evidence_tcp_stream: int
    evidence_admission_index: int
    evidence_spawn_frame: int
    evidence_refresh_frame: int
    evidence_release_frame: int
    evidence_request_frame: int
    release_delay_seconds: float
    admission_delay_seconds: float

    def response_packets(self, request_opcode: int) -> tuple[bytes, bytes, bytes]:
        if request_opcode not in {185, 222}:
            raise ValueError("item-pickup response requires opcode 185 or 222")
        removal = FieldDropRemoval(
            reason=2 if request_opcode == 222 else 5,
            drop_object_id=self.drop_spawn.drop_object_id,
            actor_id=self.drop_spawn.owner_value_1,
            trailing_value=None if request_opcode == 222 else 0,
        )
        return (
            self.inventory_update.to_bytes(),
            self.gain_notice.to_bytes(),
            removal.to_bytes(),
        )

    def safe_dict(self) -> dict[str, object]:
        return {
            "runtime_object_ids_redacted": True,
            "item_id": self.item_id,
            "inventory": self.inventory,
            "slot": self.slot,
            "quantity_before": self.quantity_before,
            "quantity_delta": self.quantity_delta,
            "quantity_after": self.quantity_after,
            "latest_player_position": {
                "x": self.player_x,
                "y": self.player_y,
            },
            "player_position_source": self.player_position_source,
            "folded_trailer_position": {
                "x": self.folded_trailer_x,
                "y": self.folded_trailer_y,
            },
            "drop_position": {
                "x": self.drop_spawn.position_x,
                "y": self.drop_spawn.position_y,
            },
            "animated_source_offset": {
                "x": self.source_offset_x,
                "y": self.source_offset_y,
            },
            "evidence": {
                "tcp_stream": self.evidence_tcp_stream,
                "admission_index": self.evidence_admission_index,
                "frames": {
                    "spawn": self.evidence_spawn_frame,
                    "refresh": self.evidence_refresh_frame,
                    "release": self.evidence_release_frame,
                    "request": self.evidence_request_frame,
                },
                "release_delay_ms": round(
                    self.release_delay_seconds * 1000.0, 3
                ),
                "admission_delay_ms": round(
                    self.admission_delay_seconds * 1000.0, 3
                ),
            },
            "prediction": {
                "server_opcodes": [311, 311, 281, 39, 49, 312],
                "requires_authentic_client_request": True,
                "inventory_quantity_delta": self.quantity_delta,
                "active_field_drop_count_delta": 0,
                "phase": "unchanged",
                "field_epoch": "unchanged",
                "map_id": "unchanged",
                "player_state": "unchanged",
                "progression": "unchanged",
            },
        }


@dataclass(frozen=True)
class ItemPickupLiveReplayResult:
    plan: ItemPickupLiveReplayPlan = field(repr=False)
    api_responses: tuple[dict[str, object], ...]
    observed_packets: tuple[dict[str, object], ...]
    request_attempts: int
    polls: int
    pickup_key: str
    pickup_input_delay_seconds: float

    def safe_dict(self) -> dict[str, object]:
        return {
            "accepted": True,
            "operation": "item_pickup",
            "plan": self.plan.safe_dict(),
            "api": list(self.api_responses),
            "verification": {
                "matched": True,
                "polls": self.polls,
                "pickup_key": self.pickup_key,
                "pickup_input_delay_ms": round(
                    self.pickup_input_delay_seconds * 1000.0, 3
                ),
                "request_attempts": self.request_attempts,
                "observed_packets": list(self.observed_packets),
                "checks": {
                    "latest_player_position_used": True,
                    "animated_pair_observed": True,
                    "controller_release_observed": True,
                    "authentic_client_request_observed": True,
                    "inventory_effect_matched": True,
                    "gain_result_matched": True,
                    "drop_removal_matched": True,
                    "pending_pickups_cleared": True,
                    "phase_unchanged": True,
                    "field_epoch_unchanged": True,
                    "map_id_unchanged": True,
                    "player_state_unchanged": True,
                    "other_inventory_unchanged": True,
                    "progression_unchanged": True,
                },
            },
        }


@dataclass(frozen=True)
class SkillRecordLiveReplayPlan:
    update: SkillRecordUpdate = field(repr=False)
    original_skill_level: int | None
    emitted_skill_level: int | None

    def safe_dict(self) -> dict[str, object]:
        records = self.update.records
        return {
            "opcode": self.update.opcode,
            "length": len(self.update.to_bytes()),
            "mode": "empty" if not records else "existing_skill",
            "flag_a": self.update.flag_a,
            "flag_b": self.update.flag_b,
            "record_count": len(records),
            "skill_id": None if not records else records[0].skill_id,
            "original_skill_level": self.original_skill_level,
            "emitted_skill_level": self.emitted_skill_level,
            "auxiliary_value": None if not records else records[0].auxiliary_value,
            "trailing_value": self.update.trailing_value,
            "prediction": {
                "skill_record_updates_delta": 1,
                "skill_record_update_records_delta": len(records),
                "matched_acknowledgements_delta": 1,
                "updates_without_request_delta": int(bool(records)),
                "skill_level": (
                    "unchanged" if not records else self.emitted_skill_level
                ),
                "phase": "unchanged",
                "field_epoch": "unchanged",
                "map_id": "unchanged",
                "player_state": "unchanged",
                "inventory": "unchanged",
                "other_progression": "unchanged",
            },
        }


@dataclass(frozen=True)
class SkillRecordLiveReplayResult:
    plan: SkillRecordLiveReplayPlan = field(repr=False)
    api_response: dict[str, object]
    observed_update: dict[str, object]
    observed_acknowledgement: dict[str, object]
    polls: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "accepted": True,
            "operation": "skill_record_update",
            "plan": self.plan.safe_dict(),
            "api": self.api_response,
            "verification": {
                "matched": True,
                "polls": self.polls,
                "observed_update": self.observed_update,
                "observed_acknowledgement": self.observed_acknowledgement,
                "checks": {
                    "typed_packet_round_trip": True,
                    "typed_update_observed": True,
                    "client_acknowledgement_observed": True,
                    "acknowledgement_matched_update": True,
                    "counter_deltas_match": True,
                    "skill_levels_match": True,
                    "phase_unchanged": True,
                    "field_epoch_unchanged": True,
                    "map_id_unchanged": True,
                    "player_state_unchanged": True,
                    "inventory_unchanged": True,
                    "other_progression_unchanged": True,
                },
            },
        }


@dataclass(frozen=True)
class MobTemporaryStatLiveReplayPlan:
    spawn: MobEnterField = field(repr=False)
    set_stat: MobTemporaryStatSet = field(repr=False)
    reset_stat: MobTemporaryStatReset = field(repr=False)
    leave: MobLeaveField = field(repr=False)
    version_id: str
    protocol_version: int
    evidence_tcp_stream: int
    evidence_spawn_direction_index: int
    evidence_set_direction_index: int
    evidence_reset_direction_index: int
    shape_names: tuple[str, str, str, str]

    def safe_dict(self) -> dict[str, object]:
        spawn = self.spawn.spawn
        return {
            "version_id": self.version_id,
            "protocol_version": self.protocol_version,
            "evidence_tcp_stream": self.evidence_tcp_stream,
            "evidence_direction_indices": {
                "spawn": self.evidence_spawn_direction_index,
                "set": self.evidence_set_direction_index,
                "reset": self.evidence_reset_direction_index,
            },
            "shape_names": list(self.shape_names),
            "runtime_object_id_redacted": True,
            "spawn": {
                "opcode": self.spawn.opcode,
                "length": len(self.spawn.to_bytes()),
                "template_id": spawn.template_id,
                "x": spawn.x,
                "y": spawn.y,
                "stance": spawn.stance,
                "foothold_id": spawn.foothold_id,
                "origin_foothold_id": spawn.origin_foothold_id,
                "spawn_effect": spawn.spawn_effect,
            },
            "set": {
                "opcode": self.set_stat.opcode,
                "length": len(self.set_stat.to_bytes()),
                **self.set_stat.safe_dict(),
            },
            "reset": {
                "opcode": self.reset_stat.opcode,
                "length": len(self.reset_stat.to_bytes()),
                **self.reset_stat.safe_dict(),
            },
            "cleanup": {
                "opcode": self.leave.opcode,
                "reason": self.leave.reason,
            },
            "prediction": {
                "mob_entries_delta": 1,
                "temporary_stat_sets_delta": 1,
                "temporary_stat_resets_delta": 1,
                "modeled_resets_delta": 1,
                "mob_leaves_delta": 1,
                "final_active_mob_count": "unchanged",
                "final_active_temporary_stat_count": "unchanged",
                "phase": "unchanged",
                "field_epoch": "unchanged",
                "map_id": "unchanged",
                "player_state": "unchanged",
                "inventory": "unchanged",
                "progression": "unchanged",
            },
        }


@dataclass(frozen=True)
class MobTemporaryStatLiveReplayResult:
    plan: MobTemporaryStatLiveReplayPlan = field(repr=False)
    api_responses: tuple[dict[str, object], ...]
    observed_packets: tuple[dict[str, object], ...]
    polls: int
    spawn_hold_seconds: float
    set_hold_seconds: float
    reset_hold_seconds: float

    def safe_dict(self) -> dict[str, object]:
        return {
            "accepted": True,
            "operation": "mob_temporary_stat_lifecycle",
            "plan": self.plan.safe_dict(),
            "api": list(self.api_responses),
            "verification": {
                "matched": True,
                "polls": self.polls,
                "spawn_hold_seconds": self.spawn_hold_seconds,
                "set_hold_seconds": self.set_hold_seconds,
                "reset_hold_seconds": self.reset_hold_seconds,
                "observed_packets": list(self.observed_packets),
                "checks": {
                    "generated_shapes_matched": True,
                    "captured_packets_reparsed": True,
                    "spawn_observed": True,
                    "set_observed": True,
                    "status_became_active": True,
                    "reset_observed": True,
                    "status_became_inactive": True,
                    "leave_observed": True,
                    "mob_removed": True,
                    "counter_deltas_match": True,
                    "phase_unchanged": True,
                    "field_epoch_unchanged": True,
                    "map_id_unchanged": True,
                    "player_state_unchanged": True,
                    "inventory_unchanged": True,
                    "progression_unchanged": True,
                },
            },
        }


@dataclass(frozen=True)
class _CapturedMobTemporaryStatLifecycle:
    spawn: MobEnterField
    set_stat: MobTemporaryStatSet
    reset_stat: MobTemporaryStatReset
    spawn_direction_index: int
    set_direction_index: int
    reset_direction_index: int
    version_id: str
    protocol_version: int


@dataclass(frozen=True)
class _CapturedItemPickupAdmission:
    drop_spawn: FieldDropSpawn
    drop_refresh: FieldDropSpawn
    controller_release: MobControllerChange
    inventory: str
    quantity_delta: int
    spawn_frame: int
    refresh_frame: int
    release_frame: int
    request_frame: int
    release_delay_seconds: float
    admission_delay_seconds: float


def validate_packet_api_url(value: str) -> str:
    """Accept only the fixed plaintext-packet endpoint on loopback HTTP."""
    parsed = urlsplit(value)
    if parsed.scheme != "http":
        raise ValueError("packet API URL must use http")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("packet API URL must not contain credentials")
    if parsed.hostname is None:
        raise ValueError("packet API URL must contain a host")
    if parsed.hostname != "localhost":
        try:
            address = ip_address(parsed.hostname)
        except ValueError as error:
            raise ValueError("packet API host must be localhost or loopback") from error
        if not address.is_loopback:
            raise ValueError("packet API host must be loopback")
    if parsed.path != "/api/v1/server-packets":
        raise ValueError("packet API URL must target /api/v1/server-packets")
    if parsed.query or parsed.fragment:
        raise ValueError("packet API URL must not contain query or fragment data")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("packet API URL has an invalid port") from error
    return value


def _post_plaintext_packet(
    api_url: str,
    plaintext: bytes,
    *,
    timeout_seconds: float,
) -> dict[str, object]:
    body = json.dumps(
        {"plaintext_hex": plaintext.hex()},
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        validate_packet_api_url(api_url),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        try:
            payload = json.loads(error.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"error": "invalid_error_response"}
        raise RuntimeError(
            f"packet API rejected the request with HTTP {error.code}: {payload}"
        ) from error
    if not isinstance(payload, dict) or payload.get("accepted") is not True:
        raise RuntimeError("packet API did not return an accepted response")
    expected_opcode = int.from_bytes(plaintext[:2], "little")
    if payload.get("opcode") != expected_opcode:
        raise RuntimeError("packet API response opcode does not match the request")
    if payload.get("plaintext_length") != len(plaintext):
        raise RuntimeError("packet API response length does not match the request")
    return payload


def _captured_item_pickup_admission(
    transcript: Transcript,
    *,
    item_id: int,
    admission_index: int,
) -> _CapturedItemPickupAdmission:
    if not 0 <= item_id <= 0xFFFF_FFFF:
        raise ValueError("item id must fit uint32")
    if admission_index < 0:
        raise ValueError("item-pickup admission index must be non-negative")
    analysis = analyze_gameplay_transcript(transcript)
    if not analysis.valid:
        raise ValueError("item-pickup evidence failed packet/state validation")
    state = analysis.state
    if (
        state.item_pickup_effect_mismatches
        or state.item_pickup_spawn_result_mismatches
        or state.item_pickup_removal_mismatches
        or state.pending_item_pickups
    ):
        raise ValueError("item-pickup evidence has incomplete or mismatched chains")
    candidates = tuple(
        observation
        for observation in analysis.observations
        if observation.direction == "client_to_server"
        and observation.opcode in {185, 222}
        and observation.kind == "item_pickup_request"
        and observation.details.get("predicted_item_id") == item_id
        and observation.details.get("request_attempt") == 1
        and observation.details.get("known_drop") is True
    )
    if admission_index >= len(candidates):
        raise ValueError(
            f"item-pickup evidence has {len(candidates)} admitted chains for "
            f"item {item_id}; index {admission_index} is unavailable"
        )
    request_observation = candidates[admission_index]
    request_details = request_observation.details
    drop_alias = request_details.get("drop")
    spawn_frame = request_details.get("drop_spawn_frame")
    release_frame = request_details.get("source_controller_release_frame")
    if (
        not isinstance(drop_alias, str)
        or type(spawn_frame) is not int
        or type(release_frame) is not int
    ):
        raise ValueError("admitted item-pickup evidence lacks spawn/release frames")
    refresh_observations = tuple(
        observation
        for observation in analysis.observations
        if observation.kind == "field_drop_spawn"
        and spawn_frame < observation.frame_index < request_observation.frame_index
        and observation.details.get("drop") == drop_alias
        and observation.details.get("spawn_mode") == 0
    )
    if len(refresh_observations) != 1:
        raise ValueError(
            "admitted item-pickup evidence must have exactly one mode-0 refresh"
        )
    refresh_frame = refresh_observations[0].frame_index
    decoded = decode_transcript(transcript)
    required_frames = (
        spawn_frame,
        refresh_frame,
        release_frame,
        request_observation.frame_index,
    )
    if any(index < 0 or index >= len(decoded.frames) for index in required_frames):
        raise ValueError("item-pickup evidence frame index is out of range")
    spawn_decoded = decoded.frames[spawn_frame]
    refresh_decoded = decoded.frames[refresh_frame]
    release_decoded = decoded.frames[release_frame]
    request_decoded = decoded.frames[request_observation.frame_index]
    if (
        spawn_decoded.direction != "server_to_client"
        or refresh_decoded.direction != "server_to_client"
        or release_decoded.direction != "server_to_client"
        or request_decoded.direction != "client_to_server"
    ):
        raise ValueError("item-pickup evidence directions do not match the chain")
    drop_spawn = FieldDropSpawn.parse(spawn_decoded.plaintext)
    drop_refresh = FieldDropSpawn.parse(refresh_decoded.plaintext)
    controller_release = MobControllerChange.parse(release_decoded.plaintext)
    if (
        drop_spawn.spawn_mode != 1
        or drop_refresh.spawn_mode != 0
        or drop_spawn.drop_object_id != drop_refresh.drop_object_id
        or drop_spawn.value != item_id
        or drop_refresh.value != item_id
        or drop_spawn.source_mob_object_id
        != drop_refresh.source_mob_object_id
        or controller_release.control_level != 0
        or controller_release.object_id != drop_spawn.source_mob_object_id
    ):
        raise ValueError("item-pickup evidence is not one matching pair/release chain")
    effects = state.item_pickup_item_effects_by_template.get(item_id, set())
    if len(effects) != 1:
        raise ValueError(
            "item-pickup evidence must prove exactly one inventory quantity effect"
        )
    inventory, quantity_delta = next(iter(effects))
    if inventory not in {"use", "setup", "etc"} or quantity_delta <= 0:
        raise ValueError("item-pickup evidence has an unsupported inventory effect")
    release_delay_seconds = (
        release_decoded.timestamp_ns - spawn_decoded.timestamp_ns
    ) / 1_000_000_000
    admission_delay_seconds = (
        request_decoded.timestamp_ns - spawn_decoded.timestamp_ns
    ) / 1_000_000_000
    if release_delay_seconds < 0 or admission_delay_seconds <= 0:
        raise ValueError("item-pickup evidence has invalid event timing")
    return _CapturedItemPickupAdmission(
        drop_spawn=drop_spawn,
        drop_refresh=drop_refresh,
        controller_release=controller_release,
        inventory=inventory,
        quantity_delta=quantity_delta,
        spawn_frame=spawn_frame,
        refresh_frame=refresh_frame,
        release_frame=release_frame,
        request_frame=request_observation.frame_index,
        release_delay_seconds=release_delay_seconds,
        admission_delay_seconds=admission_delay_seconds,
    )


def _occupied_runtime_object_ids(analysis: GameplayAnalysis) -> set[int]:
    state = analysis.state
    occupied = {
        *state.npcs,
        *state.mobs,
        *state.observed_players,
        *state.field_drops,
        *state.positioned_effect_entities,
    }
    if state.entry_character_id is not None:
        occupied.add(state.entry_character_id)
    return occupied


def _allocate_runtime_object_ids(
    analysis: GameplayAnalysis,
    count: int,
) -> tuple[int, ...]:
    if count <= 0:
        raise ValueError("runtime object-id count must be positive")
    occupied = _occupied_runtime_object_ids(analysis)
    allocated: list[int] = []
    for candidate in range(0x7FFF0001, 0x7FFE0000, -1):
        if candidate in occupied:
            continue
        allocated.append(candidate)
        occupied.add(candidate)
        if len(allocated) == count:
            return tuple(allocated)
    raise ValueError("could not allocate collision-free runtime object ids")


def _item_pickup_player_position(
    analysis: GameplayAnalysis,
) -> tuple[int, int, str]:
    """Prefer the latest movement command endpoint for proximity admission."""
    state = analysis.state
    for observation in reversed(analysis.observations):
        if (
            observation.direction != "client_to_server"
            or observation.opcode != 182
            or observation.kind != "player_movement_submission"
            or observation.details.get("field_epoch") != state.field_epoch
        ):
            continue
        final_x = observation.details.get("final_x")
        final_y = observation.details.get("final_y")
        if type(final_x) is int and type(final_y) is int:
            return final_x, final_y, "movement_command_final"
    if state.player_x is None or state.player_y is None:
        raise ValueError("live world state has no modeled player position")
    return state.player_x, state.player_y, "folded_trailer_endpoint"


def plan_item_pickup_live_replay(
    analysis: GameplayAnalysis,
    evidence_transcript: Transcript,
    *,
    evidence_tcp_stream: int = 92,
    item_id: int = 4_000_004,
    admission_index: int = 1,
) -> ItemPickupLiveReplayPlan:
    """Retarget an admitted drop to the latest proximity-relevant position."""
    if not analysis.valid:
        raise ValueError("live world transcript failed packet/state validation")
    state = analysis.state
    if state.phase.value != "active":
        raise ValueError("live world state must be active")
    if state.pending_item_pickups:
        raise ValueError("live world state has a pending item-pickup chain")
    if getattr(state, "pending_item_use_requests", 0):
        raise ValueError("live world state has a pending item-use request")
    if state.player_x is None or state.player_y is None:
        raise ValueError("live world state has no modeled player position")
    if state.entry_character_id is None:
        raise ValueError("live world state has no entry character context")
    if evidence_tcp_stream < 0:
        raise ValueError("evidence TCP stream must be non-negative")
    captured = _captured_item_pickup_admission(
        evidence_transcript,
        item_id=item_id,
        admission_index=admission_index,
    )
    if (
        captured.drop_spawn.source_x is None
        or captured.drop_spawn.source_y is None
    ):
        raise ValueError("item-pickup evidence has no animated source position")
    folded_trailer_x = state.player_x
    folded_trailer_y = state.player_y
    player_x, player_y, player_position_source = _item_pickup_player_position(
        analysis
    )
    if not -0x8000 <= player_x <= 0x7FFF or not -0x8000 <= player_y <= 0x7FFF:
        raise ValueError("latest player position exceeds int16 range")
    source_offset_x = (
        captured.drop_spawn.source_x - captured.drop_spawn.position_x
    )
    source_offset_y = (
        captured.drop_spawn.source_y - captured.drop_spawn.position_y
    )
    source_x = player_x + source_offset_x
    source_y = player_y + source_offset_y
    if not -0x8000 <= source_x <= 0x7FFF or not -0x8000 <= source_y <= 0x7FFF:
        raise ValueError("retargeted animated source position exceeds int16 range")
    drop_object_id, source_object_id = _allocate_runtime_object_ids(analysis, 2)
    rewrite = {
        "drop_object_id": drop_object_id,
        "owner_value_1": state.entry_character_id,
        "owner_value_2": state.entry_character_id,
        "position_x": player_x,
        "position_y": player_y,
        "source_mob_object_id": source_object_id,
        "source_x": source_x,
        "source_y": source_y,
    }
    drop_spawn = replace(captured.drop_spawn, **rewrite)
    drop_refresh = replace(captured.drop_refresh, **rewrite)
    controller_release = replace(
        captured.controller_release,
        object_id=source_object_id,
    )
    for packet_type, packet in (
        (FieldDropSpawn, drop_spawn),
        (FieldDropSpawn, drop_refresh),
        (MobControllerChange, controller_release),
    ):
        plaintext = packet.to_bytes()
        if packet_type.parse(plaintext).to_bytes() != plaintext:
            raise ValueError("typed item-pickup admission packet did not round-trip")
    matches = tuple(
        item
        for item in state.inventory_items.get(captured.inventory, ())
        if item.item_id == item_id and item.quantity is not None
    )
    if len(matches) != 1:
        raise ValueError(
            f"live inventory has {len(matches)} matching {captured.inventory} "
            "stacks; exactly one is required"
        )
    item = matches[0]
    if item.quantity is None:
        raise ValueError("item-pickup target stack has no quantity")
    quantity_after = item.quantity + captured.quantity_delta
    if not 1 <= quantity_after <= 0xFFFF:
        raise ValueError("item-pickup target stack cannot accept the item")
    inventory_types = {"use": 2, "setup": 3, "etc": 4}
    inventory_update = InventoryChangeSet(
        update_flag=0,
        modifications=(
            InventoryModification(
                operation=InventoryModification.UPDATE_QUANTITY,
                inventory_type=inventory_types[captured.inventory],
                slot=item.slot,
                quantity=quantity_after,
            ),
        ),
    )
    gain_notice = PickupGainNotice(
        result_flag=0,
        kind=PickupGainNotice.ITEM,
        item_id=item_id,
        quantity=captured.quantity_delta,
    )
    cleanup = FieldDropRemoval(reason=1, drop_object_id=drop_object_id)
    return ItemPickupLiveReplayPlan(
        drop_spawn=drop_spawn,
        drop_refresh=drop_refresh,
        controller_release=controller_release,
        inventory_update=inventory_update,
        gain_notice=gain_notice,
        cleanup=cleanup,
        inventory=captured.inventory,
        slot=item.slot,
        item_id=item_id,
        quantity_before=item.quantity,
        quantity_delta=captured.quantity_delta,
        quantity_after=quantity_after,
        player_x=player_x,
        player_y=player_y,
        player_position_source=player_position_source,
        folded_trailer_x=folded_trailer_x,
        folded_trailer_y=folded_trailer_y,
        source_offset_x=source_offset_x,
        source_offset_y=source_offset_y,
        evidence_tcp_stream=evidence_tcp_stream,
        evidence_admission_index=admission_index,
        evidence_spawn_frame=captured.spawn_frame,
        evidence_refresh_frame=captured.refresh_frame,
        evidence_release_frame=captured.release_frame,
        evidence_request_frame=captured.request_frame,
        release_delay_seconds=captured.release_delay_seconds,
        admission_delay_seconds=captured.admission_delay_seconds,
    )


def _progression_snapshot(analysis: GameplayAnalysis) -> tuple[object, ...]:
    state = analysis.state
    return (
        tuple(sorted(state.skill_levels.items())),
        tuple(sorted(state.string_property_code_units.items())),
        state.timestamp_property_keys,
        state.saved_map_ids,
        tuple(sorted(state.extended_property_code_units.items())),
        state.progression_variant,
        state.progression_shape,
        state.experience,
        state.character_level,
        state.job_id,
        state.current_mp,
        state.max_mp,
        state.strength,
        state.dexterity,
        state.intelligence,
        state.luck,
        state.ability_points,
        state.skill_points,
        state.fame,
        state.mesos,
    )


def _progression_snapshot_without_skill_levels(
    analysis: GameplayAnalysis,
) -> tuple[object, ...]:
    return _progression_snapshot(analysis)[1:]


def _load_json_object(path: Path, *, description: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"could not load {description}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{description} must contain one JSON object")
    return value


def _generated_shape_name(
    shape_dump: dict[str, object],
    *,
    direction: str,
    opcode: int,
    length: int,
) -> str:
    packet_shapes = shape_dump.get("packet_shapes")
    if not isinstance(packet_shapes, list):
        raise ValueError("IL2CPP shape dump has no packet_shapes array")
    matches = [
        shape
        for shape in packet_shapes
        if isinstance(shape, dict)
        and shape.get("direction") == direction
        and shape.get("opcode") == opcode
        and shape.get("length") == length
    ]
    if len(matches) != 1:
        raise ValueError(
            "IL2CPP shape dump must contain exactly one "
            f"{direction} opcode-{opcode} length-{length} shape; "
            f"found {len(matches)}"
        )
    name = matches[0].get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("IL2CPP packet shape has no non-empty name")
    return name


def _captured_mob_temporary_stat_lifecycle(
    evidence_jsonl_path: Path,
    *,
    tcp_stream: int,
    expected_version_id: str,
    expected_protocol_version: int,
) -> _CapturedMobTemporaryStatLifecycle:
    if tcp_stream < 0:
        raise ValueError("evidence TCP stream must be non-negative")
    active_spawns: dict[int, tuple[MobEnterField, int]] = {}
    pending_sets: dict[
        int, tuple[MobEnterField, int, MobTemporaryStatSet, int]
    ] = {}
    extended_fallback: _CapturedMobTemporaryStatLifecycle | None = None
    last_direction_index = -1
    try:
        source = evidence_jsonl_path.open(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"could not open IL2CPP packet JSONL: {error}") from error
    with source:
        for line_number, line in enumerate(source, start=1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"IL2CPP packet JSONL line {line_number} is invalid JSON"
                ) from error
            if not isinstance(row, dict):
                raise ValueError(
                    f"IL2CPP packet JSONL line {line_number} is not an object"
                )
            if (
                row.get("tcp_stream") != tcp_stream
                or row.get("direction") != "server_to_client"
            ):
                continue
            opcode = row.get("opcode")
            if opcode not in {279, 280, 285, 286}:
                continue
            if row.get("version_id") != expected_version_id:
                raise ValueError("packet JSONL and shape dump version ids differ")
            if row.get("protocol_version") != expected_protocol_version:
                raise ValueError(
                    "packet JSONL and shape dump protocol versions differ"
                )
            direction_index = row.get("direction_index")
            if type(direction_index) is not int or direction_index < 0:
                raise ValueError("packet JSONL direction_index must be non-negative")
            if direction_index <= last_direction_index:
                raise ValueError(
                    "packet JSONL server direction indices must increase"
                )
            last_direction_index = direction_index
            payload_hex = row.get("payload_hex")
            if not isinstance(payload_hex, str):
                raise ValueError("packet JSONL payload_hex must be a string")
            try:
                payload = bytes.fromhex(payload_hex)
            except ValueError as error:
                raise ValueError("packet JSONL payload_hex is invalid") from error
            if row.get("length") != len(payload):
                raise ValueError("packet JSONL payload length does not match metadata")
            if row.get("payload_sha256") != hashlib.sha256(payload).hexdigest():
                raise ValueError("packet JSONL payload hash does not match metadata")

            if opcode == 279:
                packet = MobEnterField.parse(payload)
                active_spawns[packet.object_id] = (packet, direction_index)
                pending_sets.pop(packet.object_id, None)
                continue
            if opcode == 280:
                packet = MobLeaveField.parse(payload)
                active_spawns.pop(packet.object_id, None)
                pending_sets.pop(packet.object_id, None)
                continue
            if opcode == 285:
                packet = MobTemporaryStatSet.parse(payload)
                spawn_record = active_spawns.get(packet.object_id)
                if spawn_record is not None:
                    pending_sets[packet.object_id] = (
                        spawn_record[0],
                        spawn_record[1],
                        packet,
                        direction_index,
                    )
                continue

            packet = MobTemporaryStatReset.parse(payload)
            matched = pending_sets.pop(packet.object_id, None)
            if matched is None:
                continue
            spawn, spawn_index, set_stat, set_index = matched
            if spawn.spawn.template_id != 3210800:
                continue
            lifecycle = _CapturedMobTemporaryStatLifecycle(
                spawn=spawn,
                set_stat=set_stat,
                reset_stat=packet,
                spawn_direction_index=spawn_index,
                set_direction_index=set_index,
                reset_direction_index=direction_index,
                version_id=expected_version_id,
                protocol_version=expected_protocol_version,
            )
            if len(spawn.to_bytes()) == 48:
                return lifecycle
            if extended_fallback is None:
                extended_fallback = lifecycle
    if extended_fallback is not None:
        return extended_fallback
    raise ValueError(
        "IL2CPP packet JSONL contains no captured template-3210800 "
        "spawn/set/reset lifecycle"
    )


def _allocate_runtime_object_id(analysis: GameplayAnalysis) -> int:
    return _allocate_runtime_object_ids(analysis, 1)[0]


def _current_player_foothold(analysis: GameplayAnalysis) -> tuple[int, int, int]:
    state = analysis.state
    if state.player_x is None or state.player_y is None:
        raise ValueError("live state has no modeled player position")
    for event in reversed(analysis.events):
        if event.kind != "player_movement_submitted":
            continue
        commands = event.details.get("commands")
        if not isinstance(commands, list):
            continue
        for command in reversed(commands):
            if not isinstance(command, dict):
                continue
            foothold_id = command.get("foothold_id")
            position_y = command.get("position_y")
            if type(foothold_id) is int and type(position_y) is int:
                return state.player_x, position_y, foothold_id
    raise ValueError(
        "live state has no player movement foothold; move once before replay"
    )


def plan_mob_temporary_stat_live_replay(
    analysis: GameplayAnalysis,
    shape_dump_path: Path,
    evidence_jsonl_path: Path,
    *,
    evidence_tcp_stream: int = 92,
    x_offset: int = 120,
) -> MobTemporaryStatLiveReplayPlan:
    """Compose one capture-backed mob spawn/set/reset/leave experiment."""
    if not analysis.valid:
        raise ValueError("live world transcript failed packet/state validation")
    if analysis.state.phase.value != "active":
        raise ValueError("live world state must be active")
    if not -2000 <= x_offset <= 2000:
        raise ValueError("mob x offset must be between -2000 and 2000")
    shape_dump = _load_json_object(
        shape_dump_path, description="IL2CPP packet shape dump"
    )
    version_id = shape_dump.get("version_id")
    protocol_version = shape_dump.get("protocol_version")
    if not isinstance(version_id, str) or not version_id:
        raise ValueError("IL2CPP shape dump has no version_id")
    if type(protocol_version) is not int or protocol_version <= 0:
        raise ValueError("IL2CPP shape dump has no valid protocol_version")
    captured = _captured_mob_temporary_stat_lifecycle(
        evidence_jsonl_path,
        tcp_stream=evidence_tcp_stream,
        expected_version_id=version_id,
        expected_protocol_version=protocol_version,
    )
    player_x, player_y, foothold_id = _current_player_foothold(analysis)
    target_x = player_x + x_offset
    if not -0x8000 <= target_x <= 0x7FFF:
        raise ValueError("planned mob x coordinate exceeds int16 range")
    if not -0x8000 <= player_y <= 0x7FFF:
        raise ValueError("planned mob y coordinate exceeds int16 range")
    if not 0 <= foothold_id <= 0xFFFF:
        raise ValueError("planned mob foothold exceeds uint16 range")
    object_id = _allocate_runtime_object_id(analysis)
    spawn_data = replace(
        captured.spawn.spawn,
        x=target_x,
        y=player_y,
        foothold_id=foothold_id,
        origin_foothold_id=foothold_id,
    )
    spawn = MobEnterField(object_id=object_id, spawn=spawn_data)
    set_stat = replace(captured.set_stat, object_id=object_id)
    reset_stat = replace(captured.reset_stat, object_id=object_id)
    leave = MobLeaveField(object_id=object_id, reason=1)
    for packet_type, packet in (
        (MobEnterField, spawn),
        (MobTemporaryStatSet, set_stat),
        (MobTemporaryStatReset, reset_stat),
        (MobLeaveField, leave),
    ):
        if packet_type.parse(packet.to_bytes()).to_bytes() != packet.to_bytes():
            raise ValueError("typed live mob packet did not round-trip exactly")
    shape_names = (
        _generated_shape_name(
            shape_dump,
            direction="server_to_client",
            opcode=spawn.opcode,
            length=len(spawn.to_bytes()),
        ),
        _generated_shape_name(
            shape_dump,
            direction="server_to_client",
            opcode=set_stat.opcode,
            length=len(set_stat.to_bytes()),
        ),
        _generated_shape_name(
            shape_dump,
            direction="server_to_client",
            opcode=reset_stat.opcode,
            length=len(reset_stat.to_bytes()),
        ),
        _generated_shape_name(
            shape_dump,
            direction="server_to_client",
            opcode=leave.opcode,
            length=len(leave.to_bytes()),
        ),
    )
    return MobTemporaryStatLiveReplayPlan(
        spawn=spawn,
        set_stat=set_stat,
        reset_stat=reset_stat,
        leave=leave,
        version_id=captured.version_id,
        protocol_version=captured.protocol_version,
        evidence_tcp_stream=evidence_tcp_stream,
        evidence_spawn_direction_index=captured.spawn_direction_index,
        evidence_set_direction_index=captured.set_direction_index,
        evidence_reset_direction_index=captured.reset_direction_index,
        shape_names=shape_names,
    )


def _mob_observation(
    analysis: GameplayAnalysis,
    *,
    first_observation: int,
    opcode: int,
    kind: str,
) -> dict[str, object] | None:
    for observation in reversed(analysis.observations[first_observation:]):
        if (
            observation.direction != "server_to_client"
            or observation.opcode != opcode
            or observation.kind != kind
        ):
            continue
        details = observation.details
        record: dict[str, object] = {
            "frame_index": observation.frame_index,
            "opcode": observation.opcode,
            "length": observation.length,
            "kind": observation.kind,
            "coverage": observation.coverage.value,
            "entity": details.get("entity"),
            "template_id": details.get("template_id"),
        }
        for name in (
            "x",
            "y",
            "foothold_id",
            "mask_pattern",
            "enabled_bit_indices",
            "source_skill_id",
            "source_level",
            "duration_value",
            "active_status_count",
            "reset_status_count",
            "reason",
        ):
            if name in details:
                record[name] = details[name]
        return record
    return None


def _wait_for_mob_fold(
    transcript_path: Path,
    *,
    first_observation: int,
    opcode: int,
    kind: str,
    predicate: Callable[[GameplayAnalysis], bool],
    timeout_seconds: float,
) -> tuple[GameplayAnalysis, dict[str, object], int]:
    deadline = time.monotonic() + timeout_seconds
    polls = 0
    while time.monotonic() < deadline:
        polls += 1
        time.sleep(0.05)
        analysis = analyze_gameplay_transcript(Transcript.load(transcript_path))
        if not analysis.valid:
            raise RuntimeError("injected transcript failed packet/state validation")
        observation = _mob_observation(
            analysis,
            first_observation=first_observation,
            opcode=opcode,
            kind=kind,
        )
        if observation is not None and predicate(analysis):
            return analysis, observation, polls
    raise TimeoutError(
        f"packet API accepted opcode {opcode}, but the live transcript did not "
        f"observe the predicted {kind} fold within {timeout_seconds:g} seconds"
    )


def _player_state_snapshot(analysis: GameplayAnalysis) -> tuple[object, ...]:
    state = analysis.state
    return (
        state.current_hp,
        state.max_hp,
        state.current_mp,
        state.max_mp,
        state.character_level,
        state.job_id,
        state.strength,
        state.dexterity,
        state.intelligence,
        state.luck,
        state.ability_points,
        state.skill_points,
        state.experience,
        state.fame,
        state.mesos,
    )


def inject_mob_temporary_stat_live(
    transcript_path: Path,
    shape_dump_path: Path,
    evidence_jsonl_path: Path,
    *,
    evidence_tcp_stream: int = 92,
    x_offset: int = 120,
    spawn_hold_seconds: float = 0.0,
    set_hold_seconds: float = 1.0,
    reset_hold_seconds: float = 0.0,
    api_url: str = DEFAULT_PACKET_API_URL,
    api_timeout_seconds: float = 5.0,
    verify_timeout_seconds: float = 5.0,
) -> MobTemporaryStatLiveReplayResult:
    """Inject and fold one generated-shape-backed mob status lifecycle."""
    for name, value, allow_zero in (
        ("API timeout", api_timeout_seconds, False),
        ("verification timeout", verify_timeout_seconds, False),
        ("spawn hold", spawn_hold_seconds, True),
        ("set hold", set_hold_seconds, True),
        ("reset hold", reset_hold_seconds, True),
    ):
        if not math.isfinite(value) or value < 0 or (not allow_zero and value == 0):
            qualifier = "non-negative" if allow_zero else "positive"
            raise ValueError(f"{name} must be {qualifier}")
    validate_packet_api_url(api_url)
    baseline = analyze_gameplay_transcript(Transcript.load(transcript_path))
    plan = plan_mob_temporary_stat_live_replay(
        baseline,
        shape_dump_path,
        evidence_jsonl_path,
        evidence_tcp_stream=evidence_tcp_stream,
        x_offset=x_offset,
    )
    object_id = plan.spawn.object_id
    enabled_bits = set(plan.set_stat.enabled_bit_indices)
    baseline_inventory = baseline.state.inventory_items
    baseline_progression = _progression_snapshot(baseline)
    baseline_player = _player_state_snapshot(baseline)
    baseline_mob_ids = set(baseline.state.mobs)
    baseline_active_stats = sum(
        len(entity.temporary_stats) for entity in baseline.state.mobs.values()
    )
    first_observation = len(baseline.observations)
    api_responses: list[dict[str, object]] = []
    observed_packets: list[dict[str, object]] = []
    polls = 0
    spawn_sent = False
    cleaned_up = False
    try:
        api_responses.append(
            _post_plaintext_packet(
                api_url,
                plan.spawn.to_bytes(),
                timeout_seconds=api_timeout_seconds,
            )
        )
        spawn_sent = True
        spawned, observation, step_polls = _wait_for_mob_fold(
            transcript_path,
            first_observation=first_observation,
            opcode=279,
            kind="mob_enter_field",
            predicate=lambda analysis: (
                object_id in analysis.state.mobs
                and analysis.state.mobs[object_id].spawn.template_id
                == plan.spawn.spawn.template_id
            ),
            timeout_seconds=verify_timeout_seconds,
        )
        polls += step_polls
        observed_packets.append(observation)
        first_observation = len(spawned.observations)
        if spawn_hold_seconds:
            time.sleep(spawn_hold_seconds)

        api_responses.append(
            _post_plaintext_packet(
                api_url,
                plan.set_stat.to_bytes(),
                timeout_seconds=api_timeout_seconds,
            )
        )
        status_set, observation, step_polls = _wait_for_mob_fold(
            transcript_path,
            first_observation=first_observation,
            opcode=285,
            kind="mob_temporary_stat_set",
            predicate=lambda analysis: (
                object_id in analysis.state.mobs
                and enabled_bits.issubset(
                    analysis.state.mobs[object_id].temporary_stats
                )
            ),
            timeout_seconds=verify_timeout_seconds,
        )
        polls += step_polls
        observed_packets.append(observation)
        first_observation = len(status_set.observations)
        if set_hold_seconds:
            time.sleep(set_hold_seconds)

        api_responses.append(
            _post_plaintext_packet(
                api_url,
                plan.reset_stat.to_bytes(),
                timeout_seconds=api_timeout_seconds,
            )
        )
        status_reset, observation, step_polls = _wait_for_mob_fold(
            transcript_path,
            first_observation=first_observation,
            opcode=286,
            kind="mob_temporary_stat_reset",
            predicate=lambda analysis: (
                object_id in analysis.state.mobs
                and enabled_bits.isdisjoint(
                    analysis.state.mobs[object_id].temporary_stats
                )
            ),
            timeout_seconds=verify_timeout_seconds,
        )
        polls += step_polls
        observed_packets.append(observation)
        first_observation = len(status_reset.observations)
        if reset_hold_seconds:
            time.sleep(reset_hold_seconds)

        api_responses.append(
            _post_plaintext_packet(
                api_url,
                plan.leave.to_bytes(),
                timeout_seconds=api_timeout_seconds,
            )
        )
        final, observation, step_polls = _wait_for_mob_fold(
            transcript_path,
            first_observation=first_observation,
            opcode=280,
            kind="mob_leave_field",
            predicate=lambda analysis: object_id not in analysis.state.mobs,
            timeout_seconds=verify_timeout_seconds,
        )
        cleaned_up = True
        polls += step_polls
        observed_packets.append(observation)
    except BaseException:
        if spawn_sent and not cleaned_up:
            try:
                _post_plaintext_packet(
                    api_url,
                    plan.leave.to_bytes(),
                    timeout_seconds=api_timeout_seconds,
                )
            except Exception:
                pass
        raise

    state = final.state
    counter_checks = {
        "mob_entries": state.mob_entries - baseline.state.mob_entries == 1,
        "mob_leaves": state.mob_leaves - baseline.state.mob_leaves == 1,
        "sets": (
            state.mob_temporary_stat_sets
            - baseline.state.mob_temporary_stat_sets
            == 1
        ),
        "resets": (
            state.mob_temporary_stat_resets
            - baseline.state.mob_temporary_stat_resets
            == 1
        ),
        "known_sets": (
            state.mob_temporary_stat_sets_for_known_mobs
            - baseline.state.mob_temporary_stat_sets_for_known_mobs
            == 1
        ),
        "known_resets": (
            state.mob_temporary_stat_resets_for_known_mobs
            - baseline.state.mob_temporary_stat_resets_for_known_mobs
            == 1
        ),
        "modeled_resets": (
            state.mob_temporary_stat_resets_with_modeled_set
            - baseline.state.mob_temporary_stat_resets_with_modeled_set
            == 1
        ),
        "unknown_sets": (
            state.mob_temporary_stat_sets_for_unknown_mobs
            == baseline.state.mob_temporary_stat_sets_for_unknown_mobs
        ),
        "unknown_resets": (
            state.mob_temporary_stat_resets_for_unknown_mobs
            == baseline.state.mob_temporary_stat_resets_for_unknown_mobs
        ),
    }
    final_active_stats = sum(
        len(entity.temporary_stats) for entity in state.mobs.values()
    )
    invariant_checks = {
        "mob_membership": set(state.mobs) == baseline_mob_ids,
        "active_temporary_stats": final_active_stats == baseline_active_stats,
        "phase": state.phase == baseline.state.phase,
        "field_epoch": state.field_epoch == baseline.state.field_epoch,
        "map_id": state.map_id == baseline.state.map_id,
        "player": _player_state_snapshot(final) == baseline_player,
        "inventory": state.inventory_items == baseline_inventory,
        "progression": _progression_snapshot(final) == baseline_progression,
    }
    failed = [
        name
        for name, matched in {**counter_checks, **invariant_checks}.items()
        if not matched
    ]
    if failed:
        raise RuntimeError(
            "typed mob temporary-stat replay violated predicted checks: "
            + ", ".join(failed)
        )
    return MobTemporaryStatLiveReplayResult(
        plan=plan,
        api_responses=tuple(api_responses),
        observed_packets=tuple(observed_packets),
        polls=polls,
        spawn_hold_seconds=spawn_hold_seconds,
        set_hold_seconds=set_hold_seconds,
        reset_hold_seconds=reset_hold_seconds,
    )


def plan_skill_record_update_live(
    analysis: GameplayAnalysis,
    *,
    skill_id: int | None = None,
    level: int | None = None,
) -> SkillRecordLiveReplayPlan:
    """Build one captured-form empty or existing-skill record update."""
    if not analysis.valid:
        raise ValueError("live world transcript failed packet/state validation")
    if skill_id is None:
        if level is not None:
            raise ValueError("skill level requires a skill id")
        update = SkillRecordUpdate(
            flag_a=False,
            flag_b=False,
            records=(),
            trailing_value=2,
        )
        original_level = None
        emitted_level = None
    else:
        if skill_id not in analysis.state.skill_levels:
            raise ValueError("skill id is not present in the live progression state")
        original_level = analysis.state.skill_levels[skill_id]
        emitted_level = original_level if level is None else level
        if not 0 <= emitted_level <= 0x7FFF_FFFF:
            raise ValueError("skill level must fit a non-negative int32")
        update = SkillRecordUpdate(
            flag_a=True,
            flag_b=False,
            records=(
                SkillRecordEntry(
                    skill_id=skill_id,
                    level=emitted_level,
                    auxiliary_value=0,
                ),
            ),
            trailing_value=2,
        )
    payload = update.to_bytes()
    if SkillRecordUpdate.parse(payload) != update:
        raise RuntimeError("skill-record update failed typed packet round trip")
    return SkillRecordLiveReplayPlan(
        update=update,
        original_skill_level=original_level,
        emitted_skill_level=emitted_level,
    )


def _matching_skill_record_transaction(
    analysis: GameplayAnalysis,
    *,
    first_observation: int,
    update: SkillRecordUpdate,
) -> tuple[dict[str, object], dict[str, object]] | None:
    expected_shape = update.safe_dict()
    update_observation = None
    for observation in analysis.observations[first_observation:]:
        if update_observation is None:
            if (
                observation.direction != "server_to_client"
                or observation.opcode != 46
                or observation.kind != "skill_record_update"
            ):
                continue
            observed_shape = {
                name: observation.details.get(name)
                for name in (
                    "flag_a",
                    "flag_b",
                    "record_count",
                    "records",
                    "trailing_value",
                )
            }
            if observed_shape != expected_shape:
                continue
            update_observation = observation
            continue
        if (
            observation.direction != "client_to_server"
            or observation.opcode != 293
            or observation.kind != "skill_record_update_acknowledgement"
            or observation.details.get("matched_update") is not True
            or observation.details.get("update_frame")
            != update_observation.frame_index
        ):
            continue
        return (
            {
                "frame_index": update_observation.frame_index,
                "opcode": update_observation.opcode,
                "kind": update_observation.kind,
                "coverage": update_observation.coverage.value,
                **expected_shape,
                "record_changes": update_observation.details.get(
                    "record_changes"
                ),
            },
            {
                "frame_index": observation.frame_index,
                "opcode": observation.opcode,
                "kind": observation.kind,
                "coverage": observation.coverage.value,
                "control_value": observation.details.get("control_value"),
                "client_tick": observation.details.get("client_tick"),
                "trailing_value": observation.details.get("trailing_value"),
                "matched_update": True,
                "update_frame": observation.details.get("update_frame"),
                "round_trip_ms": observation.details.get("round_trip_ms"),
            },
        )
    return None


def inject_skill_record_live(
    transcript_path: Path,
    *,
    skill_id: int | None = None,
    level: int | None = None,
    api_url: str = DEFAULT_PACKET_API_URL,
    api_timeout_seconds: float = 5.0,
    verify_timeout_seconds: float = 5.0,
) -> SkillRecordLiveReplayResult:
    """Plan, inject, and verify one typed skill-record transaction."""
    if not math.isfinite(api_timeout_seconds) or api_timeout_seconds <= 0:
        raise ValueError("API timeout must be positive")
    if not math.isfinite(verify_timeout_seconds) or verify_timeout_seconds <= 0:
        raise ValueError("verification timeout must be positive")
    validate_packet_api_url(api_url)
    baseline = analyze_gameplay_transcript(Transcript.load(transcript_path))
    if not baseline.valid:
        raise ValueError("live world transcript failed packet/state validation")
    if baseline.state.pending_skill_level_change_requests:
        raise ValueError("live state has pending skill-level change requests")
    if baseline.state.pending_skill_record_update_acknowledgements:
        raise ValueError("live state has pending skill-record acknowledgements")
    plan = plan_skill_record_update_live(
        baseline,
        skill_id=skill_id,
        level=level,
    )
    baseline_observations = len(baseline.observations)
    baseline_inventory = baseline.state.inventory_items
    baseline_player = _player_state_snapshot(baseline)
    baseline_other_progression = _progression_snapshot_without_skill_levels(
        baseline
    )
    expected_skill_levels = dict(baseline.state.skill_levels)
    if plan.update.records:
        record = plan.update.records[0]
        expected_skill_levels[record.skill_id] = record.level
    api_response = _post_plaintext_packet(
        api_url,
        plan.update.to_bytes(),
        timeout_seconds=api_timeout_seconds,
    )

    deadline = time.monotonic() + verify_timeout_seconds
    polls = 0
    last_analysis = baseline
    while time.monotonic() < deadline:
        polls += 1
        time.sleep(0.05)
        last_analysis = analyze_gameplay_transcript(
            Transcript.load(transcript_path)
        )
        if not last_analysis.valid:
            raise RuntimeError("injected transcript failed packet/state validation")
        transaction = _matching_skill_record_transaction(
            last_analysis,
            first_observation=baseline_observations,
            update=plan.update,
        )
        if transaction is None:
            continue
        state = last_analysis.state
        expected_records = len(plan.update.records)
        counter_checks = {
            "skill_record_updates": (
                state.skill_record_updates
                == baseline.state.skill_record_updates + 1
            ),
            "skill_record_update_records": (
                state.skill_record_update_records
                == baseline.state.skill_record_update_records + expected_records
            ),
            "acknowledgements": (
                state.skill_record_update_acknowledgements
                == baseline.state.skill_record_update_acknowledgements + 1
            ),
            "matched_acknowledgements": (
                state.matched_skill_record_update_acknowledgements
                == baseline.state.matched_skill_record_update_acknowledgements + 1
            ),
            "unmatched_acknowledgements": (
                state.unmatched_skill_record_update_acknowledgements
                == baseline.state.unmatched_skill_record_update_acknowledgements
            ),
            "pending_acknowledgements": (
                state.pending_skill_record_update_acknowledgements == 0
            ),
            "updates_without_request": (
                state.skill_record_updates_without_request
                == baseline.state.skill_record_updates_without_request
                + int(bool(expected_records))
            ),
            "requests": (
                state.skill_level_change_requests
                == baseline.state.skill_level_change_requests
            ),
            "pending_requests": state.pending_skill_level_change_requests == 0,
        }
        invariant_checks = {
            "skill_levels": state.skill_levels == expected_skill_levels,
            "phase": state.phase == baseline.state.phase,
            "field_epoch": state.field_epoch == baseline.state.field_epoch,
            "map_id": state.map_id == baseline.state.map_id,
            "player": _player_state_snapshot(last_analysis) == baseline_player,
            "inventory": state.inventory_items == baseline_inventory,
            "other_progression": (
                _progression_snapshot_without_skill_levels(last_analysis)
                == baseline_other_progression
            ),
        }
        failed = [
            name
            for name, matched in {**counter_checks, **invariant_checks}.items()
            if not matched
        ]
        if failed:
            raise RuntimeError(
                "typed skill-record replay violated predicted checks: "
                + ", ".join(failed)
            )
        observed_update, observed_acknowledgement = transaction
        return SkillRecordLiveReplayResult(
            plan=plan,
            api_response=api_response,
            observed_update=observed_update,
            observed_acknowledgement=observed_acknowledgement,
            polls=polls,
        )
    raise TimeoutError(
        "packet API accepted the skill-record update, but the live transcript "
        "did not observe its matched client acknowledgement within "
        f"{verify_timeout_seconds:g} seconds; last counters were "
        f"updates={last_analysis.state.skill_record_updates}, "
        "acknowledgements="
        f"{last_analysis.state.skill_record_update_acknowledgements}"
    )


def _matching_current_hp_packet(
    analysis: GameplayAnalysis,
    *,
    first_observation: int,
    current_hp: int,
) -> dict[str, object] | None:
    for observation in reversed(analysis.observations[first_observation:]):
        if observation.direction != "server_to_client" or observation.opcode != 41:
            continue
        current_change = observation.details.get("changes", {}).get("current_hp")
        if not isinstance(current_change, dict):
            continue
        if current_change.get("current") != current_hp:
            continue
        return {
            "frame_index": observation.frame_index,
            "opcode": observation.opcode,
            "kind": observation.kind,
            "coverage": observation.coverage.value,
            "stat_mask": observation.details.get("stat_mask"),
            "previous_current_hp": current_change.get("previous"),
            "current_hp": current_change.get("current"),
        }
    return None


def _inventory_item_snapshot(
    analysis: GameplayAnalysis,
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        sorted(
            (
                inventory,
                item.slot,
                item.record_type,
                item.item_id,
                item.cash_item,
                item.expires_at_ticks,
                item.quantity,
            )
            for inventory, items in analysis.state.inventory_items.items()
            for item in items
        )
    )


def _safe_item_pickup_observation(observation: object) -> dict[str, object]:
    details = observation.details
    record: dict[str, object] = {
        "frame_index": observation.frame_index,
        "direction": observation.direction,
        "opcode": observation.opcode,
        "kind": observation.kind,
        "coverage": observation.coverage.value,
    }
    for name in (
        "drop",
        "kind",
        "item_id",
        "spawn_mode",
        "position_x",
        "position_y",
        "control_level",
        "source_drop_count",
        "shape",
        "request_attempt",
        "request_retry",
        "drop_age_ms",
        "source_controller_release_age_ms",
        "predicted_item_id",
        "predicted_result_kind",
        "inventory",
        "slot",
        "quantity",
        "quantity_delta",
        "known_active_drop",
        "matched_pickup_request",
        "reason",
        "variant",
    ):
        if name in details:
            record[name] = details[name]
    return record


def _send_wayland_evdev_key(
    key: str,
    *,
    hold_ms: int,
    wayland_display: str,
    runtime_directory: Path,
) -> None:
    if not key or any(character.isspace() for character in key):
        raise ValueError("pickup key must be one non-whitespace token")
    if not 0 <= hold_ms <= 10_000:
        raise ValueError("pickup key hold must be between 0 and 10000 ms")
    if not wayland_display:
        raise ValueError("Wayland display cannot be empty")
    helper = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "send_wayland_evdev_key.py"
    )
    try:
        subprocess.run(
            [
                sys.executable,
                str(helper),
                key,
                "--hold-ms",
                str(hold_ms),
                "--wayland-display",
                wayland_display,
                "--runtime-directory",
                str(runtime_directory),
            ],
            env=os.environ
            | {
                "XDG_RUNTIME_DIR": str(runtime_directory),
                "WAYLAND_DISPLAY": wayland_display,
            },
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError("could not send the physical pickup key") from error


def inject_item_pickup_live(
    transcript_path: Path,
    evidence_pcap_path: Path,
    *,
    evidence_tcp_stream: int = 92,
    item_id: int = 4_000_004,
    admission_index: int = 1,
    pickup_key: str = "z",
    pickup_key_hold_ms: int = 100,
    wayland_display: str,
    wayland_runtime_directory: Path | None = None,
    pickup_input_delay_seconds: float | None = None,
    api_url: str = DEFAULT_PACKET_API_URL,
    api_timeout_seconds: float = 5.0,
    verify_timeout_seconds: float = 10.0,
) -> ItemPickupLiveReplayResult:
    """Inject, admit, serve, and verify one proximity-correct item pickup."""
    for name, value in (
        ("API timeout", api_timeout_seconds),
        ("verification timeout", verify_timeout_seconds),
    ):
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be positive")
    if pickup_input_delay_seconds is not None and (
        not math.isfinite(pickup_input_delay_seconds)
        or pickup_input_delay_seconds < 0
    ):
        raise ValueError("pickup input delay must be non-negative")
    validate_packet_api_url(api_url)
    runtime_directory = wayland_runtime_directory or Path(
        f"/run/user/{os.getuid()}"
    )
    baseline = analyze_gameplay_transcript(Transcript.load(transcript_path))
    evidence = load_pcap_tcp_stream(
        evidence_pcap_path,
        evidence_tcp_stream,
    )
    plan = plan_item_pickup_live_replay(
        baseline,
        evidence,
        evidence_tcp_stream=evidence_tcp_stream,
        item_id=item_id,
        admission_index=admission_index,
    )
    input_delay = (
        plan.admission_delay_seconds
        if pickup_input_delay_seconds is None
        else pickup_input_delay_seconds
    )
    baseline_observation_count = len(baseline.observations)
    baseline_inventory = _inventory_item_snapshot(baseline)
    expected_inventory = list(baseline_inventory)
    matching_inventory_indices = [
        index
        for index, entry in enumerate(expected_inventory)
        if entry[0] == plan.inventory and entry[1] == plan.slot
    ]
    if len(matching_inventory_indices) != 1:
        raise ValueError("planned item-pickup inventory stack is not unique")
    inventory_index = matching_inventory_indices[0]
    expected_inventory[inventory_index] = (
        *expected_inventory[inventory_index][:-1],
        plan.quantity_after,
    )
    expected_inventory_snapshot = tuple(sorted(expected_inventory))
    baseline_progression = _progression_snapshot(baseline)
    baseline_player = _player_state_snapshot(baseline)
    baseline_position = (baseline.state.player_x, baseline.state.player_y)
    baseline_drop_ids = set(baseline.state.field_drops)
    api_responses: list[dict[str, object]] = []
    polls = 0
    drop_sent = False
    removed = False
    final = baseline
    request_observation = None
    runtime_drop_alias = None
    try:
        started_at = time.monotonic()
        api_responses.append(
            _post_plaintext_packet(
                api_url,
                plan.drop_spawn.to_bytes(),
                timeout_seconds=api_timeout_seconds,
            )
        )
        drop_sent = True
        api_responses.append(
            _post_plaintext_packet(
                api_url,
                plan.drop_refresh.to_bytes(),
                timeout_seconds=api_timeout_seconds,
            )
        )
        time.sleep(
            max(
                0.0,
                plan.release_delay_seconds
                - (time.monotonic() - started_at),
            )
        )
        api_responses.append(
            _post_plaintext_packet(
                api_url,
                plan.controller_release.to_bytes(),
                timeout_seconds=api_timeout_seconds,
            )
        )
        time.sleep(max(0.0, input_delay - (time.monotonic() - started_at)))
        _send_wayland_evdev_key(
            pickup_key,
            hold_ms=pickup_key_hold_ms,
            wayland_display=wayland_display,
            runtime_directory=runtime_directory,
        )
        request_deadline = time.monotonic() + verify_timeout_seconds
        while time.monotonic() < request_deadline:
            polls += 1
            time.sleep(0.05)
            candidate = analyze_gameplay_transcript(
                Transcript.load(transcript_path)
            )
            if not candidate.valid:
                raise RuntimeError(
                    "item-pickup admission transcript failed validation"
                )
            observations = candidate.observations[baseline_observation_count:]
            for observation in observations:
                if (
                    observation.direction == "server_to_client"
                    and observation.opcode == 311
                    and observation.kind == "field_drop_spawn"
                    and observation.details.get("new_drop") is True
                    and observation.details.get("item_id") == plan.item_id
                    and observation.details.get("position_x") == plan.player_x
                    and observation.details.get("position_y") == plan.player_y
                ):
                    runtime_drop_alias = observation.details.get("drop")
                    break
            if not isinstance(runtime_drop_alias, str):
                continue
            request_observation = next(
                (
                    observation
                    for observation in observations
                    if observation.direction == "client_to_server"
                    and observation.opcode in {185, 222}
                    and observation.kind == "item_pickup_request"
                    and observation.details.get("drop") == runtime_drop_alias
                    and observation.details.get("known_drop") is True
                ),
                None,
            )
            if request_observation is not None:
                break
        if request_observation is None:
            raise TimeoutError(
                "the latest-position drop was injected, but no authentic "
                "item-pickup request arrived before the verification timeout"
            )
        for plaintext in plan.response_packets(request_observation.opcode):
            api_responses.append(
                _post_plaintext_packet(
                    api_url,
                    plaintext,
                    timeout_seconds=api_timeout_seconds,
                )
            )
        removed = True
        completion_deadline = time.monotonic() + verify_timeout_seconds
        while time.monotonic() < completion_deadline:
            polls += 1
            time.sleep(0.05)
            final = analyze_gameplay_transcript(Transcript.load(transcript_path))
            if not final.valid:
                raise RuntimeError(
                    "completed item-pickup transcript failed validation"
                )
            state = final.state
            if (
                state.pending_item_pickups == 0
                and state.item_pickup_effect_matches
                == baseline.state.item_pickup_effect_matches + 1
                and state.item_pickup_spawn_result_matches
                == baseline.state.item_pickup_spawn_result_matches + 1
                and state.item_pickup_removal_matches
                == baseline.state.item_pickup_removal_matches + 1
            ):
                break
        else:
            raise TimeoutError(
                "item-pickup response packets were accepted, but the completed "
                "chain did not fold before the verification timeout"
            )
    except BaseException:
        if drop_sent and not removed:
            try:
                _post_plaintext_packet(
                    api_url,
                    plan.cleanup.to_bytes(),
                    timeout_seconds=api_timeout_seconds,
                )
            except Exception:
                pass
        raise

    state = final.state
    request_attempts = (
        state.item_pickup_requests - baseline.state.item_pickup_requests
    )
    counter_checks = {
        "requests": request_attempts >= 1,
        "chains": (
            state.item_pickup_request_chains
            == baseline.state.item_pickup_request_chains + 1
        ),
        "retries": (
            state.item_pickup_request_retries
            == baseline.state.item_pickup_request_retries
            + request_attempts
            - 1
        ),
        "effects": (
            state.item_pickup_effect_matches
            == baseline.state.item_pickup_effect_matches + 1
        ),
        "results": (
            state.item_pickup_spawn_result_matches
            == baseline.state.item_pickup_spawn_result_matches + 1
        ),
        "removals": (
            state.item_pickup_removal_matches
            == baseline.state.item_pickup_removal_matches + 1
        ),
        "pending": state.pending_item_pickups == 0,
    }
    invariant_checks = {
        "field_drops": set(state.field_drops) == baseline_drop_ids,
        "phase": state.phase == baseline.state.phase,
        "field_epoch": state.field_epoch == baseline.state.field_epoch,
        "map_id": state.map_id == baseline.state.map_id,
        "player": _player_state_snapshot(final) == baseline_player,
        "player_position": (state.player_x, state.player_y) == baseline_position,
        "inventory": _inventory_item_snapshot(final)
        == expected_inventory_snapshot,
        "progression": _progression_snapshot(final) == baseline_progression,
    }
    failed = [
        name
        for name, matched in {**counter_checks, **invariant_checks}.items()
        if not matched
    ]
    if failed:
        raise RuntimeError(
            "typed item-pickup replay violated predicted checks: "
            + ", ".join(failed)
        )
    observed_packets = tuple(
        _safe_item_pickup_observation(observation)
        for observation in final.observations[baseline_observation_count:]
        if observation.opcode in {39, 49, 185, 222, 281, 311, 312}
        and (
            observation.details.get("drop") == runtime_drop_alias
            or observation.opcode in {39, 49, 281}
        )
    )
    return ItemPickupLiveReplayResult(
        plan=plan,
        api_responses=tuple(api_responses),
        observed_packets=observed_packets,
        request_attempts=request_attempts,
        polls=polls,
        pickup_key=pickup_key,
        pickup_input_delay_seconds=input_delay,
    )


def inject_current_hp_live(
    transcript_path: Path,
    current_hp: int,
    *,
    api_url: str = DEFAULT_PACKET_API_URL,
    api_timeout_seconds: float = 5.0,
    verify_timeout_seconds: float = 5.0,
) -> CurrentHpLiveReplayResult:
    """Plan, inject, and observe one typed current-HP update on a live replay."""
    if not math.isfinite(api_timeout_seconds) or api_timeout_seconds <= 0:
        raise ValueError("API timeout must be positive")
    if not math.isfinite(verify_timeout_seconds) or verify_timeout_seconds <= 0:
        raise ValueError("verification timeout must be positive")
    validate_packet_api_url(api_url)
    transcript = Transcript.load(transcript_path)
    baseline = analyze_gameplay_transcript(transcript)
    if not baseline.valid:
        raise ValueError("live world transcript failed packet/state validation")
    if current_hp == baseline.state.current_hp:
        raise ValueError("emitted current HP must differ from the live state")
    plan = plan_current_hp_stat_update(transcript, current_hp)
    baseline_observations = len(baseline.observations)
    baseline_inventory = baseline.state.inventory_items
    baseline_progression = _progression_snapshot(baseline)
    api_response = _post_plaintext_packet(
        api_url,
        plan.update.to_bytes(),
        timeout_seconds=api_timeout_seconds,
    )

    deadline = time.monotonic() + verify_timeout_seconds
    polls = 0
    last_analysis = baseline
    while time.monotonic() < deadline:
        polls += 1
        time.sleep(0.05)
        last_analysis = analyze_gameplay_transcript(
            Transcript.load(transcript_path)
        )
        if not last_analysis.valid:
            raise RuntimeError("injected transcript failed packet/state validation")
        observed_packet = _matching_current_hp_packet(
            last_analysis,
            first_observation=baseline_observations,
            current_hp=current_hp,
        )
        if observed_packet is None:
            continue
        state = last_analysis.state
        stat_update_delta = (
            state.player_stat_updates - baseline.state.player_stat_updates
        )
        checks = {
            "current_hp": state.current_hp == current_hp,
            "max_hp": state.max_hp == baseline.state.max_hp,
            "phase": state.phase == baseline.state.phase,
            "field_epoch": state.field_epoch == baseline.state.field_epoch,
            "map_id": state.map_id == baseline.state.map_id,
            "inventory": state.inventory_items == baseline_inventory,
            "progression": _progression_snapshot(last_analysis)
            == baseline_progression,
            "player_stat_updates": stat_update_delta == 1,
        }
        if not all(checks.values()):
            failed = ", ".join(name for name, matched in checks.items() if not matched)
            raise RuntimeError(
                f"typed current-HP replay violated predicted checks: {failed}"
            )
        return CurrentHpLiveReplayResult(
            plan=plan,
            api_response=api_response,
            observed_packet=observed_packet,
            observed_current_hp=current_hp,
            observed_player_stat_updates_delta=stat_update_delta,
            polls=polls,
        )
    raise TimeoutError(
        "packet API accepted the current-HP update, but the live transcript did "
        f"not observe it within {verify_timeout_seconds:g} seconds; last state "
        f"was current_hp={last_analysis.state.current_hp!r}"
    )


def render_skill_record_live_replay(
    result: SkillRecordLiveReplayResult,
) -> str:
    plan = result.plan.safe_dict()
    acknowledgement = result.observed_acknowledgement
    if plan["record_count"]:
        prediction = (
            f"skill {plan['skill_id']} "
            f"{plan['original_skill_level']} -> {plan['emitted_skill_level']}"
        )
    else:
        prediction = "zero records; progression unchanged"
    return "\n".join(
        (
            "live skill-record replay: matched",
            f"  predicted: {prediction}",
            (
                "  observed: opcode 46 frame "
                f"{result.observed_update['frame_index']} -> opcode 293 frame "
                f"{acknowledgement['frame_index']} in "
                f"{acknowledgement['round_trip_ms']} ms"
            ),
            (
                "  unchanged: phase, field epoch, map, player, inventory, "
                "other progression"
            ),
        )
    )


def render_current_hp_live_replay(result: CurrentHpLiveReplayResult) -> str:
    plan = result.plan.safe_dict()
    return "\n".join(
        (
            "live current-HP replay: matched",
            (
                "  predicted: "
                f"{plan['original_current_hp']} -> {plan['emitted_current_hp']} "
                f"of {plan['max_hp']}"
            ),
            (
                "  observed: "
                f"{result.observed_packet['previous_current_hp']} -> "
                f"{result.observed_packet['current_hp']} in frame "
                f"{result.observed_packet['frame_index']}"
            ),
            "  unchanged: phase, field epoch, map, inventory, progression",
        )
    )


def render_item_pickup_live_replay(result: ItemPickupLiveReplayResult) -> str:
    plan = result.plan.safe_dict()
    evidence = plan["evidence"]
    return "\n".join(
        (
            "live item-pickup replay: matched",
            (
                "  evidence: stream "
                f"{evidence['tcp_stream']} admission "
                f"{evidence['admission_index']} at "
                f"{evidence['admission_delay_ms']} ms"
            ),
            (
                "  placement: latest player position "
                f"({plan['latest_player_position']['x']},"
                f"{plan['latest_player_position']['y']}) from "
                f"{plan['player_position_source']}"
            ),
            (
                "  folded trailer: "
                f"({plan['folded_trailer_position']['x']},"
                f"{plan['folded_trailer_position']['y']})"
            ),
            (
                "  observed: "
                f"{result.request_attempts} authentic request attempt(s), "
                f"{plan['inventory']} slot {plan['slot']} "
                f"{plan['quantity_before']} -> {plan['quantity_after']}"
            ),
            (
                "  unchanged: phase, field epoch, map, player, other inventory, "
                "progression"
            ),
        )
    )


def render_mob_temporary_stat_live_replay(
    result: MobTemporaryStatLiveReplayResult,
) -> str:
    plan = result.plan.safe_dict()
    observed = result.observed_packets
    return "\n".join(
        (
            "live mob temporary-stat replay: matched",
            (
                "  evidence: "
                f"{plan['version_id']} stream {plan['evidence_tcp_stream']} "
                f"frames {plan['evidence_direction_indices']}"
            ),
            (
                "  predicted: spawn -> set bit "
                f"{plan['set']['enabled_bit_indices']} -> reset -> leave"
            ),
            (
                "  observed: "
                + " -> ".join(
                    f"{packet['kind']}@{packet['frame_index']}"
                    for packet in observed
                )
            ),
            "  unchanged: phase, field epoch, map, player, inventory, progression",
        )
    )

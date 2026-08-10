from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
import json
import math
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .gameplay import (
    CurrentHpStatUpdateReplayPlan,
    GameplayAnalysis,
    analyze_gameplay_transcript,
    plan_current_hp_stat_update,
)
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

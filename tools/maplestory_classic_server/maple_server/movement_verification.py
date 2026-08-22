"""Offline evidence checks for prefab physics and movement packet emission."""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass
import json
import math
from pathlib import Path
import statistics
from typing import Any, Mapping, Sequence

from .gamestate import PlainFrame, decode_transcript
from .navigation import MapGeometry, Physics
from .packets import (
    LifeMovementCommand,
    LifeMovementPath,
    LifeMovementSubmission,
)
from .rl_navigation import ACTIONS, LinearQModel, NavigationAgent, Observation
from .transcript import Transcript


@dataclass(frozen=True)
class TimedMovementSample:
    timestamp_ns: int
    packet_index: int
    position_x: int
    position_y: int
    velocity_x: int
    velocity_y: int
    foothold_id: int
    duration_ms: int


def rebuild_movement_command(command: LifeMovementCommand) -> LifeMovementCommand:
    """Rebuild a parsed command through its typed constructor."""

    value = command.safe_dict()
    kind = value["kind"]
    command_type = int(value["type"])
    if kind == "absolute":
        return LifeMovementCommand.absolute(
            command_type=command_type,
            position_x=int(value["position_x"]),
            position_y=int(value["position_y"]),
            last_x=int(value["last_x"]),
            last_y=int(value["last_y"]),
            foothold_id=int(value["foothold_id"]),
            stance=int(value["stance"]),
            duration_ms=int(value["duration_ms"]),
        )
    if kind == "relative":
        return LifeMovementCommand.relative(
            command_type=command_type,
            delta_x=int(value["delta_x"]),
            delta_y=int(value["delta_y"]),
            stance=int(value["stance"]),
            duration_ms=int(value["duration_ms"]),
        )
    if kind == "teleport":
        return LifeMovementCommand.teleport(
            command_type=command_type,
            position_x=int(value["position_x"]),
            position_y=int(value["position_y"]),
            unknown_value=int(value["unknown_value"]),
            stance=int(value["stance"]),
            trailing_value=int(value["trailing_value"]),
        )
    if kind == "equipment_change":
        return LifeMovementCommand.equipment_change(int(value["value"]))
    if kind == "chair":
        return LifeMovementCommand.chair(
            position_x=int(value["position_x"]),
            position_y=int(value["position_y"]),
            unknown_value=int(value["unknown_value"]),
            stance=int(value["stance"]),
            trailing_value=int(value["trailing_value"]),
        )
    if kind == "jump_down":
        return LifeMovementCommand.jump_down(
            position_x=int(value["position_x"]),
            position_y=int(value["position_y"]),
            vector_x=int(value["vector_x"]),
            vector_y=int(value["vector_y"]),
            unknown_value_1=int(value["unknown_value_1"]),
            unknown_value_2=int(value["unknown_value_2"]),
            stance=int(value["stance"]),
            trailing_value=int(value["trailing_value"]),
        )
    # The packet parser has a fixed width for these commands, but no semantic
    # field names yet.  Preserving the parsed payload is the only honest typed
    # representation until those fields are identified.
    return LifeMovementCommand(
        command_type=command.command_type,
        opaque_payload=command.opaque_payload,
    )


def rebuild_movement_submission(
    submission: LifeMovementSubmission,
) -> LifeMovementSubmission:
    """Re-emit an opcode-47 submission while preserving runtime envelope fields."""

    movement = LifeMovementPath(
        reference_x=submission.movement.reference_x,
        reference_y=submission.movement.reference_y,
        commands=tuple(
            rebuild_movement_command(command)
            for command in submission.movement.commands
        ),
    )
    return LifeMovementSubmission(
        local_object_index=submission.local_object_index,
        client_token=submission.client_token,
        control_value=submission.control_value,
        movement=movement,
        tail_type=submission.tail_type,
        tail_state_values=submission.tail_state_values,
        tail_marker=submission.tail_marker,
        path_start_x=submission.path_start_x,
        path_start_y=submission.path_start_y,
        path_end_x=submission.path_end_x,
        path_end_y=submission.path_end_y,
        opcode=submission.opcode,
    )


def movement_frames(
    transcript_path: str | Path,
    *,
    start_timestamp_ns: int,
    end_timestamp_ns: int,
) -> tuple[PlainFrame, ...]:
    session = decode_transcript(Transcript.load(transcript_path))
    return tuple(
        frame
        for frame in session.frames
        if frame.direction == "client_to_server"
        and frame.opcode == 47
        and start_timestamp_ns <= frame.timestamp_ns <= end_timestamp_ns
    )


def packet_emission_evidence(
    frames: Sequence[PlainFrame],
) -> tuple[dict[str, Any], tuple[LifeMovementSubmission, ...]]:
    submissions: list[LifeMovementSubmission] = []
    exact = 0
    command_types: Counter[int] = Counter()
    typed_commands = 0
    opaque_commands = 0
    for frame in frames:
        submission = LifeMovementSubmission.parse(frame.plaintext)
        submissions.append(submission)
        rebuilt = rebuild_movement_submission(submission)
        if rebuilt.to_bytes() == frame.plaintext:
            exact += 1
        for command in submission.movement.commands:
            command_types[command.command_type] += 1
            if command.is_typed:
                typed_commands += 1
            else:
                opaque_commands += 1
    packet_count = len(frames)
    return (
        {
            "opcode": 47,
            "submissions": packet_count,
            "plaintext_byte_exact": exact,
            "all_plaintext_byte_exact": packet_count > 0 and exact == packet_count,
            "typed_commands": typed_commands,
            "opaque_commands": opaque_commands,
            "command_types": {
                str(key): value for key, value in sorted(command_types.items())
            },
            "encrypted_wire_equality": "not_comparable_across_sessions",
            "encrypted_wire_reason": (
                "Maple frame ciphertext depends on the per-session IV and "
                "cipher progression; plaintext opcode payloads are the stable "
                "equality boundary"
            ),
        },
        tuple(submissions),
    )


def timed_absolute_samples(
    frames: Sequence[PlainFrame],
    submissions: Sequence[LifeMovementSubmission],
) -> tuple[TimedMovementSample, ...]:
    samples: list[TimedMovementSample] = []
    for packet_index, (frame, submission) in enumerate(
        zip(frames, submissions, strict=True)
    ):
        durations = [
            max(0, int(command.safe_dict().get("duration_ms", 0)))
            for command in submission.movement.commands
        ]
        elapsed_ms = 0
        total_ms = sum(durations)
        for command, duration_ms in zip(
            submission.movement.commands, durations, strict=True
        ):
            elapsed_ms += duration_ms
            value = command.safe_dict()
            if value["kind"] != "absolute":
                continue
            timestamp_ns = frame.timestamp_ns - (total_ms - elapsed_ms) * 1_000_000
            samples.append(
                TimedMovementSample(
                    timestamp_ns=timestamp_ns,
                    packet_index=packet_index,
                    position_x=int(value["position_x"]),
                    position_y=int(value["position_y"]),
                    velocity_x=int(value["last_x"]),
                    velocity_y=int(value["last_y"]),
                    foothold_id=int(value["foothold_id"]),
                    duration_ms=int(value["duration_ms"]),
                )
            )
    return tuple(samples)


def physics_rule_evidence(
    samples: Sequence[TimedMovementSample],
    geometry: MapGeometry,
) -> dict[str, Any]:
    physics = geometry.physics
    gravity_values: list[float] = []
    apex_transitions = 0
    jump_values: list[float] = []
    terminal_values: list[int] = []
    contacts = 0
    valid_contacts = 0
    endpoint_tolerance_contacts = 0
    contact_errors: list[float] = []
    unknown_footholds: Counter[int] = Counter()
    special_contacts = 0
    footholds = {
        foothold.foothold_id: foothold for foothold in geometry.footholds
    }

    for previous, current in zip(samples, samples[1:]):
        if (
            previous.foothold_id == 0
            and current.foothold_id == 0
            and current.duration_ms > 0
            and current.velocity_y >= previous.velocity_y
            and current.velocity_y < physics.terminal_fall_speed
        ):
            if previous.velocity_y < 0 <= current.velocity_y:
                # The integer VecCtrl encoding clamps/quantizes the apex split.
                # It is not a full constant-acceleration interval.
                apex_transitions += 1
            else:
                gravity_values.append(
                    (current.velocity_y - previous.velocity_y)
                    / (current.duration_ms / 1_000.0)
                )
        if (
            previous.foothold_id != 0
            and current.foothold_id == 0
            and current.velocity_y < -50
        ):
            jump_values.append(
                current.velocity_y
                - physics.gravity * (current.duration_ms / 1_000.0)
            )

    for sample in samples:
        if sample.foothold_id == 0:
            if sample.velocity_y >= physics.terminal_fall_speed:
                terminal_values.append(sample.velocity_y)
            continue
        if sample.foothold_id >= 65_000:
            special_contacts += 1
            continue
        contacts += 1
        foothold = footholds.get(sample.foothold_id)
        if foothold is None:
            unknown_footholds[sample.foothold_id] += 1
            continue
        left = min(foothold.start.x, foothold.end.x)
        right = max(foothold.start.x, foothold.end.x)
        clamped_x = min(right, max(left, sample.position_x))
        if abs(clamped_x - sample.position_x) > 1:
            continue
        if clamped_x != sample.position_x:
            endpoint_tolerance_contacts += 1
        surface_y = foothold.y_at(clamped_x)
        if surface_y is None:
            continue
        error = abs(surface_y - sample.position_y)
        contact_errors.append(error)
        if error <= 2.0:
            valid_contacts += 1

    gravity_errors = [abs(value - physics.gravity) for value in gravity_values]
    jump_errors = [abs(value + physics.jump_speed) for value in jump_values]
    terminal_errors = [
        abs(value - physics.terminal_fall_speed) for value in terminal_values
    ]
    rules_pass = (
        bool(gravity_values)
        and bool(jump_values)
        and bool(terminal_values)
        and all(error <= 4.0 for error in gravity_errors)
        and all(error <= 1e-9 for error in jump_errors)
        and all(error <= 1e-9 for error in terminal_errors)
        and contacts > 0
        and valid_contacts == contacts
        and not unknown_footholds
    )
    return {
        "coordinate_system": "+x right, +y down",
        "parameters": {
            "timestep_ms": physics.timestep_ms,
            "run_acceleration": physics.run_acceleration,
            "ground_release_deceleration": physics.ground_release_deceleration,
            "walk_speed": physics.walk_speed,
            "jump_impulse": -physics.jump_speed,
            "gravity": physics.gravity,
            "terminal_fall_speed": physics.terminal_fall_speed,
            "climb_speed": physics.climb_speed,
        },
        "gravity": {
            "transitions": len(gravity_values),
            "apex_transitions_excluded": apex_transitions,
            "exact": sum(error <= 1e-9 for error in gravity_errors),
            "within_four_units_per_second_squared": sum(
                error <= 4.0 for error in gravity_errors
            ),
            "median": statistics.median(gravity_values)
            if gravity_values
            else None,
            "maximum_error": max(gravity_errors) if gravity_errors else None,
        },
        "jump_impulse": {
            "transitions": len(jump_values),
            "exact": sum(error <= 1e-9 for error in jump_errors),
            "median": statistics.median(jump_values) if jump_values else None,
        },
        "terminal_fall_speed": {
            "samples": len(terminal_values),
            "exact": sum(error <= 1e-9 for error in terminal_errors),
            "values": sorted(set(terminal_values)),
        },
        "prefab_contacts": {
            "samples": contacts,
            "valid_within_two_map_units": valid_contacts,
            "endpoint_tolerance_samples": endpoint_tolerance_contacts,
            "maximum_y_error": max(contact_errors) if contact_errors else None,
            "median_y_error": statistics.median(contact_errors)
            if contact_errors
            else None,
            "unknown_foothold_ids": {
                str(key): value for key, value in sorted(unknown_footholds.items())
            },
            "special_vecctrl_contacts": special_contacts,
        },
        "capture_scope": {
            "confirmed": [
                "gravity",
                "jump_impulse",
                "terminal_fall_speed",
                "foothold_contact_geometry",
            ],
            "source_only_in_this_window": [
                "run_acceleration",
                "ground_release_deceleration",
                "walk_speed",
                "climb_speed",
                "timestep",
            ],
        },
        "pass": rules_pass,
    }


def load_telemetry_frames(path: str | Path) -> tuple[Observation, ...]:
    frames: list[Observation] = []
    with Path(path).open(encoding="utf-8") as source:
        for line in source:
            try:
                value = json.loads(line)
                frames.append(Observation.from_record(value))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    return tuple(frames)


def infer_success_window(
    telemetry: Sequence[Observation],
    status: Mapping[str, Any],
    *,
    window_seconds: float,
) -> tuple[int, int, tuple[Observation, ...]]:
    if window_seconds <= 0 or not math.isfinite(window_seconds):
        raise ValueError("success window must be finite and positive")
    anchor_timestamp = int(status["timestamp_ns"])
    goal_y = float(status["goal"]["y"])
    threshold_y = goal_y + 24.0
    eligible = [
        (index, frame)
        for index, frame in enumerate(telemetry)
        if frame.timestamp_ns <= anchor_timestamp
    ]
    if not eligible:
        raise ValueError("telemetry has no frame at or before RL status")
    anchor_index, _ = max(eligible, key=lambda item: item[1].timestamp_ns)
    segment_start = anchor_index
    while segment_start > 0:
        previous = telemetry[segment_start - 1]
        current = telemetry[segment_start]
        if (
            previous.timestamp_ns >= current.timestamp_ns
            or previous.frame >= current.frame
            or current.timestamp_ns - previous.timestamp_ns > 5_000_000_000
        ):
            break
        segment_start -= 1
    segment = telemetry[segment_start : anchor_index + 1]
    reached = next((frame for frame in segment if frame.y <= threshold_y), None)
    if reached is None:
        raise ValueError("RL telemetry segment never reaches the recorded goal")
    end_timestamp = reached.timestamp_ns
    start_timestamp = end_timestamp - round(window_seconds * 1_000_000_000)
    window = tuple(
        frame
        for frame in segment
        if start_timestamp <= frame.timestamp_ns <= end_timestamp
    )
    return start_timestamp, end_timestamp, window


def telemetry_alignment_evidence(
    samples: Sequence[TimedMovementSample],
    telemetry: Sequence[Observation],
    physics: Physics,
    *,
    maximum_delta_ms: float = 60.0,
) -> dict[str, Any]:
    ordered = sorted(telemetry, key=lambda item: item.timestamp_ns)
    timestamps = [item.timestamp_ns for item in ordered]
    deltas: list[float] = []
    errors_x: list[float] = []
    errors_y: list[float] = []
    for sample in samples:
        index = bisect_left(timestamps, sample.timestamp_ns)
        candidate_indexes = [
            item for item in (index - 1, index) if 0 <= item < len(ordered)
        ]
        if not candidate_indexes:
            continue
        nearest = min(
            (ordered[item] for item in candidate_indexes),
            key=lambda item: abs(item.timestamp_ns - sample.timestamp_ns),
        )
        delta_ms = abs(nearest.timestamp_ns - sample.timestamp_ns) / 1_000_000.0
        if delta_ms > maximum_delta_ms:
            continue
        deltas.append(delta_ms)
        errors_x.append(abs(nearest.x - sample.position_x))
        errors_y.append(abs(nearest.y - sample.position_y))
    matched = len(deltas)
    matched_ratio = matched / len(samples) if samples else 0.0
    horizontal_error_envelope = (
        physics.walk_speed * maximum_delta_ms / 1_000.0 + 2.0
    )
    vertical_error_envelope = (
        physics.terminal_fall_speed * maximum_delta_ms / 1_000.0 + 2.0
    )
    median_error_x = statistics.median(errors_x) if errors_x else None
    median_error_y = statistics.median(errors_y) if errors_y else None
    return {
        "samples": len(samples),
        "matched_within_ms": matched,
        "matched_ratio": matched_ratio,
        "minimum_match_ratio": 0.7,
        "maximum_delta_ms": maximum_delta_ms,
        "median_timestamp_delta_ms": statistics.median(deltas)
        if deltas
        else None,
        "median_absolute_position_error": {
            "x": median_error_x,
            "y": median_error_y,
        },
        "motion_error_envelope": {
            "x": horizontal_error_envelope,
            "y": vertical_error_envelope,
            "coordinate_quantization_allowance": 2.0,
        },
        "pass": (
            matched > 0
            and matched_ratio >= 0.7
            and median_error_x is not None
            and median_error_x <= horizontal_error_envelope
            and median_error_y is not None
            and median_error_y <= vertical_error_envelope
        ),
    }


class _RecordingController:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def apply(self, action: str) -> None:
        self.actions.append(action)


def rl_policy_mirror_evidence(
    geometry: MapGeometry,
    model_path: str | Path,
    status: Mapping[str, Any],
    telemetry: Sequence[Observation],
    samples: Sequence[TimedMovementSample],
    historical_decisions: Sequence[tuple[int, str]] | None = None,
) -> dict[str, Any]:
    trained = LinearQModel.load(model_path)
    shadow = LinearQModel(
        weights={action: list(weights) for action, weights in trained.weights.items()},
        updates=trained.updates,
        alpha=0.0,
        gamma=trained.gamma,
    )
    controller = _RecordingController()
    agent = NavigationAgent(geometry, shadow, controller, epsilon=0.0)
    decisions: list[tuple[int, str]] = []
    errors: list[str] = []
    reached = False
    for observation in telemetry:
        try:
            decision = agent.step(observation)
        except Exception as error:  # pragma: no cover - included in report
            errors.append(f"frame {observation.frame}: {error}")
            continue
        action = str(decision["action"])
        decisions.append((observation.timestamp_ns, action))
        reached = reached or bool(decision["goal"]["reached"])

    projection_decisions = (
        list(historical_decisions)
        if historical_decisions is not None
        else decisions
    )
    decision_timestamps = [item[0] for item in projection_decisions]
    directional_compared = 0
    directional_agreed = 0
    for sample in samples:
        if abs(sample.velocity_x) < 20 or not projection_decisions:
            continue
        index = bisect_left(decision_timestamps, sample.timestamp_ns)
        candidate_indexes = [
            item
            for item in (index - 1, index)
            if 0 <= item < len(projection_decisions)
        ]
        nearest_timestamp, action = min(
            (projection_decisions[item] for item in candidate_indexes),
            key=lambda item: abs(item[0] - sample.timestamp_ns),
        )
        if abs(nearest_timestamp - sample.timestamp_ns) > 100_000_000:
            continue
        expected = (
            -1
            if action.startswith("left")
            else 1
            if action.startswith("right")
            else 0
        )
        if expected == 0:
            continue
        directional_compared += 1
        actual = -1 if sample.velocity_x < 0 else 1
        directional_agreed += actual == expected

    status_updates = int(status.get("model_updates") or -1)
    return {
        "algorithm": "linear_q_learning",
        "trained_updates": trained.updates,
        "status_updates": status_updates,
        "status_model_consistent": trained.updates == status_updates,
        "epsilon": 0.0,
        "shadow_frames": len(decisions),
        "shadow_action_counts": dict(sorted(Counter(controller.actions).items())),
        "observed_trajectory_reaches_goal": reached,
        "shadow_errors": errors,
        "directional_packet_projection": {
            "decision_source": (
                "historical_action_trace"
                if historical_decisions is not None
                else "final_policy_shadow"
            ),
            "compared": directional_compared,
            "agreed": directional_agreed,
            "agreement_ratio": (
                directional_agreed / directional_compared
                if directional_compared
                else None
            ),
            "non_gating_reason": (
                "packet velocity contains momentum and does not uniquely encode "
                "the key decision at that instant"
            ),
        },
        "historical_action_trace_available": historical_decisions is not None,
        "historical_frames": (
            len(historical_decisions)
            if historical_decisions is not None
            else 0
        ),
        "historical_action_counts": (
            dict(
                sorted(
                    Counter(
                        action for _, action in historical_decisions
                    ).items()
                )
            )
            if historical_decisions is not None
            else {}
        ),
        "historical_limit": None
        if historical_decisions is not None
        else (
            "the completed run retained only its final status and weights, so "
            "the final policy can be shadowed over observed states but the "
            "evolving historical action decisions cannot be compared exactly"
        ),
        "pass": trained.updates == status_updates and reached and not errors,
    }


def load_action_trace_evidence(
    path: str | Path,
    *,
    start_timestamp_ns: int,
    end_timestamp_ns: int,
) -> tuple[list[Mapping[str, Any]], dict[str, Any]]:
    """Load and validate a per-frame RL action trace through first success."""

    source = Path(path)
    records: list[Mapping[str, Any]] = []
    errors: list[str] = []
    total_records = 0
    for line_number, line in enumerate(
        source.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        total_records += 1
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            errors.append(f"line {line_number}: {error.msg}")
            continue
        if not isinstance(value, Mapping):
            errors.append(f"line {line_number}: expected a JSON object")
            continue
        try:
            timestamp_ns = int(value["timestamp_ns"])
        except (KeyError, TypeError, ValueError):
            errors.append(f"line {line_number}: invalid timestamp_ns")
            continue
        if start_timestamp_ns <= timestamp_ns <= end_timestamp_ns:
            records.append(value)

    timestamps: list[int] = []
    frames: list[int] = []
    updates: list[int] = []
    actions: list[str] = []
    reached: list[bool] = []
    validated_records: list[Mapping[str, Any]] = []
    for index, record in enumerate(records):
        try:
            timestamps.append(int(record["timestamp_ns"]))
            frames.append(int(record["frame"]))
            updates.append(int(record["model_updates"]))
            action = str(record["action"])
            goal = record["goal"]
            if not isinstance(goal, Mapping):
                raise TypeError("goal is not an object")
            reached.append(bool(goal["reached"]))
        except (KeyError, TypeError, ValueError) as error:
            errors.append(f"window record {index}: {error}")
            continue
        actions.append(action)
        if action not in ACTIONS:
            errors.append(f"window record {index}: unknown action {action!r}")
            continue
        validated_records.append(record)

    lengths_match = len({
        len(records),
        len(timestamps),
        len(frames),
        len(updates),
        len(actions),
        len(reached),
    }) == 1
    timestamps_strict = lengths_match and all(
        after > before for before, after in zip(timestamps, timestamps[1:])
    )
    frames_strict = lengths_match and all(
        after > before for before, after in zip(frames, frames[1:])
    )
    updates_monotonic = lengths_match and all(
        after >= before for before, after in zip(updates, updates[1:])
    )
    complete_to_first_success = bool(
        lengths_match and reached and reached[-1] and not any(reached[:-1])
    )
    learning_transitions = updates[-1] - updates[0] if updates else 0
    one_update_per_transition = bool(
        lengths_match
        and updates
        and learning_transitions == len(records) - 1
    )
    passed = bool(
        records
        and not errors
        and timestamps_strict
        and frames_strict
        and updates_monotonic
        and complete_to_first_success
        and one_update_per_transition
    )
    report = {
        "available": True,
        "source": str(source),
        "total_records": total_records,
        "window_records": len(records),
        "start_frame": frames[0] if frames else None,
        "end_frame": frames[-1] if frames else None,
        "start_timestamp_ns": timestamps[0] if timestamps else None,
        "end_timestamp_ns": timestamps[-1] if timestamps else None,
        "start_model_updates": updates[0] if updates else None,
        "end_model_updates": updates[-1] if updates else None,
        "learning_transitions": learning_transitions,
        "action_counts": dict(sorted(Counter(actions).items())),
        "timestamps_strictly_increasing": timestamps_strict,
        "frames_strictly_increasing": frames_strict,
        "model_updates_monotonic": updates_monotonic,
        "one_update_per_transition": one_update_per_transition,
        "complete_to_first_success": complete_to_first_success,
        "errors": errors,
        "pass": passed,
    }
    return validated_records, report


def verify_rl_capture(
    *,
    geometry: MapGeometry,
    model_path: str | Path,
    status_path: str | Path,
    telemetry_path: str | Path,
    transcript_path: str | Path,
    action_trace_path: str | Path | None = None,
    window_seconds: float = 140.0,
) -> dict[str, Any]:
    status = json.loads(Path(status_path).read_text(encoding="utf-8"))
    telemetry = load_telemetry_frames(telemetry_path)
    start_timestamp, end_timestamp, telemetry_window = infer_success_window(
        telemetry,
        status,
        window_seconds=window_seconds,
    )
    if action_trace_path is None:
        action_records = None
        action_trace = {
            "available": False,
            "pass": True,
            "non_gating_reason": "no per-frame action trace was supplied",
        }
    else:
        action_records, action_trace = load_action_trace_evidence(
            action_trace_path,
            start_timestamp_ns=start_timestamp,
            end_timestamp_ns=end_timestamp,
        )
        if action_records:
            start_timestamp = max(
                start_timestamp,
                int(action_records[0]["timestamp_ns"]),
            )
            telemetry_window = tuple(
                frame
                for frame in telemetry_window
                if frame.timestamp_ns >= start_timestamp
            )
    frames = movement_frames(
        transcript_path,
        start_timestamp_ns=start_timestamp,
        end_timestamp_ns=end_timestamp,
    )
    packets, submissions = packet_emission_evidence(frames)
    samples = timed_absolute_samples(frames, submissions)
    physics = physics_rule_evidence(samples, geometry)
    alignment = telemetry_alignment_evidence(
        samples,
        telemetry_window,
        geometry.physics,
    )
    historical_decisions = (
        [
            (int(record["timestamp_ns"]), str(record["action"]))
            for record in action_records
        ]
        if action_records is not None
        else None
    )
    mirror = rl_policy_mirror_evidence(
        geometry,
        model_path,
        status,
        telemetry_window,
        samples,
        historical_decisions,
    )
    passed = bool(
        packets["all_plaintext_byte_exact"]
        and physics["pass"]
        and alignment["pass"]
        and mirror["pass"]
        and action_trace["pass"]
    )
    return {
        "schema_version": 2,
        "verdict": (
            "confirmed_with_historical_action_trace"
            if passed and action_trace["available"]
            else "confirmed_with_historical_action_trace_limit"
            if passed
            else "failed"
        ),
        "pass": passed,
        "map_id": geometry.map_id,
        "success_window": {
            "start_timestamp_ns": start_timestamp,
            "end_timestamp_ns": end_timestamp,
            "duration_seconds": (end_timestamp - start_timestamp) / 1_000_000_000,
            "telemetry_frames": len(telemetry_window),
        },
        "physics_rules": physics,
        "rl_policy_mirror": mirror,
        "action_trace": action_trace,
        "packet_emission": packets,
        "packet_telemetry_alignment": alignment,
        "provenance": {
            "geometry": "WZ map foothold and ladder/rope records",
            "rule_source": "/home/sdancer/ms2/docs/movement.hmtl",
            "live_evidence": str(transcript_path),
            "telemetry": str(telemetry_path),
            "model": str(model_path),
            "action_trace": (
                str(action_trace_path) if action_trace_path is not None else None
            ),
        },
    }

"""Client physics mapping for the Unity remake of MapleStory Classic.

The live IL2CPP names recovered from ``global-metadata.dat`` match the old
C++ client: ``VecCtrl``, ``VecCtrlUser``, ``VecCtrlMob``, ``PhysicalSpace2D``,
``StaticFoothold``, and ``LadderOrRope``. Per-frame dumps from those objects
are the source of truth. This module records the wire contract we already
proved and the state machine we are mapping against those dumps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import math
import re
from typing import Any, Iterable, Mapping


# Official CVecCtrl / WZ defaults. Treat these as hypotheses until a live
# VecCtrl dump confirms the Unity remake's stored units.
HYPOTHESIS_WALK_SPEED = 100
HYPOTHESIS_JUMP = 120
HYPOTHESIS_GRAVITY = 2000
HYPOTHESIS_FALL_SPEED = 670
HYPOTHESIS_TICK_MS = 30

IL2CPP_PHYSICS_TYPES = (
    ("Msc.Game.Object.Control", "VecCtrl"),
    ("Msc.Game.Object.Control", "VecCtrlUser"),
    ("Msc.Game.Object.Control", "VecCtrlMob"),
    ("Msc.Game.Object.Control", "VecCtrlNpc"),
    ("Msc.Game.Object.Control", "MovePath"),
    ("Msc.Game.Object.Control", "AttrFoothold"),
    ("Msc.Game.Object.Control.VecCtrl", "AbsPos"),
    ("Msc.Game.Object.Control.VecCtrl", "RelPos"),
    ("Msc.Game.Object.Control.VecCtrl", "FallDownData"),
    ("Msc.Game.Object.Control.VecCtrl", "ImpactNext"),
    ("Msc.Game.Object.Control.VecCtrlMob", "MoveCtx"),
    ("Msc.Game", "PhysicalSpace2D"),
    ("Msc.Game", "Foothold"),
    ("Msc.Data", "StaticFoothold"),
    ("Msc.Data", "LadderOrRope"),
    ("Msc.Game.Object", "UserLocal"),
    ("Msc.Game.Object", "Mob"),
    ("Msc.Game.Object", "MobPool"),
    ("Msc.Game.Object", "VecCtrlOwner"),
    ("Msc.Game.Object.UserLocal", "FallDownState"),
    ("Msc.Game.Object.Control.VecCtrlMob+MoveCtx", "WalkContext"),
    ("Msc.Game.Object.Control.VecCtrlMob+MoveCtx", "JumpContext"),
    ("Msc.Game.Object.Control.VecCtrlMob+MoveCtx", "StopContext"),
    ("Msc.Game.Object.Control.VecCtrlMob+MoveCtx", "FlyContext"),
)

PLAYER_MOVEMENT_CLIENT_OPCODE = 182
LIFE_MOVEMENT_CLIENT_OPCODE = 47
PLAYER_MOVEMENT_SERVER_OPCODE = 202
LIFE_MOVEMENT_SERVER_OPCODE = 217

# Wire command tags already exact-consumed on streams 92 and 126.
ABSOLUTE_COMMAND_TYPES = frozenset({0, 5})
RELATIVE_COMMAND_TYPES = frozenset({1})
POSITIONED_COMMAND_TYPES = frozenset({3, 4})
# Independent v83 names: 3 is jump-down start, 4 is a positioned teleport-like
# settle. Unity remake uses the same widths; live VecCtrl must confirm roles.
JUMP_DOWN_COMMAND_TYPE = 3
TELEPORT_LIKE_COMMAND_TYPE = 4


class PhysicsState(IntEnum):
    """High-level VecCtrl state. Numeric values are not yet wire-proven."""

    UNKNOWN = 0
    STAND = 1
    WALK = 2
    JUMP = 3
    FALL = 4
    PRONE = 5
    CLIMB = 6
    SIT = 7
    SWIM = 8
    FLY = 9
    KNOCKBACK = 10
    JUMP_DOWN = 11


@dataclass(frozen=True)
class MovementCommandContract:
    command_type: int
    kind: str
    payload_bytes: int
    fields: tuple[str, ...]
    physics_role: str


PLAYER_MOVEMENT_CONTRACT = (
    MovementCommandContract(
        command_type=0,
        kind="absolute",
        payload_bytes=13,
        fields=(
            "position_x",
            "position_y",
            "velocity_x",
            "velocity_y",
            "foothold_id",
            "stance",
            "duration_ms",
        ),
        physics_role="walk/stand/land settle: VecCtrl.AbsPos plus current foothold",
    ),
    MovementCommandContract(
        command_type=1,
        kind="relative",
        payload_bytes=7,
        fields=("velocity_x", "velocity_y", "stance", "duration_ms"),
        physics_role="air continuation: jump, fall, knockback without a foothold",
    ),
    MovementCommandContract(
        command_type=3,
        kind="positioned",
        payload_bytes=9,
        fields=("position_x", "position_y", "neutral_value", "stance", "duration_ms"),
        physics_role="jump-down / drop-through platform start (v83 type 3)",
    ),
    MovementCommandContract(
        command_type=4,
        kind="alternate_positioned",
        payload_bytes=9,
        fields=("position_x", "position_y", "neutral_value", "stance", "duration_ms"),
        physics_role="teleport-like or ladder attach/detach settle",
    ),
    MovementCommandContract(
        command_type=5,
        kind="alternate_absolute",
        payload_bytes=13,
        fields=(
            "position_x",
            "position_y",
            "velocity_x",
            "velocity_y",
            "foothold_id",
            "stance",
            "duration_ms",
        ),
        physics_role="absolute variant used for some climb/land transitions",
    ),
)


@dataclass
class PhysicsFrame:
    """One client-tick observation from the IL2CPP hook."""

    frame: int
    timestamp_ns: int
    player: dict[str, object] | None = None
    mobs: list[dict[str, object]] = field(default_factory=list)
    inputs: dict[str, object] | None = None
    x: float | None = None
    y: float | None = None
    velocity_x: float | None = None
    velocity_y: float | None = None


_NAME_PARTS = re.compile(r"[^a-z0-9]+")
_POSITION_WORDS = ("position", "pos", "abs", "absolute", "m_ap", "point")
_VELOCITY_WORDS = ("velocity", "vel", "speed", "relative", "rel")


def _numeric_leaves(
    value: object, path: tuple[str, ...] = ()
) -> Iterable[tuple[tuple[str, ...], float]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _numeric_leaves(child, (*path, str(key)))
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = float(value)
        if math.isfinite(numeric):
            yield path, numeric


def _path_tokens(path: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        token
        for part in path
        for token in _NAME_PARTS.split(part.lower())
        if token
    )


def _axis_score(path: tuple[str, ...], *, axis: str, velocity: bool) -> int:
    tokens = _path_tokens(path)
    if not tokens:
        return -1
    leaf = tokens[-1]
    joined = "_".join(tokens)
    other_axis = "y" if axis == "x" else "x"
    score = -1
    explicit_velocity = leaf in {f"v{axis}", f"d{axis}", f"{axis}v"}
    if leaf == axis:
        score = 40
    if explicit_velocity:
        score = 200 if velocity else -1
    if leaf in {f"m{axis}", f"m_{axis}"}:
        score = max(score, 45)
    if leaf.endswith(axis) and not leaf.endswith(other_axis):
        score = max(score, 20)
    words = _VELOCITY_WORDS if velocity else _POSITION_WORDS
    for index, word in enumerate(words):
        if word in joined:
            score += 80 - index * 5
            break
    opposing = _POSITION_WORDS if velocity else _VELOCITY_WORDS
    if any(word in joined for word in opposing) and not (
        velocity and explicit_velocity
    ):
        score -= 100
    # The legacy VecCtrl absolute-position member is conventionally m_ap.
    if not velocity and any(part.lower() in {"ap", "m_ap"} for part in path):
        score += 100
    return score


def _best_axis(
    leaves: Iterable[tuple[tuple[str, ...], float]], *, axis: str, velocity: bool
) -> tuple[float | None, str | None]:
    candidates = [
        (_axis_score(path, axis=axis, velocity=velocity), path, value)
        for path, value in leaves
    ]
    candidates = [item for item in candidates if item[0] >= 20]
    if not candidates:
        return None, None
    _, path, value = max(candidates, key=lambda item: (item[0], -len(item[1])))
    return value, ".".join(path)


class PhysicsFrameNormalizer:
    """Turn raw Frida fields into the prefab map coordinate system."""

    def __init__(self) -> None:
        self._previous: tuple[int, float, float] | None = None

    def normalize(self, record: Mapping[str, Any]) -> dict[str, Any]:
        normalized = dict(record)
        if record.get("type") != "frame":
            return normalized
        player = record.get("player")
        leaves = tuple(_numeric_leaves(player)) if isinstance(player, Mapping) else ()
        x, x_source = _best_axis(leaves, axis="x", velocity=False)
        y, y_source = _best_axis(leaves, axis="y", velocity=False)
        velocity_x, vx_source = _best_axis(leaves, axis="x", velocity=True)
        velocity_y, vy_source = _best_axis(leaves, axis="y", velocity=True)
        # VecCtrl's live Y axis points down while WZ prefab coordinates point up.
        # Normalize both position and velocity before deriving frame deltas so
        # telemetry, the map overlay, and navigation all share one coordinate
        # system.
        if y is not None:
            y = -y
            y_source = f"-{y_source}"
        if velocity_y is not None:
            velocity_y = -velocity_y
            vy_source = f"-{vy_source}"
        timestamp_ns = int(record.get("timestamp_ns") or 0)
        if x is not None and y is not None and self._previous is not None:
            previous_ns, previous_x, previous_y = self._previous
            elapsed = (timestamp_ns - previous_ns) / 1_000_000_000.0
            if elapsed > 0:
                if velocity_x is None:
                    velocity_x = (x - previous_x) / elapsed
                    vx_source = "derived.frame_delta"
                if velocity_y is None:
                    velocity_y = (y - previous_y) / elapsed
                    vy_source = "derived.frame_delta"
        if x is not None and y is not None:
            self._previous = timestamp_ns, x, y
        normalized.update(
            {
                "x": x,
                "y": y,
                "velocity_x": velocity_x,
                "velocity_y": velocity_y,
                "coordinate_sources": {
                    "x": x_source,
                    "y": y_source,
                    "velocity_x": vx_source,
                    "velocity_y": vy_source,
                },
            }
        )
        return normalized


def command_contract(command_type: int) -> MovementCommandContract:
    for item in PLAYER_MOVEMENT_CONTRACT:
        if item.command_type == command_type:
            return item
    raise KeyError(f"unmapped movement command type {command_type}")


def infer_state_from_command(
    *,
    command_type: int,
    foothold_id: int | None,
    velocity_y: int | None,
    stance: int | None,
) -> PhysicsState:
    """Best-effort packet-side state, not a VecCtrl enum dump."""

    if command_type == JUMP_DOWN_COMMAND_TYPE:
        return PhysicsState.JUMP_DOWN
    if command_type in RELATIVE_COMMAND_TYPES:
        if velocity_y is not None and velocity_y < 0:
            return PhysicsState.JUMP
        return PhysicsState.FALL
    if command_type in ABSOLUTE_COMMAND_TYPES:
        if foothold_id:
            if stance is not None and stance in {14, 15, 16, 17}:
                return PhysicsState.PRONE
            if velocity_y:
                return PhysicsState.WALK
            return PhysicsState.STAND
        return PhysicsState.FALL
    if command_type == TELEPORT_LIKE_COMMAND_TYPE:
        return PhysicsState.CLIMB
    return PhysicsState.UNKNOWN


def summarize_type_map(type_map: Mapping[str, object]) -> dict[str, object]:
    classes = type_map.get("classes")
    if not isinstance(classes, list):
        return {"class_count": 0, "resolved": []}
    resolved = []
    for item in classes:
        if not isinstance(item, dict):
            continue
        namespace = item.get("namespace")
        name = item.get("name")
        if isinstance(namespace, str) and isinstance(name, str):
            resolved.append(f"{namespace}.{name}")
    return {"class_count": len(resolved), "resolved": resolved}


def frames_from_records(records: Iterable[Mapping[str, object]]) -> list[PhysicsFrame]:
    frames: list[PhysicsFrame] = []
    for record in records:
        if record.get("type") != "frame":
            continue
        frames.append(
            PhysicsFrame(
                frame=int(record.get("frame") or 0),
                timestamp_ns=int(record.get("timestamp_ns") or 0),
                player=record.get("player") if isinstance(record.get("player"), dict) else None,
                mobs=list(record.get("mobs") or [])
                if isinstance(record.get("mobs"), list)
                else [],
                inputs=record.get("inputs")
                if isinstance(record.get("inputs"), dict)
                else None,
                x=float(record["x"]) if isinstance(record.get("x"), (int, float)) else None,
                y=float(record["y"]) if isinstance(record.get("y"), (int, float)) else None,
                velocity_x=float(record["velocity_x"])
                if isinstance(record.get("velocity_x"), (int, float))
                else None,
                velocity_y=float(record["velocity_y"])
                if isinstance(record.get("velocity_y"), (int, float))
                else None,
            )
        )
    return frames

"""Online linear-Q navigation model driven by Frida VecCtrl observations.

The prefab pathfinder supplies a short-horizon target and potential-based
reward; action selection and value updates remain an epsilon-greedy temporal
difference model.  Model weights persist across Wine processes and episodes.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import math
import os
from pathlib import Path
import random
import subprocess
import time
from typing import Any, Mapping

from .navigation import LocalPathfinder, LocalRouteStep, MapGeometry, Point


ACTIONS = (
    "idle",
    "left",
    "right",
    "jump",
    "left_jump",
    "right_jump",
    "up",
    "down_jump",
)
FEATURES = (
    "bias",
    "target_dx",
    "target_dy",
    "abs_dx",
    "abs_dy",
    "velocity_x",
    "velocity_y",
    "walk_step",
    "jump_step",
    "climb_step",
    "drop_step",
)


@dataclass(frozen=True)
class Observation:
    frame: int
    timestamp_ns: int
    x: float
    y: float
    velocity_x: float = 0.0
    velocity_y: float = 0.0

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> "Observation":
        if record.get("type") != "frame":
            raise ValueError("telemetry record is not a frame")
        if not isinstance(record.get("x"), (int, float)) or not isinstance(
            record.get("y"), (int, float)
        ):
            raise ValueError("telemetry frame has no normalized x/y")
        return cls(
            frame=int(record.get("frame") or 0),
            timestamp_ns=int(record.get("timestamp_ns") or 0),
            x=float(record["x"]),
            y=float(record["y"]),
            velocity_x=float(record.get("velocity_x") or 0.0),
            velocity_y=float(record.get("velocity_y") or 0.0),
        )


@dataclass
class LinearQModel:
    weights: dict[str, list[float]] = field(default_factory=dict)
    updates: int = 0
    alpha: float = 0.04
    gamma: float = 0.96

    def __post_init__(self) -> None:
        if not self.weights:
            self.weights = {action: [0.0] * len(FEATURES) for action in ACTIONS}
            # Useful priors make the first live episode exploratory but not random.
            self.weights["left"][1] = -1.0
            self.weights["right"][1] = 1.0
            self.weights["left_jump"][1] = -0.8
            self.weights["right_jump"][1] = 0.8
            for action in ("jump", "left_jump", "right_jump", "up"):
                self.weights[action][2] = -0.9
            self.weights["down_jump"][2] = 0.8
            self.weights["left_jump"][8] = 1.0
            self.weights["right_jump"][8] = 1.0
            self.weights["jump"][8] = 0.8
            self.weights["up"][9] = 1.4
            self.weights["down_jump"][10] = 1.4

    def q_values(self, features: tuple[float, ...]) -> dict[str, float]:
        return {
            action: sum(weight * value for weight, value in zip(weights, features))
            for action, weights in self.weights.items()
        }

    def select(
        self,
        features: tuple[float, ...],
        *,
        epsilon: float,
        candidates: tuple[str, ...] = ACTIONS,
    ) -> tuple[str, dict[str, float]]:
        values = self.q_values(features)
        if not candidates:
            raise ValueError("Q action candidates cannot be empty")
        if random.random() < epsilon:
            return random.choice(candidates), values
        action = max(
            candidates,
            key=lambda item: (values[item], -ACTIONS.index(item)),
        )
        return action, values

    def update(
        self,
        features: tuple[float, ...],
        action: str,
        reward: float,
        next_features: tuple[float, ...],
        *,
        terminal: bool = False,
    ) -> float:
        current = self.q_values(features)[action]
        future = 0.0 if terminal else max(self.q_values(next_features).values())
        error = reward + self.gamma * future - current
        weights = self.weights[action]
        for index, value in enumerate(features):
            weights[index] += self.alpha * error * value
            weights[index] = max(-50.0, min(50.0, weights[index]))
        self.updates += 1
        return error

    @classmethod
    def load(cls, path: str | Path) -> "LinearQModel":
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        if raw.get("schema_version") != 1 or raw.get("features") != list(FEATURES):
            raise ValueError(f"incompatible RL model: {path}")
        weights = {
            action: [float(value) for value in raw["weights"][action]]
            for action in ACTIONS
        }
        if any(len(values) != len(FEATURES) for values in weights.values()):
            raise ValueError(f"invalid RL model weight shape: {path}")
        return cls(
            weights=weights,
            updates=int(raw.get("updates") or 0),
            alpha=float(raw.get("alpha") or 0.04),
            gamma=float(raw.get("gamma") or 0.96),
        )

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        payload = {
            "schema_version": 1,
            "algorithm": "linear_q_learning",
            "features": list(FEATURES),
            "actions": list(ACTIONS),
            "alpha": self.alpha,
            "gamma": self.gamma,
            "updates": self.updates,
            "weights": self.weights,
        }
        _atomic_json(destination, payload)


def top_goal(geometry: MapGeometry) -> Point:
    walkable = [item for item in geometry.footholds if item.supports_actor]
    if not walkable:
        raise ValueError(f"map {geometry.map_id} has no walkable footholds")
    foothold = min(
        walkable,
        key=lambda item: (
            min(item.start.y, item.end.y),
            abs(item.start.x + item.end.x),
            item.foothold_id,
        ),
    )
    return Point(
        round((foothold.start.x + foothold.end.x) / 2),
        min(foothold.start.y, foothold.end.y),
    )


def route_target(
    pathfinder: LocalPathfinder, observation: Observation, goal: Point
) -> tuple[Point, str, tuple[LocalRouteStep, ...]]:
    route = pathfinder.route(
        Point(round(observation.x), round(observation.y)), goal
    )
    while (
        len(route) > 1
        and route[0].mode == "walk"
        and abs(route[0].end.x - observation.x) <= 48
    ):
        route = route[1:]
    if not route:
        return goal, "goal", route
    step = route[0]
    return step.end, step.mode, route


def route_action_candidates(
    observation: Observation,
    target: Point,
    mode: str,
    *,
    landing_x_range: tuple[int, int] | None = None,
) -> tuple[str, ...]:
    """Mask Q exploration to actions that can satisfy the prefab route step."""

    dx = target.x - observation.x
    dy = target.y - observation.y
    if mode == "jump" and landing_x_range is not None:
        minimum_x, maximum_x = landing_x_range
        if observation.x < minimum_x - 12:
            return ("right_jump",)
        if observation.x > maximum_x + 12:
            return ("left_jump",)
        return ("jump",)
    if mode == "climb":
        if abs(dx) <= 15 and abs(observation.velocity_x) <= 20:
            return ("up",)
        stopping_distance = max(30.0, abs(observation.velocity_x) * 0.4)
        moving_toward_target = dx * observation.velocity_x > 0
        if (abs(dx) <= 30 and abs(observation.velocity_x) > 20) or (
            moving_toward_target and abs(dx) <= stopping_distance
        ):
            return ("idle",)
        if dx > 0:
            return ("right",)
        return ("left",)
    if mode == "drop":
        if dx > 15:
            return ("right",)
        if dx < -15:
            return ("left",)
        return ("down_jump",)
    if dx > 2:
        return ("right",) if mode == "walk" else ("right", "right_jump")
    if dx < -2:
        return ("left",) if mode == "walk" else ("left", "left_jump")
    if mode == "jump" or dy < -24:
        return ("jump", "left_jump", "right_jump", "up")
    return ("idle", "jump")


def state_features(
    observation: Observation, target: Point, mode: str
) -> tuple[float, ...]:
    dx = max(-1.0, min(1.0, (target.x - observation.x) / 240.0))
    dy = max(-1.0, min(1.0, (target.y - observation.y) / 180.0))
    vx = max(-1.0, min(1.0, observation.velocity_x / 250.0))
    vy = max(-1.0, min(1.0, observation.velocity_y / 700.0))
    return (
        1.0,
        dx,
        dy,
        abs(dx),
        abs(dy),
        vx,
        vy,
        1.0 if mode == "walk" else 0.0,
        1.0 if mode == "jump" else 0.0,
        1.0 if mode == "climb" else 0.0,
        1.0 if mode == "drop" else 0.0,
    )


def potential(observation: Observation, target: Point, goal: Point) -> float:
    local_distance = math.hypot(target.x - observation.x, target.y - observation.y)
    height_progress = max(-4_000.0, min(4_000.0, observation.y - goal.y))
    return -0.02 * local_distance - 0.004 * height_progress


class XdotoolController:
    """Inject stateful movement keys into the focused Weston Xwayland surface."""

    _HELD_BY_ACTION = {
        "idle": frozenset(),
        "left": frozenset({"Left"}),
        "right": frozenset({"Right"}),
        "jump": frozenset(),
        "left_jump": frozenset({"Left"}),
        "right_jump": frozenset({"Right"}),
        "up": frozenset({"Up"}),
        "down_jump": frozenset({"Down"}),
    }

    def __init__(
        self, display: str, *, xauthority: str | None = None, dry_run: bool = False
    ) -> None:
        self.environment = os.environ | {"DISPLAY": display}
        if xauthority:
            self.environment["XAUTHORITY"] = xauthority
        else:
            self.environment.pop("XAUTHORITY", None)
        self.dry_run = dry_run
        self.held: set[str] = set()
        self.last_jump = 0.0

    def _run(self, *arguments: str) -> None:
        if self.dry_run:
            return
        result = subprocess.run(
            ["xdotool", *arguments],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=self.environment,
            text=True,
            timeout=2.0,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "xdotool input injection failed")

    def apply(self, action: str) -> None:
        wanted = set(self._HELD_BY_ACTION[action])
        if "jump" not in action:
            for key in sorted(self.held - wanted):
                self._run("keyup", key)
            for key in sorted(wanted - self.held):
                self._run("keydown", key)
            self.held = wanted
            return
        was_climbing = "Up" in self.held
        for key in sorted(self.held):
            self._run("keyup", key)
        self.held.clear()
        now = time.monotonic()
        if "jump" in action:
            if now - self.last_jump < 0.65:
                return
            direction = {
                "left_jump": "Left",
                "right_jump": "Right",
                "down_jump": "Down",
            }.get(action)
            if direction is None and was_climbing:
                direction = "Up"
            if direction is not None:
                self._run("keydown", direction)
            self._run("key", "Alt_L")
            if direction is not None:
                self._run("keyup", direction)
            self.last_jump = now
            return

    def release(self) -> None:
        for key in sorted(self.held):
            try:
                self._run("keyup", key)
            except RuntimeError:
                pass
        self.held.clear()


class NavigationAgent:
    def __init__(
        self,
        geometry: MapGeometry,
        model: LinearQModel,
        controller: XdotoolController,
        *,
        epsilon: float = 0.08,
    ) -> None:
        self.geometry = geometry
        live_physics = replace(
            geometry.physics,
            max_jump_rise=min(geometry.physics.max_jump_rise, 45),
        )
        self.pathfinder = LocalPathfinder(replace(geometry, physics=live_physics))
        self.footholds_by_id = {
            foothold.foothold_id: foothold for foothold in geometry.footholds
        }
        self.goal = top_goal(geometry)
        self.max_prefab_y = max(
            max(foothold.start.y, foothold.end.y)
            for foothold in geometry.footholds
            if foothold.supports_actor
        )
        self.min_prefab_x = min(
            min(foothold.start.x, foothold.end.x)
            for foothold in geometry.footholds
            if foothold.supports_actor
        )
        self.max_prefab_x = max(
            max(foothold.start.x, foothold.end.x)
            for foothold in geometry.footholds
            if foothold.supports_actor
        )
        self.entry_recovery_direction = "left"
        self.entry_stall_frames = 0
        self.walk_stall_frames = 0
        self.climb_stall_frames = 0
        self.climb_alignment_stall_frames = 0
        self.active_climb_target: Point | None = None
        self.climb_settle_frames = 0
        self.climb_idle_frames = 0
        self.model = model
        self.controller = controller
        self.epsilon = epsilon
        self.previous: tuple[Observation, tuple[float, ...], str, float] | None = None
        self.episode = 1
        self.best_y = math.inf

    def step(self, observation: Observation) -> dict[str, Any]:
        target, mode, route = route_target(self.pathfinder, observation, self.goal)
        if self.active_climb_target is not None:
            if observation.y <= self.active_climb_target.y + 24:
                self.active_climb_target = None
                self.climb_settle_frames = 12
            else:
                target = self.active_climb_target
                mode = "climb"
        elif mode == "climb" and target.y < observation.y:
            self.active_climb_target = target
        features = state_features(observation, target, mode)
        entry_recovery = observation.y > self.max_prefab_y + 200
        entry_recovery_stalled = False
        if entry_recovery:
            if self.previous is not None and abs(
                observation.x - self.previous[0].x
            ) < 0.5:
                self.entry_stall_frames += 1
            else:
                self.entry_stall_frames = 0
            if observation.x <= self.min_prefab_x + 40:
                self.entry_recovery_direction = "right"
                self.entry_stall_frames = 0
            elif observation.x >= self.max_prefab_x - 40:
                self.entry_recovery_direction = "left"
                self.entry_stall_frames = 0
            elif self.entry_stall_frames >= 8:
                self.entry_recovery_direction = (
                    "right"
                    if self.entry_recovery_direction == "left"
                    else "left"
                )
                self.entry_stall_frames = 0
                entry_recovery_stalled = True
            recovery_action = self.entry_recovery_direction
            if entry_recovery_stalled or observation.frame % 3 == 0:
                recovery_action += "_jump"
            action_candidates = (recovery_action,)
        else:
            self.entry_stall_frames = 0
            landing_x_range = None
            if route and mode == "jump":
                foothold = self.footholds_by_id.get(route[0].target_foothold_id)
                if foothold is not None:
                    landing_x_range = (
                        min(foothold.start.x, foothold.end.x),
                        max(foothold.start.x, foothold.end.x),
                    )
            action_candidates = route_action_candidates(
                observation,
                target,
                mode,
                landing_x_range=landing_x_range,
            )
        walk_recovery = False
        if (
            not entry_recovery
            and mode == "walk"
            and abs(target.x - observation.x) > 2
        ):
            if self.previous is not None and abs(
                observation.x - self.previous[0].x
            ) < 0.5:
                self.walk_stall_frames += 1
            else:
                self.walk_stall_frames = 0
            if self.walk_stall_frames >= 8:
                direction = "right" if target.x > observation.x else "left"
                action_candidates = (f"{direction}_jump",)
                self.walk_stall_frames = 0
                walk_recovery = True
        else:
            self.walk_stall_frames = 0
        climb_alignment_recovery = False
        if (
            not entry_recovery
            and mode == "climb"
            and abs(target.x - observation.x) > 15
        ):
            if self.previous is not None and abs(
                observation.x - self.previous[0].x
            ) < 0.5:
                self.climb_alignment_stall_frames += 1
            else:
                self.climb_alignment_stall_frames = 0
            if self.climb_alignment_stall_frames >= 8:
                direction = "right" if target.x > observation.x else "left"
                action_candidates = (f"{direction}_jump",)
                self.climb_alignment_stall_frames = 0
                climb_alignment_recovery = True
        else:
            self.climb_alignment_stall_frames = 0
        climb_recovery = False
        if (
            not entry_recovery
            and mode == "climb"
            and target.y < observation.y - 12
            and abs(target.x - observation.x) <= 15
        ):
            if self.previous is not None and abs(
                observation.y - self.previous[0].y
            ) < 0.5:
                self.climb_stall_frames += 1
            else:
                self.climb_stall_frames = 0
            if self.climb_stall_frames >= 8:
                action_candidates = ("jump",)
                self.climb_stall_frames = 0
                climb_recovery = True
        else:
            self.climb_stall_frames = 0
        climb_settling = self.climb_settle_frames > 0
        climb_idle = not climb_settling and self.climb_idle_frames > 0
        if climb_settling:
            action_candidates = ("up",)
            self.climb_settle_frames -= 1
            if self.climb_settle_frames == 0:
                self.climb_idle_frames = 4
        elif climb_idle:
            action_candidates = ("idle",)
            self.climb_idle_frames -= 1
        current_potential = potential(observation, target, self.goal)
        reached = observation.y <= self.goal.y + 24
        reward = 0.0
        td_error = 0.0
        if self.previous is not None:
            previous_observation, previous_features, previous_action, previous_potential = self.previous
            reward = current_potential - previous_potential - 0.01
            reward += max(-2.0, min(2.0, (previous_observation.y - observation.y) * 0.02))
            if reached:
                reward += 25.0
            td_error = self.model.update(
                previous_features,
                previous_action,
                reward,
                features,
                terminal=reached,
            )
        action, q_values = self.model.select(
            features,
            epsilon=self.epsilon,
            candidates=action_candidates,
        )
        if reached:
            action = "idle"
        self.controller.apply(action)
        self.previous = (observation, features, action, current_potential)
        self.best_y = min(self.best_y, observation.y)
        if reached:
            self.episode += 1
            self.previous = None
        return {
            "schema_version": 1,
            "algorithm": "linear_q_learning",
            "map_id": self.geometry.map_id,
            "frame": observation.frame,
            "timestamp_ns": observation.timestamp_ns,
            "episode": self.episode,
            "model_updates": self.model.updates,
            "epsilon": self.epsilon,
            "action": action,
            "action_candidates": action_candidates,
            "entry_recovery": entry_recovery,
            "entry_recovery_direction": self.entry_recovery_direction,
            "entry_recovery_stalled": entry_recovery_stalled,
            "walk_recovery": walk_recovery,
            "climb_recovery": climb_recovery,
            "climb_alignment_recovery": climb_alignment_recovery,
            "climb_settling": climb_settling,
            "climb_idle": climb_idle,
            "reward": reward,
            "td_error": td_error,
            "position": {"x": observation.x, "y": observation.y},
            "velocity": {
                "x": observation.velocity_x,
                "y": observation.velocity_y,
            },
            "goal": {"x": self.goal.x, "y": self.goal.y, "reached": reached},
            "target": {"x": target.x, "y": target.y, "mode": mode},
            "route_steps": len(route),
            "best_y": self.best_y,
            "q_values": q_values,
        }


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, separators=(",", ":"), sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def write_agent_status(path: str | Path, payload: Mapping[str, Any]) -> None:
    _atomic_json(Path(path), payload)


def append_agent_trace(path: str | Path, payload: Mapping[str, Any]) -> None:
    """Append one complete decision record for later action-exact replay."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(payload, output, separators=(",", ":"), sort_keys=True)
        output.write("\n")

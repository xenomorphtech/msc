"""Deterministic VecCtrl movement rules over WZ/prefab map geometry.

Maple coordinates use +x right and +y down.  These rules deliberately model
the stable movement envelope rather than client render state: footholds are
line segments, ladders/ropes are vertical segments, and air motion is a
ballistic integration with a terminal fall speed.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from .navigation import Foothold, LadderRope, MapGeometry, Physics, Point


@dataclass(frozen=True)
class PhysicsControl:
    """One logical controller input for a physics timestep."""

    horizontal: int = 0
    jump: bool = False
    climb: int = 0
    drop: bool = False

    def __post_init__(self) -> None:
        if self.horizontal not in {-1, 0, 1}:
            raise ValueError("horizontal control must be -1, 0, or 1")
        if self.climb not in {-1, 0, 1}:
            raise ValueError("climb control must be -1, 0, or 1")
        if self.jump and self.drop:
            raise ValueError("jump and drop cannot be requested together")

    @classmethod
    def from_action(cls, action: str) -> "PhysicsControl":
        controls = {
            "idle": cls(),
            "left": cls(horizontal=-1),
            "right": cls(horizontal=1),
            "jump": cls(jump=True),
            "left_jump": cls(horizontal=-1, jump=True),
            "right_jump": cls(horizontal=1, jump=True),
            "up": cls(climb=-1),
            "down_jump": cls(climb=1, drop=True),
        }
        try:
            return controls[action]
        except KeyError as error:
            raise ValueError(f"unsupported physics action {action!r}") from error


@dataclass(frozen=True)
class MotionState:
    """A normalized physics state at a timestep boundary."""

    x: float
    y: float
    velocity_x: float = 0.0
    velocity_y: float = 0.0
    foothold_id: int | None = None
    ladder_id: int | None = None

    @property
    def mode(self) -> str:
        if self.ladder_id is not None:
            return "climb"
        if self.foothold_id is not None:
            return "ground"
        return "air"


def _move_toward(value: float, target: float, maximum_delta: float) -> float:
    if value < target:
        return min(target, value + maximum_delta)
    return max(target, value - maximum_delta)


def _segment_intersection_fraction(
    start_x: float,
    start_y: float,
    end_x: float,
    end_y: float,
    foothold: Foothold,
) -> float | None:
    """Return the motion-segment fraction that intersects a foothold."""

    motion_x = end_x - start_x
    motion_y = end_y - start_y
    surface_x = foothold.end.x - foothold.start.x
    surface_y = foothold.end.y - foothold.start.y
    denominator = motion_x * surface_y - motion_y * surface_x
    if abs(denominator) < 1e-9:
        return None
    offset_x = foothold.start.x - start_x
    offset_y = foothold.start.y - start_y
    motion_fraction = (offset_x * surface_y - offset_y * surface_x) / denominator
    surface_fraction = (offset_x * motion_y - offset_y * motion_x) / denominator
    if (
        -1e-9 <= motion_fraction <= 1.0 + 1e-9
        and -1e-9 <= surface_fraction <= 1.0 + 1e-9
    ):
        return min(1.0, max(0.0, motion_fraction))
    return None


class PrefabPhysicsModel:
    """Step the deterministic movement envelope against prefab geometry."""

    def __init__(self, geometry: MapGeometry):
        self.geometry = geometry
        self.physics = geometry.physics
        self.footholds = {
            foothold.foothold_id: foothold
            for foothold in geometry.footholds
            if foothold.supports_actor
        }
        self.ladders = {
            ladder.ladder_id: ladder for ladder in geometry.ladder_ropes
        }

    def grounded_state(
        self, foothold_id: int, x: float, *, velocity_x: float = 0.0
    ) -> MotionState:
        foothold = self.footholds[foothold_id]
        y = foothold.y_at(round(x))
        if y is None:
            raise ValueError(f"x={x} is outside foothold {foothold_id}")
        return MotionState(x, y, velocity_x=velocity_x, foothold_id=foothold_id)

    def step(
        self,
        state: MotionState,
        control: PhysicsControl,
        *,
        duration_ms: int | None = None,
    ) -> MotionState:
        milliseconds = self.physics.timestep_ms if duration_ms is None else duration_ms
        if milliseconds <= 0:
            raise ValueError("physics duration must be positive")
        dt = milliseconds / 1_000.0
        if state.ladder_id is not None:
            return self._step_ladder(state, control, dt)
        if state.foothold_id is not None:
            return self._step_ground(state, control, dt)
        attached = self._attach_ladder(state, control)
        if attached is not None:
            return self._step_ladder(attached, control, dt)
        return self._step_air(state, control, dt)

    def _horizontal_velocity(
        self, velocity: float, horizontal: int, dt: float
    ) -> float:
        if horizontal:
            target = horizontal * self.physics.walk_speed
            return _move_toward(
                velocity,
                target,
                self.physics.run_acceleration * dt,
            )
        return _move_toward(
            velocity,
            0.0,
            self.physics.ground_release_deceleration * dt,
        )

    def _step_ground(
        self, state: MotionState, control: PhysicsControl, dt: float
    ) -> MotionState:
        foothold = self.footholds.get(state.foothold_id)
        if foothold is None:
            return self._step_air(
                MotionState(state.x, state.y, state.velocity_x, state.velocity_y),
                control,
                dt,
            )
        attached = self._attach_ladder(state, control)
        if attached is not None and not control.drop:
            return self._step_ladder(attached, control, dt)
        if control.drop and not foothold.forbid_fall_down:
            return MotionState(
                state.x,
                state.y + 1.0,
                state.velocity_x,
                0.0,
            )
        next_velocity_x = self._horizontal_velocity(
            state.velocity_x, control.horizontal, dt
        )
        if control.jump:
            return MotionState(
                state.x + 0.5 * (state.velocity_x + next_velocity_x) * dt,
                state.y - self.physics.jump_speed * dt
                + 0.5 * self.physics.gravity * dt * dt,
                next_velocity_x,
                min(
                    self.physics.terminal_fall_speed,
                    -self.physics.jump_speed + self.physics.gravity * dt,
                ),
            )
        next_x = state.x + 0.5 * (state.velocity_x + next_velocity_x) * dt
        support = self._support_at(next_x, state.y, preferred=foothold)
        if support is None:
            return MotionState(next_x, state.y, next_velocity_x, 0.0)
        support_y, next_foothold = support
        return MotionState(
            next_x,
            support_y,
            next_velocity_x,
            0.0,
            foothold_id=next_foothold.foothold_id,
        )

    def _step_air(
        self, state: MotionState, control: PhysicsControl, dt: float
    ) -> MotionState:
        # VecCtrl preserves horizontal jump momentum.  Directional input can
        # accelerate toward the ordinary walk cap; release does not apply the
        # ground-only braking force while airborne.
        next_velocity_x = state.velocity_x
        if control.horizontal:
            next_velocity_x = _move_toward(
                state.velocity_x,
                control.horizontal * self.physics.walk_speed,
                self.physics.run_acceleration * dt,
            )
        next_velocity_y = min(
            self.physics.terminal_fall_speed,
            state.velocity_y + self.physics.gravity * dt,
        )
        next_x = state.x + 0.5 * (state.velocity_x + next_velocity_x) * dt
        next_y = state.y + 0.5 * (state.velocity_y + next_velocity_y) * dt
        if next_velocity_y < 0:
            return MotionState(
                next_x,
                next_y,
                next_velocity_x,
                next_velocity_y,
            )
        landing = self._first_landing(state.x, state.y, next_x, next_y)
        if landing is None:
            return MotionState(
                next_x,
                next_y,
                next_velocity_x,
                next_velocity_y,
            )
        fraction, foothold = landing
        landed_x = state.x + (next_x - state.x) * fraction
        landed_y = foothold.y_at(round(landed_x))
        if landed_y is None:
            landed_y = state.y + (next_y - state.y) * fraction
        return MotionState(
            landed_x,
            landed_y,
            next_velocity_x,
            0.0,
            foothold_id=foothold.foothold_id,
        )

    def _step_ladder(
        self, state: MotionState, control: PhysicsControl, dt: float
    ) -> MotionState:
        ladder = self.ladders.get(state.ladder_id)
        if ladder is None:
            return MotionState(state.x, state.y)
        if control.jump or control.horizontal:
            velocity_x = control.horizontal * self.physics.walk_speed
            velocity_y = -self.physics.jump_speed if control.jump else 0.0
            return MotionState(
                float(ladder.x),
                state.y,
                velocity_x,
                velocity_y,
            )
        velocity_y = control.climb * self.physics.climb_speed
        next_y = state.y + velocity_y * dt
        if next_y <= ladder.top.y and control.climb < 0:
            support = self._support_at(float(ladder.x), float(ladder.top.y))
            if support is not None:
                support_y, foothold = support
                return MotionState(
                    float(ladder.x),
                    support_y,
                    foothold_id=foothold.foothold_id,
                )
            next_y = float(ladder.top.y)
        elif next_y >= ladder.bottom.y and control.climb > 0:
            next_y = float(ladder.bottom.y)
        return MotionState(
            float(ladder.x),
            next_y,
            0.0,
            velocity_y,
            ladder_id=ladder.ladder_id,
        )

    def _attach_ladder(
        self, state: MotionState, control: PhysicsControl
    ) -> MotionState | None:
        if control.climb == 0:
            return None
        candidates: list[tuple[float, LadderRope]] = []
        for ladder in self.ladders.values():
            if not ladder.top.y - 20 <= state.y <= ladder.bottom.y + 20:
                continue
            distance = abs(state.x - ladder.x)
            if distance <= 15:
                candidates.append((distance, ladder))
        if not candidates:
            return None
        _, ladder = min(candidates, key=lambda item: (item[0], item[1].ladder_id))
        y = min(float(ladder.bottom.y), max(float(ladder.top.y), state.y))
        return MotionState(float(ladder.x), y, ladder_id=ladder.ladder_id)

    def _support_at(
        self,
        x: float,
        expected_y: float,
        *,
        preferred: Foothold | None = None,
    ) -> tuple[float, Foothold] | None:
        ordered = (
            (preferred,) + tuple(self.footholds.values())
            if preferred is not None
            else tuple(self.footholds.values())
        )
        candidates: list[tuple[float, float, Foothold]] = []
        seen: set[int] = set()
        for foothold in ordered:
            if foothold.foothold_id in seen:
                continue
            seen.add(foothold.foothold_id)
            y = foothold.y_at(round(x))
            if y is None or abs(y - expected_y) > 24:
                continue
            preference = 0.0 if foothold is preferred else 1.0
            candidates.append((preference, abs(y - expected_y), foothold))
        if not candidates:
            return None
        _, _, foothold = min(
            candidates,
            key=lambda item: (item[0], item[1], item[2].foothold_id),
        )
        y = foothold.y_at(round(x))
        assert y is not None
        return y, foothold

    def _first_landing(
        self,
        start_x: float,
        start_y: float,
        end_x: float,
        end_y: float,
    ) -> tuple[float, Foothold] | None:
        candidates: list[tuple[float, Foothold]] = []
        for foothold in self.footholds.values():
            fraction = _segment_intersection_fraction(
                start_x,
                start_y,
                end_x,
                end_y,
                foothold,
            )
            if fraction is not None and fraction > 1e-7:
                candidates.append((fraction, foothold))
        if not candidates:
            return None
        return min(candidates, key=lambda item: (item[0], item[1].foothold_id))


def ballistic_position(
    start: Point,
    velocity_x: float,
    elapsed_seconds: float,
    physics: Physics,
) -> tuple[float, float, float]:
    """Return x, y, and vy for an unclipped jump from ``start``."""

    if elapsed_seconds < 0 or not math.isfinite(elapsed_seconds):
        raise ValueError("elapsed time must be finite and non-negative")
    terminal_time = (physics.terminal_fall_speed + physics.jump_speed) / physics.gravity
    if elapsed_seconds <= terminal_time:
        velocity_y = -physics.jump_speed + physics.gravity * elapsed_seconds
        displacement_y = (
            -physics.jump_speed * elapsed_seconds
            + 0.5 * physics.gravity * elapsed_seconds * elapsed_seconds
        )
    else:
        displacement_to_terminal = (
            -physics.jump_speed * terminal_time
            + 0.5 * physics.gravity * terminal_time * terminal_time
        )
        displacement_y = displacement_to_terminal + physics.terminal_fall_speed * (
            elapsed_seconds - terminal_time
        )
        velocity_y = physics.terminal_fall_speed
    return (
        start.x + velocity_x * elapsed_seconds,
        start.y + displacement_y,
        velocity_y,
    )

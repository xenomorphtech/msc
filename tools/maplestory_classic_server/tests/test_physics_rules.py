from __future__ import annotations

from pathlib import Path
import tempfile
import unittest


from maple_server.movement_verification import (
    TimedMovementSample,
    load_action_trace_evidence,
    physics_rule_evidence,
    rebuild_movement_submission,
    telemetry_alignment_evidence,
)
from maple_server.navigation import (
    Foothold,
    LadderRope,
    MapGeometry,
    Physics,
    Point,
)
from maple_server.packets import (
    LifeMovementCommand,
    LifeMovementPath,
    LifeMovementSubmission,
)
from maple_server.physics_rules import (
    MotionState,
    PhysicsControl,
    PrefabPhysicsModel,
    ballistic_position,
)
from maple_server.rl_navigation import Observation, append_agent_trace


def fixture_geometry(*, forbid_fall_down: bool = False) -> MapGeometry:
    return MapGeometry(
        map_id=1,
        footholds=(
            Foothold(
                foothold_id=10,
                layer=0,
                group=0,
                start=Point(-100, 0),
                end=Point(100, 0),
                forbid_fall_down=forbid_fall_down,
            ),
            Foothold(
                foothold_id=11,
                layer=0,
                group=0,
                start=Point(-100, 100),
                end=Point(100, 100),
            ),
        ),
        ladder_ropes=(
            LadderRope(
                ladder_id=20,
                x=0,
                y1=-40,
                y2=100,
                is_ladder=True,
            ),
        ),
        portals=(),
    )


class PrefabPhysicsModelTest(unittest.TestCase):
    def test_default_parameters_match_movement_source(self) -> None:
        physics = Physics()
        self.assertEqual(physics.timestep_ms, 30)
        self.assertEqual(physics.run_acceleration, 1_400.0)
        self.assertEqual(physics.ground_release_deceleration, 800.0)
        self.assertEqual(physics.walk_speed, 125.0)
        self.assertEqual(physics.jump_speed, 555.0)
        self.assertEqual(physics.gravity, 2_000.0)
        self.assertEqual(physics.terminal_fall_speed, 670.0)
        self.assertEqual(physics.climb_speed, 60.0)

    def test_ground_acceleration_release_and_jump(self) -> None:
        model = PrefabPhysicsModel(fixture_geometry())
        start = model.grounded_state(10, -50)
        running = model.step(start, PhysicsControl(horizontal=1))
        self.assertAlmostEqual(running.velocity_x, 42.0)
        self.assertAlmostEqual(running.x, -49.37)
        released = model.step(running, PhysicsControl())
        self.assertAlmostEqual(released.velocity_x, 18.0)
        jumping = model.step(released, PhysicsControl(jump=True))
        self.assertEqual(jumping.mode, "air")
        self.assertAlmostEqual(jumping.velocity_y, -495.0)
        self.assertAlmostEqual(jumping.y, -15.75)

    def test_air_gravity_terminal_velocity_and_landing(self) -> None:
        model = PrefabPhysicsModel(fixture_geometry())
        falling = MotionState(50.0, -10.0, velocity_y=100.0)
        landed = model.step(falling, PhysicsControl(), duration_ms=100)
        self.assertEqual(landed.foothold_id, 10)
        self.assertEqual(landed.y, 0.0)
        terminal = model.step(
            MotionState(150.0, 0.0, velocity_y=660.0),
            PhysicsControl(),
        )
        self.assertEqual(terminal.velocity_y, 670.0)

    def test_ladder_attach_climb_and_drop_guard(self) -> None:
        model = PrefabPhysicsModel(fixture_geometry(forbid_fall_down=True))
        start = model.grounded_state(10, 0)
        attached = model.step(start, PhysicsControl(climb=-1))
        self.assertEqual(attached.ladder_id, 20)
        self.assertAlmostEqual(attached.velocity_y, -60.0)
        self.assertAlmostEqual(attached.y, -1.8)
        guarded = model.step(start, PhysicsControl(climb=1, drop=True))
        self.assertEqual(guarded.foothold_id, 10)

    def test_ballistic_equation_uses_down_positive_coordinates(self) -> None:
        x, y, velocity_y = ballistic_position(Point(0, 0), 125.0, 0.15, Physics())
        self.assertAlmostEqual(x, 18.75)
        self.assertAlmostEqual(y, -60.75)
        self.assertAlmostEqual(velocity_y, -255.0)


class MovementEmissionTest(unittest.TestCase):
    def test_typed_submission_rebuild_is_byte_exact(self) -> None:
        submission = LifeMovementSubmission(
            local_object_index=3,
            client_token=123,
            control_value=456,
            movement=LifeMovementPath(
                reference_x=-10,
                reference_y=20,
                commands=(
                    LifeMovementCommand.absolute(
                        position_x=-5,
                        position_y=10,
                        last_x=42,
                        last_y=-495,
                        foothold_id=0,
                        stance=6,
                        duration_ms=30,
                    ),
                    LifeMovementCommand.relative(
                        delta_x=42,
                        delta_y=-495,
                        stance=6,
                        duration_ms=30,
                    ),
                ),
            ),
            tail_type=17,
            tail_state_values=(0,) * 8,
            tail_marker=0,
            path_start_x=-10,
            path_start_y=20,
            path_end_x=-5,
            path_end_y=10,
        )
        encoded = submission.to_bytes()
        parsed = LifeMovementSubmission.parse(encoded)
        self.assertEqual(rebuild_movement_submission(parsed).to_bytes(), encoded)

    def test_action_trace_appends_complete_json_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actions.jsonl"
            append_agent_trace(path, {"frame": 1, "action": "right"})
            append_agent_trace(path, {"frame": 2, "action": "jump"})
            self.assertEqual(
                path.read_text(encoding="utf-8").splitlines(),
                [
                    '{"action":"right","frame":1}',
                    '{"action":"jump","frame":2}',
                ],
            )

    def test_action_trace_evidence_covers_first_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "actions.jsonl"
            for frame, action, reached in (
                (10, "left", False),
                (11, "jump", False),
                (12, "idle", True),
                (13, "idle", True),
            ):
                append_agent_trace(
                    path,
                    {
                        "frame": frame,
                        "timestamp_ns": frame * 100,
                        "model_updates": 90 + frame,
                        "action": action,
                        "goal": {"reached": reached},
                    },
                )
            records, report = load_action_trace_evidence(
                path,
                start_timestamp_ns=1_000,
                end_timestamp_ns=1_200,
            )
            self.assertEqual(len(records), 3)
            self.assertEqual(report["learning_transitions"], 2)
            self.assertEqual(
                report["action_counts"], {"idle": 1, "jump": 1, "left": 1}
            )
            self.assertTrue(report["complete_to_first_success"])
            self.assertTrue(report["pass"])

    def test_physics_evidence_excludes_quantized_apex_split(self) -> None:
        samples = (
            TimedMovementSample(0, 0, 0, 0, 0, 0, 10, 0),
            TimedMovementSample(30, 0, 0, -1, 0, -495, 0, 30),
            TimedMovementSample(270, 0, 0, -2, 0, -15, 0, 240),
            TimedMovementSample(280, 0, 0, -2, 0, 0, 0, 10),
            TimedMovementSample(310, 0, 0, -1, 0, 60, 0, 30),
            TimedMovementSample(615, 0, 0, 0, 0, 670, 0, 305),
        )
        report = physics_rule_evidence(samples, fixture_geometry())
        self.assertEqual(report["gravity"]["apex_transitions_excluded"], 1)
        self.assertEqual(report["gravity"]["exact"], 2)
        self.assertTrue(report["pass"])

    def test_telemetry_alignment_uses_motion_envelope(self) -> None:
        sample = TimedMovementSample(1_000, 0, 0, 0, 125, 0, 10, 30)
        telemetry = (Observation(1, 51_000_000, 6.0, 0.0, 125.0, 0.0),)
        report = telemetry_alignment_evidence(
            (sample,),
            telemetry,
            fixture_geometry().physics,
        )
        self.assertEqual(report["median_absolute_position_error"]["x"], 6.0)
        self.assertTrue(report["pass"])


if __name__ == "__main__":
    unittest.main()

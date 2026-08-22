from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SERVER_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SERVER_ROOT.parents[1]
PLAINTEXT_JSONL = (
    PROJECT_ROOT / "tools/il2cpp_packet_dump/target/private/111.streams-83-92-114.jsonl"
)
LAUNCHER = SERVER_ROOT / "tools/run_physics_lab.py"


def load_launcher():
    spec = importlib.util.spec_from_file_location("run_physics_lab", LAUNCHER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PhysicsSourceTest(unittest.TestCase):
    def test_stream_114_round_trips_through_synthetic_transcript(self) -> None:
        if not PLAINTEXT_JSONL.is_file():
            self.skipTest("private plaintext JSONL is not present")
        from maple_server.gamestate import decode_transcript
        from maple_server.plaintext_source import (
            interleave_world_bootstrap,
            load_plaintext_packets,
            transcript_from_plaintext_jsonl,
        )

        packets = interleave_world_bootstrap(
            load_plaintext_packets(PLAINTEXT_JSONL, tcp_stream=114)
        )
        transcript = transcript_from_plaintext_jsonl(PLAINTEXT_JSONL, tcp_stream=114)
        decoded = decode_transcript(transcript)
        self.assertEqual(decoded.handshake.version, 300)
        self.assertEqual(len(decoded.frames), len(packets))
        self.assertEqual(packets[0].opcode, 8)
        self.assertEqual(
            [frame.plaintext for frame in decoded.frames],
            [packet.payload for packet in packets],
        )

    def test_stream_114_gameplay_fold_is_valid(self) -> None:
        if not PLAINTEXT_JSONL.is_file():
            self.skipTest("private plaintext JSONL is not present")
        from maple_server.gameplay import analyze_gameplay_transcript
        from maple_server.plaintext_source import transcript_from_plaintext_jsonl

        analysis = analyze_gameplay_transcript(
            transcript_from_plaintext_jsonl(PLAINTEXT_JSONL, tcp_stream=114)
        )
        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.map_id, 101000000)
        self.assertGreaterEqual(analysis.state.initial_field_snapshots, 1)
        self.assertIn(
            analysis.state.phase.value,
            {"active", "exit_requested", "terminated"},
        )


class PhysicsContractTest(unittest.TestCase):
    def test_absolute_and_jump_down_roles(self) -> None:
        from maple_server.physics import (
            JUMP_DOWN_COMMAND_TYPE,
            PhysicsState,
            command_contract,
            infer_state_from_command,
        )

        absolute = command_contract(0)
        self.assertEqual(absolute.payload_bytes, 13)
        self.assertIn("foothold_id", absolute.fields)
        self.assertEqual(
            infer_state_from_command(
                command_type=JUMP_DOWN_COMMAND_TYPE,
                foothold_id=None,
                velocity_y=None,
                stance=None,
            ),
            PhysicsState.JUMP_DOWN,
        )
        self.assertEqual(
            infer_state_from_command(
                command_type=1,
                foothold_id=None,
                velocity_y=-120,
                stance=6,
            ),
            PhysicsState.JUMP,
        )

    def test_normalizes_nested_frida_position_and_derives_velocity(self) -> None:
        from maple_server.physics import PhysicsFrameNormalizer

        normalizer = PhysicsFrameNormalizer()
        first = normalizer.normalize(
            {
                "type": "frame",
                "frame": 1,
                "timestamp_ns": 1_000_000_000,
                "player": {"fields": {"m_ap": {"x": 100, "y": 200}}},
            }
        )
        second = normalizer.normalize(
            {
                "type": "frame",
                "frame": 2,
                "timestamp_ns": 1_100_000_000,
                "player": {"fields": {"m_ap": {"x": 105, "y": 197}}},
            }
        )
        self.assertEqual((first["x"], first["y"]), (100.0, -200.0))
        self.assertAlmostEqual(second["velocity_x"], 50.0)
        self.assertAlmostEqual(second["velocity_y"], 30.0)
        self.assertEqual(second["coordinate_sources"]["y"], "-fields.m_ap.y")
        self.assertEqual(
            second["coordinate_sources"]["velocity_x"], "derived.frame_delta"
        )

    def test_linear_q_model_round_trips(self) -> None:
        from maple_server.rl_navigation import FEATURES, LinearQModel

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.json"
            model = LinearQModel()
            features = (1.0,) + (0.0,) * (len(FEATURES) - 1)
            error = model.update(features, "jump", 2.0, features)
            self.assertGreater(error, 0.0)
            model.save(path)
            loaded = LinearQModel.load(path)
            self.assertEqual(loaded.updates, 1)
            self.assertEqual(loaded.weights, model.weights)

    def test_route_target_advances_past_nearly_complete_walk(self) -> None:
        from maple_server.navigation import LocalRouteStep, Point
        from maple_server.rl_navigation import (
            Observation,
            route_action_candidates,
            route_target,
        )

        route = (
            LocalRouteStep("walk", Point(368, 290), Point(395, 290)),
            LocalRouteStep("jump", Point(395, 290), Point(359, 241)),
        )

        class Pathfinder:
            def route(self, start: Point, goal: Point) -> tuple[LocalRouteStep, ...]:
                return route

        target, mode, remaining = route_target(
            Pathfinder(),
            Observation(frame=1, timestamp_ns=1, x=368, y=308),
            Point(33, -4188),
        )
        self.assertEqual((target, mode), (Point(359, 241), "jump"))
        self.assertEqual(remaining, route[1:])
        self.assertEqual(
            route_action_candidates(
                Observation(frame=2, timestamp_ns=2, x=364, y=308),
                Point(359, 241),
                "jump",
                landing_x_range=(312, 359),
            ),
            ("jump",),
        )
        self.assertEqual(
            route_action_candidates(
                Observation(frame=3, timestamp_ns=3, x=200, y=-2053),
                Point(193, -2303),
                "climb",
            ),
            ("up",),
        )
        self.assertEqual(
            route_action_candidates(
                Observation(frame=4, timestamp_ns=4, x=214, y=-2053),
                Point(193, -2303),
                "climb",
            ),
            ("left",),
        )
        self.assertEqual(
            route_action_candidates(
                Observation(
                    frame=5,
                    timestamp_ns=5,
                    x=-459,
                    y=-3066,
                    velocity_x=130,
                ),
                Point(-455, -3793),
                "climb",
            ),
            ("idle",),
        )

    def test_directional_jump_is_one_simultaneous_pulse(self) -> None:
        from maple_server.rl_navigation import XdotoolController

        calls: list[tuple[str, ...]] = []
        controller = XdotoolController(":test", dry_run=True)
        controller._run = lambda *arguments: calls.append(arguments)  # type: ignore[method-assign]
        controller.apply("right_jump")
        controller.apply("right_jump")
        self.assertEqual(
            calls,
            [
                ("keydown", "Right"),
                ("key", "Alt_L"),
                ("keyup", "Right"),
            ],
        )

    def test_jump_from_held_up_is_an_upward_climb_pulse(self) -> None:
        from maple_server.rl_navigation import XdotoolController

        calls: list[tuple[str, ...]] = []
        controller = XdotoolController(":test", dry_run=True)
        controller._run = lambda *arguments: calls.append(arguments)  # type: ignore[method-assign]
        controller.apply("up")
        controller.apply("jump")
        self.assertEqual(
            calls,
            [
                ("keydown", "Up"),
                ("keyup", "Up"),
                ("keydown", "Up"),
                ("key", "Alt_L"),
                ("keyup", "Up"),
            ],
        )

    def test_walk_direction_is_held_until_the_action_changes(self) -> None:
        from maple_server.rl_navigation import XdotoolController

        calls: list[tuple[str, ...]] = []
        controller = XdotoolController(":test", dry_run=True)
        controller._run = lambda *arguments: calls.append(arguments)  # type: ignore[method-assign]
        controller.apply("left")
        controller.apply("left")
        controller.apply("right")
        controller.release()
        self.assertEqual(
            calls,
            [
                ("keydown", "Left"),
                ("keyup", "Left"),
                ("keydown", "Right"),
                ("keyup", "Right"),
            ],
        )


class PhysicsLabLauncherTest(unittest.TestCase):
    def test_game_assembly_accepts_adjacent_anonymous_executable_mapping(self) -> None:
        launcher = load_launcher()
        mappings = [
            "6fffed940000-6fffed941000 r--p 00000000 00:01 1 /game/GameAssembly.dll",
            "6fffed941000-6ffff2c58000 r-xp 00000000 00:00 0",
        ]
        self.assertTrue(launcher.game_assembly_mappings_ready(mappings))

    def test_weston_screen_parser_accepts_xvfb_geometry(self) -> None:
        from maple_server.weston import parse_screen

        self.assertEqual(parse_screen("1360x768x24"), (1360, 768))
        with self.assertRaises(ValueError):
            parse_screen("100x100")

    def test_login_replies_rewrite_handoff_to_requested_world_port(self) -> None:
        if not PLAINTEXT_JSONL.is_file():
            self.skipTest("private plaintext JSONL is not present")
        from ipaddress import IPv4Address

        from maple_server.packets import WorldHandoff

        launcher = load_launcher()
        replies = launcher.login_reply_hex(
            PLAINTEXT_JSONL, tcp_stream=83, world_port=13857
        )
        self.assertEqual(len(replies[13]), 8)
        handoff = WorldHandoff.parse(bytes.fromhex(replies[7][0]))
        self.assertEqual(handoff.address, IPv4Address("127.0.0.1"))
        self.assertEqual(handoff.port, 13857)

    def test_writes_world_transcript_from_plaintext(self) -> None:
        if not PLAINTEXT_JSONL.is_file():
            self.skipTest("private plaintext JSONL is not present")
        launcher = load_launcher()
        with tempfile.TemporaryDirectory() as directory:
            arguments = launcher.parse_args(
                [
                    "--plaintext-jsonl",
                    str(PLAINTEXT_JSONL),
                    "--world-tcp-stream",
                    "114",
                    "--work-dir",
                    directory,
                ]
            )
            path = launcher.write_world_transcript(arguments, Path(directory))
            first = json.loads(path.read_text(encoding="ascii").splitlines()[0])
            self.assertEqual(first["event"], "connect")
            self.assertEqual(first["tcp_stream"], 114)


if __name__ == "__main__":
    unittest.main()

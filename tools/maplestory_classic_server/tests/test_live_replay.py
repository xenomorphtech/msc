from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gamestate import ShapeCoverage  # noqa: E402
from maple_server.gameplay import GameplayPhase  # noqa: E402
from maple_server.live_replay import (  # noqa: E402
    DEFAULT_PACKET_API_URL,
    inject_current_hp_live,
    plan_mob_temporary_stat_live_replay,
    validate_packet_api_url,
)
from maple_server.packets import (  # noqa: E402
    MobEnterField,
    MobSpawnData,
    MobTemporaryStatReset,
    MobTemporaryStatSet,
)


def state(*, current_hp: int, player_stat_updates: int) -> SimpleNamespace:
    return SimpleNamespace(
        current_hp=current_hp,
        max_hp=222,
        phase="active",
        field_epoch=1,
        map_id=101000000,
        inventory_items={"use": ("unchanged",)},
        skill_levels={2001002: 1},
        string_property_code_units={1: 3},
        timestamp_property_keys=(1,),
        saved_map_ids=(101000000,),
        extended_property_code_units={2: 4},
        progression_variant=23,
        progression_shape="marker_23",
        experience=1464,
        character_level=12,
        job_id=200,
        current_mp=97,
        max_mp=342,
        strength=4,
        dexterity=4,
        intelligence=57,
        luck=15,
        ability_points=0,
        skill_points=0,
        fame=0,
        mesos=4567,
        player_stat_updates=player_stat_updates,
    )


class LiveReplayTest(unittest.TestCase):
    def test_packet_api_url_is_fixed_to_loopback_plain_http(self) -> None:
        self.assertEqual(
            validate_packet_api_url(DEFAULT_PACKET_API_URL),
            DEFAULT_PACKET_API_URL,
        )
        self.assertEqual(
            validate_packet_api_url(
                "http://[::1]:12858/api/v1/server-packets"
            ),
            "http://[::1]:12858/api/v1/server-packets",
        )
        for value in (
            "https://127.0.0.1:12858/api/v1/server-packets",
            "http://10.0.0.2:12858/api/v1/server-packets",
            "http://127.0.0.1:12858/api/v1/status",
            "http://user@127.0.0.1:12858/api/v1/server-packets",
            "http://127.0.0.1:12858/api/v1/server-packets?raw=1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_packet_api_url(value)

    def test_live_hp_injection_requires_the_predicted_observed_fold(self) -> None:
        baseline = SimpleNamespace(
            valid=True,
            state=state(current_hp=50, player_stat_updates=1),
            observations=(),
        )
        observation = SimpleNamespace(
            direction="server_to_client",
            opcode=41,
            details={
                "stat_mask": "0x00000400",
                "changes": {
                    "current_hp": {"previous": 50, "current": 49}
                },
            },
            frame_index=81,
            kind="character_stat_update",
            coverage=ShapeCoverage.PARTIAL,
        )
        observed = SimpleNamespace(
            valid=True,
            state=state(current_hp=49, player_stat_updates=2),
            observations=(observation,),
        )
        update = SimpleNamespace(to_bytes=lambda: bytes.fromhex("29000000040000310000"))
        plan = SimpleNamespace(
            update=update,
            safe_dict=lambda: {
                "original_current_hp": 50,
                "emitted_current_hp": 49,
                "max_hp": 222,
            },
        )
        api_response = {
            "accepted": True,
            "opcode": 41,
            "plaintext_length": 10,
        }

        with (
            patch("maple_server.live_replay.Transcript.load", return_value=object()),
            patch(
                "maple_server.live_replay.analyze_gameplay_transcript",
                side_effect=(baseline, observed),
            ),
            patch(
                "maple_server.live_replay.plan_current_hp_stat_update",
                return_value=plan,
            ),
            patch(
                "maple_server.live_replay._post_plaintext_packet",
                return_value=api_response,
            ) as post,
        ):
            result = inject_current_hp_live(Path("live.jsonl"), 49)

        post.assert_called_once_with(
            DEFAULT_PACKET_API_URL,
            bytes.fromhex("29000000040000310000"),
            timeout_seconds=5.0,
        )
        report = result.safe_dict()
        self.assertTrue(report["verification"]["matched"])
        self.assertEqual(report["verification"]["observed_current_hp"], 49)
        self.assertEqual(
            report["verification"]["observed_packet"]["frame_index"], 81
        )

    def test_live_hp_injection_rejects_a_noop_before_posting(self) -> None:
        baseline = SimpleNamespace(
            valid=True,
            state=state(current_hp=50, player_stat_updates=1),
            observations=(),
        )
        with (
            patch("maple_server.live_replay.Transcript.load", return_value=object()),
            patch(
                "maple_server.live_replay.analyze_gameplay_transcript",
                return_value=baseline,
            ),
            patch("maple_server.live_replay._post_plaintext_packet") as post,
            self.assertRaisesRegex(ValueError, "must differ"),
        ):
            inject_current_hp_live(Path("live.jsonl"), 50)

        post.assert_not_called()

    def test_mob_stat_plan_uses_generated_shapes_and_capture_pair(self) -> None:
        object_id = 1234
        spawn = MobEnterField(
            object_id=object_id,
            spawn=MobSpawnData(
                spawn_marker=1,
                template_id=3210800,
                opaque_status=bytes(30),
                x=371,
                y=-562,
                stance=4,
                foothold_id=134,
                origin_foothold_id=134,
                spawn_effect=-1,
                opaque_tail=bytes(4),
            ),
        )
        set_stat = MobTemporaryStatSet(
            object_id=object_id,
            value=1,
            source_skill_id=3101005,
            source_level=6,
            duration_value=1142,
        )
        reset_stat = MobTemporaryStatReset(object_id=object_id)
        short_object_id = 5678
        short_spawn = MobEnterField(
            object_id=short_object_id,
            spawn=MobSpawnData(
                spawn_marker=1,
                template_id=3210800,
                opaque_status=bytes(22),
                x=1348,
                y=-562,
                stance=4,
                foothold_id=110,
                origin_foothold_id=110,
                spawn_effect=-1,
                opaque_tail=bytes(4),
            ),
        )
        short_set = MobTemporaryStatSet(
            object_id=short_object_id,
            value=1,
            source_skill_id=3101005,
            source_level=6,
            duration_value=1079,
        )
        short_reset = MobTemporaryStatReset(object_id=short_object_id)
        packets = (
            spawn,
            set_stat,
            reset_stat,
            short_spawn,
            short_set,
            short_reset,
        )
        shape_dump = {
            "version_id": "test-build",
            "protocol_version": 300,
            "packet_shapes": [
                {
                    "name": "mob_enter_field_extended_status",
                    "direction": "server_to_client",
                    "opcode": 279,
                    "length": 56,
                },
                {
                    "name": "mob_enter_field_short_status",
                    "direction": "server_to_client",
                    "opcode": 279,
                    "length": 48,
                },
                {
                    "name": "server_opcode_285",
                    "direction": "server_to_client",
                    "opcode": 285,
                    "length": 33,
                },
                {
                    "name": "server_opcode_286",
                    "direction": "server_to_client",
                    "opcode": 286,
                    "length": 23,
                },
                {
                    "name": "mob_leave_field",
                    "direction": "server_to_client",
                    "opcode": 280,
                    "length": 7,
                },
            ],
        }
        rows = []
        for direction_index, packet in enumerate(packets, start=10):
            payload = packet.to_bytes()
            rows.append(
                {
                    "tcp_stream": 92,
                    "direction": "server_to_client",
                    "direction_index": direction_index,
                    "opcode": packet.opcode,
                    "length": len(payload),
                    "payload_hex": payload.hex(),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "protocol_version": 300,
                    "version_id": "test-build",
                }
            )
        plan_state = state(current_hp=50, player_stat_updates=1)
        plan_state.phase = GameplayPhase.ACTIVE
        plan_state.player_x = 600
        plan_state.player_y = -2600
        plan_state.npcs = {}
        plan_state.mobs = {}
        plan_state.observed_players = {}
        plan_state.field_drops = {}
        plan_state.positioned_effect_entities = {}
        plan_state.entry_character_id = 42
        analysis = SimpleNamespace(
            valid=True,
            state=plan_state,
            events=(
                SimpleNamespace(
                    kind="player_movement_submitted",
                    details={
                        "commands": [
                            {
                                "position_y": -2693,
                                "foothold_id": 635,
                            }
                        ]
                    },
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            shape_path = directory_path / "shapes.json"
            evidence_path = directory_path / "packets.jsonl"
            shape_path.write_text(json.dumps(shape_dump), encoding="utf-8")
            evidence_path.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            plan = plan_mob_temporary_stat_live_replay(
                analysis,
                shape_path,
                evidence_path,
                x_offset=120,
            )

        report = plan.safe_dict()
        self.assertEqual(report["shape_names"][0], "mob_enter_field_short_status")
        self.assertEqual(report["evidence_direction_indices"]["spawn"], 13)
        self.assertEqual(report["spawn"]["template_id"], 3210800)
        self.assertEqual(report["spawn"]["x"], 720)
        self.assertEqual(report["spawn"]["y"], -2693)
        self.assertEqual(report["spawn"]["foothold_id"], 635)
        self.assertEqual(report["set"]["enabled_bit_indices"], [103])
        self.assertEqual(report["set"]["source_skill_id"], 3101005)
        self.assertNotEqual(plan.spawn.object_id, short_object_id)
        self.assertEqual(plan.spawn.object_id, plan.set_stat.object_id)
        self.assertEqual(plan.spawn.object_id, plan.reset_stat.object_id)


if __name__ == "__main__":
    unittest.main()

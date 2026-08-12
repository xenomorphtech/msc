from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gamestate import ShapeCoverage  # noqa: E402
from maple_server.gameplay import (  # noqa: E402
    GameplayPhase,
    InventoryItemEntity,
)
from maple_server.live_replay import (  # noqa: E402
    DEFAULT_PACKET_API_URL,
    _CapturedItemPickupAdmission,
    _item_pickup_player_position,
    inject_current_hp_live,
    inject_item_pickup_live,
    inject_skill_record_live,
    plan_item_pickup_live_replay,
    plan_mob_temporary_stat_live_replay,
    plan_skill_record_update_live,
    validate_packet_api_url,
)
from maple_server.packets import (  # noqa: E402
    FieldDropSpawn,
    MobEnterField,
    MobControllerChange,
    MobSpawnData,
    MobTemporaryStatReset,
    MobTemporaryStatSet,
    SkillRecordUpdate,
)


def state(
    *,
    current_hp: int,
    player_stat_updates: int,
    skill_record_updates: int = 0,
    skill_record_update_records: int = 0,
    skill_record_update_acknowledgements: int = 0,
    matched_skill_record_update_acknowledgements: int = 0,
    skill_record_updates_without_request: int = 0,
) -> SimpleNamespace:
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
        skill_level_change_requests=0,
        pending_skill_level_change_requests=0,
        skill_record_updates=skill_record_updates,
        skill_record_update_records=skill_record_update_records,
        skill_record_update_acknowledgements=(
            skill_record_update_acknowledgements
        ),
        matched_skill_record_update_acknowledgements=(
            matched_skill_record_update_acknowledgements
        ),
        unmatched_skill_record_update_acknowledgements=0,
        pending_skill_record_update_acknowledgements=0,
        skill_record_updates_without_request=skill_record_updates_without_request,
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

    def test_skill_record_plan_builds_both_captured_forms(self) -> None:
        analysis = SimpleNamespace(
            valid=True,
            state=state(current_hp=50, player_stat_updates=1),
        )

        empty = plan_skill_record_update_live(analysis)
        existing = plan_skill_record_update_live(
            analysis,
            skill_id=2_001_002,
        )

        self.assertEqual(empty.update.to_bytes(), bytes.fromhex("2e000000000002"))
        self.assertEqual(
            existing.update.to_bytes(),
            bytes.fromhex("2e00010001006a881e00010000000000000002"),
        )
        self.assertEqual(existing.safe_dict()["mode"], "existing_skill")
        with self.assertRaisesRegex(ValueError, "requires a skill id"):
            plan_skill_record_update_live(analysis, level=2)
        with self.assertRaisesRegex(ValueError, "not present"):
            plan_skill_record_update_live(analysis, skill_id=9_999_999)

    def test_item_pickup_plan_prefers_latest_movement_command_position(
        self,
    ) -> None:
        captured_drop = FieldDropSpawn(
            spawn_mode=1,
            drop_object_id=1234,
            drop_kind=FieldDropSpawn.ITEM,
            value=4_000_004,
            owner_value_1=99,
            owner_value_2=99,
            ownership_flag=0,
            position_x=-536,
            position_y=1757,
            source_mob_object_id=5678,
            source_x=-526,
            source_y=1754,
            animation_duration_ms=450,
            expiration_ticks=150842304000000000,
            final_flag=1,
        )
        captured = _CapturedItemPickupAdmission(
            drop_spawn=captured_drop,
            drop_refresh=replace(captured_drop, spawn_mode=0),
            controller_release=MobControllerChange(
                control_level=0,
                object_id=5678,
            ),
            inventory="etc",
            quantity_delta=1,
            spawn_frame=26024,
            refresh_frame=26025,
            release_frame=26045,
            request_frame=26071,
            release_delay_seconds=0.398819,
            admission_delay_seconds=1.591279,
        )
        plan_state = SimpleNamespace(
            phase=GameplayPhase.ACTIVE,
            pending_item_pickups=0,
            pending_item_use_requests=0,
            field_epoch=1,
            player_x=675,
            player_y=-2693,
            entry_character_id=42,
            inventory_items={
                "etc": (
                    InventoryItemEntity(
                        slot=7,
                        record_type=2,
                        item_id=4_000_004,
                        cash_item=False,
                        expires_at_ticks=150842304000000000,
                        quantity=74,
                    ),
                )
            },
            npcs={},
            mobs={},
            observed_players={},
            field_drops={},
            reactors={},
        )
        movement_observation = SimpleNamespace(
            direction="client_to_server",
            opcode=182,
            kind="player_movement_submission",
            details={
                "field_epoch": 1,
                "final_x": 676,
                "final_y": -2695,
                "path_end_x": 675,
                "path_end_y": -2693,
            },
        )
        analysis = SimpleNamespace(
            valid=True,
            state=plan_state,
            observations=(movement_observation,),
        )

        with patch(
            "maple_server.live_replay._captured_item_pickup_admission",
            return_value=captured,
        ):
            plan = plan_item_pickup_live_replay(
                analysis,
                object(),
                evidence_tcp_stream=92,
            )

        report = plan.safe_dict()
        self.assertEqual(
            report["latest_player_position"],
            {"x": 676, "y": -2695},
        )
        self.assertEqual(report["drop_position"], {"x": 676, "y": -2695})
        self.assertEqual(report["player_position_source"], "movement_command_final")
        self.assertEqual(
            report["folded_trailer_position"],
            {"x": 675, "y": -2693},
        )
        self.assertEqual(
            report["animated_source_offset"],
            {"x": 10, "y": -3},
        )
        self.assertEqual(plan.drop_spawn.source_x, 686)
        self.assertEqual(plan.drop_spawn.source_y, -2698)
        self.assertEqual(plan.drop_spawn.owner_value_1, 42)
        self.assertEqual(plan.drop_spawn.owner_value_2, 42)
        self.assertEqual(
            plan.drop_spawn.source_mob_object_id,
            plan.controller_release.object_id,
        )
        self.assertNotEqual(plan.drop_spawn.drop_object_id, 1234)
        self.assertEqual(plan.inventory_update.modifications[0].quantity, 75)
        self.assertEqual(plan.gain_notice.quantity, 1)
        self.assertEqual(
            [
                int.from_bytes(packet[:2], "little")
                for packet in plan.response_packets(185)
            ],
            [39, 49, 312],
        )

    def test_item_pickup_position_falls_back_to_folded_trailer(self) -> None:
        analysis = SimpleNamespace(
            state=SimpleNamespace(
                field_epoch=2,
                player_x=10,
                player_y=20,
            ),
            observations=(
                SimpleNamespace(
                    direction="client_to_server",
                    opcode=182,
                    kind="player_movement_submission",
                    details={
                        "field_epoch": 1,
                        "final_x": 30,
                        "final_y": 40,
                    },
                ),
            ),
        )

        self.assertEqual(
            _item_pickup_player_position(analysis),
            (10, 20, "folded_trailer_endpoint"),
        )

    def test_item_pickup_timeout_removes_the_injected_drop(self) -> None:
        def packet(opcode: int) -> SimpleNamespace:
            return SimpleNamespace(
                to_bytes=lambda: opcode.to_bytes(2, "little")
            )

        plan = SimpleNamespace(
            drop_spawn=packet(311),
            drop_refresh=packet(311),
            controller_release=packet(281),
            cleanup=packet(312),
            inventory="etc",
            slot=7,
            item_id=4_000_004,
            quantity_after=75,
            player_x=633,
            player_y=-2677,
            release_delay_seconds=0.0,
            admission_delay_seconds=0.0,
        )
        baseline = SimpleNamespace(
            valid=True,
            observations=(),
            state=SimpleNamespace(
                player_x=633,
                player_y=-2677,
                field_drops={},
            ),
        )
        observed_spawn = SimpleNamespace(
            direction="server_to_client",
            opcode=311,
            kind="field_drop_spawn",
            details={
                "new_drop": True,
                "item_id": 4_000_004,
                "position_x": 633,
                "position_y": -2677,
                "drop": "drop:2",
            },
        )
        candidate = SimpleNamespace(
            valid=True,
            observations=(observed_spawn,),
        )
        inventory_snapshot = (
            ("etc", 7, 2, 4_000_004, False, 150842304000000000, 74),
        )

        with (
            patch("maple_server.live_replay.Transcript.load", return_value=object()),
            patch(
                "maple_server.live_replay.analyze_gameplay_transcript",
                side_effect=(baseline, candidate),
            ),
            patch(
                "maple_server.live_replay.load_pcap_tcp_stream",
                return_value=object(),
            ),
            patch(
                "maple_server.live_replay.plan_item_pickup_live_replay",
                return_value=plan,
            ),
            patch(
                "maple_server.live_replay._inventory_item_snapshot",
                return_value=inventory_snapshot,
            ),
            patch(
                "maple_server.live_replay._progression_snapshot",
                return_value=("progression",),
            ),
            patch(
                "maple_server.live_replay._player_state_snapshot",
                return_value=("player",),
            ),
            patch(
                "maple_server.live_replay._post_plaintext_packet",
                return_value={"accepted": True},
            ) as post,
            patch("maple_server.live_replay._send_wayland_evdev_key") as send_key,
        ):
            with self.assertRaisesRegex(
                TimeoutError,
                "no authentic item-pickup request",
            ):
                inject_item_pickup_live(
                    Path("live.jsonl"),
                    Path("111.pcapng"),
                    wayland_display="wayland-3",
                    verify_timeout_seconds=0.001,
                )

        self.assertEqual(
            [call.args[1][:2] for call in post.call_args_list],
            [
                (311).to_bytes(2, "little"),
                (311).to_bytes(2, "little"),
                (281).to_bytes(2, "little"),
                (312).to_bytes(2, "little"),
            ],
        )
        send_key.assert_called_once()

    def test_live_skill_record_injection_requires_update_and_ack_fold(self) -> None:
        baseline = SimpleNamespace(
            valid=True,
            state=state(current_hp=50, player_stat_updates=1),
            observations=(),
        )
        update_observation = SimpleNamespace(
            direction="server_to_client",
            opcode=46,
            details={
                "flag_a": True,
                "flag_b": False,
                "record_count": 1,
                "records": [
                    {
                        "skill_id": 2_001_002,
                        "level": 1,
                        "auxiliary_value": 0,
                    }
                ],
                "trailing_value": 2,
                "record_changes": [
                    {
                        "skill_id": 2_001_002,
                        "previous_level": 1,
                        "current_level": 1,
                        "level_delta": 0,
                        "auxiliary_value": 0,
                    }
                ],
            },
            frame_index=81,
            kind="skill_record_update",
            coverage=ShapeCoverage.FULL,
        )
        acknowledgement_observation = SimpleNamespace(
            direction="client_to_server",
            opcode=293,
            details={
                "control_value": 346,
                "client_tick": 400_000,
                "trailing_value": 0,
                "matched_update": True,
                "update_frame": 81,
                "round_trip_ms": 11.25,
            },
            frame_index=82,
            kind="skill_record_update_acknowledgement",
            coverage=ShapeCoverage.FULL,
        )
        observed = SimpleNamespace(
            valid=True,
            state=state(
                current_hp=50,
                player_stat_updates=1,
                skill_record_updates=1,
                skill_record_update_records=1,
                skill_record_update_acknowledgements=1,
                matched_skill_record_update_acknowledgements=1,
                skill_record_updates_without_request=1,
            ),
            observations=(update_observation, acknowledgement_observation),
        )
        api_response = {
            "accepted": True,
            "opcode": 46,
            "plaintext_length": 19,
        }

        with (
            patch("maple_server.live_replay.Transcript.load", return_value=object()),
            patch(
                "maple_server.live_replay.analyze_gameplay_transcript",
                side_effect=(baseline, observed),
            ),
            patch(
                "maple_server.live_replay._post_plaintext_packet",
                return_value=api_response,
            ) as post,
        ):
            result = inject_skill_record_live(
                Path("live.jsonl"),
                skill_id=2_001_002,
            )

        payload = post.call_args.args[1]
        self.assertEqual(SkillRecordUpdate.parse(payload).records[0].level, 1)
        report = result.safe_dict()
        self.assertTrue(report["verification"]["matched"])
        self.assertEqual(
            report["verification"]["observed_acknowledgement"][
                "control_value"
            ],
            346,
        )

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
        plan_state.reactors = {}
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

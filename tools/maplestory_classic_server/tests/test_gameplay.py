from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gameplay import (  # noqa: E402
    GameplayPhase,
    analyze_gameplay_transcript,
    derive_mob_movement_acknowledgement_policy,
    plan_final_field_npc_state_replay,
    render_gameplay_analysis,
    world_session_termination_frame_index,
)
from maple_server.packets import (  # noqa: E402
    FieldLoadStage,
    FieldSnapshotEnvelope,
    HeartbeatProbe,
    HeartbeatResponse,
    MobControllerChange,
    MobEnterField,
    MobLeaveField,
    MobMovementAcknowledgement,
    MobMovementBroadcast,
    MobMovementCommand,
    MobMovementPath,
    MobMovementSubmission,
    MobSpawnData,
    NpcSpawn,
    NpcStateUpdate,
    PacketShapeError,
    WorldBootstrapAcknowledgement,
    WorldEntryRequest,
    WorldSessionTermination,
)
from maple_server.protocol import (  # noqa: E402
    crypt_payload,
    encode_frame_header,
    shuffle_iv,
)
from maple_server.transcript import Transcript, TranscriptEvent  # noqa: E402


FIRST_IV = bytes.fromhex("6e3c795a")
SECOND_IV = bytes.fromhex("885db958")
HANDSHAKE = bytes.fromhex(
    "1f00 2c01 0300 330030003000 6e3c795a 885db958 04 "
    "2c010000 2c010000 00000000"
)
CHARACTER_ID = 300_001
NPC_OBJECT_ID = 10_001
MOB_OBJECT_ID = 20_001


def fixture_npc() -> NpcSpawn:
    return NpcSpawn(
        object_id=NPC_OBJECT_ID,
        template_id=1_032_000,
        x=-120,
        cy=45,
        faces_left=True,
        foothold_id=7,
        range_left=-300,
        range_right=200,
        hidden=False,
    )


def fixture_movement_path() -> MobMovementPath:
    return MobMovementPath(
        opaque_control=b"\x00anitized-control".ljust(19, b"\x00"),
        reference_x=100,
        reference_y=-200,
        commands=(
            MobMovementCommand.absolute(
                position_x=110,
                position_y=-200,
                velocity_x=10,
                velocity_y=0,
                foothold_id=7,
                stance=2,
                duration_ms=90,
            ),
        ),
        trailer_marker=0,
        path_start_x=90,
        path_start_y=-200,
        path_end_x=110,
        path_end_y=-200,
    )


def fixture_mob_spawn(*, extended_status: bool = False) -> MobSpawnData:
    return MobSpawnData(
        spawn_marker=1,
        template_id=210_100,
        opaque_status=b"\x00" * (30 if extended_status else 22),
        x=100,
        y=-200,
        stance=2,
        foothold_id=7,
        origin_foothold_id=8,
        spawn_effect=-1,
        opaque_tail=b"\x00" * 4,
    )


def fixture_gameplay_transcript(
    *,
    repeat_npc_update: bool = False,
    leave_mob: bool = False,
    terminate: bool = False,
    close: bool = True,
    acknowledgement_flag: int = 0,
    acknowledgement_auxiliary_1: int = 0,
    acknowledgement_auxiliary_2: int = 0,
) -> Transcript:
    events = [
        TranscriptEvent(event="connect", timestamp_ns=1),
        TranscriptEvent(
            event="data",
            timestamp_ns=2,
            direction="server_to_client",
            data=HANDSHAKE,
        ),
    ]
    ivs = {
        "client_to_server": FIRST_IV,
        "server_to_client": SECOND_IV,
    }
    masks = {"client_to_server": 3, "server_to_client": ~300}
    timestamp_ns = 3

    def append(direction: str, plaintext: bytes) -> None:
        nonlocal timestamp_ns
        iv = ivs[direction]
        wire = (
            encode_frame_header(len(plaintext), iv, masks[direction])
            + crypt_payload(plaintext, iv)
        )
        ivs[direction] = shuffle_iv(iv)
        events.append(
            TranscriptEvent(
                event="data",
                timestamp_ns=timestamp_ns,
                direction=direction,
                data=wire,
            )
        )
        timestamp_ns += 1

    append(
        "client_to_server",
        WorldEntryRequest(
            character_id=CHARACTER_ID,
            opaque_ticket=b"sanitized-ticket".ljust(60, b"\x00"),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        FieldSnapshotEnvelope(opaque_snapshot=b"sanitized-field").to_bytes(),
    )
    append("server_to_client", fixture_npc().to_bytes())
    append(
        "server_to_client",
        NpcStateUpdate(
            object_id=NPC_OBJECT_ID,
            action=3,
            parameter=1,
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobControllerChange(
            control_level=1,
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobMovementBroadcast(
            object_id=MOB_OBJECT_ID,
            opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
            reference_x=100,
            reference_y=-200,
            commands=fixture_movement_path().commands,
        ).to_bytes(),
    )
    append(
        "client_to_server",
        WorldBootstrapAcknowledgement(opaque_value=0).to_bytes(),
    )
    append("client_to_server", FieldLoadStage(stage=1).to_bytes())
    append("client_to_server", FieldLoadStage(stage=2).to_bytes())
    append(
        "client_to_server",
        MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=9,
            opaque_movement=fixture_movement_path().to_bytes(),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobMovementAcknowledgement(
            object_id=MOB_OBJECT_ID,
            sequence=9,
            status_flag=acknowledgement_flag,
            status_value=35,
            status_auxiliary_1=acknowledgement_auxiliary_1,
            status_auxiliary_2=acknowledgement_auxiliary_2,
        ).to_bytes(),
    )
    if leave_mob:
        append(
            "server_to_client",
            MobLeaveField(object_id=MOB_OBJECT_ID, reason=0).to_bytes(),
        )
    append("server_to_client", HeartbeatProbe().to_bytes())
    append(
        "client_to_server",
        HeartbeatResponse(opaque_token=b"\x00" * 8).to_bytes(),
    )
    if repeat_npc_update:
        append(
            "server_to_client",
            NpcStateUpdate(
                object_id=NPC_OBJECT_ID,
                action=3,
                parameter=1,
            ).to_bytes(),
        )
    if terminate:
        append(
            "server_to_client",
            WorldSessionTermination(opaque_reason=b"ended!!").to_bytes(),
        )
    if close:
        events.append(TranscriptEvent(event="close", timestamp_ns=timestamp_ns))
    return Transcript(path=Path("sanitized-gameplay.jsonl"), events=tuple(events))


class GameplayPacketShapeTest(unittest.TestCase):
    def test_npc_spawn_round_trip(self) -> None:
        spawn = fixture_npc()

        self.assertEqual(len(spawn.to_bytes()), 22)
        self.assertEqual(NpcSpawn.parse(spawn.to_bytes()), spawn)

    def test_npc_spawn_rejects_boolean_and_reversed_range(self) -> None:
        malformed_boolean = bytearray(fixture_npc().to_bytes())
        malformed_boolean[14] = 2
        with self.assertRaisesRegex(PacketShapeError, "faces_left"):
            NpcSpawn.parse(bytes(malformed_boolean))

        with self.assertRaisesRegex(PacketShapeError, "reversed"):
            NpcSpawn(
                object_id=1,
                template_id=2,
                x=0,
                cy=0,
                faces_left=False,
                foothold_id=0,
                range_left=10,
                range_right=-10,
                hidden=False,
            ).to_bytes()

    def test_movement_header_and_ack_round_trip(self) -> None:
        movement_path = MobMovementPath(
            opaque_control=b"opaque-control".ljust(19, b"\x00"),
            reference_x=-12,
            reference_y=34,
            commands=(
                MobMovementCommand.absolute(
                    position_x=-10,
                    position_y=35,
                    velocity_x=3,
                    velocity_y=-4,
                    foothold_id=5,
                    stance=6,
                    duration_ms=90,
                ),
                MobMovementCommand.relative(
                    command_type=1,
                    velocity_x=100,
                    velocity_y=-555,
                    stance=7,
                    duration_ms=0,
                ),
                MobMovementCommand.relative(
                    command_type=2,
                    velocity_x=-117,
                    velocity_y=-54,
                    stance=3,
                    duration_ms=0,
                ),
            ),
            trailer_marker=0,
            path_start_x=-20,
            path_start_y=30,
            path_end_x=-4,
            path_end_y=38,
        )
        submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=42,
            opaque_movement=movement_path.to_bytes(),
        )
        acknowledgement = MobMovementAcknowledgement(
            object_id=MOB_OBJECT_ID,
            sequence=42,
            status_flag=1,
            status_value=35,
            status_auxiliary_1=0,
            status_auxiliary_2=0,
        )

        self.assertEqual(
            MobMovementSubmission.parse(submission.to_bytes()), submission
        )
        parsed_path = MobMovementSubmission.parse(
            submission.to_bytes()
        ).movement_path
        self.assertEqual(parsed_path, movement_path)
        self.assertEqual(
            [command.byte_length for command in parsed_path.commands],
            [14, 8, 8],
        )
        self.assertEqual(
            parsed_path.commands[0].safe_dict(),
            {
                "type": 0,
                "kind": "absolute",
                "position_x": -10,
                "position_y": 35,
                "velocity_x": 3,
                "velocity_y": -4,
                "foothold_id": 5,
                "stance": 6,
                "duration_ms": 90,
            },
        )
        self.assertEqual(
            parsed_path.commands[1].safe_dict(),
            {
                "type": 1,
                "kind": "relative",
                "velocity_x": 100,
                "velocity_y": -555,
                "stance": 7,
                "duration_ms": 0,
            },
        )
        self.assertEqual(
            MobMovementAcknowledgement.parse(acknowledgement.to_bytes()),
            acknowledgement,
        )
        self.assertEqual(acknowledgement.status_flag, 1)
        self.assertEqual(acknowledgement.status_value, 35)
        self.assertEqual(acknowledgement.status_auxiliary_1, 0)
        self.assertEqual(acknowledgement.status_auxiliary_2, 0)
        with self.assertRaises(PacketShapeError):
            replace(
                acknowledgement, status_flag=2
            ).to_bytes()

    def test_movement_path_rejects_unmodeled_or_truncated_commands(self) -> None:
        encoded = bytearray(fixture_movement_path().to_bytes())
        encoded[24] = 3
        with self.assertRaises(PacketShapeError):
            MobMovementPath.parse(bytes(encoded))

        with self.assertRaises(PacketShapeError):
            MobMovementPath.parse(fixture_movement_path().to_bytes()[:-1])

        encoded = bytearray(fixture_movement_path().to_bytes())
        encoded[-9] = 1
        with self.assertRaises(PacketShapeError):
            MobMovementPath.parse(bytes(encoded))

    def test_mob_lifecycle_and_broadcast_round_trip(self) -> None:
        entered = MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        )
        extended_enter = MobEnterField(
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(extended_status=True),
        )
        left = MobLeaveField(object_id=MOB_OBJECT_ID, reason=1)
        released = MobControllerChange(
            control_level=0,
            object_id=MOB_OBJECT_ID,
        )
        controlled = MobControllerChange(
            control_level=2,
            object_id=MOB_OBJECT_ID,
            spawn=fixture_mob_spawn(),
        )
        broadcast = MobMovementBroadcast(
            object_id=MOB_OBJECT_ID,
            opaque_control=b"\x00\x00\xff\x00\x00\x00\x00",
            reference_x=100,
            reference_y=-200,
            commands=fixture_movement_path().commands,
        )

        for packet_type, packet in (
            (MobEnterField, entered),
            (MobEnterField, extended_enter),
            (MobLeaveField, left),
            (MobControllerChange, released),
            (MobControllerChange, controlled),
            (MobMovementBroadcast, broadcast),
        ):
            self.assertEqual(packet_type.parse(packet.to_bytes()), packet)
        self.assertEqual(len(entered.to_bytes()), 48)
        self.assertEqual(len(extended_enter.to_bytes()), 56)
        self.assertEqual(len(left.to_bytes()), 7)
        self.assertEqual(len(released.to_bytes()), 7)
        self.assertEqual(len(controlled.to_bytes()), 49)
        self.assertEqual(len(broadcast.to_bytes()), 32)
        with self.assertRaises(PacketShapeError):
            MobControllerChange(
                control_level=0,
                object_id=MOB_OBJECT_ID,
                spawn=fixture_mob_spawn(),
            ).to_bytes()

    def test_world_session_termination_round_trip(self) -> None:
        termination = WorldSessionTermination(opaque_reason=b"ended!!")

        self.assertEqual(len(termination.to_bytes()), 9)
        self.assertEqual(
            WorldSessionTermination.parse(termination.to_bytes()), termination
        )

    def test_heartbeat_probe_and_response_round_trip(self) -> None:
        probe = HeartbeatProbe()
        response = HeartbeatResponse(opaque_token=b"response")

        self.assertEqual(HeartbeatProbe.parse(probe.to_bytes()), probe)
        self.assertEqual(
            HeartbeatResponse.parse(response.to_bytes()), response
        )


class GameplayStateFoldTest(unittest.TestCase):
    def test_folds_packets_into_field_state_and_timestamped_events(self) -> None:
        analysis = analyze_gameplay_transcript(fixture_gameplay_transcript())

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.phase, GameplayPhase.ACTIVE)
        self.assertEqual(analysis.state.field_epoch, 1)
        self.assertEqual(analysis.state.field_load_stage, 2)
        self.assertEqual(len(analysis.state.npcs), 1)
        self.assertEqual(analysis.state.npc_spawns, 1)
        self.assertEqual(analysis.state.npc_state_updates, 1)
        self.assertEqual(len(analysis.state.mobs), 1)
        self.assertEqual(analysis.state.mobs[MOB_OBJECT_ID].controller_level, 1)
        self.assertEqual(analysis.state.mob_entries, 1)
        self.assertEqual(analysis.state.mob_controller_changes, 1)
        self.assertEqual(analysis.state.mob_movement_broadcasts, 1)
        self.assertEqual(analysis.state.mob_broadcast_commands, 1)
        self.assertEqual(analysis.state.mob_broadcast_commands_by_type, {0: 1})
        self.assertEqual(analysis.state.unknown_mob_broadcasts, 0)
        self.assertEqual(analysis.state.unknown_mob_leaves, 0)
        self.assertEqual(analysis.state.movement_submissions, 1)
        self.assertEqual(analysis.state.movement_submissions_for_unknown_mobs, 0)
        self.assertEqual(
            analysis.state.movement_submissions_with_unknown_template, 0
        )
        self.assertEqual(analysis.state.movement_commands, 1)
        self.assertEqual(analysis.state.movement_commands_by_type, {0: 1})
        self.assertEqual(analysis.state.matched_movement_acknowledgements, 1)
        self.assertEqual(
            analysis.state.movement_acknowledgements_for_unknown_mobs, 0
        )
        self.assertEqual(
            analysis.state.movement_acknowledgement_statuses,
            {(0, 35, 0, 0): 1},
        )
        self.assertEqual(analysis.state.movement_acknowledgement_flag_matches, 1)
        self.assertEqual(
            analysis.state.movement_acknowledgement_flag_mismatches, 0
        )
        self.assertEqual(
            analysis.state.movement_acknowledgement_zero_auxiliary_pairs, 1
        )
        self.assertEqual(
            analysis.state.movement_acknowledgements_with_known_template, 1
        )
        self.assertEqual(
            analysis.state.movement_acknowledgement_values_by_template,
            {210_100: {35}},
        )
        self.assertEqual(analysis.state.pending_movements, 0)
        self.assertEqual(analysis.state.heartbeat_probes, 1)
        self.assertEqual(analysis.state.heartbeat_responses, 1)
        self.assertEqual(analysis.state.matched_heartbeat_responses, 1)
        self.assertEqual(analysis.state.unmatched_heartbeat_responses, 0)
        self.assertEqual(analysis.state.pending_heartbeat_probes, 0)
        self.assertEqual(analysis.state.last_heartbeat_round_trip_ms, 1e-6)
        event_kinds = [event.kind for event in analysis.events]
        self.assertIn("field_snapshot_received", event_kinds)
        self.assertIn("npc_spawned", event_kinds)
        self.assertIn("npc_state_updated", event_kinds)
        self.assertIn("mob_entered_field", event_kinds)
        self.assertIn("mob_controller_changed", event_kinds)
        self.assertIn("mob_movement_broadcast", event_kinds)
        self.assertIn("field_became_active", event_kinds)
        self.assertIn("mob_movement_submitted", event_kinds)
        self.assertIn("mob_movement_acknowledged", event_kinds)
        self.assertEqual(event_kinds[-1], "session_ended")
        self.assertEqual(
            [event.index for event in analysis.events],
            list(range(len(analysis.events))),
        )

    def test_safe_output_uses_correlatable_aliases_and_redacts_raw_ids(self) -> None:
        analysis = analyze_gameplay_transcript(fixture_gameplay_transcript())

        safe_json = analysis.to_json()
        identified = analysis.safe_dict(show_identifiers=True)
        self.assertNotIn(str(CHARACTER_ID), safe_json)
        self.assertNotIn(str(NPC_OBJECT_ID), safe_json)
        self.assertNotIn(str(MOB_OBJECT_ID), safe_json)
        self.assertIn('"entity": "npc:1"', safe_json)
        self.assertEqual(identified["state"]["entry_character_id"], CHARACTER_ID)
        self.assertEqual(identified["state"]["npcs"][0]["object_id"], NPC_OBJECT_ID)
        self.assertEqual(identified["state"]["mobs"][0]["object_id"], MOB_OBJECT_ID)

    def test_text_report_can_emit_events_and_packet_shapes(self) -> None:
        analysis = analyze_gameplay_transcript(fixture_gameplay_transcript())

        report = render_gameplay_analysis(
            analysis,
            show_events=True,
            show_packets=True,
        )

        self.assertIn("kind=npc_spawned", report)
        self.assertIn("opcode=300 kind=npc_spawn coverage=full", report)
        self.assertIn("opcode=279 kind=mob_enter_field coverage=partial", report)
        self.assertIn("mobs=active:1 entries:1 leaves:0", report)
        self.assertIn("matched_submission\":true", report)
        self.assertIn("command_types\":[0]", report)
        self.assertIn('commands:1 command_types:{"0": 1}', report)
        self.assertIn(
            "movement_ack_policy=flag_matches:1 flag_mismatches:0",
            report,
        )

    def test_derives_identifier_free_movement_acknowledgement_policy(self) -> None:
        policy = derive_mob_movement_acknowledgement_policy(
            fixture_gameplay_transcript()
        )
        submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=10,
            opaque_movement=fixture_movement_path().to_bytes(),
        )

        self.assertEqual(
            policy.acknowledge(submission),
            MobMovementAcknowledgement(
                object_id=MOB_OBJECT_ID,
                sequence=10,
                status_flag=0,
                status_value=35,
                status_auxiliary_1=0,
                status_auxiliary_2=0,
            ),
        )
        safe = policy.safe_dict()
        self.assertEqual(
            safe["status_values_by_template"],
            [
                {
                    "template_id": 210_100,
                    "status_value": 35,
                    "observations": 1,
                }
            ],
        )
        self.assertEqual(safe["active_known_mob_count"], 1)
        self.assertEqual(safe["field_known_mob_count"], 1)
        self.assertNotIn(str(MOB_OBJECT_ID), str(safe))
        nonzero_control_path = replace(
            fixture_movement_path(),
            opaque_control=(
                b"\x01" + fixture_movement_path().opaque_control[1:]
            ),
        )
        flagged = policy.acknowledge(
            MobMovementSubmission(
                object_id=MOB_OBJECT_ID,
                sequence=11,
                opaque_movement=nonzero_control_path.to_bytes(),
            )
        )
        self.assertEqual(flagged.status_flag, 1)

    def test_movement_acknowledgement_policy_rejects_unknown_field_mob(
        self,
    ) -> None:
        policy = derive_mob_movement_acknowledgement_policy(
            fixture_gameplay_transcript()
        )
        unknown_submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID + 1,
            sequence=10,
            opaque_movement=fixture_movement_path().to_bytes(),
        )

        with self.assertRaisesRegex(ValueError, "no explicit field-local"):
            policy.acknowledge(unknown_submission)

    def test_movement_acknowledgement_policy_retains_template_after_leave(
        self,
    ) -> None:
        policy = derive_mob_movement_acknowledgement_policy(
            fixture_gameplay_transcript(leave_mob=True)
        )
        submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=10,
            opaque_movement=fixture_movement_path().to_bytes(),
        )

        self.assertEqual(policy.safe_dict()["active_known_mob_count"], 0)
        self.assertEqual(policy.safe_dict()["field_known_mob_count"], 1)
        self.assertEqual(policy.acknowledge(submission).status_value, 35)

    def test_movement_acknowledgement_policy_rejects_capture_rule_mismatch(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "packet/state validation"):
            derive_mob_movement_acknowledgement_policy(
                fixture_gameplay_transcript(acknowledgement_flag=1)
            )
        with self.assertRaisesRegex(ValueError, "packet/state validation"):
            derive_mob_movement_acknowledgement_policy(
                fixture_gameplay_transcript(acknowledgement_auxiliary_1=1)
            )

    def test_mob_leave_removes_known_active_entity(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(leave_mob=True)
        )

        self.assertTrue(analysis.valid)
        self.assertEqual(len(analysis.state.mobs), 0)
        self.assertEqual(analysis.state.mob_leaves, 1)
        leave_event = next(
            event for event in analysis.events if event.kind == "mob_left_field"
        )
        self.assertTrue(leave_event.details["known_entity"])

    def test_repeated_npc_update_has_the_predicted_field_local_delta(self) -> None:
        baseline = analyze_gameplay_transcript(fixture_gameplay_transcript())
        injected = analyze_gameplay_transcript(
            fixture_gameplay_transcript(repeat_npc_update=True)
        )

        self.assertTrue(baseline.valid)
        self.assertTrue(injected.valid)
        self.assertEqual(len(injected.state.npcs), len(baseline.state.npcs))
        self.assertEqual(injected.state.phase, baseline.state.phase)
        self.assertEqual(
            injected.state.npc_state_updates,
            baseline.state.npc_state_updates + 1,
        )
        self.assertEqual(len(injected.events), len(baseline.events) + 1)

    def test_plans_identifier_free_final_field_npc_state_replay(self) -> None:
        plan = plan_final_field_npc_state_replay(
            fixture_gameplay_transcript(terminate=True)
        )

        self.assertEqual(
            plan.update,
            NpcStateUpdate(
                object_id=NPC_OBJECT_ID,
                action=3,
                parameter=1,
            ),
        )
        self.assertEqual(plan.field_epoch, 1)
        self.assertEqual(
            plan.safe_dict(),
            {
                "entity": "npc:1",
                "field_epoch": 1,
                "action": 3,
                "parameter": 1,
                "prediction": {
                    "npc_state_updates_delta": 1,
                    "events_delta": 1,
                    "active_npc_count_delta": 0,
                    "phase": "unchanged",
                },
            },
        )
        self.assertNotIn(str(NPC_OBJECT_ID), str(plan.safe_dict()))

    def test_terminal_packet_changes_phase_and_is_discoverable_for_omission(
        self,
    ) -> None:
        transcript = fixture_gameplay_transcript(terminate=True)
        analysis = analyze_gameplay_transcript(transcript)

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.phase, GameplayPhase.TERMINATED)
        self.assertTrue(analysis.state.termination_received)
        self.assertEqual(
            world_session_termination_frame_index(transcript),
            analysis.decoded.frames[-1].direction_index,
        )
        self.assertIn(
            "world_session_termination_received",
            [event.kind for event in analysis.events],
        )

    def test_live_partial_transcript_does_not_emit_session_ended(self) -> None:
        analysis = analyze_gameplay_transcript(
            fixture_gameplay_transcript(close=False)
        )

        self.assertFalse(analysis.transport_closed)
        self.assertNotIn(
            "session_ended", [event.kind for event in analysis.events]
        )

    def test_termination_discovery_rejects_capture_without_terminal_packet(
        self,
    ) -> None:
        with self.assertRaisesRegex(PacketShapeError, "no server opcode-9"):
            world_session_termination_frame_index(
                fixture_gameplay_transcript(terminate=False)
            )

    def test_heartbeat_correlation_rejects_reversed_temporal_interpretation(
        self,
    ) -> None:
        transcript = fixture_gameplay_transcript()
        events = list(transcript.events)
        probe_event = events[-3]
        response_event = events[-2]
        events[-3] = replace(
            response_event, timestamp_ns=probe_event.timestamp_ns
        )
        events[-2] = replace(
            probe_event, timestamp_ns=response_event.timestamp_ns
        )

        analysis = analyze_gameplay_transcript(
            Transcript(path=transcript.path, events=tuple(events))
        )

        self.assertEqual(analysis.state.matched_heartbeat_responses, 0)
        self.assertEqual(analysis.state.unmatched_heartbeat_responses, 1)
        self.assertEqual(analysis.state.pending_heartbeat_probes, 1)
        self.assertEqual(len(analysis.warnings), 2)


if __name__ == "__main__":
    unittest.main()

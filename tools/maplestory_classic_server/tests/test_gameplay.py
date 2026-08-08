from __future__ import annotations

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gameplay import (  # noqa: E402
    GameplayPhase,
    analyze_gameplay_transcript,
    render_gameplay_analysis,
)
from maple_server.packets import (  # noqa: E402
    FieldLoadStage,
    FieldSnapshotEnvelope,
    HeartbeatAcknowledgement,
    HeartbeatRequest,
    MobMovementAcknowledgement,
    MobMovementSubmission,
    NpcSpawn,
    NpcStateUpdate,
    PacketShapeError,
    WorldBootstrapAcknowledgement,
    WorldEntryRequest,
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


def fixture_gameplay_transcript(*, repeat_npc_update: bool = False) -> Transcript:
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
            opaque_movement=b"sanitized-movement",
        ).to_bytes(),
    )
    append(
        "server_to_client",
        MobMovementAcknowledgement(
            object_id=MOB_OBJECT_ID,
            sequence=9,
            opaque_status=b"\x00" * 5,
        ).to_bytes(),
    )
    append(
        "client_to_server",
        HeartbeatRequest(opaque_token=b"\x00" * 8).to_bytes(),
    )
    append("server_to_client", HeartbeatAcknowledgement().to_bytes())
    if repeat_npc_update:
        append(
            "server_to_client",
            NpcStateUpdate(
                object_id=NPC_OBJECT_ID,
                action=3,
                parameter=1,
            ).to_bytes(),
        )
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
        submission = MobMovementSubmission(
            object_id=MOB_OBJECT_ID,
            sequence=42,
            opaque_movement=b"opaque",
        )
        acknowledgement = MobMovementAcknowledgement(
            object_id=MOB_OBJECT_ID,
            sequence=42,
            opaque_status=b"12345",
        )

        self.assertEqual(
            MobMovementSubmission.parse(submission.to_bytes()), submission
        )
        self.assertEqual(
            MobMovementAcknowledgement.parse(acknowledgement.to_bytes()),
            acknowledgement,
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
        self.assertEqual(analysis.state.movement_submissions, 1)
        self.assertEqual(analysis.state.matched_movement_acknowledgements, 1)
        self.assertEqual(analysis.state.pending_movements, 0)
        self.assertEqual(analysis.state.heartbeat_requests, 1)
        self.assertEqual(analysis.state.heartbeat_acknowledgements, 1)
        event_kinds = [event.kind for event in analysis.events]
        self.assertIn("field_snapshot_received", event_kinds)
        self.assertIn("npc_spawned", event_kinds)
        self.assertIn("npc_state_updated", event_kinds)
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

    def test_text_report_can_emit_events_and_packet_shapes(self) -> None:
        analysis = analyze_gameplay_transcript(fixture_gameplay_transcript())

        report = render_gameplay_analysis(
            analysis,
            show_events=True,
            show_packets=True,
        )

        self.assertIn("kind=npc_spawned", report)
        self.assertIn("opcode=300 kind=npc_spawn coverage=full", report)
        self.assertIn("matched_submission\":true", report)

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


if __name__ == "__main__":
    unittest.main()

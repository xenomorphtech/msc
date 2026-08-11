from __future__ import annotations

from ipaddress import IPv4Address
from pathlib import Path
import struct
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gamestate import (  # noqa: E402
    LoginPhase,
    ShapeCoverage,
    analyze_login_transcript,
    render_login_analysis,
)
from maple_server.packets import (  # noqa: E402
    AccountLoginResponse,
    ChannelRecord,
    ChannelSelection,
    ChannelTransitionResponse,
    CharacterListAppearance,
    CharacterListEnvelope,
    CharacterListRecord,
    CharacterLookEntry,
    CharacterSelection,
    ClientOpcode31Record,
    ClientStatusMessage,
    HeartbeatProbe,
    HeartbeatResponse,
    InitialCharacterSnapshot,
    PacketShapeError,
    Opcode13Ack,
    Opcode13Envelope,
    ServerTime,
    WorldHandoff,
    WorldListEnd,
    WorldRecord,
    WorldSelection,
)
from maple_server.pcap import (  # noqa: E402
    TcpEndpoint,
    TcpSegment,
    parse_tshark_tcp_segments,
    transcript_from_tcp_segments,
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


def fixture_account() -> AccountLoginResponse:
    return AccountLoginResponse(
        result=0,
        account_id=1234,
        gender=0,
        administrator=0,
        restricted=False,
        account_name="fixture-account",
        unknown_u16=0,
        account_flags=(0, 0, 0),
        created_at_ticks=0,
        secondary_name="",
        tertiary_name="",
    )


def fixture_world() -> WorldRecord:
    return WorldRecord(
        world_id=4,
        name="FixtureWorld",
        flag=1,
        event_description="test event",
        event_exp_rate=100,
        event_drop_rate=100,
        channels=(
            ChannelRecord(
                name="FixtureWorld-23",
                population=10,
                world_id=4,
                channel_id=23,
                adult_channel=False,
                unknown=200,
            ),
        ),
    )


def fixture_character_list() -> CharacterListEnvelope:
    snapshot = InitialCharacterSnapshot(
        character_id=300_001,
        data_flags=4,
        name="FixtureHero",
        gender=0,
        skin=1,
        face_id=20_000,
        hair_id=30_000,
        companion_id=0,
        level=12,
        job_id=200,
        strength=4,
        dexterity=4,
        intelligence=53,
        luck=14,
        current_hp=70,
        max_hp=222,
        current_mp=136,
        max_mp=342,
        ability_points=5,
        skill_points=0,
        experience=1_567,
        fame=0,
        map_id=101_000_000,
        portal_index=1,
        opaque_state_flag=0,
        opaque_state_u64=0,
    )
    return CharacterListEnvelope(
        result=0,
        records=(
            CharacterListRecord(
                snapshot=snapshot,
                appearance=CharacterListAppearance(
                    gender=snapshot.gender,
                    skin=snapshot.skin,
                    face_id=snapshot.face_id,
                    visible_entries=(
                        CharacterLookEntry(slot=0, item_id=snapshot.hair_id),
                        CharacterLookEntry(slot=5, item_id=1_041_006),
                    ),
                    masked_entries=(),
                    cash_weapon_id=0,
                    opaque_style_values=(5_000_046, 0, 0, 0, 0, 0, 0),
                ),
                entry_code=0,
            ),
        ),
        trailer_u8_1=2,
        trailer_u8_2=1,
        trailer_u32=3,
    )


def fixture_login_transcript(
    *,
    selected_channel: int = 23,
    transition_world: int = 4,
    selected_character: int = 300_001,
    heartbeat_rounds: int = 0,
    pending_heartbeat_probe: bool = False,
    opcode_31_record: ClientOpcode31Record | None = None,
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

    for round_index in range(heartbeat_rounds):
        append("server_to_client", HeartbeatProbe().to_bytes())
        append(
            "client_to_server",
            HeartbeatResponse(
                opaque_token=round_index.to_bytes(8, "little")
            ).to_bytes(),
        )
    if pending_heartbeat_probe:
        append("server_to_client", HeartbeatProbe().to_bytes())
    if opcode_31_record is not None:
        append("client_to_server", opcode_31_record.to_bytes())
    append("server_to_client", fixture_account().to_bytes())
    append("server_to_client", fixture_world().to_bytes())
    append("server_to_client", WorldListEnd().to_bytes())
    append("client_to_server", WorldSelection(world_id=4).to_bytes())
    append(
        "server_to_client",
        ChannelTransitionResponse(
            stage=0,
            transition_values=(267_748, 267_744),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        ChannelTransitionResponse(
            stage=1,
            world_id=transition_world,
        ).to_bytes(),
    )
    append(
        "client_to_server",
        ChannelSelection(
            world_id=4,
            channel_id=selected_channel,
            client_address=IPv4Address("192.0.2.10"),
        ).to_bytes(),
    )
    append(
        "server_to_client",
        fixture_character_list().to_bytes(),
    )
    append(
        "client_to_server",
        CharacterSelection(character_id=selected_character).to_bytes(),
    )
    append(
        "server_to_client",
        WorldHandoff(
            result=0,
            address=IPv4Address("127.0.0.1"),
            port=8587,
            character_id=300_001,
        ).to_bytes(),
    )
    events.append(TranscriptEvent(event="close", timestamp_ns=timestamp_ns))
    return Transcript(path=Path("sanitized-fixture.jsonl"), events=tuple(events))


class PacketShapeTest(unittest.TestCase):
    def test_client_opcode_31_variable_record_round_trip_and_redact(self) -> None:
        record = ClientOpcode31Record(
            reserved_prefix=b"\x00" * 20,
            variant=2,
            opaque_texts=("1234567890", "", "opaque-text"),
            opaque_blob=bytes(range(48)),
            reserved_suffix=b"\x00" * 3,
        )

        payload = record.to_bytes()
        parsed = ClientOpcode31Record.parse(payload)

        self.assertEqual(parsed, record)
        self.assertEqual(parsed.text_code_units, (10, 0, 11))
        self.assertEqual(parsed.safe_dict()["text_code_units"], [10, 0, 11])
        self.assertEqual(parsed.safe_dict()["opaque_blob_bytes"], 48)
        self.assertNotIn("1234567890", str(parsed.safe_dict()))
        self.assertNotIn("opaque-text", str(parsed.safe_dict()))
        with self.assertRaisesRegex(PacketShapeError, "variant must be 2"):
            ClientOpcode31Record(
                reserved_prefix=b"\x00" * 20,
                variant=1,
                opaque_texts=("", "", ""),
                opaque_blob=bytes(48),
                reserved_suffix=b"\x00" * 3,
            ).to_bytes()
        with self.assertRaisesRegex(PacketShapeError, "contain 48 bytes"):
            ClientOpcode31Record(
                reserved_prefix=b"\x00" * 20,
                variant=2,
                opaque_texts=("", "", ""),
                opaque_blob=bytes(47),
                reserved_suffix=b"\x00" * 3,
            ).to_bytes()

    def test_account_success_round_trip(self) -> None:
        account = fixture_account()
        self.assertEqual(AccountLoginResponse.parse(account.to_bytes()), account)

    def test_world_record_round_trip(self) -> None:
        world = fixture_world()
        parsed = WorldRecord.parse(world.to_bytes())
        self.assertEqual(parsed, world)
        self.assertEqual(len(parsed.channels), 1)
        self.assertEqual(parsed.channels[0].unknown, 200)

    def test_world_string_requires_observed_trailing_byte(self) -> None:
        malformed = (
            struct.pack("<HbH", 2, 4, 3)
            + "bad".encode("utf-16-le")
        )
        with self.assertRaisesRegex(PacketShapeError, "trailing_byte"):
            WorldRecord.parse(malformed)

    def test_handoff_round_trip_preserves_network_address_and_little_endian_port(
        self,
    ) -> None:
        handoff = WorldHandoff(
            result=0,
            address=IPv4Address("203.0.113.8"),
            port=8587,
            character_id=400_024,
        )
        payload = handoff.to_bytes()
        self.assertEqual(payload[4:8], IPv4Address("203.0.113.8").packed)
        self.assertEqual(payload[8:10], struct.pack("<H", 8587))
        self.assertEqual(WorldHandoff.parse(payload), handoff)

    def test_channel_transition_variants_round_trip(self) -> None:
        stage_zero = ChannelTransitionResponse(
            stage=0,
            transition_values=(267_748, 267_744),
        )
        stage_one = ChannelTransitionResponse(stage=1, world_id=4)

        self.assertEqual(len(stage_zero.to_bytes()), 12)
        self.assertEqual(len(stage_one.to_bytes()), 8)
        self.assertEqual(
            ChannelTransitionResponse.parse(stage_zero.to_bytes()), stage_zero
        )
        self.assertEqual(
            ChannelTransitionResponse.parse(stage_one.to_bytes()), stage_one
        )

    def test_character_list_records_round_trip_from_typed_state(self) -> None:
        character_list = fixture_character_list()

        parsed = CharacterListEnvelope.parse(character_list.to_bytes())

        self.assertEqual(parsed, character_list)
        self.assertEqual(len(parsed.records), 1)
        self.assertEqual(parsed.records[0].snapshot.character_id, 300_001)
        self.assertEqual(parsed.records[0].snapshot.name, "FixtureHero")
        self.assertEqual(parsed.records[0].appearance.hair_id, 30_000)

    def test_observed_empty_character_list_shape_round_trips(self) -> None:
        payload = bytes.fromhex("040000000000000000000000000103000000")

        parsed = CharacterListEnvelope.parse(payload)

        self.assertEqual(parsed.result, 0)
        self.assertEqual(parsed.records, ())
        self.assertEqual(parsed.to_bytes(), payload)

    def test_character_list_rejects_mismatched_appearance_identity(self) -> None:
        character_list = fixture_character_list()
        record = character_list.records[0]
        malformed = CharacterListRecord(
            snapshot=record.snapshot,
            appearance=CharacterListAppearance(
                gender=record.appearance.gender,
                skin=record.appearance.skin,
                face_id=record.appearance.face_id + 1,
                visible_entries=record.appearance.visible_entries,
                masked_entries=record.appearance.masked_entries,
                cash_weapon_id=record.appearance.cash_weapon_id,
                opaque_style_values=record.appearance.opaque_style_values,
            ),
            entry_code=record.entry_code,
        )

        with self.assertRaisesRegex(PacketShapeError, "does not match"):
            malformed.to_bytes()

    def test_opcode_13_envelopes_round_trip_and_validate_length(self) -> None:
        acknowledgment = Opcode13Ack(result=0)
        message = Opcode13Envelope(message_type=7, opaque_payload=b"message")

        self.assertEqual(Opcode13Ack.parse(acknowledgment.to_bytes()), acknowledgment)
        self.assertEqual(Opcode13Envelope.parse(message.to_bytes()), message)
        with self.assertRaisesRegex(PacketShapeError, "needs 7 bytes"):
            Opcode13Envelope.parse(message.to_bytes()[:-1])

    def test_client_status_message_round_trip(self) -> None:
        status = ClientStatusMessage(
            message="Please check the network connection status."
        )

        self.assertEqual(ClientStatusMessage.parse(status.to_bytes()), status)

    def test_server_time_round_trip(self) -> None:
        server_time = ServerTime(ticks=134_145_748_450_000_000)

        self.assertEqual(ServerTime.parse(server_time.to_bytes()), server_time)


class GameStateFoldTest(unittest.TestCase):
    def test_folds_sanitized_successful_login_to_handoff(self) -> None:
        analysis = analyze_login_transcript(fixture_login_transcript())

        self.assertTrue(analysis.valid)
        self.assertEqual(analysis.state.phase, LoginPhase.HANDOFF_READY)
        self.assertEqual(tuple(analysis.state.worlds), (4,))
        self.assertEqual(analysis.state.selected_world_id, 4)
        self.assertEqual(analysis.state.selected_channel_id, 23)
        self.assertEqual(analysis.state.selected_character_id, 300_001)
        self.assertEqual(analysis.state.handoff.port, 8587)
        partial = [
            observation
            for observation in analysis.observations
            if observation.coverage == ShapeCoverage.PARTIAL
        ]
        self.assertEqual(partial, [])
        self.assertEqual(len(analysis.state.character_list.records), 1)
        self.assertEqual(
            analysis.state.character_list.records[0].snapshot.character_id,
            300_001,
        )

    def test_correlates_login_heartbeat_probe_response_pairs(self) -> None:
        transcript = fixture_login_transcript(
            heartbeat_rounds=3,
            pending_heartbeat_probe=True,
        )
        transcript = Transcript(
            path=transcript.path,
            events=tuple(
                TranscriptEvent(
                    event=event.event,
                    timestamp_ns=event.timestamp_ns * 1_000_000,
                    direction=event.direction,
                    data=event.data,
                    metadata=event.metadata,
                )
                for event in transcript.events
            ),
        )

        analysis = analyze_login_transcript(transcript)

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.heartbeat_probes, 4)
        self.assertEqual(analysis.state.heartbeat_responses, 3)
        self.assertEqual(analysis.state.matched_heartbeat_responses, 3)
        self.assertEqual(analysis.state.unmatched_heartbeat_responses, 0)
        self.assertEqual(analysis.state.pending_heartbeat_probes, 1)
        self.assertEqual(analysis.state.last_heartbeat_round_trip_ms, 1.0)
        self.assertEqual(analysis.state.max_heartbeat_round_trip_ms, 1.0)
        responses = [
            observation
            for observation in analysis.observations
            if observation.kind == "heartbeat_response"
        ]
        self.assertEqual(len(responses), 3)
        self.assertTrue(
            all(response.details["matched_probe"] for response in responses)
        )
        self.assertTrue(
            all(response.details["round_trip_ms"] == 1.0 for response in responses)
        )
        self.assertTrue(
            all(response.coverage == ShapeCoverage.PARTIAL for response in responses)
        )
        self.assertTrue(
            all(
                set(response.details)
                == {"matched_probe", "opaque_token_bytes", "round_trip_ms"}
                for response in responses
            )
        )
        self.assertIn(
            "heartbeats=probes:4 responses:3 matched:3 unmatched:0 pending:1",
            render_login_analysis(analysis),
        )

    def test_folds_client_opcode_31_variable_record_without_content(self) -> None:
        record = ClientOpcode31Record(
            reserved_prefix=b"\x00" * 20,
            variant=2,
            opaque_texts=("1", "x" * 51, "y" * 5),
            opaque_blob=bytes(range(48)),
            reserved_suffix=b"\x00" * 3,
        )
        analysis = analyze_login_transcript(
            fixture_login_transcript(opcode_31_record=record)
        )

        self.assertTrue(analysis.valid, analysis.issues)
        self.assertEqual(analysis.state.client_opcode_31_records, 1)
        self.assertEqual(
            analysis.state.client_opcode_31_text_code_unit_patterns,
            {"1/51/5": 1},
        )
        self.assertEqual(analysis.state.client_opcode_31_opaque_blob_bytes, 48)
        observation = next(
            observation
            for observation in analysis.observations
            if observation.kind == "client_opcode_31_record"
        )
        self.assertEqual(observation.coverage, ShapeCoverage.PARTIAL)
        self.assertEqual(observation.details["text_code_units"], [1, 51, 5])
        self.assertEqual(observation.details["opaque_blob_bytes"], 48)
        self.assertNotIn("x" * 51, str(analysis.safe_dict()))
        self.assertNotIn("y" * 5, str(analysis.safe_dict()))
        self.assertIn(
            "client_opcode_31=records:1 text_patterns:{'1/51/5': 1} "
            "opaque_blob_bytes:48",
            render_login_analysis(analysis),
        )

    def test_rejects_character_selection_not_in_advertised_list(self) -> None:
        analysis = analyze_login_transcript(
            fixture_login_transcript(selected_character=300_002)
        )
        self.assertIn(
            "client selected a character not advertised by the server",
            analysis.issues,
        )

    def test_rejects_semantically_unadvertised_channel(self) -> None:
        analysis = analyze_login_transcript(
            fixture_login_transcript(selected_channel=99)
        )

        self.assertFalse(analysis.valid)
        self.assertIn(
            "client selected unadvertised channel 99 in world 4",
            analysis.issues,
        )

    def test_rejects_transition_for_different_world(self) -> None:
        analysis = analyze_login_transcript(
            fixture_login_transcript(transition_world=2)
        )

        self.assertFalse(analysis.valid)
        self.assertIn(
            "channel transition world 2 does not match selected world 4",
            analysis.issues,
        )

    def test_text_report_can_include_frame_aligned_packet_decoding(self) -> None:
        analysis = analyze_login_transcript(fixture_login_transcript())

        report = render_login_analysis(analysis, show_packets=True)

        self.assertIn(
            "opcode=402 kind=channel_transition coverage=full", report
        )
        self.assertIn('details={"stage":1,"world_id":4}', report)

    def test_safe_report_redacts_account_and_character_identifiers(self) -> None:
        analysis = analyze_login_transcript(fixture_login_transcript())

        safe = analysis.safe_dict()
        identifiers = analysis.safe_dict(show_identifiers=True)
        self.assertEqual(safe["state"]["account_id"], "present")
        self.assertEqual(safe["state"]["selected_character_id"], "present")
        self.assertEqual(identifiers["state"]["account_id"], 1234)
        self.assertEqual(
            identifiers["state"]["selected_character_id"], 300_001
        )


class PcapInputTest(unittest.TestCase):
    def test_parses_tshark_rows_without_a_shell(self) -> None:
        output = (
            "1700000000.000000001\t192.0.2.1\t50000\t"
            "198.51.100.2\t10282\t1\t01:02:03:04\n"
        )
        segments = parse_tshark_tcp_segments(output)

        self.assertEqual(segments[0].timestamp_ns, 1_700_000_000_000_000_001)
        self.assertEqual(segments[0].payload, bytes.fromhex("01020304"))

    def test_reassembles_pcap_segments_into_transcript_directions(self) -> None:
        client = TcpEndpoint("192.0.2.10", 50000)
        server = TcpEndpoint("198.51.100.20", 10282)
        segments = (
            TcpSegment(10, server, client, 1, HANDSHAKE[:10]),
            TcpSegment(11, client, server, 1, b"\x00\x00\x00\x00"),
            TcpSegment(12, server, client, 11, HANDSHAKE[10:]),
            TcpSegment(13, server, client, 1, HANDSHAKE[:10]),
        )

        transcript = transcript_from_tcp_segments(
            "fixture.pcapng", 7, segments
        )

        self.assertEqual(transcript.server_bytes, HANDSHAKE)
        self.assertEqual(transcript.client_bytes, b"\x00\x00\x00\x00")
        self.assertEqual(
            transcript.events[0].metadata["server_endpoint"], str(server)
        )

    def test_trims_transport_prelude_before_maple_handshake(self) -> None:
        client = TcpEndpoint("192.0.2.10", 50000)
        server = TcpEndpoint("198.51.100.20", 12324)
        segments = (
            TcpSegment(8, client, server, 1, b"pre!"),
            TcpSegment(9, server, client, 1, b"hello"),
            TcpSegment(10, server, client, 6, HANDSHAKE[:10]),
            TcpSegment(11, client, server, 5, b"\x00\x00\x00\x00"),
            TcpSegment(12, server, client, 16, HANDSHAKE[10:]),
        )

        transcript = transcript_from_tcp_segments(
            "fixture-with-prelude.pcapng", 126, segments
        )

        self.assertEqual(transcript.server_bytes, HANDSHAKE)
        self.assertEqual(transcript.client_bytes, b"\x00\x00\x00\x00")
        self.assertEqual(
            transcript.events[0].metadata["transport_prelude_bytes"],
            {"client_to_server": 4, "server_to_client": 5},
        )


if __name__ == "__main__":
    unittest.main()

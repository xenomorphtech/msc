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
)
from maple_server.packets import (  # noqa: E402
    AccountLoginResponse,
    ChannelRecord,
    ChannelSelection,
    CharacterListEnvelope,
    CharacterSelection,
    PacketShapeError,
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


def fixture_login_transcript(*, selected_channel: int = 23) -> Transcript:
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

    append("server_to_client", fixture_account().to_bytes())
    append("server_to_client", fixture_world().to_bytes())
    append("server_to_client", WorldListEnd().to_bytes())
    append("client_to_server", WorldSelection(world_id=4).to_bytes())
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
        CharacterListEnvelope(result=0, opaque_payload=b"fixture").to_bytes(),
    )
    append(
        "client_to_server", CharacterSelection(character_id=300_001).to_bytes()
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
        self.assertEqual([observation.kind for observation in partial], ["character_list"])

    def test_rejects_semantically_unadvertised_channel(self) -> None:
        analysis = analyze_login_transcript(
            fixture_login_transcript(selected_channel=99)
        )

        self.assertFalse(analysis.valid)
        self.assertIn(
            "client selected unadvertised channel 99 in world 4",
            analysis.issues,
        )

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


if __name__ == "__main__":
    unittest.main()

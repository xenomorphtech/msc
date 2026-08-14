from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from maple_server.gamestate import PlainFrame
from maple_server.login_audit import audit_login_pcap, render_login_pcap_audit
from maple_server.packets import CharacterListEnvelope
from maple_server.pcap import (
    PcapError,
    TcpEndpoint,
    TcpSegment,
    _assemble_source_stream,
    parse_tshark_tcp_stream_groups,
)
from maple_server.protocol import ProtocolError
from maple_server.server import build_parser


def tshark_row(
    tcp_stream: int,
    timestamp: str,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    sequence: int,
    payload_hex: str,
) -> str:
    return "\t".join(
        (
            str(tcp_stream),
            timestamp,
            source,
            str(source_port),
            destination,
            str(destination_port),
            str(sequence),
            payload_hex,
        )
    )


class PcapStreamGroupTest(unittest.TestCase):
    def test_groups_rows_by_sorted_tcp_stream(self) -> None:
        output = "\n".join(
            (
                tshark_row(
                    9,
                    "2.000000000",
                    "10.0.0.2",
                    50000,
                    "10.0.0.1",
                    10282,
                    7,
                    "03:04",
                ),
                tshark_row(
                    3,
                    "1.000000000",
                    "10.0.0.1",
                    10282,
                    "10.0.0.2",
                    50000,
                    1,
                    "01:02",
                ),
                tshark_row(
                    9,
                    "3.000000000",
                    "10.0.0.1",
                    10282,
                    "10.0.0.2",
                    50000,
                    11,
                    "05:06",
                ),
            )
        )

        groups = parse_tshark_tcp_stream_groups(output)

        self.assertEqual([stream for stream, _ in groups], [3, 9])
        self.assertEqual([len(segments) for _, segments in groups], [1, 2])
        self.assertEqual(groups[0][1][0].payload, b"\x01\x02")

    def test_rejects_malformed_or_empty_group_output(self) -> None:
        with self.assertRaises(PcapError):
            parse_tshark_tcp_stream_groups("")
        with self.assertRaises(PcapError):
            parse_tshark_tcp_stream_groups("3\ttoo\tfew")
        with self.assertRaises(PcapError):
            parse_tshark_tcp_stream_groups(
                tshark_row(
                    -1,
                    "1",
                    "10.0.0.1",
                    10282,
                    "10.0.0.2",
                    50000,
                    1,
                    "01",
                )
            )

    def test_empty_source_stream_is_a_bounded_pcap_error(self) -> None:
        with self.assertRaisesRegex(PcapError, "empty TCP source stream"):
            _assemble_source_stream(())


class LoginPcapAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        endpoint_a = TcpEndpoint("10.0.0.1", 10282)
        endpoint_b = TcpEndpoint("10.0.0.2", 50000)
        self.segment = TcpSegment(
            timestamp_ns=1,
            source=endpoint_a,
            destination=endpoint_b,
            sequence=1,
            payload=b"x",
        )

    def test_audit_counts_expected_failures_and_safe_character_lists(self) -> None:
        groups = tuple(
            (stream, (self.segment,)) for stream in (1, 2, 3, 4)
        )
        empty_list = CharacterListEnvelope(result=0).to_bytes()

        def reconstruct(_path: Path, stream: int, _segments: object) -> object:
            if stream == 1:
                raise PcapError("not a Maple stream")
            return SimpleNamespace(tcp_stream=stream)

        def decode(transcript: object) -> object:
            stream = transcript.tcp_stream
            if stream == 2:
                raise ProtocolError("incomplete encrypted frame")
            plaintext = empty_list if stream == 3 else b"\x04\x00\x00"
            return SimpleNamespace(
                frames=(
                    PlainFrame(
                        index=0,
                        direction_index=7,
                        timestamp_ns=1,
                        direction="server_to_client",
                        wire_offset=0,
                        wire_length=len(plaintext) + 4,
                        plaintext=plaintext,
                    ),
                )
            )

        with (
            patch(
                "maple_server.login_audit.read_pcap_tcp_stream_groups",
                return_value=groups,
            ),
            patch(
                "maple_server.login_audit.transcript_from_tcp_segments",
                side_effect=reconstruct,
            ),
            patch(
                "maple_server.login_audit.decode_transcript",
                side_effect=decode,
            ),
        ):
            audit = audit_login_pcap("capture.pcapng", 10282)

        self.assertEqual(audit.payload_rows, 4)
        self.assertEqual(audit.tcp_streams, 4)
        self.assertEqual(audit.reconstructed_streams, 3)
        self.assertEqual(audit.decoded_streams, 2)
        self.assertEqual(audit.reconstruction_failures, 1)
        self.assertEqual(audit.decode_failures, 1)
        self.assertEqual(audit.invalid_character_list_packets, 1)
        self.assertEqual(audit.observed_character_counts, (0,))
        self.assertEqual(audit.observed_ranking_present_values, ())
        self.assertFalse(audit.has_ranked_or_multi_character_variant)
        self.assertEqual(len(audit.character_lists), 1)
        packet = audit.character_lists[0]
        self.assertEqual(packet.tcp_stream, 3)
        self.assertEqual(packet.server_frame_index, 7)
        self.assertEqual(packet.character_count, 0)
        self.assertTrue(packet.exact_round_trip)
        self.assertNotIn("character_id", str(audit.safe_dict()))
        self.assertNotIn("name", str(audit.safe_dict()))

        report = render_login_pcap_audit(audit)
        self.assertIn("4 payload rows / 4 TCP streams", report)
        self.assertIn("stream 3 frame 7", report)
        self.assertIn("has_ranked_or_multi_character_variant: no", report)

    def test_parser_accepts_all_stream_login_audit_gates(self) -> None:
        arguments = build_parser().parse_args(
            (
                "audit-login-pcap",
                "--pcap",
                "capture.pcapng",
                "--server-port",
                "12324",
                "--tshark",
                "/opt/tshark",
                "--json",
                "--require-character-list",
                "--require-ranked-or-multi-character",
            )
        )

        self.assertEqual(arguments.command, "audit-login-pcap")
        self.assertEqual(arguments.pcap, Path("capture.pcapng"))
        self.assertEqual(arguments.server_port, 12324)
        self.assertEqual(arguments.tshark, "/opt/tshark")
        self.assertTrue(arguments.json)
        self.assertTrue(arguments.require_character_list)
        self.assertTrue(arguments.require_ranked_or_multi_character)


if __name__ == "__main__":
    unittest.main()

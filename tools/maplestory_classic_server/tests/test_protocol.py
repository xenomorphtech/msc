from __future__ import annotations

from pathlib import Path
import struct
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.protocol import (  # noqa: E402
    ProtocolError,
    crypt_payload,
    decode_frame_length,
    encode_frame_header,
    parse_encrypted_frames,
    parse_handshake,
    shuffle_iv,
)


class ProtocolTest(unittest.TestCase):
    def test_parses_observed_handshake_layout(self) -> None:
        handshake_bytes = bytes.fromhex(
            "1f00 2c01 0300 330030003000 6e3c795a 885db958 04 "
            "2c010000 2c010000 00000000"
        )

        handshake = parse_handshake(handshake_bytes)

        self.assertEqual(handshake.packet_length, 31)
        self.assertEqual(handshake.wire_length, 33)
        self.assertEqual(handshake.version, 300)
        self.assertEqual(handshake.subversion, "300")
        self.assertEqual(handshake.first_iv, bytes.fromhex("6e3c795a"))
        self.assertEqual(handshake.second_iv, bytes.fromhex("885db958"))
        self.assertEqual(handshake.locale, 4)
        self.assertEqual(
            handshake.trailing, bytes.fromhex("2c0100002c01000000000000")
        )

    def test_decodes_and_splits_frame_stream(self) -> None:
        def frame(payload: bytes, first_word: int) -> bytes:
            second_word = first_word ^ len(payload)
            return struct.pack("<HH", first_word, second_word) + payload

        stream = frame(b"one", 0x1234) + frame(b"second", 0xABCD)
        frames = parse_encrypted_frames(stream)

        self.assertEqual(tuple(item.payload for item in frames), (b"one", b"second"))
        self.assertEqual(decode_frame_length(frames[0].header), 3)
        self.assertEqual(tuple(item.offset for item in frames), (0, 7))

    def test_rejects_truncated_frame(self) -> None:
        with self.assertRaisesRegex(ProtocolError, "declares 8 payload bytes"):
            parse_encrypted_frames(struct.pack("<HH", 0x1111, 0x1119) + b"short")

    def test_encrypts_observed_client_payload(self) -> None:
        plaintext = bytes.fromhex(
            "1f00000000000000000000000000000000000000000002010031000033003300"
            "2f0031002e00310033002e0036002f0031002e0030002e0030002f0064003300"
            "6100360033003800630061002d0031003600620030002d003400300033003100"
            "2d0039003800630063002d003000640035003700350038006300360065003400"
            "66003800000500640075006d006d00790000300000000e2d592d191d2a2d5b"
            "2d2d30492d471d492d6d2d2d2d902d891d5a2d612d102d2230231d1c2d252d"
            "2d2d1d2d031d612d000000"
        )
        encrypted = bytes.fromhex(
            "13fc69ed96595d6b3a71b7eb85a5a13752f8a0d4fc265d5a57c8aeb4e53d08e"
            "356c3a38a0e19e9898bde11b0be9621607578fd52ceba04145cf21ed4268965e"
            "7060c29008d3075d35b4df0e5c4b8009563321dd78614acb7daacaab4f4f5c73"
            "eee8a677578dbf8459adf7f94945372e722bfc6ca011592b74907dcb044f113dd"
            "94a1f27a465f1e67a4cf795c9b530999b25ab434b59ea0f307e8f93e85c6fd78"
            "9028c04bd9f403a7a19005f53321b315102e7f977f42208ea4601eb9d4592d58"
            "5762aa0796aeb62712"
        )
        iv = bytes.fromhex("6e3c795a")

        self.assertEqual(crypt_payload(plaintext, iv), encrypted)
        self.assertEqual(crypt_payload(encrypted, iv), plaintext)

    def test_builds_observed_directional_headers(self) -> None:
        self.assertEqual(
            encode_frame_header(275, bytes.fromhex("6e3c795a"), 3),
            bytes.fromhex("7a5a695b"),
        )
        self.assertEqual(
            encode_frame_header(27, bytes.fromhex("885db958"), ~300),
            bytes.fromhex("6aa671a6"),
        )

    def test_shuffles_observed_client_iv_sequence(self) -> None:
        first = shuffle_iv(bytes.fromhex("6e3c795a"))
        second = shuffle_iv(first)

        self.assertEqual(first, bytes.fromhex("25954910"))
        self.assertEqual(second, bytes.fromhex("0abdbba5"))


if __name__ == "__main__":
    unittest.main()

import struct
import unittest

from decode import (Segment, crypt_aes, decode_stream, decrypt_direction,
                    parse_greeting, reassemble, shuffle_iv)


class DecodeTests(unittest.TestCase):
    def segment(self, seq, data, number=1):
        return Segment(number, number * 1000, "client:1", "server:2", seq, data)

    def test_binary_derived_key_capture_vector(self):
        # Stream 61's first server packet, containing no account/session values.
        self.assertEqual(crypt_aes(bytes.fromhex("5447f32f442643"),
                                   bytes.fromhex("7156bc60")),
                         bytes.fromhex("20000000000000"))

    def test_shuffle_capture_headers(self):
        # The second server frame starts fa764a76; its mask is 0xfffe.
        iv = shuffle_iv(bytes.fromhex("7156bc60"))
        self.assertEqual(int.from_bytes(iv[2:], "little") ^ 0xfffe, 0x76fa)

    def test_reassembly_reordering_overlap_and_sequence_wrap(self):
        segments = [self.segment(0xfffffffe, b"abcd", 2),
                    self.segment(0, b"cdef", 1)]
        data, spans, evidence = reassemble(segments)
        self.assertEqual(data, b"abcdef")
        self.assertEqual(evidence["identical_overlap_bytes"], 2)
        self.assertEqual([(start, end, s.number) for start, end, s in spans],
                         [(0, 2, 2), (2, 6, 1)])

    def test_gap_and_conflicting_overlap_fail(self):
        with self.assertRaisesRegex(ValueError, "gap"):
            reassemble([self.segment(1, b"ab"), self.segment(4, b"d", 2)])
        with self.assertRaisesRegex(ValueError, "conflicting"):
            reassemble([self.segment(1, b"ab"), self.segment(2, b"x", 2)])

    def test_reject_partial_frame_and_wrong_iv(self):
        data = bytes.fromhex("429f459f5447f32f442643")
        segment = self.segment(0, data)
        spans = [(0, len(data), segment)]
        args = ("aes256_ofb", 0xfffe, 61, "server_to_client", spans)
        with self.assertRaisesRegex(ValueError, "IV/header"):
            decrypt_direction(data, 0, bytes(4), *args)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            decrypt_direction(data[:-1], 0, bytes.fromhex("7156bc60"), *args)

    def test_additive_mode_and_full_consumption(self):
        iv = bytes.fromhex("67984b14")
        plaintexts = [bytes.fromhex("2b060000"), bytes.fromhex("4f0000")]
        wire = bytearray()
        for plain in plaintexts:
            first = int.from_bytes(iv[2:], "little") ^ 0xfffe
            wire += struct.pack("<HH", first, first ^ len(plain))
            wire += bytes((v + iv[0]) & 255 for v in plain)
            iv = shuffle_iv(iv)
        data = bytes(wire)
        rows = decrypt_direction(data, 0, bytes.fromhex("67984b14"),
                                 "add_iv_byte", 0xfffe, 91, "server_to_client",
                                 [(0, len(data), self.segment(0, data))])
        self.assertEqual([bytes.fromhex(r["plaintext_hex"]) for r in rows], plaintexts)
        self.assertEqual(sum(r["wire_length"] for r in rows), len(data))

    def test_native_greeting_variants(self):
        legacy = bytes.fromhex("100001000300303a300b583a2e7156bc6001")
        extended = bytes.fromhex("1300010001000000010030b079ec9967984b140104")
        self.assertEqual(parse_greeting(legacy)["subversion"], "0:0")
        parsed = parse_greeting(extended)
        self.assertEqual(parsed["client_iv"], bytes.fromhex("b079ec99"))
        self.assertEqual(parsed["server_iv"], bytes.fromhex("67984b14"))
        self.assertEqual(parsed["trailing_hex"], "04")

    def test_unknown_cipher_profile_is_rejected(self):
        greeting = bytes.fromhex("1300010001000000010030b079ec9967984b140105")
        segments = [Segment(1, 0, "server:2", "client:1", 100, greeting),
                    self.segment(200, b"abcd", 2)]
        with self.assertRaisesRegex(ValueError, "unsupported native"):
            decode_stream(1, segments)


if __name__ == "__main__":
    unittest.main()

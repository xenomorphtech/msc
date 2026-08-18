from __future__ import annotations

import os
from pathlib import Path
import unittest


from maple_server.security_type1 import (
    SecurityType1Unicorn,
    build_security_type1_packet,
    security_type1_triggered,
    security_type1_value,
)


class SecurityType1Test(unittest.TestCase):
    def test_matches_observed_iv_value_pairs(self) -> None:
        pairs = (
            ("f2b30b1b", 0xE3B72C49),
            ("083d7daa", 0x6FB7A811),
            ("f6466bf2", 0x38EE9B82),
            ("d900148f", 0x8BCAAD49),
        )
        for iv_hex, expected in pairs:
            with self.subTest(iv=iv_hex):
                self.assertEqual(security_type1_value(bytes.fromhex(iv_hex)), expected)

    def test_builds_observed_eleven_byte_envelope(self) -> None:
        packet = build_security_type1_packet(bytes.fromhex("f2b30b1b"))

        self.assertEqual(packet.hex(), "0d0001492cb7e300000000")
        self.assertEqual(len(packet), 11)

    def test_trigger_uses_low_uint16_modulo_31(self) -> None:
        self.assertTrue(security_type1_triggered(bytes.fromhex("f2b30b1b")))
        self.assertFalse(security_type1_triggered(bytes.fromhex("01000000")))

    @unittest.skipUnless(
        os.environ.get("MAPLE_GAME_ASSEMBLY"),
        "set MAPLE_GAME_ASSEMBLY for the native Unicorn integration test",
    )
    def test_unicorn_executes_original_native_helper(self) -> None:
        emulator = SecurityType1Unicorn(Path(os.environ["MAPLE_GAME_ASSEMBLY"]))

        for iv_hex in ("f2b30b1b", "083d7daa", "f6466bf2", "d900148f"):
            iv = bytes.fromhex(iv_hex)
            with self.subTest(iv=iv_hex):
                self.assertEqual(emulator.compute(iv), security_type1_value(iv))
                self.assertEqual(emulator.packet(iv), build_security_type1_packet(iv))


if __name__ == "__main__":
    unittest.main()

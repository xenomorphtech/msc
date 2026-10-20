from pathlib import Path
import unittest

from patch import ORIGINAL_SHA256, PATCHES, digest, patch


SOURCE = Path(__file__).resolve().parents[3] / "maplestorycw/appdata/MapleStory.exe"


@unittest.skipUnless(SOURCE.is_file(), "private reference executable is absent")
class PatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = SOURCE.read_bytes()

    def test_wrong_version_fails_closed(self):
        wrong = bytearray(self.original)
        wrong[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "source hash"):
            patch(bytes(wrong), ["loopback-login"])

    def test_only_declared_bytes_change_and_restore_exactly(self):
        modified, manifest = patch(self.original, list(PATCHES))
        restored = bytearray(modified)
        for change in manifest:
            offset = int(change["file_offset"], 16)
            expected = bytes.fromhex(change["original_hex"])
            restored[offset:offset + len(expected)] = expected
        self.assertEqual(bytes(restored), self.original)
        self.assertEqual(len(modified), len(self.original))
        self.assertEqual(digest(self.original), ORIGINAL_SHA256)


if __name__ == "__main__":
    unittest.main()

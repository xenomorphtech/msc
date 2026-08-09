from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = (
    Path(__file__).parents[1] / "tools" / "send_wayland_evdev_key.py"
)
SPEC = importlib.util.spec_from_file_location("send_wayland_evdev_key", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
send_wayland_evdev_key = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(send_wayland_evdev_key)


class SendWaylandEvdevKeyTest(unittest.TestCase):
    def test_resolves_named_physical_keys(self) -> None:
        self.assertEqual(send_wayland_evdev_key.resolve_keycode("escape"), 1)
        self.assertEqual(send_wayland_evdev_key.resolve_keycode("KEY_LEFTCTRL"), 29)
        self.assertEqual(send_wayland_evdev_key.resolve_keycode("insert"), 110)

    def test_accepts_numeric_evdev_keycode(self) -> None:
        self.assertEqual(send_wayland_evdev_key.resolve_keycode("1"), 1)
        self.assertEqual(send_wayland_evdev_key.resolve_keycode("0x1d"), 29)

    def test_rejects_unknown_or_out_of_range_keycode(self) -> None:
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "unknown key"):
            send_wayland_evdev_key.resolve_keycode("not-a-key")
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "between 0"):
            send_wayland_evdev_key.resolve_keycode("0x300")


if __name__ == "__main__":
    unittest.main()

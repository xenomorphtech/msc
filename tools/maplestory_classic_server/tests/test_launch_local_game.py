from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "tools/launch_local_game.py"
SPEC = importlib.util.spec_from_file_location("launch_local_game", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
launch_local_game = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launch_local_game)


class LaunchLocalGameTest(unittest.TestCase):
    def test_selects_only_active_nested_x11_sway_socket(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime_directory = Path(directory)
            nested = runtime_directory / "sway-ipc.1000.123.sock"
            host = runtime_directory / "sway-ipc.1000.456.sock"
            nested.touch()
            host.touch()
            responses = {
                str(nested): [{"active": True, "name": "X11-1"}],
                str(host): [{"active": True, "name": "DP-1"}],
            }

            def outputs(command: list[str]) -> str:
                return json.dumps(responses[command[2]])

            with patch.object(launch_local_game, "command_output", side_effect=outputs):
                self.assertEqual(
                    launch_local_game.nested_sway_socket(runtime_directory), nested
                )

    def test_finds_maplestory_window_in_floating_sway_tree(self) -> None:
        tree = {
            "nodes": [],
            "floating_nodes": [
                {
                    "id": 42,
                    "pid": 1001,
                    "window_properties": {"class": "maplestory_classic.exe"},
                    "nodes": [],
                    "floating_nodes": [],
                }
            ],
        }
        with patch.object(
            launch_local_game, "command_output", return_value=json.dumps(tree)
        ):
            self.assertTrue(
                launch_local_game.window_is_ready(
                    Path("sway.sock"), {1001}
                )
            )
            self.assertEqual(
                launch_local_game.maple_window_id(
                    Path("sway.sock"), {1001}
                ),
                42,
            )
            self.assertFalse(
                launch_local_game.window_is_ready(
                    Path("sway.sock"), {9999}
                )
            )

    def test_launch_uses_only_local_placeholder_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "prefix"
            executable = (
                prefix
                / "drive_c/Program Files/Gamania/maplestory_classic/Maplestory_Classic.exe"
            )
            executable.parent.mkdir(parents=True)
            executable.touch()
            patched_httpapi = prefix / "drive_c/windows/system32/httpapi.dll"
            patched_httpapi.parent.mkdir(parents=True)
            patched_httpapi.touch()
            wine_log = root / "wine.log"
            with patch.object(
                launch_local_game.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0),
            ) as run:
                launch_local_game.launch_game(
                    namespace="mapleproxy",
                    username="player",
                    uid=1000,
                    display=":1",
                    xauthority=Path("/home/player/.Xauthority"),
                    prefix=prefix,
                    wine_log=wine_log,
                )

            command = run.call_args.args[0]
            self.assertEqual(command[-4:], ["1", "dummy", "1", "1"])
            self.assertIn(
                f"MAPLE_PATCHED_HTTPAPI={patched_httpapi}", command
            )
            wrapper_index = command.index(
                str(launch_local_game.HTTPAPI_COMPATIBILITY_WRAPPER)
            )
            self.assertLess(wrapper_index, command.index("wine"))
            joined = " ".join(command).lower()
            self.assertNotIn("chromium", joined)
            self.assertNotIn("cdp", joined)
            self.assertNotIn("ngm", joined)
            self.assertNotIn("beanfun", joined)

    def test_launch_requires_patched_httpapi_compatibility_dll(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "prefix"
            executable = (
                prefix
                / "drive_c/Program Files/Gamania/maplestory_classic/Maplestory_Classic.exe"
            )
            executable.parent.mkdir(parents=True)
            executable.touch()

            with self.assertRaisesRegex(
                RuntimeError, "compatibility DLL does not exist"
            ):
                launch_local_game.launch_game(
                    namespace="mapleproxy",
                    username="player",
                    uid=1000,
                    display=":1",
                    xauthority=Path("/home/player/.Xauthority"),
                    prefix=prefix,
                    wine_log=Path(directory) / "wine.log",
                )


if __name__ == "__main__":
    unittest.main()

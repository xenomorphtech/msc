from __future__ import annotations

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.audio_mute import (  # noqa: E402
    find_maplestory_audio_nodes,
    is_maplestory_audio_node,
)


class AudioMuteTest(unittest.TestCase):
    def test_matches_maplestory_output_by_application_name(self) -> None:
        self.assertTrue(
            is_maplestory_audio_node(
                {
                    "media.class": "Stream/Output/Audio",
                    "application.name": "Maplestory_Classic.exe",
                    "application.process.binary": "wine-preloader",
                }
            )
        )

    def test_does_not_match_other_apps_or_input_streams(self) -> None:
        self.assertFalse(
            is_maplestory_audio_node(
                {
                    "media.class": "Stream/Output/Audio",
                    "application.name": "scrcpy",
                }
            )
        )
        self.assertFalse(
            is_maplestory_audio_node(
                {
                    "media.class": "Stream/Input/Audio",
                    "application.name": "Maplestory_Classic.exe",
                }
            )
        )

    def test_extracts_only_unique_matching_node_ids(self) -> None:
        snapshot = [
            {
                "id": 89,
                "type": "PipeWire:Interface:Node",
                "info": {
                    "props": {
                        "media.class": "Stream/Output/Audio",
                        "application.name": "Maplestory_Classic.exe",
                    }
                },
            },
            {
                "id": 72,
                "type": "PipeWire:Interface:Node",
                "info": {
                    "props": {
                        "media.class": "Stream/Output/Audio",
                        "application.name": "scrcpy",
                    }
                },
            },
        ]

        self.assertEqual(find_maplestory_audio_nodes(snapshot), (89,))


if __name__ == "__main__":
    unittest.main()

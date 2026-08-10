from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.gamestate import ShapeCoverage  # noqa: E402
from maple_server.live_replay import (  # noqa: E402
    DEFAULT_PACKET_API_URL,
    inject_current_hp_live,
    validate_packet_api_url,
)


def state(*, current_hp: int, player_stat_updates: int) -> SimpleNamespace:
    return SimpleNamespace(
        current_hp=current_hp,
        max_hp=222,
        phase="active",
        field_epoch=1,
        map_id=101000000,
        inventory_items={"use": ("unchanged",)},
        skill_levels={2001002: 1},
        string_property_code_units={1: 3},
        timestamp_property_keys=(1,),
        saved_map_ids=(101000000,),
        extended_property_code_units={2: 4},
        progression_variant=23,
        progression_shape="marker_23",
        experience=1464,
        character_level=12,
        job_id=200,
        current_mp=97,
        max_mp=342,
        strength=4,
        dexterity=4,
        intelligence=57,
        luck=15,
        ability_points=0,
        skill_points=0,
        fame=0,
        mesos=4567,
        player_stat_updates=player_stat_updates,
    )


class LiveReplayTest(unittest.TestCase):
    def test_packet_api_url_is_fixed_to_loopback_plain_http(self) -> None:
        self.assertEqual(
            validate_packet_api_url(DEFAULT_PACKET_API_URL),
            DEFAULT_PACKET_API_URL,
        )
        self.assertEqual(
            validate_packet_api_url(
                "http://[::1]:12858/api/v1/server-packets"
            ),
            "http://[::1]:12858/api/v1/server-packets",
        )
        for value in (
            "https://127.0.0.1:12858/api/v1/server-packets",
            "http://10.0.0.2:12858/api/v1/server-packets",
            "http://127.0.0.1:12858/api/v1/status",
            "http://user@127.0.0.1:12858/api/v1/server-packets",
            "http://127.0.0.1:12858/api/v1/server-packets?raw=1",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_packet_api_url(value)

    def test_live_hp_injection_requires_the_predicted_observed_fold(self) -> None:
        baseline = SimpleNamespace(
            valid=True,
            state=state(current_hp=50, player_stat_updates=1),
            observations=(),
        )
        observation = SimpleNamespace(
            direction="server_to_client",
            opcode=41,
            details={
                "stat_mask": "0x00000400",
                "changes": {
                    "current_hp": {"previous": 50, "current": 49}
                },
            },
            frame_index=81,
            kind="character_stat_update",
            coverage=ShapeCoverage.PARTIAL,
        )
        observed = SimpleNamespace(
            valid=True,
            state=state(current_hp=49, player_stat_updates=2),
            observations=(observation,),
        )
        update = SimpleNamespace(to_bytes=lambda: bytes.fromhex("29000000040000310000"))
        plan = SimpleNamespace(
            update=update,
            safe_dict=lambda: {
                "original_current_hp": 50,
                "emitted_current_hp": 49,
                "max_hp": 222,
            },
        )
        api_response = {
            "accepted": True,
            "opcode": 41,
            "plaintext_length": 10,
        }

        with (
            patch("maple_server.live_replay.Transcript.load", return_value=object()),
            patch(
                "maple_server.live_replay.analyze_gameplay_transcript",
                side_effect=(baseline, observed),
            ),
            patch(
                "maple_server.live_replay.plan_current_hp_stat_update",
                return_value=plan,
            ),
            patch(
                "maple_server.live_replay._post_plaintext_packet",
                return_value=api_response,
            ) as post,
        ):
            result = inject_current_hp_live(Path("live.jsonl"), 49)

        post.assert_called_once_with(
            DEFAULT_PACKET_API_URL,
            bytes.fromhex("29000000040000310000"),
            timeout_seconds=5.0,
        )
        report = result.safe_dict()
        self.assertTrue(report["verification"]["matched"])
        self.assertEqual(report["verification"]["observed_current_hp"], 49)
        self.assertEqual(
            report["verification"]["observed_packet"]["frame_index"], 81
        )

    def test_live_hp_injection_rejects_a_noop_before_posting(self) -> None:
        baseline = SimpleNamespace(
            valid=True,
            state=state(current_hp=50, player_stat_updates=1),
            observations=(),
        )
        with (
            patch("maple_server.live_replay.Transcript.load", return_value=object()),
            patch(
                "maple_server.live_replay.analyze_gameplay_transcript",
                return_value=baseline,
            ),
            patch("maple_server.live_replay._post_plaintext_packet") as post,
            self.assertRaisesRegex(ValueError, "must differ"),
        ):
            inject_current_hp_live(Path("live.jsonl"), 50)

        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()

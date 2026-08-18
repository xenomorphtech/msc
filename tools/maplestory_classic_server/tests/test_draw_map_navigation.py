from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "tools/draw_map_navigation.py"
SPEC = importlib.util.spec_from_file_location("draw_map_navigation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
draw_map_navigation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(draw_map_navigation)


class MapNavigationTest(unittest.TestCase):
    def test_flattens_and_renders_footholds_ladders_ropes_and_portals(self) -> None:
        document = {
            "foothold": {
                "0": {
                    "4": {
                        "7": {
                            "x1": 10,
                            "y1": 20,
                            "x2": 100,
                            "y2": 30,
                            "prev": 0,
                            "next": 8,
                        }
                    }
                }
            },
            "ladderRope": {
                "1": {"x": 30, "y1": 10, "y2": 90, "l": 1},
                "2": {"x": 80, "y1": 0, "y2": 50, "l": 0},
            },
            "portal": {"0": {"x": 50, "y": 25, "pn": "sp"}},
        }
        footholds = draw_map_navigation.flatten_footholds(document)
        ladder_ropes = draw_map_navigation.flatten_ladder_ropes(document)
        portals = draw_map_navigation.flatten_portals(document)
        self.assertEqual(footholds[0]["id"], 7)
        self.assertEqual(footholds[0]["layer"], 0)
        self.assertEqual(footholds[0]["group"], 4)
        svg = draw_map_navigation.render_navigation_svg(
            "100000000", footholds, ladder_ropes, portals, 800
        )
        self.assertIn('class="platform"', svg)
        self.assertIn('<title>ladder 1</title>', svg)
        self.assertIn('<title>rope 2</title>', svg)
        self.assertIn('<title>portal sp</title>', svg)

    def test_follows_geometry_link_and_preserves_requested_payload(self) -> None:
        requested = SimpleNamespace(
            root_path="Map/Map/Map9/910010001",
            document={"info": {"link": "910010000", "town": 0}},
        )
        linked = SimpleNamespace(
            root_path="Map/Map/Map9/910010000",
            document={
                "foothold": {
                    "0": {
                        "0": {
                            "1": {
                                "x1": 0,
                                "y1": 0,
                                "x2": 100,
                                "y2": 0,
                                "prev": 0,
                                "next": 0,
                            }
                        }
                    }
                },
                "ladderRope": {},
                "portal": {},
                "info": {"town": 0},
                "miniMap": {"canvas": None, "width": 100},
            },
        )
        calls = {
            "910010001": (
                "requested.bundle",
                "Assets/WzAssets/Json/Map/Map/Map9/910010001.wzjson",
                b"requested-payload",
                requested,
            ),
            "910010000": (
                "geometry.bundle",
                "Assets/WzAssets/Json/Map/Map/Map9/910010000.wzjson",
                b"geometry-payload",
                linked,
            ),
        }
        with tempfile.TemporaryDirectory() as directory, patch.object(
            draw_map_navigation,
            "find_map_asset",
            side_effect=lambda _root, map_id: calls[map_id],
        ):
            output = Path(directory)
            geometry = draw_map_navigation.draw_map(
                Path("unused"), output, "910010001", 800
            )
            self.assertEqual(
                geometry["geometry_link_chain"], ["910010001", "910010000"]
            )
            self.assertEqual(geometry["geometry_source_bundle"], "geometry.bundle")
            self.assertEqual(
                (output / "910010001.wzjson").read_bytes(), b"requested-payload"
            )
            self.assertNotIn("canvas", geometry["mini_map"])

    def test_normalizes_map_id(self) -> None:
        self.assertEqual(draw_map_navigation.normalize_map_id("30000"), "000030000")
        with self.assertRaises(draw_map_navigation.NavigationDrawError):
            draw_map_navigation.normalize_map_id("Henesys")


if __name__ == "__main__":
    unittest.main()

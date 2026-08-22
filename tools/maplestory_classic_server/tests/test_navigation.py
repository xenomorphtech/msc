from __future__ import annotations

from pathlib import Path
import unittest


from maple_server.navigation import (
    MOB_LIFECYCLE_SERVER_OPCODES,
    LocalPathfinder,
    audit_map,
    load_world_maps,
)


NAVIGATION = (
    Path(__file__).resolve().parents[3]
    / "downloads/maplestory_classic_navigation"
)
WORLD = Path("/home/sdancer/ms4/knowledge/world-v300.json")


class NavigationGeometryTest(unittest.TestCase):
    def test_maple_island_spawn_can_walk_and_climb(self) -> None:
        path = NAVIGATION / "000030000.json"
        if not path.is_file():
            self.skipTest("000030000 navigation JSON is not present")
        geometry = load_world_maps(path)[0]
        pathfinder = LocalPathfinder(geometry)
        spawn = next(portal for portal in geometry.portals if portal.is_spawn)
        landing = geometry.landing_below(spawn.position)
        self.assertIsNotNone(landing)
        start = landing[0]
        reachable = pathfinder.reachable_foothold_ids(start)
        self.assertGreater(len(reachable), 10)
        travel = [portal for portal in geometry.portals if portal.is_travel]
        self.assertTrue(travel)
        route = pathfinder.route(start, travel[0].position)
        self.assertTrue(any(step.mode in {"walk", "jump", "climb", "drop"} for step in route) or route == ())

    def test_audit_marks_complete_or_reports_gaps(self) -> None:
        path = NAVIGATION / "000030000.json"
        if not path.is_file():
            self.skipTest("000030000 navigation JSON is not present")
        report = audit_map(load_world_maps(path)[0])
        self.assertEqual(report["map_id"], 30000)
        self.assertGreater(report["reachable_footholds"], 0)
        self.assertIn("complete", report)


class MobOmitTest(unittest.TestCase):
    def test_lifecycle_opcodes_cover_spawn_and_combat_relays(self) -> None:
        self.assertEqual(
            MOB_LIFECYCLE_SERVER_OPCODES,
            frozenset({218, 219, 279, 280, 281, 282, 285, 286, 293}),
        )


class WorldKnowledgeTest(unittest.TestCase):
    def test_ellinia_has_ladders_and_travel_portals(self) -> None:
        if not WORLD.is_file():
            self.skipTest("world-v300.json is not present")
        maps = {item.map_id: item for item in load_world_maps(WORLD)}
        ellinia = maps[101_000_000]
        self.assertGreater(len(ellinia.ladder_ropes), 10)
        self.assertTrue(any(portal.is_travel for portal in ellinia.portals))
        report = audit_map(ellinia)
        self.assertGreater(report["reachable_travel_portals"], 0)
        self.assertGreater(report["reachable_ladder_ropes"], 0)

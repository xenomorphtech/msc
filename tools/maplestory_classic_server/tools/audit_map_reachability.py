#!/usr/bin/env python3
"""Audit walk/jump/climb/drop reachability for extracted Maple maps."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


SERVER_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SERVER_ROOT.parents[1]
DEFAULT_WORLD = Path("/home/sdancer/ms4/knowledge/world-v300.json")
DEFAULT_NAVIGATION = PROJECT_ROOT / "downloads/maplestory_classic_navigation"
BEGINNER_AND_VICTORIA = (
    0,
    10000,
    20000,
    30000,
    40000,
    50000,
    50001,
    60000,
    1_000_000,
    100_000_000,
    101_000_000,
    102_000_000,
    103_000_000,
    104_000_000,
    104_000_100,
    104_000_400,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--world", type=Path, default=DEFAULT_WORLD)
    parser.add_argument("--navigation-dir", type=Path, default=DEFAULT_NAVIGATION)
    parser.add_argument(
        "--map-id",
        action="append",
        type=int,
        dest="map_ids",
        help="audit only these map ids; default is Maple Island plus Victoria towns",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def load_maps(arguments: argparse.Namespace):
    sys.path.insert(0, str(SERVER_ROOT))
    from maple_server.navigation import load_world_maps

    maps = []
    if arguments.world.is_file():
        maps.extend(load_world_maps(arguments.world))
    if arguments.navigation_dir.is_dir():
        for path in sorted(arguments.navigation_dir.glob("*.json")):
            maps.extend(load_world_maps(path))
    by_id = {item.map_id: item for item in maps}
    wanted = tuple(arguments.map_ids) if arguments.map_ids else BEGINNER_AND_VICTORIA
    selected = []
    missing = []
    for map_id in wanted:
        item = by_id.get(map_id)
        if item is None or not item.footholds:
            missing.append(map_id)
            continue
        selected.append(item)
    return selected, missing


def main() -> int:
    arguments = parse_args()
    sys.path.insert(0, str(SERVER_ROOT))
    from maple_server.navigation import audit_maps

    selected, missing = load_maps(arguments)
    reports = audit_maps(selected)
    if arguments.json:
        print(json.dumps({"missing": missing, "maps": reports}, indent=2))
        return 0 if all(item["complete"] for item in reports) else 1
    print(f"audited {len(reports)} maps; missing geometry {missing}")
    failures = 0
    for report in reports:
        status = "ok" if report["complete"] else "GAP"
        if not report["complete"]:
            failures += 1
        print(
            f"{status} map {report['map_id']}: "
            f"footholds {report['reachable_footholds']}/{report['walkable_footholds']} "
            f"portals {report['reachable_travel_portals']}/{report['travel_portals']} "
            f"ladders {report['reachable_ladder_ropes']}/{report['ladder_ropes']}"
        )
        for portal in report["unreachable_travel_portals"]:
            print(
                f"  portal {portal['name']} -> {portal['target']} "
                f"({portal['x']},{portal['y']}) {portal['reason']}"
            )
        for ladder in report["unreachable_ladder_ropes"]:
            print(
                f"  ladder {ladder['id']} x={ladder['x']} "
                f"top={ladder['top_foothold']} bottom={ladder['bottom_foothold']}"
            )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Client-side movement graph over WZ footholds, ladders, and jumps.

Player motion is computed by the official client's ``VecCtrl``. The custom
server only accepts the resulting opcode-182/47 path. This module reconstructs
the same walk / jump / climb / drop graph so we can prove every spawn, portal,
and ladder that a beginner character can physically use is connected.
"""

from __future__ import annotations

from dataclasses import dataclass
import heapq
import json
import math
from pathlib import Path
from typing import Any, Iterable, Mapping


NO_DESTINATION = 999_999_999
MOB_LIFECYCLE_SERVER_OPCODES = frozenset({218, 219, 279, 280, 281, 282, 285, 286, 293})


class NavigationError(ValueError):
    """Raised when map geometry is unusable or a route does not exist."""


@dataclass(frozen=True, order=True)
class Point:
    x: int
    y: int

    def distance_to(self, other: "Point") -> float:
        return math.hypot(other.x - self.x, other.y - self.y)


@dataclass(frozen=True)
class Physics:
    """Deterministic beginner movement envelope in Maple map units.

    The force constants come from the WZ/prefab model documented by the
    earlier movement laboratory and are independently checked against typed
    VecCtrl movement commands.  Coordinates use +x right and +y down.
    ``max_jump_gap`` and ``max_drop`` remain route-search allowances rather
    than additional impulses.
    """

    walk_speed: float = 125.0
    jump_speed: float = 555.0
    gravity: float = 2_000.0
    run_acceleration: float = 1_400.0
    ground_release_deceleration: float = 800.0
    terminal_fall_speed: float = 670.0
    climb_speed: float = 60.0
    timestep_ms: int = 30
    max_jump_gap: int = 180
    max_jump_rise: int = 120
    max_drop: int = 460

    @property
    def ballistic_jump_rise(self) -> float:
        if self.gravity <= 0:
            return float(self.max_jump_rise)
        apex = self.jump_speed * self.jump_speed / (2.0 * self.gravity)
        return min(float(self.max_jump_rise), apex)


@dataclass(frozen=True)
class Foothold:
    foothold_id: int
    layer: int
    group: int
    start: Point
    end: Point
    previous: int = 0
    next: int = 0
    forbid_fall_down: bool = False

    @property
    def supports_actor(self) -> bool:
        return self.start.x != self.end.x

    def y_at(self, x: int) -> float | None:
        left, right = sorted((self.start.x, self.end.x))
        if x < left or x > right:
            return None
        if self.start.x == self.end.x:
            return float(min(self.start.y, self.end.y))
        ratio = (x - self.start.x) / (self.end.x - self.start.x)
        return self.start.y + ratio * (self.end.y - self.start.y)

    def closest_point(self, point: Point) -> Point:
        dx = self.end.x - self.start.x
        dy = self.end.y - self.start.y
        denominator = dx * dx + dy * dy
        if denominator == 0:
            return self.start
        ratio = (
            (point.x - self.start.x) * dx + (point.y - self.start.y) * dy
        ) / denominator
        ratio = min(1.0, max(0.0, ratio))
        return Point(
            round(self.start.x + ratio * dx),
            round(self.start.y + ratio * dy),
        )


@dataclass(frozen=True)
class LadderRope:
    ladder_id: int
    x: int
    y1: int
    y2: int
    is_ladder: bool
    page: int = 0
    upper_foothold: int = 0

    @property
    def top(self) -> Point:
        return Point(self.x, min(self.y1, self.y2))

    @property
    def bottom(self) -> Point:
        return Point(self.x, max(self.y1, self.y2))


@dataclass(frozen=True)
class Portal:
    portal_id: int
    name: str
    portal_type: int
    target_map_id: int
    target_name: str
    position: Point

    @property
    def is_spawn(self) -> bool:
        return self.portal_type == 0 or self.name == "sp"

    @property
    def is_travel(self) -> bool:
        """Ordinary walk-to or press-up portal onto another map.

        Type 3 is forced/event, 6/7 are scripts, and 10 is a same-map hidden
        warp. Those are not beginner left/right/jump surfaces.
        """
        return (
            self.portal_type in {1, 2}
            and self.target_map_id not in {NO_DESTINATION, -1}
            and not self.is_spawn
        )


@dataclass(frozen=True)
class MapGeometry:
    map_id: int
    footholds: tuple[Foothold, ...]
    ladder_ropes: tuple[LadderRope, ...]
    portals: tuple[Portal, ...]
    physics: Physics = Physics()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MapGeometry":
        try:
            map_id = int(value["map_id"])
        except (KeyError, TypeError, ValueError) as error:
            raise NavigationError("map record lacks a valid map_id") from error
        footholds = tuple(
            Foothold(
                foothold_id=int(item["id"]),
                layer=int(item.get("layer", 0)),
                group=int(item.get("group", 0)),
                start=Point(int(item["x1"]), int(item["y1"])),
                end=Point(int(item["x2"]), int(item["y2"])),
                previous=int(item.get("prev", 0)),
                next=int(item.get("next", 0)),
                forbid_fall_down=bool(item.get("forbidFallDown", False)),
            )
            for item in value.get("footholds", ())
        )
        ladder_ropes = tuple(
            LadderRope(
                ladder_id=int(item["id"]),
                x=int(item["x"]),
                y1=int(item["y1"]),
                y2=int(item["y2"]),
                is_ladder=bool(item.get("l", False)),
                page=int(item.get("page", 0)),
                upper_foothold=int(item.get("uf", 0)),
            )
            for item in value.get("ladder_ropes", ())
        )
        portals = tuple(
            Portal(
                portal_id=int(item["id"]),
                name=str(item.get("pn", "")),
                portal_type=int(item.get("pt", 0)),
                target_map_id=int(item.get("tm", NO_DESTINATION)),
                target_name=str(item.get("tn", "")),
                position=Point(int(item["x"]), int(item["y"])),
            )
            for item in value.get("portals", ())
        )
        raw_physics = value.get("physics") or {}
        return cls(
            map_id=map_id,
            footholds=footholds,
            ladder_ropes=ladder_ropes,
            portals=portals,
            physics=Physics(
                walk_speed=float(raw_physics.get("walk_speed", 125.0)),
                jump_speed=float(raw_physics.get("jump_speed", 555.0)),
                gravity=float(raw_physics.get("gravity", 2_000.0)),
                run_acceleration=float(
                    raw_physics.get("run_acceleration", 1_400.0)
                ),
                ground_release_deceleration=float(
                    raw_physics.get("ground_release_deceleration", 800.0)
                ),
                terminal_fall_speed=float(
                    raw_physics.get("terminal_fall_speed", 670.0)
                ),
                climb_speed=float(raw_physics.get("climb_speed", 60.0)),
                timestep_ms=int(raw_physics.get("timestep_ms", 30)),
                max_jump_gap=int(raw_physics.get("max_jump_gap", 180)),
                max_jump_rise=int(raw_physics.get("max_jump_rise", 120)),
                max_drop=int(raw_physics.get("max_drop", 460)),
            ),
        )

    def landing_below(self, point: Point) -> tuple[Point, Foothold] | None:
        candidates: list[tuple[float, Foothold]] = []
        for foothold in self.footholds:
            if not foothold.supports_actor:
                continue
            y = foothold.y_at(point.x)
            if y is None or y < point.y - 8:
                continue
            candidates.append((y, foothold))
        if not candidates:
            return None
        y, foothold = min(candidates, key=lambda item: (item[0], item[1].foothold_id))
        return Point(point.x, round(y)), foothold


@dataclass(frozen=True)
class LocalRouteStep:
    mode: str
    start: Point
    end: Point
    foothold_id: int | None = None
    target_foothold_id: int | None = None
    ladder_id: int | None = None
    cost: float = 0.0


@dataclass(frozen=True)
class _Edge:
    target: int
    mode: str
    start: Point
    end: Point
    cost: float
    ladder_id: int | None = None


class LocalPathfinder:
    """A* over walkable footholds with ladder, drop, and jump edges."""

    def __init__(self, geometry: MapGeometry):
        surfaces = tuple(item for item in geometry.footholds if item.supports_actor)
        if not surfaces:
            raise NavigationError(f"map {geometry.map_id} has no walkable footholds")
        self.geometry = geometry
        self._surfaces = surfaces
        self._by_id = {item.foothold_id: item for item in surfaces}
        self._edges: dict[int, list[_Edge]] = {item.foothold_id: [] for item in surfaces}
        self._build_walk_connections()
        self._build_ladder_connections()
        self._build_air_connections()

    def nearest_foothold(
        self, point: Point, *, maximum_distance: float | None = None
    ) -> Foothold:
        foothold = min(
            self._surfaces,
            key=lambda item: item.closest_point(point).distance_to(point),
        )
        distance = foothold.closest_point(point).distance_to(point)
        if maximum_distance is not None and distance > maximum_distance:
            raise NavigationError(
                f"no foothold within {maximum_distance:g} of ({point.x},{point.y})"
            )
        return foothold

    def reachable_foothold_ids(self, start: Point) -> frozenset[int]:
        origin = self.nearest_foothold(start)
        seen = {origin.foothold_id}
        pending = [origin.foothold_id]
        while pending:
            current = pending.pop()
            for edge in self._edges[current]:
                if edge.target in seen:
                    continue
                seen.add(edge.target)
                pending.append(edge.target)
        return frozenset(seen)

    def route(self, start: Point, goal: Point) -> tuple[LocalRouteStep, ...]:
        start_fh = self.nearest_foothold(start)
        goal_fh = self.nearest_foothold(goal)
        start_point = start_fh.closest_point(start)
        final_point = goal_fh.closest_point(goal)
        if start_fh.foothold_id == goal_fh.foothold_id:
            if start_point == final_point:
                return ()
            return (
                LocalRouteStep(
                    "walk",
                    start_point,
                    final_point,
                    foothold_id=start_fh.foothold_id,
                    target_foothold_id=goal_fh.foothold_id,
                    cost=start_point.distance_to(final_point),
                ),
            )
        start_key = (start_fh.foothold_id, start_point.x, start_point.y)
        queue: list[tuple[float, int, int, int]] = [
            (0.0, start_fh.foothold_id, start_point.x, start_point.y)
        ]
        distance = {start_key: 0.0}
        previous: dict[tuple[int, int, int], tuple[tuple[int, int, int], _Edge]] = {}
        goal_key: tuple[int, int, int] | None = None
        goal_cost = math.inf
        while queue:
            cost, current, current_x, current_y = heapq.heappop(queue)
            current_key = (current, current_x, current_y)
            if cost != distance[current_key]:
                continue
            if current == goal_fh.foothold_id:
                candidate_goal = cost + Point(current_x, current_y).distance_to(
                    final_point
                )
                if candidate_goal < goal_cost:
                    goal_cost = candidate_goal
                    goal_key = current_key
                continue
            if cost >= goal_cost:
                continue
            current_point = Point(current_x, current_y)
            for edge in self._edges[current]:
                candidate = cost + current_point.distance_to(edge.start) + edge.cost
                target_key = (edge.target, edge.end.x, edge.end.y)
                if candidate >= distance.get(target_key, math.inf):
                    continue
                distance[target_key] = candidate
                previous[target_key] = (current_key, edge)
                heapq.heappush(queue, (candidate, edge.target, edge.end.x, edge.end.y))
        if goal_key is None:
            raise NavigationError(
                f"no local route on map {self.geometry.map_id} from {start} to {goal}"
            )
        transitions: list[tuple[tuple[int, int, int], _Edge]] = []
        cursor = goal_key
        while cursor != start_key:
            source_key, edge = previous[cursor]
            transitions.append((source_key, edge))
            cursor = source_key
        transitions.reverse()
        result: list[LocalRouteStep] = []
        current_point = start_point
        for source_key, edge in transitions:
            source = source_key[0]
            if current_point != edge.start:
                result.append(
                    LocalRouteStep(
                        "walk",
                        current_point,
                        edge.start,
                        foothold_id=source,
                        target_foothold_id=source,
                        cost=current_point.distance_to(edge.start),
                    )
                )
            if edge.start != edge.end:
                result.append(
                    LocalRouteStep(
                        edge.mode,
                        edge.start,
                        edge.end,
                        foothold_id=source,
                        target_foothold_id=edge.target,
                        ladder_id=edge.ladder_id,
                        cost=edge.cost,
                    )
                )
            current_point = edge.end
        if current_point != final_point:
            result.append(
                LocalRouteStep(
                    "walk",
                    current_point,
                    final_point,
                    foothold_id=goal_fh.foothold_id,
                    target_foothold_id=goal_fh.foothold_id,
                    cost=current_point.distance_to(final_point),
                )
            )
        return tuple(result)

    def _connect(
        self,
        source: Foothold,
        target: Foothold,
        mode: str,
        start: Point,
        end: Point,
        *,
        scale: float = 1.0,
        ladder_id: int | None = None,
    ) -> None:
        cost = max(1.0, start.distance_to(end) * scale)
        edge = _Edge(target.foothold_id, mode, start, end, cost, ladder_id)
        existing = self._edges[source.foothold_id]
        if not any(
            item.target == edge.target
            and item.mode == edge.mode
            and item.ladder_id == edge.ladder_id
            for item in existing
        ):
            existing.append(edge)

    def _build_walk_connections(self) -> None:
        endpoints: dict[tuple[int, int], list[Foothold]] = {}
        for foothold in self._surfaces:
            endpoints.setdefault((foothold.start.x, foothold.start.y), []).append(
                foothold
            )
            endpoints.setdefault((foothold.end.x, foothold.end.y), []).append(foothold)
            for neighbor_id in (foothold.previous, foothold.next):
                neighbor = self._by_id.get(neighbor_id)
                if neighbor is None:
                    continue
                source_point, target_point = _nearest_endpoint_pair(foothold, neighbor)
                self._connect(foothold, neighbor, "walk", source_point, target_point)
        for joined in endpoints.values():
            for source in joined:
                for target in joined:
                    if source is target:
                        continue
                    point_source, point_target = _nearest_endpoint_pair(source, target)
                    self._connect(source, target, "walk", point_source, point_target)

    def _build_ladder_connections(self) -> None:
        for ladder in self.geometry.ladder_ropes:
            top_fh = self._nearest_at(ladder.top, horizontal=50, vertical=140)
            bottom_fh = self._nearest_at(ladder.bottom, horizontal=50, vertical=140)
            if top_fh is None or bottom_fh is None or top_fh is bottom_fh:
                continue
            top = top_fh.closest_point(ladder.top)
            bottom = bottom_fh.closest_point(ladder.bottom)
            self._connect(
                bottom_fh, top_fh, "climb", bottom, top, scale=1.25, ladder_id=ladder.ladder_id
            )
            self._connect(
                top_fh, bottom_fh, "climb", top, bottom, scale=1.05, ladder_id=ladder.ladder_id
            )

    def _build_air_connections(self) -> None:
        physics = self.geometry.physics
        for source in self._surfaces:
            for target in self._surfaces:
                if source is target:
                    continue
                start, end = _nearest_endpoint_pair(source, target)
                dx = abs(end.x - start.x)
                dy = end.y - start.y
                if dx <= 4 and 2 < dy <= physics.max_drop and not source.forbid_fall_down:
                    self._connect(source, target, "drop", start, end, scale=1.1)
                if (
                    dx <= physics.max_jump_gap
                    and -physics.ballistic_jump_rise <= dy <= physics.max_drop
                ):
                    self._connect(source, target, "jump", start, end, scale=1.7)

    def _nearest_at(
        self, point: Point, *, horizontal: int, vertical: int
    ) -> Foothold | None:
        candidates: list[tuple[float, Foothold]] = []
        for foothold in self._surfaces:
            projected = foothold.closest_point(point)
            if (
                abs(projected.x - point.x) <= horizontal
                and abs(projected.y - point.y) <= vertical
            ):
                candidates.append((projected.distance_to(point), foothold))
        if not candidates:
            return None
        return min(candidates, key=lambda item: item[0])[1]


def _nearest_endpoint_pair(left: Foothold, right: Foothold) -> tuple[Point, Point]:
    return min(
        (
            (source, target)
            for source in (left.start, left.end)
            for target in (right.start, right.end)
        ),
        key=lambda pair: pair[0].distance_to(pair[1]),
    )


def load_world_maps(path: str | Path) -> tuple[MapGeometry, ...]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict) and raw.get("maps") is not None:
        records = raw["maps"]
    elif isinstance(raw, dict) and "map_id" in raw:
        records = [raw]
    elif isinstance(raw, list):
        records = raw
    else:
        raise NavigationError(f"unrecognized map knowledge: {path}")
    return tuple(MapGeometry.from_dict(item) for item in records)


def audit_map(geometry: MapGeometry) -> dict[str, Any]:
    """Prove spawn-connected walk/jump/climb/drop reachability."""

    pathfinder = LocalPathfinder(geometry)
    walkable = {item.foothold_id for item in geometry.footholds if item.supports_actor}
    spawns = [portal for portal in geometry.portals if portal.is_spawn]
    if not spawns:
        start = pathfinder._surfaces[0].start
        origins = [("foothold", start)]
    else:
        origins = []
        for portal in spawns:
            landing = geometry.landing_below(portal.position)
            origins.append(
                (
                    f"spawn:{portal.portal_id}",
                    landing[0] if landing is not None else portal.position,
                )
            )
    reachable: set[int] = set()
    for _, point in origins:
        reachable |= set(pathfinder.reachable_foothold_ids(point))

    warp_destinations = {
        item.target_name
        for item in geometry.portals
        if item.target_name and item.target_map_id in {geometry.map_id, NO_DESTINATION}
    }
    unreachable_portals: list[dict[str, Any]] = []
    reachable_portals: list[dict[str, Any]] = []
    for portal in geometry.portals:
        if not portal.is_travel:
            continue
        if portal.name in warp_destinations:
            continue
        try:
            foothold = pathfinder.nearest_foothold(portal.position, maximum_distance=80)
        except NavigationError:
            unreachable_portals.append(
                {
                    "id": portal.portal_id,
                    "name": portal.name,
                    "target": portal.target_map_id,
                    "x": portal.position.x,
                    "y": portal.position.y,
                    "reason": "no nearby foothold",
                }
            )
            continue
        record = {
            "id": portal.portal_id,
            "name": portal.name,
            "target": portal.target_map_id,
            "x": portal.position.x,
            "y": portal.position.y,
            "foothold_id": foothold.foothold_id,
        }
        if foothold.foothold_id in reachable:
            reachable_portals.append(record)
        else:
            record["reason"] = "foothold not reachable from spawn"
            unreachable_portals.append(record)

    unreachable_ladders: list[dict[str, Any]] = []
    reachable_ladders = 0
    for ladder in geometry.ladder_ropes:
        top = pathfinder._nearest_at(ladder.top, horizontal=50, vertical=140)
        bottom = pathfinder._nearest_at(ladder.bottom, horizontal=50, vertical=140)
        top_ok = top is not None and top.foothold_id in reachable
        bottom_ok = bottom is not None and bottom.foothold_id in reachable
        if top_ok or bottom_ok:
            reachable_ladders += 1
            continue
        unreachable_ladders.append(
            {
                "id": ladder.ladder_id,
                "x": ladder.x,
                "ladder": ladder.is_ladder,
                "top_foothold": None if top is None else top.foothold_id,
                "bottom_foothold": None if bottom is None else bottom.foothold_id,
            }
        )

    return {
        "map_id": geometry.map_id,
        "walkable_footholds": len(walkable),
        "reachable_footholds": len(reachable),
        "spawn_count": len(spawns),
        "travel_portals": len(reachable_portals) + len(unreachable_portals),
        "reachable_travel_portals": len(reachable_portals),
        "unreachable_travel_portals": unreachable_portals,
        "ladder_ropes": len(geometry.ladder_ropes),
        "reachable_ladder_ropes": reachable_ladders,
        "unreachable_ladder_ropes": unreachable_ladders,
        "physics": {
            "walk_speed": geometry.physics.walk_speed,
            "jump_speed": geometry.physics.jump_speed,
            "gravity": geometry.physics.gravity,
            "ballistic_jump_rise": round(geometry.physics.ballistic_jump_rise, 2),
            "max_jump_gap": geometry.physics.max_jump_gap,
            "max_drop": geometry.physics.max_drop,
        },
        "complete": not unreachable_portals and not unreachable_ladders,
    }


def audit_maps(maps: Iterable[MapGeometry]) -> list[dict[str, Any]]:
    return [audit_map(item) for item in maps]

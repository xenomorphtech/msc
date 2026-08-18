#!/usr/bin/env python3
"""Extract a MapleStory Classic map and draw its navigation geometry as SVG."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Iterable

import UnityPy


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.wzjson import (  # noqa: E402
    WzJsonError,
    decode_wzjson,
    extract_serialized_wzjson,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ADDRESSABLES_ROOT = (
    PROJECT_ROOT
    / "downloads/maplestory_classic_wine_prefix/drive_c/Program Files/Gamania"
    / "maplestory_classic/Maplestory_Classic_Data/StreamingAssets/aa/w"
)
DEFAULT_OUTPUT_DIRECTORY = PROJECT_ROOT / "downloads/maplestory_classic_navigation"
MAP_ASSET_PREFIX = PurePosixPath("Assets/WzAssets/Json/Map/Map")


class NavigationDrawError(RuntimeError):
    """Raised when a requested map or its navigation data is invalid."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("map_id", help="numeric map ID, with or without zero padding")
    parser.add_argument(
        "--addressables-root", type=Path, default=DEFAULT_ADDRESSABLES_ROOT
    )
    parser.add_argument("--output-directory", type=Path, default=DEFAULT_OUTPUT_DIRECTORY)
    parser.add_argument("--width", type=int, default=1800, help="SVG viewport width")
    return parser.parse_args()


def normalize_map_id(value: str) -> str:
    if not value.isdecimal():
        raise NavigationDrawError(f"map ID must be decimal: {value!r}")
    numeric = int(value)
    if numeric < 0 or numeric > 999_999_999:
        raise NavigationDrawError(f"map ID is out of range: {value!r}")
    return f"{numeric:09d}"


def find_map_asset(
    addressables_root: Path, map_id: str
) -> tuple[str, str, bytes, Any]:
    """Find and decode one exact nine-digit map asset."""

    suffix = f"/{map_id}.wzjson"
    matches: list[tuple[str, str, bytes, Any]] = []
    for bundle in sorted(addressables_root.glob("json_*.bundle")):
        environment = UnityPy.load(str(bundle))
        for asset_path, pointer in environment.container.items():
            source = PurePosixPath(asset_path)
            if not asset_path.endswith(suffix):
                continue
            try:
                source.relative_to(MAP_ASSET_PREFIX)
            except ValueError:
                continue
            reader = pointer.deref()
            if reader is None or reader.type.name != "MonoBehaviour":
                raise NavigationDrawError(
                    f"{asset_path} is not a readable MonoBehaviour"
                )
            serialized = reader.get_raw_data()
            try:
                payload, layout = extract_serialized_wzjson(serialized, asset_path)
                result = decode_wzjson(payload, layout)
            except WzJsonError as error:
                raise NavigationDrawError(f"cannot decode {asset_path}: {error}") from error
            matches.append((bundle.name, asset_path, payload, result))
    if not matches:
        raise NavigationDrawError(f"map {map_id} is not installed")
    if len(matches) != 1:
        raise NavigationDrawError(
            f"map {map_id} matched {len(matches)} assets instead of one"
        )
    return matches[0]


def flatten_footholds(document: dict[str, Any]) -> list[dict[str, Any]]:
    footholds: list[dict[str, Any]] = []
    root = document.get("foothold", {})
    if not isinstance(root, dict):
        raise NavigationDrawError("map foothold root is not an object")
    for layer, groups in root.items():
        if not isinstance(groups, dict):
            continue
        for group, segments in groups.items():
            if not isinstance(segments, dict):
                continue
            for foothold_id, segment in segments.items():
                if not isinstance(segment, dict):
                    continue
                required = ("x1", "y1", "x2", "y2")
                if not all(isinstance(segment.get(key), int) for key in required):
                    raise NavigationDrawError(
                        f"foothold {layer}/{group}/{foothold_id} lacks integer endpoints"
                    )
                footholds.append(
                    {
                        "id": int(foothold_id),
                        "layer": int(layer),
                        "group": int(group),
                        **segment,
                    }
                )
    footholds.sort(key=lambda item: (item["id"], item["layer"], item["group"]))
    return footholds


def flatten_ladder_ropes(document: dict[str, Any]) -> list[dict[str, Any]]:
    ladder_ropes: list[dict[str, Any]] = []
    root = document.get("ladderRope", {})
    if not isinstance(root, dict):
        raise NavigationDrawError("map ladderRope root is not an object")
    for ladder_id, ladder in root.items():
        if not isinstance(ladder, dict):
            continue
        if not all(isinstance(ladder.get(key), int) for key in ("x", "y1", "y2")):
            raise NavigationDrawError(
                f"ladder/rope {ladder_id} lacks integer coordinates"
            )
        ladder_ropes.append({"id": int(ladder_id), **ladder})
    ladder_ropes.sort(key=lambda item: item["id"])
    return ladder_ropes


def flatten_portals(document: dict[str, Any]) -> list[dict[str, Any]]:
    portals: list[dict[str, Any]] = []
    root = document.get("portal", {})
    if not isinstance(root, dict):
        return portals
    for portal_id, portal in root.items():
        if (
            isinstance(portal, dict)
            and isinstance(portal.get("x"), int)
            and isinstance(portal.get("y"), int)
        ):
            portals.append({"id": int(portal_id), **portal})
    portals.sort(key=lambda item: item["id"])
    return portals


def _geometry_points(
    footholds: Iterable[dict[str, Any]],
    ladder_ropes: Iterable[dict[str, Any]],
    portals: Iterable[dict[str, Any]],
) -> list[tuple[int, int]]:
    points: list[tuple[int, int]] = []
    for foothold in footholds:
        points.extend(
            [
                (foothold["x1"], foothold["y1"]),
                (foothold["x2"], foothold["y2"]),
            ]
        )
    for ladder in ladder_ropes:
        points.extend([(ladder["x"], ladder["y1"]), (ladder["x"], ladder["y2"])])
    for portal in portals:
        points.append((portal["x"], portal["y"]))
    return points


def render_navigation_svg(
    map_id: str,
    footholds: list[dict[str, Any]],
    ladder_ropes: list[dict[str, Any]],
    portals: list[dict[str, Any]],
    width: int = 1800,
) -> str:
    """Render exact game-coordinate line segments with a compact legend."""

    points = _geometry_points(footholds, ladder_ropes, portals)
    if not points:
        raise NavigationDrawError(f"map {map_id} has no navigation coordinates")
    if width < 400:
        raise NavigationDrawError("SVG width must be at least 400 pixels")

    min_x = min(x for x, _ in points)
    max_x = max(x for x, _ in points)
    min_y = min(y for _, y in points)
    max_y = max(y for _, y in points)
    coordinate_width = max(max_x - min_x, 1)
    coordinate_height = max(max_y - min_y, 1)
    margin = 70
    header = 78
    scale = (width - margin * 2) / coordinate_width
    height = round(coordinate_height * scale + margin * 2 + header)

    def sx(x: int) -> float:
        return margin + (x - min_x) * scale

    def sy(y: int) -> float:
        return header + margin + (y - min_y) * scale

    rows = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}">'
        ),
        "<style>",
        "text{font-family:ui-monospace,monospace;fill:#dbeafe}",
        ".platform{stroke:#f8fafc;stroke-width:2.2;stroke-linecap:round}",
        ".wall{stroke:#64748b;stroke-width:1.25;stroke-linecap:round}",
        ".ladder{stroke:#f59e0b;stroke-width:3;stroke-linecap:round}",
        ".rope{stroke:#22d3ee;stroke-width:3;stroke-linecap:round}",
        ".portal{fill:#c084fc;stroke:#f3e8ff;stroke-width:1.5}",
        "</style>",
        f'<rect width="{width}" height="{height}" fill="#07111f"/>',
        f'<text x="{margin}" y="35" font-size="24">Map {html.escape(map_id)} navigation</text>',
        (
            f'<text x="{margin}" y="61" font-size="14" fill="#94a3b8">'
            f'{len(footholds)} footholds · {len(ladder_ropes)} ladders/ropes · '
            f'{len(portals)} portals · x {min_x}..{max_x} · y {min_y}..{max_y}</text>'
        ),
    ]
    for foothold in footholds:
        vertical = foothold["x1"] == foothold["x2"]
        css_class = "wall" if vertical else "platform"
        rows.append(
            f'<line class="{css_class}" x1="{sx(foothold["x1"]):.2f}" '
            f'y1="{sy(foothold["y1"]):.2f}" x2="{sx(foothold["x2"]):.2f}" '
            f'y2="{sy(foothold["y2"]):.2f}"><title>foothold '
            f'{foothold["id"]} layer {foothold["layer"]} group '
            f'{foothold["group"]}</title></line>'
        )
    for ladder in ladder_ropes:
        css_class = "ladder" if ladder.get("l") else "rope"
        kind = "ladder" if ladder.get("l") else "rope"
        rows.append(
            f'<line class="{css_class}" x1="{sx(ladder["x"]):.2f}" '
            f'y1="{sy(ladder["y1"]):.2f}" x2="{sx(ladder["x"]):.2f}" '
            f'y2="{sy(ladder["y2"]):.2f}"><title>{kind} '
            f'{ladder["id"]}</title></line>'
        )
    for portal in portals:
        rows.append(
            f'<circle class="portal" cx="{sx(portal["x"]):.2f}" '
            f'cy="{sy(portal["y"]):.2f}" r="4"><title>portal '
            f'{html.escape(str(portal.get("pn", portal["id"])))}</title></circle>'
        )
    rows.extend(
        [
            f'<line class="platform" x1="{width - 390}" y1="29" x2="{width - 350}" y2="29"/>',
            f'<text x="{width - 340}" y="34" font-size="13">platform</text>',
            f'<line class="ladder" x1="{width - 240}" y1="17" x2="{width - 240}" y2="41"/>',
            f'<text x="{width - 228}" y="34" font-size="13">ladder</text>',
            f'<line class="rope" x1="{width - 150}" y1="17" x2="{width - 150}" y2="41"/>',
            f'<text x="{width - 138}" y="34" font-size="13">rope</text>',
            "</svg>",
        ]
    )
    return "\n".join(rows) + "\n"


def draw_map(
    addressables_root: Path, output_directory: Path, map_id: str, width: int = 1800
) -> dict[str, Any]:
    normalized = normalize_map_id(map_id)
    source_bundle, asset_path, payload, result = find_map_asset(
        addressables_root, normalized
    )
    if not isinstance(result.document, dict):
        raise NavigationDrawError(f"map {normalized} did not decode to an object")
    geometry_document = result.document
    geometry_asset_path = asset_path
    geometry_source_bundle = source_bundle
    link_chain = [normalized]
    while not flatten_footholds(geometry_document):
        link = geometry_document.get("info", {}).get("link")
        if not isinstance(link, str) or not link.isdecimal():
            break
        linked_id = normalize_map_id(link)
        if linked_id in link_chain:
            raise NavigationDrawError(
                "cyclic map geometry links: " + " -> ".join((*link_chain, linked_id))
            )
        link_chain.append(linked_id)
        (
            geometry_source_bundle,
            geometry_asset_path,
            _,
            geometry_result,
        ) = find_map_asset(addressables_root, linked_id)
        if not isinstance(geometry_result.document, dict):
            raise NavigationDrawError(
                f"linked map {linked_id} did not decode to an object"
            )
        geometry_document = geometry_result.document

    footholds = flatten_footholds(geometry_document)
    ladder_ropes = flatten_ladder_ropes(geometry_document)
    portals = flatten_portals(geometry_document)
    svg = render_navigation_svg(normalized, footholds, ladder_ropes, portals, width)
    geometry = {
        "format": "maplestory-classic-navigation-v1",
        "map_id": normalized,
        "asset_path": asset_path,
        "source_bundle": source_bundle,
        "root_path": result.root_path,
        "geometry_link_chain": link_chain,
        "geometry_asset_path": geometry_asset_path,
        "geometry_source_bundle": geometry_source_bundle,
        "footholds": footholds,
        "ladder_ropes": ladder_ropes,
        "portals": portals,
        "info": result.document.get("info", {}),
        "geometry_info": geometry_document.get("info", {}),
        "mini_map": {
            key: value
            for key, value in geometry_document.get("miniMap", {}).items()
            if key != "canvas"
        },
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / f"{normalized}.wzjson").write_bytes(payload)
    (output_directory / f"{normalized}.json").write_text(
        json.dumps(geometry, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_directory / f"{normalized}.svg").write_text(svg, encoding="utf-8")
    return geometry


def main() -> int:
    arguments = parse_args()
    try:
        geometry = draw_map(
            arguments.addressables_root,
            arguments.output_directory,
            arguments.map_id,
            arguments.width,
        )
    except (OSError, NavigationDrawError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"drew map {geometry['map_id']}: {len(geometry['footholds'])} footholds, "
        f"{len(geometry['ladder_ropes'])} ladders/ropes, "
        f"{len(geometry['portals'])} portals"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

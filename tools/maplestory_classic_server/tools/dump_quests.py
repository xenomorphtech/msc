#!/usr/bin/env python3
"""Extract, decode, and correlate MapleStory Classic Quest/*.wzjson assets.

The quest assets are WZJS v5 ScriptableObjects, not encrypted JSON text.  This
tool preserves their exact WZJS byte arrays, decodes their object trees, and
joins the four quest-ID tables to the installed Traditional Chinese QuestData
text by symbolic ``QuestInfo`` and ``Say`` references.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any

import UnityPy


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.wzjson import (  # noqa: E402
    WZJSON_VERSION,
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
DEFAULT_OUTPUT_DIRECTORY = PROJECT_ROOT / "downloads/maplestory_classic_quests"
QUEST_ASSET_ROOT = PurePosixPath("Assets/WzAssets/Json/Quest")
EXPECTED_QUEST_TABLES = {
    "Act",
    "Check",
    "Exclusive",
    "PQuest",
    "PQuestSearch",
    "QuestInfo",
    "Say",
}
CORE_QUEST_TABLES = ("Act", "Check", "QuestInfo", "Say", "QuestData")
CORRELATED_TABLES = (
    "Act",
    "Check",
    "QuestInfo",
    "Say",
    "PQuest",
    "Exclusive",
    "QuestData",
)
MANIFEST_NAME = "manifest.json"


class QuestDumpError(RuntimeError):
    """Raised when the installed quest data cannot be dumped unambiguously."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--addressables-root",
        type=Path,
        default=DEFAULT_ADDRESSABLES_ROOT,
        help="directory containing the client's json_*.bundle files",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
        help="directory that receives raw, decoded, and correlated quest data",
    )
    parser.add_argument(
        "--locale",
        default="TW",
        help="String/<locale>/QuestData.json text to correlate (default: TW)",
    )
    return parser.parse_args()


def quest_asset_name(asset_path: str) -> str | None:
    """Return the safe table stem for a direct Quest/*.wzjson asset."""

    source = PurePosixPath(asset_path)
    try:
        relative = source.relative_to(QUEST_ASSET_ROOT)
    except ValueError:
        return None
    if len(relative.parts) != 1 or relative.suffix.casefold() != ".wzjson":
        return None
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise QuestDumpError(f"unsafe quest asset path: {asset_path!r}")
    return relative.stem


def quest_data_asset_path(locale: str) -> str:
    if not locale or any(character in locale for character in "/\\"):
        raise QuestDumpError(f"unsafe locale: {locale!r}")
    return f"Assets/WzAssets/Json/String/{locale}/QuestData.json"


def text_asset_bytes(text_asset: Any, source: str) -> bytes:
    script = text_asset.m_Script
    if isinstance(script, bytes):
        return script
    if not isinstance(script, str):
        raise QuestDumpError(
            f"{source} TextAsset m_Script has unsupported type "
            f"{type(script).__name__}"
        )
    return script.encode("utf-8", "surrogateescape")


def parse_json_object(raw: bytes, source: str) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QuestDumpError(f"invalid JSON in {source}: {error}") from error
    if not isinstance(document, dict):
        raise QuestDumpError(
            f"{source} has top-level {type(document).__name__}; expected object"
        )
    return document


def _write_json(path: Path, document: Any) -> bytes:
    encoded = (
        json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return encoded


def _quest_sort_key(quest_id: str) -> tuple[int, int | str, str]:
    try:
        return (0, int(quest_id), quest_id)
    except ValueError:
        return (1, quest_id, quest_id)


def resolve_symbolic_references(
    value: Any,
    translations: dict[str, Any],
    path: tuple[str, ...] = (),
) -> tuple[Any, int, list[dict[str, str]]]:
    """Replace string leaves found in a text lookup and report misses."""

    if isinstance(value, str):
        if value in translations:
            return translations[value], 1, []
        return value, 0, [{"path": "/".join(path), "token": value}]
    if isinstance(value, dict):
        resolved: dict[str, Any] = {}
        resolved_count = 0
        unresolved: list[dict[str, str]] = []
        for key, child in value.items():
            child_value, child_count, child_unresolved = resolve_symbolic_references(
                child, translations, (*path, key)
            )
            resolved[key] = child_value
            resolved_count += child_count
            unresolved.extend(child_unresolved)
        return resolved, resolved_count, unresolved
    if isinstance(value, list):
        resolved_list: list[Any] = []
        resolved_count = 0
        unresolved: list[dict[str, str]] = []
        for index, child in enumerate(value):
            child_value, child_count, child_unresolved = resolve_symbolic_references(
                child, translations, (*path, str(index))
            )
            resolved_list.append(child_value)
            resolved_count += child_count
            unresolved.extend(child_unresolved)
        return resolved_list, resolved_count, unresolved
    return value, 0, []


def correlate_quests(
    decoded: dict[str, dict[str, Any]], quest_data: dict[str, Any], locale: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Join quest tables and resolve localized QuestInfo/Say references."""

    exclusive_groups: dict[str, list[str]] = {}
    for group, members in decoded["Exclusive"].items():
        if not isinstance(members, dict):
            raise QuestDumpError(
                f"Exclusive[{group!r}] is {type(members).__name__}; expected object"
            )
        for quest_id in members:
            exclusive_groups.setdefault(quest_id, []).append(group)
    for groups in exclusive_groups.values():
        groups.sort(key=_quest_sort_key)

    table_documents = {
        "Act": decoded["Act"],
        "Check": decoded["Check"],
        "QuestInfo": decoded["QuestInfo"],
        "Say": decoded["Say"],
        "PQuest": decoded["PQuest"],
        "Exclusive": exclusive_groups,
        "QuestData": quest_data,
    }
    table_ids = {name: set(document) for name, document in table_documents.items()}
    all_ids = set().union(*table_ids.values())
    core_ids = set().union(*(table_ids[name] for name in CORE_QUEST_TABLES))
    complete_ids = set.intersection(*(table_ids[name] for name in CORE_QUEST_TABLES))
    pattern_counts: Counter[tuple[str, ...]] = Counter()
    reference_totals = {
        "QuestInfo": {"total": 0, "resolved": 0, "unresolved": 0},
        "Say": {"total": 0, "resolved": 0, "unresolved": 0},
    }
    correlated: dict[str, Any] = {}

    for quest_id in sorted(all_ids, key=_quest_sort_key):
        presence = tuple(
            table for table in CORRELATED_TABLES if quest_id in table_ids[table]
        )
        pattern_counts[presence] += 1
        localized = quest_data.get(quest_id)
        if localized is not None and not isinstance(localized, dict):
            raise QuestDumpError(
                f"QuestData[{quest_id!r}] is {type(localized).__name__}; "
                "expected object"
            )
        localized = localized or {}
        info_text = localized.get("Info", {})
        say_text = localized.get("Say", {})
        if not isinstance(info_text, dict) or not isinstance(say_text, dict):
            raise QuestDumpError(
                f"QuestData[{quest_id!r}] Info/Say must be JSON objects"
            )

        record: dict[str, Any] = {
            "presence": list(presence),
            "name": localized.get("name"),
            "act": decoded["Act"].get(quest_id),
            "check": decoded["Check"].get(quest_id),
            "pquest": decoded["PQuest"].get(quest_id),
            "exclusive_groups": exclusive_groups.get(quest_id, []),
            "localized": localized or None,
        }
        for table_name, lookup in (
            ("QuestInfo", {**info_text, "name": localized.get("name")}),
            ("Say", say_text),
        ):
            output_key = "quest_info" if table_name == "QuestInfo" else "say"
            structure = decoded[table_name].get(quest_id)
            if structure is None:
                record[output_key] = None
                continue
            clean_lookup = {key: value for key, value in lookup.items() if value is not None}
            resolved, resolved_count, unresolved = resolve_symbolic_references(
                structure, clean_lookup
            )
            total = resolved_count + len(unresolved)
            reference_totals[table_name]["total"] += total
            reference_totals[table_name]["resolved"] += resolved_count
            reference_totals[table_name]["unresolved"] += len(unresolved)
            record[output_key] = {
                "references": structure,
                "resolved": resolved,
                "unresolved": unresolved,
            }
        correlated[quest_id] = record

    summary: dict[str, Any] = {
        "locale": locale,
        "quest_count": len(all_ids),
        "complete_quest_count": len(complete_ids),
        "table_counts": {
            **{name: len(ids) for name, ids in table_ids.items()},
            "PQuestSearchRoots": len(decoded["PQuestSearch"]),
        },
        "presence_patterns": [
            {"tables": list(pattern), "count": count}
            for pattern, count in sorted(
                pattern_counts.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "missing_from_core_table": {
            name: sorted(core_ids - table_ids[name], key=_quest_sort_key)
            for name in CORE_QUEST_TABLES
        },
        "auxiliary_correlations": {
            "PQuest": {
                "matched_core_ids": sorted(
                    table_ids["PQuest"] & core_ids, key=_quest_sort_key
                ),
                "unmatched_ids": sorted(
                    table_ids["PQuest"] - core_ids, key=_quest_sort_key
                ),
            },
            "Exclusive": {
                "groups": len(decoded["Exclusive"]),
                "quest_ids": len(exclusive_groups),
                "matched_core_ids": sorted(
                    table_ids["Exclusive"] & core_ids, key=_quest_sort_key
                ),
                "unmatched_ids": sorted(
                    table_ids["Exclusive"] - core_ids, key=_quest_sort_key
                ),
            },
            "PQuestSearch": {
                "root_keys": list(decoded["PQuestSearch"]),
                "note": "party-search configuration; roots are not quest IDs",
            },
        },
        "symbolic_references": reference_totals,
    }
    output = {
        "format": "maplestory-classic-correlated-quests-v1",
        "locale": locale,
        "summary": summary,
        "quests": correlated,
        "pquest_search": decoded["PQuestSearch"],
    }
    return output, summary


def dump_quests(
    addressables_root: Path, output_directory: Path, locale: str = "TW"
) -> dict[str, Any]:
    """Extract every direct Quest/*.wzjson asset and return its manifest."""

    if not addressables_root.is_dir():
        raise QuestDumpError(
            f"Addressables directory does not exist: {addressables_root}"
        )
    bundles = sorted(addressables_root.glob("json_*.bundle"))
    if not bundles:
        raise QuestDumpError(
            f"no json_*.bundle files found under {addressables_root}"
        )

    output_directory.mkdir(parents=True, exist_ok=True)
    wanted_quest_data = quest_data_asset_path(locale)
    decoded: dict[str, dict[str, Any]] = {}
    assets: list[dict[str, Any]] = []
    quest_data: dict[str, Any] | None = None
    quest_data_entry: dict[str, Any] | None = None

    for bundle in bundles:
        environment = UnityPy.load(str(bundle))
        for asset_path, pointer in sorted(environment.container.items()):
            table_name = quest_asset_name(asset_path)
            if table_name is not None:
                if table_name in decoded:
                    raise QuestDumpError(
                        f"duplicate Quest/{table_name}.wzjson asset: {asset_path}"
                    )
                reader = pointer.deref()
                if reader is None or reader.type.name != "MonoBehaviour":
                    object_type = None if reader is None else reader.type.name
                    raise QuestDumpError(
                        f"{asset_path} is not a readable MonoBehaviour: {object_type}"
                    )
                serialized = reader.get_raw_data()
                try:
                    payload, layout = extract_serialized_wzjson(serialized, asset_path)
                    result = decode_wzjson(payload, layout)
                except WzJsonError as error:
                    raise QuestDumpError(f"cannot decode {asset_path}: {error}") from error
                if not isinstance(result.document, dict):
                    raise QuestDumpError(
                        f"{asset_path} decoded to {type(result.document).__name__}; "
                        "expected object"
                    )
                expected_root = f"Quest/{table_name}"
                if result.root_path != expected_root:
                    raise QuestDumpError(
                        f"{asset_path} root path is {result.root_path!r}; "
                        f"expected {expected_root!r}"
                    )

                raw_path = Path("raw/Quest") / f"{table_name}.wzjson"
                layout_path = Path("raw/Quest") / f"{table_name}.layout.json"
                decoded_path = Path("decoded/Quest") / f"{table_name}.json"
                raw_destination = output_directory / raw_path
                raw_destination.parent.mkdir(parents=True, exist_ok=True)
                raw_destination.write_bytes(payload)
                layout_bytes = _write_json(
                    output_directory / layout_path,
                    {
                        "format": "maplestory-classic-wzjs-layout-v1",
                        "wzjs_version": WZJSON_VERSION,
                        "asset_path": asset_path,
                        "layout": layout.to_dict(),
                    },
                )
                decoded_bytes = _write_json(
                    output_directory / decoded_path, result.document
                )
                decoded[table_name] = result.document
                assets.append(
                    {
                        "name": table_name,
                        "asset_path": asset_path,
                        "source_bundle": bundle.name,
                        "raw_path": raw_path.as_posix(),
                        "raw_bytes": len(payload),
                        "raw_sha256": hashlib.sha256(payload).hexdigest(),
                        "serialized_object_bytes": len(serialized),
                        "serialized_object_sha256": hashlib.sha256(serialized).hexdigest(),
                        "layout_path": layout_path.as_posix(),
                        "layout_bytes": len(layout_bytes),
                        "layout_sha256": hashlib.sha256(layout_bytes).hexdigest(),
                        "decoded_path": decoded_path.as_posix(),
                        "decoded_bytes": len(decoded_bytes),
                        "decoded_sha256": hashlib.sha256(decoded_bytes).hexdigest(),
                        "root_path": result.root_path,
                        "entries": len(result.document),
                        "nodes": result.node_count,
                        "keys": result.key_count,
                        "paths": result.path_count,
                        "unique_string_values": result.string_count,
                        "scalar_counts": result.scalar_counts,
                    }
                )
                continue

            if asset_path != wanted_quest_data:
                continue
            if quest_data is not None:
                raise QuestDumpError(f"duplicate localized quest data: {asset_path}")
            reader = pointer.deref()
            if reader is None or reader.type.name != "TextAsset":
                object_type = None if reader is None else reader.type.name
                raise QuestDumpError(
                    f"{asset_path} is not a readable TextAsset: {object_type}"
                )
            raw = text_asset_bytes(reader.parse_as_object(), asset_path)
            quest_data = parse_json_object(raw, asset_path)
            localized_path = Path("localized/String") / locale / "QuestData.json"
            localized_destination = output_directory / localized_path
            localized_destination.parent.mkdir(parents=True, exist_ok=True)
            localized_destination.write_bytes(raw)
            quest_data_entry = {
                "asset_path": asset_path,
                "source_bundle": bundle.name,
                "output_path": localized_path.as_posix(),
                "entries": len(quest_data),
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }

    missing = sorted(EXPECTED_QUEST_TABLES - set(decoded))
    if missing:
        raise QuestDumpError(
            "installed client is missing expected Quest/*.wzjson tables: "
            + ", ".join(missing)
        )
    if quest_data is None or quest_data_entry is None:
        raise QuestDumpError(f"localized quest data not found: {wanted_quest_data}")

    correlation, correlation_summary = correlate_quests(decoded, quest_data, locale)
    correlation_path = Path("correlated/quests.json")
    correlation_bytes = _write_json(output_directory / correlation_path, correlation)
    assets.sort(key=lambda asset: asset["name"])
    manifest: dict[str, Any] = {
        "format": "maplestory-classic-quest-dump-v1",
        "source_addressables_root": str(addressables_root.resolve()),
        "unitypy_version": UnityPy.__version__,
        "wzjs_version": WZJSON_VERSION,
        "quest_asset_count": len(assets),
        "quest_assets": assets,
        "localized_quest_data": quest_data_entry,
        "correlation": {
            "output_path": correlation_path.as_posix(),
            "bytes": len(correlation_bytes),
            "sha256": hashlib.sha256(correlation_bytes).hexdigest(),
            **correlation_summary,
        },
    }
    _write_json(output_directory / MANIFEST_NAME, manifest)
    return manifest


def main() -> int:
    arguments = parse_args()
    try:
        manifest = dump_quests(
            arguments.addressables_root, arguments.output_directory, arguments.locale
        )
    except (OSError, QuestDumpError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    correlation = manifest["correlation"]
    print(
        f"dumped {manifest['quest_asset_count']} Quest/*.wzjson assets and "
        f"correlated {correlation['quest_count']} quest IDs "
        f"({correlation['complete_quest_count']} complete) into "
        f"{arguments.output_directory}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

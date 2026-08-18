#!/usr/bin/env python3
"""Extract MapleStory Classic table JSON from the installed Unity bundles.

The current client stores these files as ordinary Unity ``TextAsset`` objects
inside LZ4-compressed UnityFS Addressables bundles.  Their payloads are already
UTF-8 JSON once the bundle is decompressed; no game-specific cipher is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

import UnityPy


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ADDRESSABLES_ROOT = (
    PROJECT_ROOT
    / "downloads/maplestory_classic_wine_prefix/drive_c/Program Files/Gamania"
    / "maplestory_classic/Maplestory_Classic_Data/StreamingAssets/aa/w"
)
DEFAULT_OUTPUT_DIRECTORY = PROJECT_ROOT / "downloads/maplestory_classic_gametables"
JSON_ASSET_ROOT = PurePosixPath("Assets/WzAssets/Json")
MANIFEST_NAME = "manifest.json"


class GameTableDumpError(RuntimeError):
    """Raised when a table asset cannot be extracted without ambiguity."""


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
        help="directory that receives the extracted JSON and manifest",
    )
    return parser.parse_args()


def game_table_relative_path(asset_path: str) -> Path | None:
    """Return a safe output path for a table-named WZ JSON asset."""

    source = PurePosixPath(asset_path)
    try:
        relative = source.relative_to(JSON_ASSET_ROOT)
    except ValueError:
        return None
    if relative.suffix.casefold() != ".json" or not relative.stem.endswith("Table"):
        return None
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise GameTableDumpError(f"unsafe table asset path: {asset_path!r}")
    return Path(*relative.parts)


def text_asset_bytes(text_asset: Any) -> bytes:
    """Recover the original bytes from UnityPy's surrogate-safe TextAsset text."""

    script = text_asset.m_Script
    if isinstance(script, bytes):
        return script
    if not isinstance(script, str):
        raise GameTableDumpError(
            f"TextAsset m_Script has unsupported type {type(script).__name__}"
        )
    return script.encode("utf-8", "surrogateescape")


def parse_table_json(raw: bytes, asset_path: str) -> tuple[str, int]:
    """Validate one table document and return its top-level kind and size."""

    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GameTableDumpError(f"invalid JSON in {asset_path}: {error}") from error
    if isinstance(document, dict):
        return "object", len(document)
    if isinstance(document, list):
        return "array", len(document)
    raise GameTableDumpError(
        f"table {asset_path} has unsupported top-level JSON "
        f"type {type(document).__name__}"
    )


def dump_game_tables(addressables_root: Path, output_directory: Path) -> dict[str, Any]:
    """Extract all table-named JSON TextAssets and return their manifest."""

    if not addressables_root.is_dir():
        raise GameTableDumpError(
            f"Addressables directory does not exist: {addressables_root}"
        )
    bundles = sorted(addressables_root.glob("json_*.bundle"))
    if not bundles:
        raise GameTableDumpError(
            f"no json_*.bundle files found under {addressables_root}"
        )

    tables: list[dict[str, Any]] = []
    claimed_outputs: dict[str, str] = {}
    output_directory.mkdir(parents=True, exist_ok=True)

    for bundle in bundles:
        environment = UnityPy.load(str(bundle))
        for asset_path, pointer in sorted(environment.container.items()):
            relative_output = game_table_relative_path(asset_path)
            if relative_output is None:
                continue
            output_key = relative_output.as_posix()
            if output_key in claimed_outputs:
                raise GameTableDumpError(
                    f"duplicate output {output_key!r} from {claimed_outputs[output_key]} "
                    f"and {asset_path}"
                )

            object_reader = pointer.deref()
            if object_reader is None or object_reader.type.name != "TextAsset":
                object_type = None if object_reader is None else object_reader.type.name
                raise GameTableDumpError(
                    f"table {asset_path} is not a readable TextAsset: {object_type}"
                )
            text_asset = object_reader.parse_as_object()
            raw = text_asset_bytes(text_asset)
            json_type, entries = parse_table_json(raw, asset_path)

            destination = output_directory / relative_output
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            claimed_outputs[output_key] = asset_path
            tables.append(
                {
                    "asset_path": asset_path,
                    "source_bundle": bundle.name,
                    "output_path": output_key,
                    "json_type": json_type,
                    "entries": entries,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )

    if not tables:
        raise GameTableDumpError(
            f"no table-named JSON TextAssets found under {addressables_root}"
        )

    tables.sort(key=lambda table: table["output_path"])
    manifest: dict[str, Any] = {
        "format": "maplestory-classic-gametable-dump-v1",
        "source_addressables_root": str(addressables_root.resolve()),
        "unitypy_version": UnityPy.__version__,
        "table_count": len(tables),
        "total_bytes": sum(table["bytes"] for table in tables),
        "tables": tables,
    }
    manifest_path = output_directory / MANIFEST_NAME
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    arguments = parse_args()
    try:
        manifest = dump_game_tables(
            arguments.addressables_root, arguments.output_directory
        )
    except GameTableDumpError as error:
        raise SystemExit(str(error)) from error

    for table in manifest["tables"]:
        print(
            f"{table['output_path']}: {table['entries']} entries, "
            f"{table['bytes']} bytes"
        )
    print(
        f"gametable_dump_complete tables={manifest['table_count']} "
        f"bytes={manifest['total_bytes']} "
        f"manifest={arguments.output_directory / MANIFEST_NAME}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

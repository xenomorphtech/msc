from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "tools/dump_gametables.py"
SPEC = importlib.util.spec_from_file_location("dump_gametables", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
dump_gametables = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dump_gametables)


class FakeObjectReader:
    def __init__(self, name: str, raw: bytes) -> None:
        self.type = SimpleNamespace(name="TextAsset")
        self._asset = SimpleNamespace(
            m_Name=name,
            m_Script=raw.decode("utf-8", "surrogateescape"),
        )

    def parse_as_object(self) -> SimpleNamespace:
        return self._asset


class FakePointer:
    def __init__(self, name: str, raw: bytes) -> None:
        self._reader = FakeObjectReader(name, raw)

    def deref(self) -> FakeObjectReader:
        return self._reader


class GameTableDumperTest(unittest.TestCase):
    def test_selects_table_json_and_preserves_category_path(self) -> None:
        self.assertEqual(
            dump_gametables.game_table_relative_path(
                "Assets/WzAssets/Json/Sound/MobTable.json"
            ),
            Path("Sound/MobTable.json"),
        )
        self.assertIsNone(
            dump_gametables.game_table_relative_path(
                "Assets/WzAssets/Json/String/Mob.json"
            )
        )
        self.assertIsNone(
            dump_gametables.game_table_relative_path("Assets/Other/MobTable.json")
        )

    def test_parses_bom_prefixed_object_and_array_tables(self) -> None:
        self.assertEqual(
            dump_gametables.parse_table_json(b'\xef\xbb\xbf{"1": {}}', "one.json"),
            ("object", 1),
        )
        self.assertEqual(
            dump_gametables.parse_table_json(b"[1, 2, 3]", "many.json"),
            ("array", 3),
        )

    def test_dumps_distinct_pet_tables_and_writes_a_verified_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            addressables = root / "aa/w"
            output = root / "dump"
            addressables.mkdir(parents=True)
            first_bundle = addressables / "json_first.bundle"
            second_bundle = addressables / "json_second.bundle"
            first_bundle.touch()
            second_bundle.touch()

            item_pet = b"[5000000, 5000001]"
            sound_pet = b'{"5000000": {"name": "pet"}}'
            mob_table = b'{"100100": {"name": "mob"}}'
            environments = {
                str(first_bundle): SimpleNamespace(
                    container={
                        "Assets/WzAssets/Json/Item/PetTable.json": FakePointer(
                            "PetTable", item_pet
                        ),
                        "Assets/WzAssets/Json/Item/Item.json": FakePointer(
                            "Item", b"{}"
                        ),
                    }
                ),
                str(second_bundle): SimpleNamespace(
                    container={
                        "Assets/WzAssets/Json/Sound/PetTable.json": FakePointer(
                            "PetTable", sound_pet
                        ),
                        "Assets/WzAssets/Json/Sound/MobTable.json": FakePointer(
                            "MobTable", mob_table
                        ),
                    }
                ),
            }

            with patch.object(
                dump_gametables.UnityPy,
                "load",
                side_effect=lambda path: environments[path],
            ):
                manifest = dump_gametables.dump_game_tables(addressables, output)

            self.assertEqual(manifest["table_count"], 3)
            self.assertEqual((output / "Item/PetTable.json").read_bytes(), item_pet)
            self.assertEqual((output / "Sound/PetTable.json").read_bytes(), sound_pet)
            self.assertEqual((output / "Sound/MobTable.json").read_bytes(), mob_table)
            persisted = json.loads((output / "manifest.json").read_text())
            self.assertEqual(persisted["tables"], manifest["tables"])
            self.assertEqual(
                [table["output_path"] for table in persisted["tables"]],
                [
                    "Item/PetTable.json",
                    "Sound/MobTable.json",
                    "Sound/PetTable.json",
                ],
            )


if __name__ == "__main__":
    unittest.main()

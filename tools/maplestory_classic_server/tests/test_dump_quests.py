from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).parents[1]
SCRIPT = PROJECT / "tools/dump_quests.py"
SPEC = importlib.util.spec_from_file_location("dump_quests", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
dump_quests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dump_quests)

from maple_server.wzjson import (  # noqa: E402
    WzJsonError,
    decode_wzjson,
    extract_serialized_wzjson,
)


def _align(buffer: bytearray, alignment: int) -> None:
    buffer.extend(b"\x00" * (-len(buffer) % alignment))


def _append(buffer: bytearray, data: bytes, alignment: int = 4) -> int:
    _align(buffer, alignment)
    offset = len(buffer)
    buffer.extend(data)
    return offset


def _string_pool(buffer: bytearray, values: list[str]) -> tuple[int, int]:
    encoded = [value.encode("utf-8") for value in values]
    data_offset = _append(buffer, b"".join(encoded), 1)
    offsets = [0]
    for value in encoded:
        offsets.append(offsets[-1] + len(value))
    offsets_offset = _append(
        buffer, struct.pack(f"<{len(offsets)}I", *offsets), 4
    )
    return data_offset, offsets_offset


def build_serialized_wzjson(table_name: str) -> tuple[bytes, bytes]:
    if table_name == "Exclusive":
        keys = [table_name, "0", "10415"]
        paths = ["0", "0/10415", f"Quest/{table_name}"]
        strings = [""]
        nodes = [
            (2, 0, -1, 1, 1, -1, 2, 0),
            (2, 1, -1, 2, 1, 0, 0, 0),
            (11, 2, 0, -1, 0, 1, 1, 0),
        ]
        child_indexes = (1, 2)
        bool_data = b""
        int32_data = b""
        vector2_data = b""
    else:
        keys = [table_name, "1000", "enabled", "level", "text", "position"]
        paths = [
            "1000",
            "1000/enabled",
            "1000/level",
            "1000/text",
            "1000/position",
            f"Quest/{table_name}",
        ]
        strings = ["hello"]
        nodes = [
            (2, 0, -1, 1, 1, -1, 5, 0),
            (2, 1, -1, 2, 4, 0, 0, 0),
            (3, 2, 0, -1, 0, 1, 1, 0),
            (6, 3, 0, -1, 0, 1, 2, 0),
            (11, 4, 0, -1, 0, 1, 3, 0),
            (14, 5, 0, -1, 0, 1, 4, 0),
        ]
        child_indexes = (1, 2, 3, 4, 5)
        bool_data = b"\x01"
        int32_data = struct.pack("<i", 7)
        vector2_data = struct.pack("<2f", 1.5, -2.5)

    payload = bytearray(b"WZJS" + struct.pack("<I", 5))
    node_offset = _append(
        payload, b"".join(struct.pack("<8i", *node) for node in nodes), 4
    )
    child_index_offset = _append(
        payload,
        struct.pack(f"<{len(child_indexes)}i", *child_indexes),
        4,
    )
    bool_offset = _append(payload, bool_data, 1)
    byte_offset = len(payload)
    int16_offset = len(payload)
    int32_offset = _append(payload, int32_data, 4)
    int64_offset = len(payload)
    float32_offset = len(payload)
    vector2_offset = _append(payload, vector2_data, 4)
    float64_offset = len(payload)
    vector2int_offset = len(payload)
    rect_offset = len(payload)
    rectint_offset = len(payload)
    key_data_offset, key_offsets_offset = _string_pool(payload, keys)
    path_data_offset, path_offsets_offset = _string_pool(payload, paths)
    string_data_offset, string_offsets_offset = _string_pool(payload, strings)

    layout = (
        len(nodes),
        node_offset,
        len(child_indexes),
        child_index_offset,
        len(bool_data),
        bool_offset,
        0,
        byte_offset,
        0,
        int16_offset,
        len(int32_data) // 4,
        int32_offset,
        0,
        int64_offset,
        0,
        float32_offset,
        len(vector2_data) // 8,
        vector2_offset,
        0,
        float64_offset,
        0,
        vector2int_offset,
        0,
        rect_offset,
        0,
        rectint_offset,
        len(keys),
        key_data_offset,
        key_offsets_offset,
        len(paths),
        path_data_offset,
        path_offsets_offset,
        len(strings),
        string_data_offset,
        string_offsets_offset,
    )
    serialized = (
        b"\x00" * 36
        + struct.pack("<35I", *layout)
        + struct.pack("<I", len(payload))
        + bytes(payload)
    )
    return serialized, bytes(payload)


class FakeObjectReader:
    def __init__(self, object_type: str, raw: bytes) -> None:
        self.type = SimpleNamespace(name=object_type)
        self._raw = raw

    def get_raw_data(self) -> bytes:
        return self._raw

    def parse_as_object(self) -> SimpleNamespace:
        return SimpleNamespace(m_Script=self._raw.decode("utf-8", "surrogateescape"))


class FakePointer:
    def __init__(self, object_type: str, raw: bytes) -> None:
        self._reader = FakeObjectReader(object_type, raw)

    def deref(self) -> FakeObjectReader:
        return self._reader


class WzJsonDecoderTest(unittest.TestCase):
    def test_extracts_layout_and_decodes_typed_tree(self) -> None:
        serialized, payload = build_serialized_wzjson("Act")
        extracted, layout = extract_serialized_wzjson(serialized, "Act.wzjson")
        self.assertEqual(extracted, payload)
        result = decode_wzjson(extracted, layout)
        self.assertEqual(result.root_path, "Quest/Act")
        self.assertEqual(result.node_count, 6)
        self.assertEqual(
            result.document,
            {
                "1000": {
                    "enabled": True,
                    "level": 7,
                    "text": "hello",
                    "position": {"x": 1.5, "y": -2.5},
                }
            },
        )

    def test_rejects_a_second_magic_marker(self) -> None:
        serialized, _ = build_serialized_wzjson("Act")
        with self.assertRaisesRegex(WzJsonError, "more than one"):
            extract_serialized_wzjson(serialized + b"WZJS", "bad.wzjson")


class QuestDumperTest(unittest.TestCase):
    def test_selects_only_direct_quest_wzjson_assets(self) -> None:
        self.assertEqual(
            dump_quests.quest_asset_name("Assets/WzAssets/Json/Quest/Act.wzjson"),
            "Act",
        )
        self.assertIsNone(
            dump_quests.quest_asset_name(
                "Assets/WzAssets/Json/Mob/QuestCountGroup/1.wzjson"
            )
        )
        self.assertIsNone(
            dump_quests.quest_asset_name(
                "Assets/WzAssets/Json/Quest/Nested/Act.wzjson"
            )
        )

    def test_dumps_all_tables_and_resolves_localized_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            addressables = root / "aa/w"
            output = root / "dump"
            addressables.mkdir(parents=True)
            quest_bundle = addressables / "json_quest.bundle"
            string_bundle = addressables / "json_string.bundle"
            quest_bundle.touch()
            string_bundle.touch()

            quest_container = {}
            payloads = {}
            for table_name in sorted(dump_quests.EXPECTED_QUEST_TABLES):
                serialized, payload = build_serialized_wzjson(table_name)
                payloads[table_name] = payload
                quest_container[
                    f"Assets/WzAssets/Json/Quest/{table_name}.wzjson"
                ] = FakePointer("MonoBehaviour", serialized)
            localized = json.dumps(
                {
                    "1000": {
                        "name": "Localized quest",
                        "Info": {"hello": "Localized info"},
                        "Say": {"hello": "Localized speech"},
                    }
                }
            ).encode()
            environments = {
                str(quest_bundle): SimpleNamespace(container=quest_container),
                str(string_bundle): SimpleNamespace(
                    container={
                        "Assets/WzAssets/Json/String/TW/QuestData.json": FakePointer(
                            "TextAsset", localized
                        )
                    }
                ),
            }

            with patch.object(
                dump_quests.UnityPy,
                "load",
                side_effect=lambda path: environments[path],
            ):
                manifest = dump_quests.dump_quests(addressables, output)

            self.assertEqual(manifest["quest_asset_count"], 7)
            self.assertEqual(manifest["correlation"]["quest_count"], 2)
            self.assertEqual(manifest["correlation"]["complete_quest_count"], 1)
            self.assertEqual(
                (output / "raw/Quest/Act.wzjson").read_bytes(), payloads["Act"]
            )
            correlation = json.loads(
                (output / "correlated/quests.json").read_text()
            )
            quest = correlation["quests"]["1000"]
            self.assertEqual(
                quest["quest_info"]["resolved"]["text"], "Localized info"
            )
            self.assertEqual(quest["say"]["resolved"]["text"], "Localized speech")
            self.assertEqual(quest["quest_info"]["unresolved"], [])
            self.assertEqual(quest["say"]["unresolved"], [])
            self.assertIsNotNone(quest["pquest"])
            self.assertEqual(
                correlation["quests"]["10415"]["exclusive_groups"], ["0"]
            )


if __name__ == "__main__":
    unittest.main()

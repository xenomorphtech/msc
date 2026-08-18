"""Decode the compact WZJS v5 documents used by MapleStory Classic.

The Unity client imports ``*.wzjson`` files as a ScriptableObject.  Its byte
array starts with ``WZJS`` while the 35-word section directory is serialized
immediately before that array.  This module recovers both pieces from the raw
MonoBehaviour object and decodes the node tree without executing game code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import struct
from typing import Any


WZJSON_MAGIC = b"WZJS"
WZJSON_VERSION = 5
LAYOUT_WORD_COUNT = 35
NODE_SIZE = 32


class WzJsonError(ValueError):
    """Raised when a serialized WZJS document is malformed or unsupported."""


@dataclass(frozen=True)
class WzJsonLayout:
    node_count: int
    node_offset: int
    child_index_count: int
    child_index_offset: int
    bool_count: int
    bool_offset: int
    byte_count: int
    byte_offset: int
    int16_count: int
    int16_offset: int
    int32_count: int
    int32_offset: int
    int64_count: int
    int64_offset: int
    float32_count: int
    float32_offset: int
    vector2_count: int
    vector2_offset: int
    float64_count: int
    float64_offset: int
    vector2int_count: int
    vector2int_offset: int
    rect_count: int
    rect_offset: int
    rectint_count: int
    rectint_offset: int
    key_count: int
    key_data_offset: int
    key_offsets_offset: int
    path_count: int
    path_data_offset: int
    path_offsets_offset: int
    string_count: int
    string_data_offset: int
    string_offsets_offset: int

    @classmethod
    def from_words(cls, words: tuple[int, ...]) -> "WzJsonLayout":
        if len(words) != LAYOUT_WORD_COUNT:
            raise WzJsonError(
                f"WZJS layout has {len(words)} words; expected {LAYOUT_WORD_COUNT}"
            )
        return cls(*words)

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class WzJsonNode:
    kind: int
    key_index: int
    value_index: int
    first_child: int
    child_count: int
    parent_index: int
    path_index: int
    lookup_index: int


@dataclass(frozen=True)
class WzJsonDecodeResult:
    document: Any
    root_path: str
    node_count: int
    key_count: int
    path_count: int
    string_count: int
    scalar_counts: dict[str, int]


def extract_serialized_wzjson(
    raw_object: bytes, source: str = "MonoBehaviour"
) -> tuple[bytes, WzJsonLayout]:
    """Extract a WZJS byte array and its external layout from a Unity object."""

    magic_offset = raw_object.find(WZJSON_MAGIC)
    if magic_offset < 0:
        raise WzJsonError(f"{source} does not contain a WZJS payload")
    if raw_object.find(WZJSON_MAGIC, magic_offset + 1) >= 0:
        raise WzJsonError(f"{source} contains more than one WZJS marker")

    layout_size = LAYOUT_WORD_COUNT * 4
    layout_offset = magic_offset - 4 - layout_size
    if layout_offset < 0:
        raise WzJsonError(f"{source} is too short to contain the WZJS layout")

    declared_size = struct.unpack_from("<I", raw_object, magic_offset - 4)[0]
    payload_end = magic_offset + declared_size
    if declared_size < 8 or payload_end > len(raw_object):
        raise WzJsonError(
            f"{source} declares an invalid WZJS payload size {declared_size}"
        )
    trailing = raw_object[payload_end:]
    if len(trailing) > 3 or any(trailing):
        raise WzJsonError(f"{source} has unexpected data after its WZJS payload")

    payload = raw_object[magic_offset:payload_end]
    version = struct.unpack_from("<I", payload, 4)[0]
    if version != WZJSON_VERSION:
        raise WzJsonError(
            f"{source} uses WZJS version {version}; expected {WZJSON_VERSION}"
        )
    words = struct.unpack_from(f"<{LAYOUT_WORD_COUNT}I", raw_object, layout_offset)
    return payload, WzJsonLayout.from_words(words)


def _checked_span(
    payload: bytes, offset: int, count: int, item_size: int, label: str
) -> memoryview:
    if offset < 0 or count < 0:
        raise WzJsonError(f"negative {label} section bounds")
    end = offset + count * item_size
    if end > len(payload):
        raise WzJsonError(
            f"{label} section {offset:#x}:{end:#x} exceeds "
            f"the {len(payload):#x}-byte payload"
        )
    return memoryview(payload)[offset:end]


def _unpack_values(
    payload: bytes, offset: int, count: int, code: str, label: str
) -> tuple[Any, ...]:
    size = struct.calcsize(code)
    _checked_span(payload, offset, count, size, label)
    if not count:
        return ()
    return struct.unpack_from(f"<{count}{code}", payload, offset)


def _read_strings(
    payload: bytes,
    count: int,
    data_offset: int,
    offsets_offset: int,
    label: str,
) -> tuple[str, ...]:
    offsets = _unpack_values(
        payload, offsets_offset, count + 1, "I", f"{label} offsets"
    )
    if not offsets or offsets[0] != 0:
        raise WzJsonError(f"{label} offsets do not start at zero")
    if any(right < left for left, right in zip(offsets, offsets[1:])):
        raise WzJsonError(f"{label} offsets are not monotonic")
    _checked_span(payload, data_offset, offsets[-1], 1, f"{label} data")

    strings: list[str] = []
    for index, (start, end) in enumerate(zip(offsets, offsets[1:])):
        try:
            value = payload[data_offset + start : data_offset + end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise WzJsonError(f"invalid UTF-8 in {label} entry {index}") from error
        strings.append(value)
    return tuple(strings)


def decode_wzjson(payload: bytes, layout: WzJsonLayout) -> WzJsonDecodeResult:
    """Decode one WZJS v5 payload using its serialized section directory."""

    if payload[:4] != WZJSON_MAGIC:
        raise WzJsonError("payload does not start with WZJS")
    if len(payload) < 8 or struct.unpack_from("<I", payload, 4)[0] != WZJSON_VERSION:
        raise WzJsonError("payload is not WZJS version 5")
    if layout.node_count < 1:
        raise WzJsonError("WZJS document has no root node")

    node_bytes = _checked_span(
        payload, layout.node_offset, layout.node_count, NODE_SIZE, "nodes"
    )
    nodes = tuple(
        WzJsonNode(*struct.unpack_from("<8i", node_bytes, index * NODE_SIZE))
        for index in range(layout.node_count)
    )

    child_indexes = _unpack_values(
        payload,
        layout.child_index_offset,
        layout.child_index_count,
        "i",
        "child indexes",
    )
    if any(index < 0 or index >= layout.node_count for index in child_indexes):
        raise WzJsonError("child-index section references an invalid node")

    bool_bytes = bytes(
        _checked_span(payload, layout.bool_offset, layout.bool_count, 1, "booleans")
    )
    if any(value not in (0, 1) for value in bool_bytes):
        raise WzJsonError("boolean section contains a value other than zero or one")
    bool_values = tuple(bool(value) for value in bool_bytes)
    byte_values = tuple(
        _checked_span(payload, layout.byte_offset, layout.byte_count, 1, "bytes")
    )
    int16_values = _unpack_values(
        payload, layout.int16_offset, layout.int16_count, "h", "int16 values"
    )
    int32_values = _unpack_values(
        payload, layout.int32_offset, layout.int32_count, "i", "int32 values"
    )
    int64_values = _unpack_values(
        payload, layout.int64_offset, layout.int64_count, "q", "int64 values"
    )
    float32_values = _unpack_values(
        payload, layout.float32_offset, layout.float32_count, "f", "float32 values"
    )
    float64_values = _unpack_values(
        payload, layout.float64_offset, layout.float64_count, "d", "float64 values"
    )
    vector2_flat = _unpack_values(
        payload, layout.vector2_offset, layout.vector2_count * 2, "f", "Vector2 values"
    )
    vector2_values = tuple(
        {"x": vector2_flat[index], "y": vector2_flat[index + 1]}
        for index in range(0, len(vector2_flat), 2)
    )

    # Validate the Unity-specific pools even though current quest data does not
    # use these node kinds.
    for label, offset, count, size in (
        ("Vector2Int", layout.vector2int_offset, layout.vector2int_count, 8),
        ("Rect", layout.rect_offset, layout.rect_count, 16),
        ("RectInt", layout.rectint_offset, layout.rectint_count, 16),
    ):
        _checked_span(payload, offset, count, size, label)

    keys = _read_strings(
        payload,
        layout.key_count,
        layout.key_data_offset,
        layout.key_offsets_offset,
        "keys",
    )
    paths = _read_strings(
        payload,
        layout.path_count,
        layout.path_data_offset,
        layout.path_offsets_offset,
        "paths",
    )
    strings = _read_strings(
        payload,
        layout.string_count,
        layout.string_data_offset,
        layout.string_offsets_offset,
        "strings",
    )

    scalar_pools: dict[int, tuple[Any, ...]] = {
        3: bool_values,
        4: byte_values,
        5: int16_values,
        6: int32_values,
        7: int64_values,
        8: float32_values,
        9: float64_values,
        11: strings,
        14: vector2_values,
    }
    visited: set[int] = set()

    def decode_node(index: int, expected_parent: int, expected_path: str) -> Any:
        if index < 0 or index >= len(nodes):
            raise WzJsonError(f"node index {index} is out of bounds")
        if index in visited:
            raise WzJsonError(f"node {index} is referenced more than once")
        visited.add(index)
        node = nodes[index]

        if node.parent_index != expected_parent:
            raise WzJsonError(
                f"node {index} has parent {node.parent_index}; "
                f"expected {expected_parent}"
            )
        if node.key_index < 0 or node.key_index >= len(keys):
            raise WzJsonError(f"node {index} has invalid key index {node.key_index}")
        if node.path_index < 0 or node.path_index >= len(paths):
            raise WzJsonError(f"node {index} has invalid path index {node.path_index}")
        if paths[node.path_index] != expected_path:
            raise WzJsonError(
                f"node {index} path is {paths[node.path_index]!r}; "
                f"expected {expected_path!r}"
            )

        if node.kind in (1, 2, 18):
            if node.first_child < 0 and node.child_count:
                raise WzJsonError(f"container node {index} has no first child")
            child_end = node.first_child + node.child_count
            if node.child_count < 0 or child_end > len(nodes):
                raise WzJsonError(f"container node {index} has invalid child bounds")

            children: list[tuple[str, Any]] = []
            for child_index in range(node.first_child, child_end):
                child = nodes[child_index]
                if child.key_index < 0 or child.key_index >= len(keys):
                    raise WzJsonError(
                        f"child node {child_index} has invalid key index "
                        f"{child.key_index}"
                    )
                key = keys[child.key_index]
                # The root carries a diagnostic asset path (for example
                # ``Quest/Act``), while its children start the JSON path at the
                # first document key (for example ``1000``).
                child_path = (
                    key
                    if index == 0
                    else f"{expected_path}/{key}" if expected_path else key
                )
                value = decode_node(child_index, index, child_path)
                children.append((key, value))

            if node.kind == 1:
                return [value for _, value in children]
            if node.kind == 18 and not children:
                # WZ Canvas nodes carry their image data outside the JSON
                # property tree.  Navigation consumers only need their child
                # metadata, when present.
                return None
            document: dict[str, Any] = {}
            for key, value in children:
                if key in document:
                    raise WzJsonError(
                        f"object node {index} contains duplicate key {key!r}"
                    )
                document[key] = value
            return document

        if node.first_child != -1 or node.child_count != 0:
            raise WzJsonError(f"scalar node {index} unexpectedly has children")
        pool = scalar_pools.get(node.kind)
        if pool is None:
            raise WzJsonError(
                f"node {index} uses unsupported WZJS kind {node.kind}"
            )
        if node.value_index < 0 or node.value_index >= len(pool):
            raise WzJsonError(
                f"node {index} has invalid value index {node.value_index} "
                f"for kind {node.kind}"
            )
        return pool[node.value_index]

    root = nodes[0]
    if root.parent_index != -1:
        raise WzJsonError(f"root node has parent {root.parent_index}")
    if root.path_index < 0 or root.path_index >= len(paths):
        raise WzJsonError(f"root node has invalid path index {root.path_index}")
    document = decode_node(0, -1, paths[root.path_index])
    if len(visited) != len(nodes):
        unreachable = sorted(set(range(len(nodes))) - visited)
        raise WzJsonError(
            f"WZJS tree leaves {len(unreachable)} nodes unreachable: "
            f"{unreachable[:8]}"
        )

    return WzJsonDecodeResult(
        document=document,
        root_path=paths[root.path_index],
        node_count=layout.node_count,
        key_count=layout.key_count,
        path_count=layout.path_count,
        string_count=layout.string_count,
        scalar_counts={
            "bool": layout.bool_count,
            "byte": layout.byte_count,
            "int16": layout.int16_count,
            "int32": layout.int32_count,
            "int64": layout.int64_count,
            "float32": layout.float32_count,
            "float64": layout.float64_count,
            "vector2": layout.vector2_count,
            "vector2int": layout.vector2int_count,
            "rect": layout.rect_count,
            "rectint": layout.rectint_count,
            "string": layout.string_count,
        },
    )

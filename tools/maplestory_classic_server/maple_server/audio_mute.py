from __future__ import annotations

import argparse
import json
import subprocess
import time


TARGET_APPLICATION_NAMES = frozenset(
    {
        "maplestory_classic.exe",
        "maplestory classic",
    }
)


def is_maplestory_audio_node(properties: dict[str, object]) -> bool:
    if properties.get("media.class") != "Stream/Output/Audio":
        return False
    names = (
        properties.get("application.name"),
        properties.get("node.name"),
    )
    return any(
        isinstance(name, str) and name.casefold() in TARGET_APPLICATION_NAMES
        for name in names
    )


def find_maplestory_audio_nodes(snapshot: object) -> tuple[int, ...]:
    if not isinstance(snapshot, list):
        raise ValueError("pw-dump root must be a JSON array")
    node_ids: list[int] = []
    for item in snapshot:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "PipeWire:Interface:Node":
            continue
        info = item.get("info")
        if not isinstance(info, dict):
            continue
        properties = info.get("props")
        if not isinstance(properties, dict) or not is_maplestory_audio_node(
            properties
        ):
            continue
        node_id = item.get("id")
        if isinstance(node_id, int):
            node_ids.append(node_id)
    return tuple(sorted(set(node_ids)))


def read_pipewire_snapshot() -> object:
    completed = subprocess.run(
        ["pw-dump"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return json.loads(completed.stdout)


def node_is_muted(node_id: int) -> bool:
    completed = subprocess.run(
        ["wpctl", "get-volume", str(node_id)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return "[MUTED]" in completed.stdout


def mute_node(node_id: int) -> None:
    subprocess.run(
        ["wpctl", "set-mute", str(node_id), "1"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )


def enforce_maplestory_mute(*, verbose: bool = False) -> tuple[int, ...]:
    muted: list[int] = []
    for node_id in find_maplestory_audio_nodes(read_pipewire_snapshot()):
        if node_is_muted(node_id):
            continue
        mute_node(node_id)
        muted.append(node_id)
        if verbose:
            print(f"muted MapleStory PipeWire node {node_id}", flush=True)
    return tuple(muted)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Continuously mute MapleStory Classic PipeWire output streams by "
            "stable application identity"
        )
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=0.25)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main() -> None:
    arguments = build_parser().parse_args()
    if arguments.interval <= 0:
        raise SystemExit("--interval must be greater than zero")
    while True:
        try:
            enforce_maplestory_mute(verbose=arguments.verbose)
        except (
            FileNotFoundError,
            json.JSONDecodeError,
            subprocess.SubprocessError,
            ValueError,
        ) as error:
            if arguments.once:
                raise SystemExit(f"could not enforce MapleStory mute: {error}")
            if arguments.verbose:
                print(f"audio mute retry: {error}", flush=True)
        if arguments.once:
            return
        time.sleep(arguments.interval)


if __name__ == "__main__":
    main()

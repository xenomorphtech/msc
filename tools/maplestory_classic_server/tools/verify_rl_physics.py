#!/usr/bin/env python3
"""Verify prefab physics and opcode-47 emission against a live RL capture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

from maple_server.movement_verification import verify_rl_capture
from maple_server.navigation import load_world_maps


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--world",
        type=Path,
        default=Path("/home/sdancer/ms4/knowledge/world-v300.json"),
    )
    parser.add_argument("--map-id", type=int, default=101_000_000)
    parser.add_argument(
        "--model",
        type=Path,
        default=Path(".codex_tmp/physics-lab/rl-model-prefab.json"),
    )
    parser.add_argument(
        "--status", type=Path, default=Path("/tmp/maple-rl-agent.json")
    )
    parser.add_argument(
        "--telemetry", type=Path, default=Path("/tmp/maple-physics.jsonl")
    )
    parser.add_argument(
        "--transcript",
        type=Path,
        default=Path(
            ".codex_tmp/physics-lab/world/"
            "1787369081842491203_replay_12857.jsonl"
        ),
    )
    parser.add_argument("--window-seconds", type=float, default=140.0)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    maps = {item.map_id: item for item in load_world_maps(arguments.world)}
    try:
        geometry = maps[arguments.map_id]
    except KeyError as error:
        raise RuntimeError(
            f"map {arguments.map_id} is absent from {arguments.world}"
        ) from error
    report = verify_rl_capture(
        geometry=geometry,
        model_path=arguments.model,
        status_path=arguments.status,
        telemetry_path=arguments.telemetry,
        transcript_path=arguments.transcript,
        window_seconds=arguments.window_seconds,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

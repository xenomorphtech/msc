#!/usr/bin/env python3
"""Train/run the live RL policy and inject actions into Weston Xwayland."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time


SERVER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_ROOT))

from maple_server.navigation import load_world_maps
from maple_server.rl_navigation import (
    LinearQModel,
    NavigationAgent,
    Observation,
    XdotoolController,
    write_agent_status,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--telemetry", type=Path, default=Path("/tmp/maple-physics-latest.json"))
    parser.add_argument("--world", type=Path, default=Path("/home/sdancer/ms4/knowledge/world-v300.json"))
    parser.add_argument("--map-id", type=int, default=101_000_000)
    parser.add_argument("--model", type=Path, default=Path(".codex_tmp/physics-lab/rl-model.json"))
    parser.add_argument("--status", type=Path, default=Path("/tmp/maple-rl-agent.json"))
    parser.add_argument("--display", required=True)
    parser.add_argument("--xauthority")
    parser.add_argument("--epsilon", type=float, default=0.08)
    parser.add_argument("--interval", type=float, default=0.03)
    parser.add_argument("--max-frame-age", type=float, default=1.0)
    parser.add_argument("--max-frames", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    arguments = parser.parse_args()
    if not 0.0 <= arguments.epsilon <= 1.0:
        parser.error("--epsilon must be between zero and one")
    if arguments.interval <= 0:
        parser.error("--interval must be positive")
    if arguments.max_frame_age <= 0:
        parser.error("--max-frame-age must be positive")
    return arguments


def main() -> int:
    arguments = parse_args()
    maps = {item.map_id: item for item in load_world_maps(arguments.world)}
    try:
        geometry = maps[arguments.map_id]
    except KeyError as error:
        raise RuntimeError(f"map {arguments.map_id} is absent from {arguments.world}") from error
    model = LinearQModel.load(arguments.model)
    controller = XdotoolController(
        arguments.display,
        xauthority=arguments.xauthority,
        dry_run=arguments.dry_run,
    )
    agent = NavigationAgent(geometry, model, controller, epsilon=arguments.epsilon)
    last_frame = -1
    processed = 0
    try:
        while arguments.max_frames is None or processed < arguments.max_frames:
            try:
                record = json.loads(arguments.telemetry.read_text(encoding="utf-8"))
                observation = Observation.from_record(record)
            except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
                time.sleep(arguments.interval)
                continue
            if (
                observation.timestamp_ns <= 0
                or time.time_ns() - observation.timestamp_ns
                > arguments.max_frame_age * 1_000_000_000
            ):
                controller.release()
                time.sleep(arguments.interval)
                continue
            if observation.frame == last_frame:
                time.sleep(arguments.interval)
                continue
            last_frame = observation.frame
            status = agent.step(observation)
            write_agent_status(arguments.status, status)
            if not arguments.quiet:
                print(
                    json.dumps(status, separators=(",", ":"), sort_keys=True),
                    flush=True,
                )
            processed += 1
            if model.updates % 20 == 0:
                model.save(arguments.model)
            time.sleep(arguments.interval)
    except KeyboardInterrupt:
        return 0
    finally:
        controller.release()
        model.save(arguments.model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

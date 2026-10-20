#!/usr/bin/env python3
"""Publish consistent graph snapshots as background analysis finishes modules."""
import argparse
import json
import os
from pathlib import Path
import time

from build import DEFAULT_STATE, ensure_thunks
from store import ingest


def fingerprint(state):
    files = sorted((state / "modules").glob("*/summary.json"))
    files += sorted(p for p in (state / "modules").glob("*/functions.jsonl") if not (p.parent / "summary.json").exists())
    files += sorted((state / "validation").glob("*/validation.json"))
    result = []
    for path in files:
        stat = path.stat()
        result.append((str(path), stat.st_size, stat.st_mtime_ns))
        if path.parent.parent.name == "validation":
            report = json.loads(path.read_text())
            for artifact in [report.get("source"), *[r.get("executable") for r in report.get("results", [])],
                             *[item.get("path") for item in report.get("integration", {}).get("artifacts", [])]]:
                if artifact and Path(artifact).exists():
                    s = Path(artifact).stat()
                    result.append((artifact, s.st_size, s.st_mtime_ns))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--interval", type=int, default=120)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("interval must be positive")
    args.state = args.state.resolve()
    args.ghidra = sorted((args.state / "toolchain").glob("ghidra_*_PUBLIC"))[-1]
    inventory = json.loads((args.state / "inventory.json").read_text())
    previous = None
    while True:
        current = fingerprint(args.state)
        complete = [b for b in inventory if (args.state / "modules" / b["id"] / "summary.json").exists()]
        if complete and current != previous:
            try:
                for binary in complete:
                    ensure_thunks(binary, args)
                report = ingest(args.state, allow_partial=True, publish=True)
            except Exception as error:
                failure = {"pid": os.getpid(), "error": str(error), "at_ns": time.time_ns()}
                (args.state / "watch-error.json").write_text(json.dumps(failure, indent=2) + "\n")
                print(json.dumps(failure), flush=True)
                if args.once:
                    raise
                time.sleep(args.interval)
                continue
            # A module may finish while ingestion is running. Keep the starting
            # fingerprint so a later iteration cannot overlook that new export.
            previous = current
            status = {"pid": os.getpid(), "published_at_ns": time.time_ns(),
                      "modules_complete": report["modules_complete"], "modules_requested": len(inventory),
                      "function_status": report["function_status"], "rebuild_coverage": report["rebuild_coverage"],
                      "database": report["database"]}
            (args.state / "watch-status.json").write_text(json.dumps(status, indent=2) + "\n")
            (args.state / "watch-error.json").unlink(missing_ok=True)
            print(json.dumps(status), flush=True)
        if args.once or len(complete) == len(inventory):
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

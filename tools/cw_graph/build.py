#!/usr/bin/env python3
"""Analyse supplied native PE files, decompile their functions, and build a Kuzu graph."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import subprocess
import time

import pefile

from store import ingest, file_sha256


REPO = Path(__file__).resolve().parents[2]
DEFAULT_STATE = REPO / "downloads/cw_graph"


def inventory(directory, selected=None):
    paths = [directory / name for name in selected] if selected else sorted(
        [directory / "MapleStory.exe", *directory.glob("*.dll")], key=lambda p: (p.name != "MapleStory.exe", p.name.lower()))
    result = []
    for path in paths:
        path = path.resolve()
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[0, 1, 13])
        sha = file_sha256(path)
        exports = [{"name": e.name.decode("utf-8", "replace") if e.name else f"Ordinal_{e.ordinal}",
                    "ordinal": e.ordinal, "rva": e.address,
                    "forwarder": e.forwarder.decode("ascii", "replace") if e.forwarder else ""}
                   for e in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])]
        imports = sorted({entry.dll.decode("ascii", "replace") for attr in ["DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"]
                          for entry in getattr(pe, attr, [])})
        result.append({"id": sha, "sha256": sha, "name": path.name, "path": str(path),
                       "bytes": path.stat().st_size, "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                       "machine": hex(pe.FILE_HEADER.Machine), "imports": imports, "exports": exports})
        pe.close()
    return result


def analyse(binary, args):
    directory = args.state / "modules" / binary["id"]
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "summary.json").exists():
        ensure_thunks(binary, args)
        return {"name": binary["name"], "status": "reused"}
    running = directory / "running.json"
    if running.exists():
        pid = json.loads(running.read_text())["pid"]
        while Path(f"/proc/{pid}").exists():
            try:
                command_line = Path(f"/proc/{pid}/cmdline").read_bytes()
                if b"analyzeHeadless" not in command_line or binary["path"].encode() not in command_line:
                    break
            except FileNotFoundError:
                break
            if (directory / "summary.json").exists():
                ensure_thunks(binary, args)
                return {"name": binary["name"], "status": "complete"}
            stat = Path(f"/proc/{pid}/stat")
            try:
                if stat.read_text().split(")", 1)[1].strip().startswith("Z"):
                    break
            except FileNotFoundError:
                break
            time.sleep(2)
        if (directory / "summary.json").exists():
            ensure_thunks(binary, args)
            return {"name": binary["name"], "status": "complete"}
    project = "cw_" + binary["id"][:16]
    old_exports = [directory / name for name in ["console.log", "function-index.jsonl", "functions.jsonl",
                   "calls.jsonl", "external.jsonl", "thunks.jsonl", "incremental-functions.jsonl", "incremental-summary.json"]]
    old_exports = [path for path in old_exports if path.exists()]
    if old_exports:
        archive = directory / "attempts" / str(time.time_ns())
        archive.mkdir(parents=True)
        for path in old_exports:
            path.replace(archive / path.name)
    command = [str(args.ghidra / "support/analyzeHeadless"), str(args.state / "projects"), project,
               "-import", binary["path"], "-overwrite",
               "-preScript", "PrepareFunctions.java",
               "-scriptPath", str(Path(__file__).parent.resolve()),
               "-postScript", "ExportGraph.java", str(directory), binary["id"], str(args.workers), str(args.timeout),
               "-max-cpu", str(args.workers), "-log", str(directory / "ghidra.log"), "-scriptlog", str(directory / "script.log")]
    started = time.time()
    with (directory / "console.log").open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                   env={**os.environ, "GHIDRA_HEADLESS_MAXMEM": args.heap})
        (directory / "running.json").write_text(json.dumps({"pid": process.pid, "started": started, "command": command}) + "\n")
        code = process.wait()
    if code or not (directory / "summary.json").exists():
        raise RuntimeError(f"analysis failed for {binary['name']} (exit {code}); inspect {directory / 'console.log'}")
    return {"name": binary["name"], "status": "complete", "seconds": round(time.time() - started, 2)}


def ensure_thunks(binary, args):
    directory = args.state / "modules" / binary["id"]
    if (directory / "thunks.jsonl").exists():
        return
    running = directory / "running.json"
    if running.exists():
        pid = json.loads(running.read_text())["pid"]
        while Path(f"/proc/{pid}/cmdline").exists():
            try:
                command_line = Path(f"/proc/{pid}/cmdline").read_bytes()
            except FileNotFoundError:
                break
            if b"analyzeHeadless" not in command_line or binary["path"].encode() not in command_line:
                break
            time.sleep(1)
    command = [str(args.ghidra / "support/analyzeHeadless"), str(args.state / "projects"),
               "cw_" + binary["id"][:16], "-process", binary["name"], "-noanalysis", "-readOnly",
               "-scriptPath", str(Path(__file__).parent.resolve()), "-postScript", "ExportThunks.java",
               str(directory), binary["id"]]
    with (directory / "thunks.log").open("a") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                env={**os.environ, "GHIDRA_HEADLESS_MAXMEM": "2G"})
    if result.returncode or not (directory / "thunks.jsonl").exists():
        raise RuntimeError(f"thunk export failed for {binary['name']}; inspect {directory / 'thunks.log'}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", type=Path, default=REPO.parent / "maplestorycw/appdata")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--module", action="append", help="exact filename; repeat to restrict scope")
    parser.add_argument("--ghidra", type=Path)
    parser.add_argument("--jobs", type=int, default=1, help="independent modules analysed concurrently")
    parser.add_argument("--workers", type=int, default=6, help="decompiler processes per module")
    parser.add_argument("--timeout", type=int, default=60, help="seconds per function; failed bodies remain in graph")
    parser.add_argument("--heap", default="10G")
    parser.add_argument("--exports-only", action="store_true", help="defer graph import until exports are complete")
    args = parser.parse_args()
    if min(args.jobs, args.workers, args.timeout) <= 0:
        parser.error("jobs, workers and timeout must be positive")
    args.state = args.state.resolve()
    args.state.mkdir(parents=True, exist_ok=True)
    args.state.chmod(0o700)
    (args.state / "projects").mkdir(exist_ok=True)
    if not args.ghidra:
        choices = sorted((args.state / "toolchain").glob("ghidra_*_PUBLIC"))
        if not choices:
            parser.error("provide --ghidra pointing to an extracted Ghidra distribution")
        args.ghidra = choices[-1]
    args.ghidra = args.ghidra.resolve()
    binaries = inventory(args.binary_dir, args.module)
    inventory_path = args.state / "inventory.json"
    if inventory_path.exists() and json.loads(inventory_path.read_text()) != binaries:
        parser.error("this state directory belongs to a different module inventory; use a separate --state")
    inventory_path.write_text(json.dumps(binaries, indent=2) + "\n")
    progress = []
    failures = []
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {executor.submit(analyse, binary, args): binary for binary in binaries}
        for future in as_completed(futures):
            try:
                item = future.result()
            except Exception as error:
                item = {"name": futures[future]["name"], "status": "failed", "error": str(error)}
                failures.append(item)
            progress.append(item)
            (args.state / "build-progress.json").write_text(json.dumps(progress, indent=2) + "\n")
            print(json.dumps(item), flush=True)
    if failures:
        raise RuntimeError(f"{len(failures)} modules failed; inspect build-progress.json and rerun to resume")
    # Prove analysis did not modify any reference file.
    for binary in binaries:
        if file_sha256(binary["path"]) != binary["id"]:
            raise ValueError(f"source changed during analysis: {binary['path']}")
    if not args.exports_only:
        ingest(args.state, publish=True)


if __name__ == "__main__":
    main()

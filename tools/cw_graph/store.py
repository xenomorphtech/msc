#!/usr/bin/env python3
"""Load Ghidra exports into a local Kuzu property graph, without losing call sites."""
import argparse
from collections import Counter
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time

import kuzu
from baseline import baseline_records
from incremental import snapshot


NODE_COLUMNS = {
    "Binary": ["id", "name", "path", "sha256", "image_base", "language", "status"],
    "Function": ["id", "binary_id", "name", "qualified_name", "address", "rva", "entry_rva", "end_rva", "size",
                 "signature", "is_external", "is_thunk", "status", "c", "error", "body_ranges",
                 "compile_status", "link_status", "test_status", "integration_status", "validation_path"],
    "CallSite": ["id", "binary_id", "caller_id", "address", "rva", "instruction", "kind", "resolved"],
    "ExpectedFunction": ["id", "binary_id", "rva", "body_ranges"],
}
SCHEMA = [
    "CREATE NODE TABLE Binary(id STRING PRIMARY KEY, name STRING, path STRING, sha256 STRING, image_base STRING, language STRING, status STRING)",
    "CREATE NODE TABLE Function(id STRING PRIMARY KEY, binary_id STRING, name STRING, qualified_name STRING, address STRING, rva STRING, entry_rva INT64, end_rva INT64, size INT64, signature STRING, is_external BOOL, is_thunk BOOL, status STRING, c STRING, error STRING, body_ranges STRING, compile_status STRING, link_status STRING, test_status STRING, integration_status STRING, validation_path STRING)",
    "CREATE NODE TABLE CallSite(id STRING PRIMARY KEY, binary_id STRING, caller_id STRING, address STRING, rva STRING, instruction STRING, kind STRING, resolved BOOL)",
    "CREATE NODE TABLE ExpectedFunction(id STRING PRIMARY KEY, binary_id STRING, rva STRING, body_ranges STRING)",
    "CREATE REL TABLE DECLARES(FROM Binary TO ExpectedFunction)",
    "CREATE REL TABLE COVERS(FROM Function TO ExpectedFunction)",
    "CREATE REL TABLE CONTAINS(FROM Binary TO Function)",
    "CREATE REL TABLE HAS_CALLSITE(FROM Function TO CallSite)",
    "CREATE REL TABLE TARGETS(FROM CallSite TO Function)",
    "CREATE REL TABLE CALLS(FROM Function TO Function, site_id STRING, site_rva STRING, kind STRING)",
    "CREATE REL TABLE RESOLVES_TO(FROM Function TO Function, evidence STRING)",
    "CREATE REL TABLE THUNKS_TO(FROM Function TO Function)",
    "CREATE REL TABLE IMPORTS(FROM Binary TO Binary)",
]
REL_COLUMNS = {"CONTAINS": ["from", "to"], "HAS_CALLSITE": ["from", "to"],
               "TARGETS": ["from", "to"], "CALLS": ["from", "to", "site_id", "site_rva", "kind"],
               "RESOLVES_TO": ["from", "to", "evidence"], "THUNKS_TO": ["from", "to"], "IMPORTS": ["from", "to"],
               "DECLARES": ["from", "to"], "COVERS": ["from", "to"]}


def records(path):
    with path.open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def literal(text):
    return "'" + str(text).replace("\\", "\\\\").replace("'", "\\'") + "'"


def file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validations(state):
    result = {}
    for path in (state / "validation").glob("*/validation.json"):
        report = json.loads(path.read_text())
        if not report.get("results"):
            continue
        source = Path(report.get("source", ""))
        if not source.is_file() or file_sha256(source) != report.get("source_sha256"):
            continue
        if not all(Path(r.get("executable", "")).is_file() and
                   file_sha256(r["executable"]) == r.get("executable_sha256")
                   for r in report["results"] if r.get("link_status", "passed" if r.get("run_status") == "passed" else "pending") == "passed"):
            continue
        required = report.get("required_targets", [r.get("target", str(i)) for i, r in enumerate(report["results"])])
        integration = report.get("integration", {})
        evidence = integration.get("artifacts", [])
        integration_valid = integration.get("status") == "passed" and evidence and all(
            Path(item["path"]).is_file() and file_sha256(item["path"]) == item["sha256"] for item in evidence)
        stages = {}
        actual_targets = [r.get("target", str(i)) for i, r in enumerate(report["results"])]
        complete = len(actual_targets) == len(required) and set(actual_targets) == set(required)
        for name in ["compile_status", "link_status", "run_status"]:
            values = [r.get(name, "passed" if name == "link_status" and r.get("run_status") == "passed" else "pending") for r in report["results"]]
            if name == "run_status" and not integration_valid:
                values = ["pending" if r.get("runtime_evidence") else value for r, value in zip(report["results"], values)]
            stages[name] = "failed" if "failed" in values else "passed" if complete and all(v == "passed" for v in values) else "pending"
        for row in report["functions"]:
            function_stages = dict(stages)
            if any(row["id"] in r.get("function_results", {}) for r in report["results"]):
                values = [r.get("function_results", {}).get(row["id"], {}).get("run_status", r.get("run_status", "pending"))
                          for r in report["results"]]
                function_stages["run_status"] = "failed" if "failed" in values else "passed" if complete and all(v == "passed" for v in values) else "pending"
            result[row["id"]] = {**row, **function_stages,
                                 "integration_status": "passed" if integration_valid and function_stages["run_status"] == "passed" and row.get("integration_status") == "passed" else "pending",
                                 "path": str(path.resolve())}
    return result


def convert(state, allow_partial=False):
    """Write ordered CSVs and enforce referential integrity before database import."""
    inventory = json.loads((state / "inventory.json").read_text())
    for binary in inventory:
        if "expected_functions" not in binary and file_sha256(binary["path"]) != binary["id"]:
            raise ValueError(f"reference binary hash changed: {binary['name']}")
    csv_dir = state / "csv"
    csv_dir.mkdir(exist_ok=True)
    modules = []
    for binary in inventory:
        directory = state / "modules" / binary["id"]
        if not (directory / "summary.json").is_file():
            if allow_partial:
                summary = snapshot(state, binary)
                if summary:
                    modules.append((binary, directory, summary))
                continue
            raise ValueError(f"module is incomplete: {binary['name']}")
        summary = json.loads((directory / "summary.json").read_text())
        if summary["binary_id"] != binary["id"]:
            raise ValueError("module export hash mismatch")
        modules.append((binary, directory, summary))
    if not modules:
        raise ValueError("no completed module exports")
    handles = {}
    writers = {}
    counts = Counter()
    for table, columns in (NODE_COLUMNS | REL_COLUMNS).items():
        handle = (csv_dir / f"{table}.csv").open("w", newline="")
        writer = csv.writer(handle)
        writer.writerow(columns)
        handles[table], writers[table] = handle, writer

    def write(table, row):
        writers[table].writerow(row)
        counts[table] += 1

    module_names = {b["name"].lower(): b["id"] for b in inventory}
    binaries = {b["id"]: {**b, "status": "pending_analysis"} for b in inventory}
    binaries.update({b["id"]: {**b, **s, "status": "decompiling" if s.get("incremental") else "analysed"} for b, _, s in modules})
    externals = {}
    function_ids = set()
    export_targets = {}
    status_counts = Counter()
    build_counts = Counter()
    checks = validations(state)
    try:
        for binary, directory, summary in modules:
            total = 0
            for row in records(directory / ("incremental-functions.jsonl" if summary.get("incremental") else "functions.jsonl")):
                if row["id"] in function_ids:
                    raise ValueError(f"duplicate function: {row['id']}")
                if row["binary_id"] != binary["id"] or row["external"]:
                    raise ValueError("invalid internal function provenance")
                if row["status"] == "ok" and not row.get("c"):
                    raise ValueError("successful decompile has empty code")
                function_ids.add(row["id"])
                status_counts[row["status"]] += 1
                check = checks.get(row["id"])
                checked = bool(check and check["body_sha256"] == hashlib.sha256(row.get("c", "").encode()).hexdigest())
                stages = [check["compile_status"], check["link_status"], check["run_status"], check.get("integration_status", "pending"), check["path"]] if checked else ["pending", "pending", "pending", "pending", ""]
                if checked:
                    for name, value in zip(["compiled", "linked", "tested", "integrated"], stages):
                        if value == "passed":
                            build_counts[name] += 1
                total += 1
                write("Function", [row[k] for k in ["id", "binary_id", "name", "qualified_name", "address", "rva"]]
                      + [int(row["rva"], 16), max(int(r[1], 16) for r in row["ranges"]), row["size"], row["signature"]]
                      + [False, row["thunk"], row["status"], row.get("c", ""), row.get("error", ""), json.dumps(row["ranges"])] + stages)
                write("CONTAINS", [binary["id"], row["id"]])
            if total != summary["functions"]:
                raise ValueError(f"truncated function export for {binary['name']}")
            for row in records(directory / "external.jsonl"):
                externals.setdefault(row["id"], row)
            # Export metadata comes from the original PE, not inferred names.
            for export in binary.get("exports", []):
                target = binary["id"] + ":" + hex(export["rva"])
                if target in function_ids:
                    export_targets[(binary["name"].lower(), export["name"])] = target
                    export_targets[(binary["name"].lower(), f"Ordinal_{export['ordinal']}")] = target

        for identifier, row in externals.items():
            library, symbol = identifier.removeprefix("external:").split("!", 1)
            binary_id = module_names.get(library, "library:" + library)
            if binary_id not in binaries:
                binaries[binary_id] = {"id": binary_id, "name": library, "status": "external"}
            function_ids.add(identifier)
            status_counts["external"] += 1
            write("Function", [identifier, binary_id, row["name"], row["qualified_name"], "", "", -1, -1, 0,
                               row["signature"], True, False, "external", "", "Imported symbol; body is not in the importing module", "[]",
                               "external", "external", "external", "external", ""])
            write("CONTAINS", [binary_id, identifier])
            target = export_targets.get((library, symbol))
            if target:
                write("RESOLVES_TO", [identifier, target, "PE import name/ordinal matched to supplied DLL export RVA"])

        baseline_count = covered_count = 0
        for binary in inventory:
            for row in baseline_records(state, binary):
                write("ExpectedFunction", [row["id"], binary["id"], row["rva"], json.dumps(row["ranges"])])
                write("DECLARES", [binary["id"], row["id"]])
                baseline_count += 1
                if row["id"] in function_ids:
                    write("COVERS", [row["id"], row["id"]])
                    covered_count += 1

        for binary in binaries.values():
            write("Binary", [binary.get(k, "") for k in NODE_COLUMNS["Binary"]])
        for binary, directory, summary in modules:
            if not (directory / "thunks.jsonl").exists():
                raise ValueError(f"thunk export is missing: {binary['name']}; rerun build.py to export it")
            for row in records(directory / "thunks.jsonl"):
                if row["from"] not in function_ids or row["to"] not in function_ids:
                    raise ValueError("thunk target absent from function export")
                write("THUNKS_TO", [row["from"], row["to"]])
            imported = set()
            for library in binary.get("imports", []):
                name = library.lower()
                target = module_names.get(name, "library:" + name)
                # Import libraries with no referenced functions still get a node.
                if target not in binaries:
                    item = {"id": target, "name": name, "status": "external"}
                    binaries[target] = item
                    write("Binary", [item.get(k, "") for k in NODE_COLUMNS["Binary"]])
                if target not in imported:
                    write("IMPORTS", [binary["id"], target])
                    imported.add(target)
            total = 0
            for row in records(directory / "calls.jsonl"):
                if row["caller"] not in function_ids:
                    raise ValueError(f"unknown caller {row['caller']}")
                targets = list(dict.fromkeys(row["targets"]))
                if any(target not in function_ids for target in targets):
                    raise ValueError(f"call target absent from function export: {row['id']}")
                write("CallSite", [row["id"], binary["id"], row["caller"], row["address"], row["rva"],
                                   row["instruction"], row["kind"], bool(targets)])
                write("HAS_CALLSITE", [row["caller"], row["id"]])
                for target in targets:
                    write("TARGETS", [row["id"], target])
                    write("CALLS", [row["caller"], target, row["id"], row["rva"], row["kind"]])
                total += 1
            if total != summary["callsites"]:
                raise ValueError(f"truncated call export for {binary['name']}")
    finally:
        for handle in handles.values():
            handle.close()
    report = {"counts": dict(counts), "function_status": dict(status_counts),
              "rebuild_coverage": {"denominator": "discovered local function bodies", "functions": sum(s["functions"] for _, _, s in modules),
                                   "compiled": build_counts["compiled"], "linked": build_counts["linked"], "tested": build_counts["tested"], "integrated": build_counts["integrated"]},
              "independent_baseline": {"unwind_root_functions": baseline_count, "matched_functions": covered_count,
                                       "percent": round(covered_count / baseline_count * 100, 4) if baseline_count else None,
                                       "limit": "Known unwind roots only; leaf, packed, generated and inlined code can have no unwind entry."},
              "modules_complete": sum(not s.get("incremental", False) for _, _, s in modules),
              "modules_in_progress": sum(bool(s.get("incremental")) for _, _, s in modules), "modules_requested": len(inventory),
              "module_summaries": [s for _, _, s in modules]}
    known_inventory = report["rebuild_coverage"]["functions"] + baseline_count - covered_count
    report["rebuild_coverage"]["known_inventory_functions"] = known_inventory
    report["rebuild_coverage"]["compiled_percent_of_known_inventory"] = round(build_counts["compiled"] / known_inventory * 100, 6) if known_inventory else 0
    return csv_dir, report


def _ingest(state, destination=None, allow_partial=False, publish=False):
    csv_dir, report = convert(state, allow_partial)
    if publish:
        if destination is not None:
            raise ValueError("--publish uses the default graph.kuzu destination")
        destination = state / ("graph-" + str(time.time_ns()) + ".next.kuzu")
    destination = destination or state / "graph.kuzu"
    if destination.exists():
        raise FileExistsError(f"database already exists; choose a new --database path: {destination}")
    database = kuzu.Database(str(destination), buffer_pool_size=4 * 1024**3, max_num_threads=4)
    connection = kuzu.Connection(database)
    try:
        for command in SCHEMA:
            connection.execute(command)
        for table in NODE_COLUMNS | REL_COLUMNS:
            start = time.monotonic()
            # Multiline C bodies require the serial CSV reader; CSV quoting preserves them exactly.
            connection.execute(f"COPY {table} FROM {literal((csv_dir / (table + '.csv')).resolve())} (HEADER=true, PARALLEL=false)")
            result = connection.execute(f"MATCH (n:{table}) RETURN count(n)" if table in NODE_COLUMNS
                                        else f"MATCH ()-[r:{table}]->() RETURN count(r)")
            actual = result.get_next()[0]
            if actual != report["counts"].get(table, 0):
                raise ValueError(f"database count differs for {table}: {actual}")
            connection.execute("CHECKPOINT")
            print(json.dumps({"table": table, "rows": actual, "seconds": round(time.monotonic() - start, 3)}), flush=True)
        connection.execute("CHECKPOINT")
    finally:
        connection.close()
        database.close()
    report["database"] = str(destination.resolve())
    if publish:
        target = state / "graph.kuzu"
        if target.exists():
            snapshots = state / "snapshots"
            snapshots.mkdir(exist_ok=True)
            os.link(target, snapshots / (str(time.time_ns()) + ".kuzu"))
        destination.replace(target)
        report["database"] = str(target.resolve())
    staging = state / "graph-summary.json.partial"
    staging.write_text(json.dumps(report, indent=2) + "\n")
    staging.replace(state / "graph-summary.json")
    return report


def ingest(state, destination=None, allow_partial=False, publish=False):
    with (state / ".ingest.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _ingest(state, destination, allow_partial, publish)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--allow-partial", action="store_true", help="explicitly load completed modules only")
    parser.add_argument("--publish", action="store_true", help="atomically publish graph.kuzu and preserve its previous snapshot")
    args = parser.parse_args()
    print(json.dumps(ingest(args.state, args.database, args.allow_partial, args.publish), indent=2))


if __name__ == "__main__":
    main()

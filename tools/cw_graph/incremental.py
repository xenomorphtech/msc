"""Materialize consistent function snapshots while bulk decompilation is running."""
from collections import Counter
import json
import re

from baseline import baseline_records


def snapshot(state, binary):
    directory = state / "modules" / binary["id"]
    console = directory / "console.log"
    if not console.exists():
        return None
    log = console.read_text()
    calls_match = re.findall(r"CW_CALLS sites=(\d+) resolved=(\d+) unresolved=(\d+)", log)
    function_match = re.findall(r"CW_EXPORT functions=(\d+) external=(\d+)", log)
    if not calls_match or not function_match or not (directory / "functions.jsonl").exists():
        return None
    calls_total, resolved, unresolved = map(int, calls_match[-1])
    index_path = directory / "function-index.jsonl"
    if not index_path.exists():
        # Compatibility with runs started before ExportGraph emitted an index.
        # Only actual Ghidra call owners/targets become Function nodes here.
        # Unwind entries alone remain ExpectedFunction nodes until confirmed.
        identifiers = set()
        count = 0
        with (directory / "calls.jsonl").open() as stream:
            for line in stream:
                row = json.loads(line)
                identifiers.add(row["caller"])
                identifiers.update(t for t in row["targets"] if not t.startswith("external:"))
                count += 1
        if count != calls_total:
            raise ValueError("incomplete call export cannot seed a function index")
        thunk_sources = set()
        if (directory / "thunks.jsonl").exists():
            with (directory / "thunks.jsonl").open() as stream:
                for line in stream:
                    row = json.loads(line)
                    thunk_sources.add(row["from"])
                    identifiers.update(t for t in [row["from"], row["to"]] if not t.startswith("external:"))
        ranges = {row["id"]: row["ranges"] for row in baseline_records(state, binary)}
        staging = index_path.with_suffix(".partial")
        with staging.open("w") as stream:
            for identifier in sorted(identifiers):
                rva = identifier.rsplit(":", 1)[1]
                numeric = int(rva, 16)
                body = [[hex(int(a, 0) if isinstance(a, str) else a), hex(int(b, 0) if isinstance(b, str) else b)]
                        for a, b in ranges.get(identifier, [[numeric, numeric]])]
                row = {"id": identifier, "binary_id": binary["id"], "name": "sub_" + rva,
                       "qualified_name": "sub_" + rva, "address": hex(int(binary["image_base"], 16) + numeric),
                       "rva": rva, "size": sum(int(b, 16) - int(a, 16) + 1 for a, b in body),
                       "signature": "", "external": False, "thunk": identifier in thunk_sources, "ranges": body,
                       "status": "pending", "c": "", "error": "Metadata from confirmed Ghidra call references; decompilation pending"}
                stream.write(json.dumps(row) + "\n")
        staging.replace(index_path)
    with index_path.open() as stream:
        rows = {row["id"]: row for row in map(json.loads, stream)}
    # The exporter may be halfway through writing its final JSONL line. Only
    # newline-terminated, valid records enter this immutable snapshot.
    with (directory / "functions.jsonl").open("rb") as stream:
        for line in stream:
            if not line.endswith(b"\n"):
                break
            row = json.loads(line)
            rows[row["id"]] = row
    destination = directory / "incremental-functions.jsonl"
    staging = destination.with_suffix(".partial")
    with staging.open("w") as stream:
        for row in rows.values():
            stream.write(json.dumps(row) + "\n")
    staging.replace(destination)
    statuses = Counter(row["status"] for row in rows.values())
    summary = {"binary_id": binary["id"], "name": binary["name"], "image_base": binary["image_base"],
               "language": "x86:LE:64:default", "functions": len(rows),
               "detected_functions": int(function_match[-1][0]), "external_functions": int(function_match[-1][1]),
               "decompiled": statuses["ok"], "failed": sum(v for k, v in statuses.items() if k not in ["ok", "pending"]),
               "pending": statuses["pending"], "callsites": calls_total, "resolved_callsites": resolved,
               "unresolved_callsites": unresolved, "incremental": True}
    (directory / "incremental-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary

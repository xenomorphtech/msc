import json
import hashlib
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

import kuzu

from graph import neighborhood, query, resolve, write_html
from store import convert, ingest, validations


class GraphTests(unittest.TestCase):
    def setUp(self):
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name)
        self.code = 'char *Foo(void) {\n  return "quotes: \\\"; path: C:\\\\game; </script>; λ";\n}\n'
        self.inventory = [
            {"id": "a", "name": "MapleStory.exe", "path": "/reference/MapleStory.exe", "sha256": "a",
             "imports": ["other.dll", "unused.dll"], "exports": []},
            {"id": "b", "name": "other.dll", "path": "/reference/other.dll", "sha256": "b",
             "imports": [], "exports": [{"name": "Foo", "ordinal": 7, "rva": 256}]},
        ]
        self.external = "external:other.dll!Foo"
        self.functions = {
            "a": [self.function("a", "0x1000", "Foo", self.code, [["0x1000", "0x1020"], ["0x3000", "0x3010"]]),
                  self.function("a", "0x2000", "Bar", "", [["0x2000", "0x2010"]], "failed"),
                  {**self.function("a", "0x4000", "thunk_Foo", "int thunk_Foo() { return Foo(); }", [["0x4000", "0x4010"]]), "thunk": True}],
            "b": [self.function("b", "0x100", "Foo", "int Foo() { return 1; }\n", [["0x100", "0x110"]])],
        }
        self.calls = [self.call("0x1001", ["a:0x2000"]), self.call("0x1006", ["a:0x2000"]),
                      self.call("0x1010", [], "indirect"), self.call("0x1015", ["a:0x4000"], "indirect")]
        for binary in self.inventory:
            binary["image_base"] = "0x140000000"
            binary["expected_functions"] = [{"id": row["id"], "rva": row["rva"], "ranges": row["ranges"]}
                                            for row in self.functions[binary["id"]]]
        self.write_fixture()

    def tearDown(self):
        self.temporary.cleanup()

    def function(self, binary, rva, name, code, ranges, status="ok"):
        return {"id": binary + ":" + rva, "binary_id": binary, "name": name, "qualified_name": name,
                "address": "14000" + rva[2:], "rva": rva, "size": 32, "signature": "int " + name + "()",
                "external": False, "thunk": False, "status": status, "c": code, "error": "test error" if status != "ok" else "",
                "ranges": ranges}

    def call(self, rva, targets, kind="direct"):
        return {"id": "a:call:" + rva, "binary_id": "a", "caller": "a:0x1000", "rva": rva,
                "address": "14000" + rva[2:], "instruction": "CALL RAX" if kind == "indirect" else "CALL 0x140002000",
                "kind": kind, "targets": targets}

    def write_fixture(self):
        (self.state / "inventory.json").write_text(json.dumps(self.inventory))
        for binary, rows in self.functions.items():
            directory = self.state / "modules" / binary
            directory.mkdir(parents=True, exist_ok=True)
            calls = self.calls if binary == "a" else []
            external = {**rows[0], "id": self.external, "name": "Foo", "external": True, "status": "external", "c": ""}
            for filename, data in [("functions.jsonl", rows), ("calls.jsonl", calls),
                                   ("external.jsonl", [external] if binary == "a" else [])]:
                (directory / filename).write_text("".join(json.dumps(row) + "\n" for row in data))
            (directory / "summary.json").write_text(json.dumps({"binary_id": binary, "functions": len(rows), "callsites": len(calls)}))
            (directory / "thunks.jsonl").write_text(json.dumps({"from": "a:0x4000", "to": self.external}) + "\n" if binary == "a" else "")

    def test_import_preserves_code_calls_and_external_resolution(self):
        report = ingest(self.state)
        self.assertEqual(report["counts"]["Function"], 5)
        self.assertEqual(report["independent_baseline"]["percent"], 100)
        database = kuzu.Database(str(self.state / "graph.kuzu"), read_only=True, buffer_pool_size=128 * 1024**2)
        connection = kuzu.Connection(database)
        try:
            function = resolve(connection, module="MapleStory.exe", rva="0x1005")
            self.assertEqual(function["c"], self.code)
            # A split body belongs to the same function; its intervening gap does not.
            self.assertEqual(resolve(connection, module="MapleStory.exe", rva="0x3005")["id"], "a:0x1000")
            with self.assertRaises(ValueError):
                resolve(connection, module="MapleStory.exe", rva="0x2500")
            self.assertEqual(query(connection, "MATCH ()-[r:CALLS]->() RETURN count(r) AS n"), [{"n": 3}])
            self.assertEqual(query(connection, "MATCH (s:CallSite) WHERE NOT s.resolved RETURN count(s) AS n"), [{"n": 1}])
            self.assertEqual(query(connection, "MATCH (a:Function)-[:RESOLVES_TO]->(b:Function) RETURN b.id AS id"), [{"id": "b:0x100"}])
            self.assertEqual(query(connection, "MATCH (:Function)-[:CALLS]->(:Function)-[:THUNKS_TO]->(:Function)-[:RESOLVES_TO]->(f:Function) RETURN f.id AS id"), [{"id": "b:0x100"}])
            self.assertEqual(resolve(connection, identifier="a:0x2000")["status"], "failed")
            graph = neighborhood(connection, function, max_nodes=20)
            self.assertEqual(len(graph["edges"]), 3)
            self.assertEqual(len(graph["nodes"]), 3)
            self.assertEqual(len(graph["unresolved"]), 1)
            html = self.state / "view.html"
            write_html(html, graph)
            content = html.read_text()
            self.assertNotIn('path: C:\\\\game; </script>', content)
            self.assertIn("\\u003c/script\\u003e", content)
            self.assertNotIn("https://", content)
        finally:
            connection.close()
            database.close()

    def test_rejects_dangling_target_and_partial_export(self):
        self.calls[0]["targets"] = ["missing"]
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "call target absent"):
            convert(self.state)
        self.calls[0]["targets"] = ["a:0x2000"]
        self.write_fixture()
        directory = self.state / "modules/a/functions.jsonl"
        directory.write_text(json.dumps(self.functions["a"][0]) + "\n")
        with self.assertRaisesRegex(ValueError, "truncated function"):
            convert(self.state)

    def test_validation_freshness_and_pending_default(self):
        directory = self.state / "validation/fixture"
        directory.mkdir(parents=True)
        source = directory / "code.c"
        executable = directory / "program.fixture"
        source.write_text(self.code)
        executable.write_bytes(b"fixture artifact")
        report = {"source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "functions": [{"id": "a:0x1000", "body_sha256": hashlib.sha256(self.code.encode()).hexdigest(),
                                 "compile_status": "passed", "run_status": "passed"}],
                  "results": [{"compile_status": "passed", "run_status": "passed", "executable": str(executable),
                               "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}]}
        (directory / "validation.json").write_text(json.dumps(report))
        self.assertIn("a:0x1000", validations(self.state))
        source.write_text("changed")
        self.assertEqual(validations(self.state), {})
        source.write_text(self.code)
        executable.write_bytes(b"changed")
        self.assertEqual(validations(self.state), {})
        result = ingest(self.state)
        self.assertEqual(result["rebuild_coverage"]["compiled"], 0)

    def test_failed_build_remains_visible_in_ledger(self):
        directory = self.state / "validation/failed"
        directory.mkdir(parents=True)
        source = directory / "code.c"
        source.write_text(self.code)
        report = {"source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "functions": [{"id": "a:0x1000", "body_sha256": hashlib.sha256(self.code.encode()).hexdigest()}],
                  "results": [{"compile_status": "failed", "link_status": "pending", "run_status": "pending"}]}
        (directory / "validation.json").write_text(json.dumps(report))
        self.assertEqual(validations(self.state)["a:0x1000"]["compile_status"], "failed")
        ingest(self.state)
        database = kuzu.Database(str(self.state / "graph.kuzu"), read_only=True, buffer_pool_size=128 * 1024**2)
        connection = kuzu.Connection(database)
        try:
            row = resolve(connection, identifier="a:0x1000")
            self.assertEqual(row["compile_status"], "failed")
            self.assertEqual(row["test_status"], "pending")
        finally:
            connection.close()
            database.close()

    def test_mixed_batch_keeps_individual_test_verdicts(self):
        directory = self.state / "validation/mixed"
        directory.mkdir(parents=True)
        source, executable = directory / "batch.c", directory / "batch.fixture"
        source.write_text(self.code + self.functions["b"][0]["c"])
        executable.write_bytes(b"mixed batch")
        functions = [self.functions["a"][0], self.functions["b"][0]]
        report = {"source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "required_targets": ["oracle"],
                  "functions": [{"id": row["id"], "body_sha256": hashlib.sha256(row["c"].encode()).hexdigest()} for row in functions],
                  "results": [{"target": "oracle", "compile_status": "passed", "link_status": "passed", "run_status": "failed",
                               "executable": str(executable), "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                               "function_results": {"a:0x1000": {"run_status": "passed"}, "b:0x100": {"run_status": "failed"}}}]}
        (directory / "validation.json").write_text(json.dumps(report))
        result = ingest(self.state)
        self.assertEqual(result["rebuild_coverage"]["compiled"], 2)
        self.assertEqual(result["rebuild_coverage"]["tested"], 1)

    def test_gameplay_evidence_must_remain_intact(self):
        directory = self.state / "validation/runtime"
        directory.mkdir(parents=True)
        source, executable, trace = [directory / name for name in ["code.c", "runtime.dll", "trace.jsonl"]]
        source.write_text(self.code)
        executable.write_bytes(b"built DLL")
        trace.write_text('{"event":"returned"}\n')
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        report = {"source": str(source), "source_sha256": digest(source), "required_targets": ["runtime"],
                  "functions": [{"id": "a:0x1000", "body_sha256": hashlib.sha256(self.code.encode()).hexdigest(),
                                 "integration_status": "passed"}],
                  "integration": {"status": "passed", "artifacts": [{"path": str(trace), "sha256": digest(trace)}]},
                  "results": [{"target": "runtime", "compile_status": "passed", "link_status": "passed", "run_status": "passed",
                               "runtime_evidence": str(trace), "executable": str(executable), "executable_sha256": digest(executable)}]}
        (directory / "validation.json").write_text(json.dumps(report))
        self.assertEqual(validations(self.state)["a:0x1000"]["integration_status"], "passed")
        self.assertEqual(ingest(self.state, publish=True)["rebuild_coverage"]["integrated"], 1)
        trace.write_text("changed")
        result = validations(self.state)["a:0x1000"]
        self.assertEqual(result["compile_status"], "passed")
        self.assertEqual(result["run_status"], "pending")
        self.assertEqual(result["integration_status"], "pending")
        self.assertEqual(ingest(self.state, publish=True)["rebuild_coverage"]["integrated"], 0)

    def test_atomic_publication_preserves_previous_database(self):
        ingest(self.state, publish=True)
        self.functions["a"][0]["c"] = "void Foo(void) { return; }"
        self.write_fixture()
        ingest(self.state, publish=True)
        snapshots = list((self.state / "snapshots").glob("*.kuzu"))
        self.assertEqual(len(snapshots), 1)
        for path, expected in [(self.state / "graph.kuzu", self.functions["a"][0]["c"]), (snapshots[0], self.code)]:
            database = kuzu.Database(str(path), read_only=True, buffer_pool_size=128 * 1024**2)
            connection = kuzu.Connection(database)
            try:
                self.assertEqual(resolve(connection, identifier="a:0x1000")["c"], expected)
            finally:
                connection.close()
                database.close()

    def test_incremental_snapshot_does_not_skip_pending_or_read_partial_record(self):
        directory = self.state / "modules/a"
        (directory / "summary.json").unlink()
        (directory / "console.log").write_text("CW_EXPORT functions=3 external=1\nCW_CALLS sites=4 resolved=3 unresolved=1\n")
        (directory / "functions.jsonl").write_bytes((json.dumps(self.functions["a"][0]) + "\n").encode() + b'{"id":"unfinished"')
        result = ingest(self.state, allow_partial=True)
        self.assertEqual(result["modules_complete"], 1)
        self.assertEqual(result["modules_in_progress"], 1)
        self.assertEqual(result["function_status"]["pending"], 2)
        self.assertEqual(result["counts"]["CALLS"], 3)
        self.assertEqual(result["independent_baseline"]["percent"], 100)


if __name__ == "__main__":
    unittest.main()

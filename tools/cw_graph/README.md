# Native CW function graph and incremental rebuild ledger

This tool imports the original native PE files into Ghidra, discovers function
bodies, attempts to decompile every discovered local function, and loads the
results into an embedded **Kùzu** property graph. The database, projects,
exports, and visualizations stay in ignored `downloads/cw_graph/`; reference
binaries are read without modification.

The graph is a coverage ledger for a gradual rebuild. **Decompilation success
does not mean compilation or execution success.** Each local function has
separate `compile_status`, `link_status`, `test_status`, and
`integration_status`. Unchecked functions stay `pending`; the full client is
not rebuilt by this initial batch.

The [playable incremental rebuild](../cw_rebuild/README.md) uses this ledger for
compiled transport and integer-function replacements. Its validation records
include independent native-code comparisons and live Wine gameplay evidence;
only functions actually executed during that checkpoint become integrated.

## Build

From the workspace containing `msc/`, `maplestorycw/`, and `.venv/`:

```sh
.venv/bin/pip install -r msc/tools/cw_graph/requirements.txt
.venv/bin/python msc/tools/cw_graph/build.py \
  --ghidra /path/to/ghidra_12.1.4_PUBLIC --jobs 2 --workers 4 --heap 8G
```

The default scope is `MapleStory.exe` and every top-level `*.dll` in the supplied
`maplestorycw/appdata/`: 28 modules for this reference set. Nested browser,
overlay, and security-helper bundles are outside this inventory. Their imports
can still appear as external symbols. Restrict a run to selected files using
repeated `--module` options and a separate `--state` directory.

This environment uses Ghidra 12.1.4 with OpenJDK 25 and Kùzu 0.11.3. The
Ghidra distribution is under `downloads/cw_graph/toolchain/`, so `--ghidra` is
optional here. Its official release is
[Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build).
The downloaded ZIP's SHA-256 was checked against the release asset digest:

```text
ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
```

Each module has a separate persistent Ghidra project. A completed module is
reused on restart; `summary.json` is written only after every function attempt
and call-site export finishes. Incomplete modules are reimported. The importer
rejects truncated exports and dangling call targets. The builder publishes
`graph.kuzu` atomically and preserves previous versions under `snapshots/`.
Standalone imports preserve existing databases unless `--publish` is explicit.

The native executable has 122,117 `.pdata` records, but its PE exception
directory points into a different, uninitialized region. `PrepareFunctions.java`
reads the actual initialized `.pdata` section. It groups the 19,209 chained
unwind fragments with their parent functions instead of treating each fragment
as an independent function. Other analysis discovers leaf functions and thunks.

## Graph model

| Node / relationship | Content |
| --- | --- |
| `Binary` | Original file SHA-256, path, image base, analysis status; external library placeholders have `status='external'`. |
| `Function` | Binary identity, RVA/VA, name, signature, exact body ranges, thunk flag, decompilation status, C pseudocode in `c`, and any error. |
| `CallSite` | Exact instruction RVA/VA and text, direct/indirect/tail-call classification, whether targets were resolved. |
| `ExpectedFunction` | Independent inventory of primary x64 unwind entries from the original PE, grouping chained fragments. Includes modules still awaiting analysis. |
| `Binary -[:DECLARES]-> ExpectedFunction` | Baseline entries exist even before decompilation, so missing work cannot disappear from the denominator. |
| `Function -[:COVERS]-> ExpectedFunction` | An analysed function matches a known unwind entry. Missing links are coverage gaps. |
| `Binary -[:CONTAINS]-> Function` | Function ownership. External symbols belong to their library, with a placeholder library if no binary was supplied. |
| `Function -[:HAS_CALLSITE]-> CallSite` | Every observed call instruction in a discovered function body. |
| `CallSite -[:TARGETS]-> Function` | Only targets resolved by static references. |
| `Function -[:CALLS]-> Function` | One edge per resolved call site and target, with `site_id`, `site_rva`, and `kind`. Multiple calls between the same pair remain distinct. |
| `Function -[:RESOLVES_TO]-> Function` | Imported symbol matched by DLL name and PE export name/ordinal to an analysed local function. |
| `Function -[:THUNKS_TO]-> Function` | Ghidra's explicit thunk forwarding target, including import thunks whose jump is indirect. |
| `Binary -[:IMPORTS]-> Binary` | PE import and delay-import library dependencies. |

Function IDs include the original binary hash and RVA. Imported symbol IDs use
the normalized library name and symbol. Calls through imports retain that
symbol as their target; local import thunks may intervene. Follow
`CALLS -> THUNKS_TO -> RESOLVES_TO` to a supplied implementation.
Unresolved indirect calls retain their `CallSite` nodes with no
invented target. Tail calls are unconditional direct jumps to another known
function; ordinary internal branches are not call edges.

The graph describes **statically discovered machine-code functions**, including
compiler/runtime routines. Decompiled C is recovered pseudocode, not original
source. Optimized, inlined, packed, dynamically generated, or otherwise
undiscovered code cannot be promised complete coverage. All discovered local
bodies receive a decompilation attempt, including leaf functions and thunks.
Failures and per-function timeouts are retained explicitly. Imported symbols
without a local body have `status='external'` and cannot be decompiled from the
importing file. Protected runtime-only code needs a separately identified
memory image; this build analyses the supplied files on disk.

## Query and inspect

```sh
.venv/bin/python msc/tools/cw_graph/graph.py stats
.venv/bin/python msc/tools/cw_graph/graph.py coverage
.venv/bin/python msc/tools/cw_graph/graph.py gaps --module MapleStory.exe
.venv/bin/python msc/tools/cw_graph/graph.py frontier --module ZLZ64.dll

# An RVA inside a split function body resolves to its parent function.
.venv/bin/python msc/tools/cw_graph/graph.py function \
  --module MapleStory.exe --rva 0x741677

# Save one function's pseudocode as a C file.
.venv/bin/python msc/tools/cw_graph/graph.py function \
  --module ZLZ64.dll --rva 0x4250 --output /tmp/key-expansion.c

# Search discovered names and pseudocode, optionally within one module.
.venv/bin/python msc/tools/cw_graph/graph.py search CSecurityNGSXRunFailed

# Standalone, interactive SVG graph: click functions to read/save their C code.
.venv/bin/python msc/tools/cw_graph/graph.py view \
  --module MapleStory.exe --rva 0x741677 --depth 1 --max-nodes 80 \
  --output msc/downloads/cw_graph/packet-receive.html
```

The visualization embeds only a bounded neighborhood. It needs no CDN or
database server. The full database remains queryable through Cypher:

```sh
.venv/bin/python msc/tools/cw_graph/graph.py query \
  'MATCH (f:Function) RETURN f.status, count(*) AS total'

.venv/bin/python msc/tools/cw_graph/graph.py query \
  'MATCH (a:Function)-[c:CALLS]->(b:Function) WHERE a.id=$id RETURN a.name,c.site_rva,b.name' \
  --parameters '{"id":"BINARY_SHA256:0xFUNCTION_RVA"}'

.venv/bin/python msc/tools/cw_graph/graph.py query \
  'MATCH (f:Function)-[:HAS_CALLSITE]->(s:CallSite) WHERE NOT s.resolved RETURN f.name,s.rva,s.instruction LIMIT 30'

.venv/bin/python msc/tools/cw_graph/graph.py query \
  'MATCH (f:Function) WHERE f.status <> "ok" AND NOT f.is_external RETURN f.id,f.status,f.error LIMIT 30'
```

For a standalone load from completed exports:

```sh
.venv/bin/python msc/tools/cw_graph/store.py msc/downloads/cw_graph \
  --database msc/downloads/cw_graph/another.kuzu
```

Use `--allow-partial` only when deliberately inspecting completed modules from
an unfinished run. `graph-summary.json` records both completed and requested
module counts, function statuses, and node/edge totals. Per-module console
logs and `CW_DECOMPILE` progress lines are under `modules/<sha256>/`.
An explicit intermediate snapshot can include all baseline entries and only
the completed decompilation exports:

```sh
.venv/bin/python msc/tools/cw_graph/store.py msc/downloads/cw_graph \
  --allow-partial --publish

# Automatically publish completed modules while headless analysis continues.
.venv/bin/python msc/tools/cw_graph/watch.py
```

The publisher also snapshots functions already decompiled in an unfinished
module. A function index retains the other known routines as `pending` nodes;
its call edges remain queryable before all C bodies finish. The initial run
started before index export was added, so its index is bootstrapped from
confirmed Ghidra call owners, targets and thunk metadata. Address-only names
and unwind ranges are provisional until that function's full metadata arrives.
It does not promote unwind entries alone into confirmed function nodes.
Partial trailing JSONL records are excluded from snapshots. The default watch
interval is 120 seconds; each published database is internally consistent.

`baseline.py` derives the denominator independently of Ghidra's discovered
functions. Unwind coverage is a lower bound: leaf routines, inlined code,
unavailable runtime-generated code, and protected code without unwind records
need other evidence. Report this baseline and discovered-function rebuild
coverage separately; neither is proof of recovering every original source
function. `gaps` and unresolved `CallSite` nodes retain missing work explicitly.

## First compiled and executed batch

```sh
.venv/bin/python msc/tools/cw_graph/validate_crypto.py
```

This builds three recovered `ZLZ64.dll` functions: RVA `0x43d0` (AES table
initialization), `0x4250` (key expansion), and `0x2ba0` (AES-256 block encryption).
Their function bodies are included unchanged from the decompiler output.
The harness supplies recovered primitive types, an aliased backing allocation
for the original globals, original initialized data, and a test entry point.
There are no replacement crypto-function stubs.

The harness compiles with GCC for Linux with AddressSanitizer and with
`x86_64-w64-mingw32-gcc` for Windows, then executes the Windows build under Wine
in the existing loopback-only namespace/prefix. Both builds must match all
256 deterministic AES vectors, including the FIPS-197 AES-256 example, and
reproduce the captured seven-byte plaintext vector. It requires the previous
Wine setup and `Xvfb :97` for the Windows execution check.
Compilation to an object file and linking to an executable are separate
commands. Failed compile/link/run attempts retain their diagnostics and a
failed stage in the ledger instead of reverting to an untested state.

Compile/run logs, the generated C file, both executables, compiler commands,
source/body/artifact hashes, and vector-output hashes are under
`downloads/cw_graph/validation/aes/`. The loader grants passed build/link/test
states only when the report is successful and its function-body, harness-source,
and executable hashes still match. Integration into the complete client
remains `pending`. Vector success measures this batch's tested behavior, not
all possible input paths or whole-client equivalence.
Run `watch.py --once` after a later batch if the background publisher has
already exited. The publisher exits once every module has a final export.

Continue with dependency closures from `frontier`, recovering declarations,
globals, data layouts, imports and ABI details as required. Each batch must
compile and link, then pass meaningful execution comparisons before its test
status advances. A later integration step must test the reconstructed client
against the original behavior and local gameplay flow.

## Validation

```sh
.venv/bin/python -m unittest discover -s msc/tools/cw_graph -v
```

Integration tests use a real temporary Kùzu database. They check exact multiline
C round trips, quoted text and backslashes, split-body lookup, duplicate
call-site edges, unresolved calls, imported-symbol resolution, failure status,
and refusal of truncated exports or dangling targets. Additional tests check
thunk paths, independent inventory matches, stale validation rejection, and
atomic publication retaining the previous database. Exported HTML escapes
embedded code and includes no remote assets.

API references: [Ghidra DecompInterface](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html),
[Kùzu Python API](https://kuzudb.github.io/docs/client-apis/python/),
[Kùzu CSV import](https://kuzudb.github.io/docs/import/csv/).

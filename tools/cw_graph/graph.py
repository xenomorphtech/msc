#!/usr/bin/env python3
"""Query the native-client Kuzu graph and export interactive function neighborhoods."""
import argparse
from collections import deque
from decimal import Decimal
import json
from pathlib import Path

import kuzu


DEFAULT_DB = Path(__file__).resolve().parents[2] / "downloads/cw_graph/graph.kuzu"


def query(connection, cypher, parameters=None):
    result = connection.execute(cypher, parameters or {})
    columns = result.get_column_names()
    rows = []
    while result.has_next():
        values = result.get_next()
        rows.append(dict(zip(columns, [int(v) if isinstance(v, Decimal) and v == int(v) else v for v in values])))
    return rows


def resolve(connection, identifier=None, module=None, rva=None):
    if identifier:
        rows = query(connection, "MATCH (f:Function) WHERE f.id=$id RETURN f.*", {"id": identifier})
    else:
        offset = int(rva, 0)
        # The numeric envelope narrows the search; the actual range list handles split bodies.
        rows = query(connection, "MATCH (b:Binary)-[:CONTAINS]->(f:Function) WHERE lower(b.name)=lower($module) "
                     "AND NOT f.is_external AND f.entry_rva<=$rva AND f.end_rva>=$rva RETURN f.*",
                     {"module": module, "rva": offset})
        rows = [row for row in rows if any(int(a, 16) <= offset <= int(b, 16)
                                          for a, b in json.loads(row["f.body_ranges"]))]
    if len(rows) != 1:
        raise ValueError(f"expected one function, found {len(rows)}")
    return {key.removeprefix("f."): value for key, value in rows[0].items()}


def neighborhood(connection, center, depth=1, max_nodes=100):
    nodes = {center["id"]: center}
    edges = {}
    queue = deque([(center["id"], 0)])
    clipped = False
    while queue:
        current, level = queue.popleft()
        if level >= depth:
            continue
        rows = query(connection, "MATCH (f:Function)-[r:CALLS]->(t:Function) "
                     "WHERE f.id=$id OR t.id=$id RETURN f.id AS source,t.id AS target,"
                     "r.site_id AS site_id,r.site_rva AS site_rva,r.kind AS kind LIMIT $limit",
                     {"id": current, "limit": max_nodes * 20 + 1})
        if len(rows) > max_nodes * 20:
            clipped = True
            rows = rows[:max_nodes * 20]
        for edge in rows:
            keep = True
            for identifier in [edge["source"], edge["target"]]:
                if identifier in nodes:
                    continue
                if len(nodes) >= max_nodes:
                    clipped = True
                    keep = False
                    break
                nodes[identifier] = resolve(connection, identifier=identifier)
                queue.append((identifier, level + 1))
            if keep:
                edges[edge["site_id"] + ":" + edge["target"]] = edge
    unresolved = query(connection, "MATCH (f:Function)-[:HAS_CALLSITE]->(s:CallSite) "
                       "WHERE f.id IN $ids AND NOT s.resolved RETURN f.id AS caller,s.rva AS site_rva,"
                       "s.instruction AS instruction LIMIT $limit",
                       {"ids": list(nodes), "limit": max_nodes * 20 + 1})
    if len(unresolved) > max_nodes * 20:
        unresolved = unresolved[:max_nodes * 20]
        clipped = True
    return {"center": center["id"], "nodes": list(nodes.values()), "edges": list(edges.values()),
            "unresolved": unresolved, "truncated": clipped}


def write_html(path, graph):
    # A self-contained SVG visualization: no CDN, server, or full-graph download.
    data = json.dumps(graph).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = Path(__file__).with_name("viewer.html").read_text()
    path.write_text(template.replace("/*GRAPH_DATA*/null", data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=DEFAULT_DB)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("stats")
    commands.add_parser("coverage")
    gaps = commands.add_parser("gaps")
    gaps.add_argument("--module", default="MapleStory.exe")
    gaps.add_argument("--limit", type=int, default=30)
    frontier = commands.add_parser("frontier")
    frontier.add_argument("--module", default="ZLZ64.dll")
    frontier.add_argument("--limit", type=int, default=20)
    custom = commands.add_parser("query")
    custom.add_argument("cypher")
    custom.add_argument("--parameters", default="{}", help="JSON object")
    search = commands.add_parser("search")
    search.add_argument("text")
    search.add_argument("--module")
    search.add_argument("--limit", type=int, default=30)
    for name in ["function", "view"]:
        command = commands.add_parser(name)
        command.add_argument("--id")
        command.add_argument("--module", default="MapleStory.exe")
        command.add_argument("--rva")
        command.add_argument("--output", type=Path)
        if name == "view":
            command.add_argument("--depth", type=int, default=1)
            command.add_argument("--max-nodes", type=int, default=100)
    args = parser.parse_args()
    if args.command in ["function", "view"] and not args.id and args.rva is None:
        parser.error("provide --id or --rva")
    database = kuzu.Database(str(args.database), read_only=True, buffer_pool_size=256 * 1024**2, max_num_threads=4)
    connection = kuzu.Connection(database)
    try:
        if args.command == "stats":
            result = {"modules": query(connection, "MATCH (b:Binary) RETURN b.name,b.status ORDER BY b.name"),
                      "functions": query(connection, "MATCH (f:Function) RETURN f.status,count(*) AS count ORDER BY count DESC"),
                      "callsites": query(connection, "MATCH (s:CallSite) RETURN s.kind,s.resolved,count(*) AS count ORDER BY count DESC"),
                      "calls": query(connection, "MATCH ()-[r:CALLS]->() RETURN count(r) AS count"),
                      "cross_module_resolutions": query(connection, "MATCH ()-[r:RESOLVES_TO]->() RETURN count(r) AS count")}
            result["thunk_links"] = query(connection, "MATCH ()-[r:THUNKS_TO]->() RETURN count(r) AS count")
        elif args.command == "query":
            result = query(connection, args.cypher, json.loads(args.parameters))
        elif args.command == "coverage":
            stages = query(connection, "MATCH (b:Binary)-[:CONTAINS]->(f:Function) WHERE NOT f.is_external "
                           "RETURN b.name AS module,count(*) AS discovered,"
                           "sum(CASE WHEN f.status='ok' THEN 1 ELSE 0 END) AS decompiled,"
                           "sum(CASE WHEN f.compile_status='passed' THEN 1 ELSE 0 END) AS compiled,"
                           "sum(CASE WHEN f.link_status='passed' THEN 1 ELSE 0 END) AS linked,"
                           "sum(CASE WHEN f.test_status='passed' THEN 1 ELSE 0 END) AS tested,"
                           "sum(CASE WHEN f.integration_status='passed' THEN 1 ELSE 0 END) AS integrated ORDER BY module")
            baseline = query(connection, "MATCH (b:Binary)-[:DECLARES]->(e:ExpectedFunction) "
                             "OPTIONAL MATCH (f:Function)-[:COVERS]->(e) "
                             "RETURN b.name AS module,count(DISTINCT e.id) AS expected,count(DISTINCT f.id) AS matched ORDER BY module")
            result = {"stages": stages, "unwind_baseline": baseline,
                      "limit": "Unwind coverage is a lower-bound inventory; it excludes routines without unwind records and unknown packed/generated code."}
            known = sum(r["discovered"] for r in stages) + sum(r["expected"] - r["matched"] for r in baseline)
            result["known_inventory_functions"] = known
            result["compiled_functions"] = sum(r["compiled"] for r in stages)
            result["compiled_percent_of_known_inventory"] = round(result["compiled_functions"] / known * 100, 6) if known else 0
        elif args.command == "gaps":
            result = query(connection, "MATCH (b:Binary)-[:DECLARES]->(e:ExpectedFunction) "
                           "WHERE lower(b.name)=lower($module) OPTIONAL MATCH (f:Function)-[:COVERS]->(e) "
                           "WITH b,e,f WHERE f.id IS NULL RETURN b.name AS module,e.id AS id,e.rva AS rva LIMIT $limit",
                           {"module": args.module, "limit": args.limit})
        elif args.command == "frontier":
            result = query(connection, "MATCH (b:Binary)-[:CONTAINS]->(f:Function) WHERE lower(b.name)=lower($module) "
                           "AND NOT f.is_external AND NOT f.is_thunk AND f.status='ok' AND f.compile_status<>'passed' "
                           "OPTIONAL MATCH (f)-[:CALLS]->(d:Function) "
                           "RETURN f.id AS id,f.rva AS rva,f.name AS name,f.size AS bytes,"
                           "count(DISTINCT d.id) AS dependencies,"
                           "count(DISTINCT CASE WHEN NOT d.is_external AND d.compile_status<>'passed' THEN d.id ELSE NULL END) AS pending_dependencies "
                           "ORDER BY pending_dependencies,dependencies,bytes LIMIT $limit",
                           {"module": args.module, "limit": args.limit})
        elif args.command == "search":
            result = query(connection, "MATCH (b:Binary)-[:CONTAINS]->(f:Function) WHERE "
                           "(contains(lower(f.name),lower($text)) OR contains(lower(f.c),lower($text))) "
                           "AND ($module='' OR lower(b.name)=lower($module)) "
                           "RETURN b.name AS module,f.id AS id,f.rva AS rva,f.name AS name,f.status AS status LIMIT $limit",
                           {"text": args.text, "module": args.module or "", "limit": args.limit})
        else:
            function = resolve(connection, args.id, args.module, args.rva)
            if args.command == "function":
                if args.output:
                    args.output.write_text(function["c"] or ("/* " + function["status"] + ": " + (function["error"] or "") + " */\n"))
                    result = {"output": str(args.output), "id": function["id"], "status": function["status"]}
                else:
                    result = function
            else:
                result = neighborhood(connection, function, args.depth, args.max_nodes)
                output = args.output or Path("function-graph.html")
                write_html(output, result)
                result = {"output": str(output.resolve()), "nodes": len(result["nodes"]), "edges": len(result["edges"]), "truncated": result["truncated"]}
        print(json.dumps(result, indent=2, default=str))
    finally:
        connection.close()
        database.close()


if __name__ == "__main__":
    main()

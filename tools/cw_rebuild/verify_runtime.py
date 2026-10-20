#!/usr/bin/env python3
"""Record a hybrid gameplay checkpoint without promoting unexecuted functions."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def verify(directory, client, trace, login, world, screenshots, leaf_trace=None, combat=False, quest_state=None):
    manifest = json.loads((client / "cw-rebuilt-build.json").read_text())
    report_path = directory / "validation.json"
    report = json.loads(report_path.read_text())
    if digest(client / "cw_rebuilt.dll") != manifest["dll_sha256"]:
        raise ValueError("installed DLL differs from build manifest")
    leaf_manifest = json.loads((client / "cw-leaf-build.json").read_text()) if leaf_trace else None
    final_sha = manifest["hybrid_client_sha256"]
    if leaf_manifest:
        if leaf_manifest["input_sha256"] != final_sha or digest(client / "cw_leaf.dll") != leaf_manifest["dll_sha256"]:
            raise ValueError("leaf DLL or combined import chain differs from its manifest")
        final_sha = leaf_manifest["hybrid_client_sha256"]
    if digest(client / "MapleStory.exe") != final_sha:
        raise ValueError("hybrid executable differs from install manifest")
    target = next(r for r in report["results"] if r["target"] == "windows-x64-client-dll")
    if target["executable_sha256"] != manifest["dll_sha256"]:
        raise ValueError("installed DLL differs from validation build")
    events = rows(trace)
    if len({r["pid"] for r in events}) != 1:
        raise ValueError("trace combines different processes")
    if any(r["event"] not in ("installed", "returned", "total") for r in events):
        raise ValueError("runtime installation failed")
    installed = {r["function"] for r in events if r["event"] == "installed"}
    called = {r["function"] for r in events if r["event"] == "returned" and r["calls"] > 0}
    if installed != set(range(5)) or called != set(range(5)):
        raise ValueError("all five recovered functions must execute in the live client")
    logs = {"login": rows(login), "world": rows(world)}
    counts = {role: Counter((r["direction"], r["opcode"]) for r in records) for role, records in logs.items()}
    required = {"login": [("client_to_server", 118), ("client_to_server", 121), ("server_to_client", 16)],
                "world": [("client_to_server", 125), ("server_to_client", 1579),
                          ("client_to_server", 0x43dd), ("client_to_server", 0x8111)]}
    for role, packets in required.items():
        for packet in packets:
            if counts[role][packet] < 1:
                raise ValueError(f"missing gameplay evidence: {role} {packet}")
    movement = [bytes.fromhex(r["plaintext_hex"]) for r in logs["world"]
                if r["direction"] == "client_to_server" and r["opcode"] == 0x8111]
    origins = {body[16:20] for body in movement if len(body) >= 20 and body[2] in (1, 2)}
    if len(movement) < 3 or len(origins) < 2:
        raise ValueError("fresh movement with changing reported origins must follow the initial spawn packet")
    combat_result = None
    if combat:
        attacks, killed, damaged, progress = set(), set(), set(), []
        kill_times, spawn_times, experience = {}, {}, []
        for packet in logs["world"]:
            body = bytes.fromhex(packet["plaintext_hex"])
            if packet["direction"] == "client_to_server" and packet["opcode"] == 0x5c9a and len(body) in (224, 232) and body[3] == 1:
                attacks.add(int.from_bytes(body[125:129], "little"))
            if packet["direction"] == "server_to_client":
                if packet["opcode"] == 1008 and len(body) == 11 and 0 < int.from_bytes(body[6:10], "little") < 100:
                    damaged.add(int.from_bytes(body[2:6], "little"))
                elif packet["opcode"] == 977 and len(body) == 16:
                    identifier = int.from_bytes(body[2:6], "little")
                    killed.add(identifier)
                    kill_times.setdefault(identifier, packet["timestamp_ns"])
                elif packet["opcode"] == 966 and len(body) == 312:
                    identifier = int.from_bytes(body[3:7], "little")
                    spawn_times.setdefault(identifier, []).append(packet["timestamp_ns"])
                elif packet["opcode"] == 126 and len(body) == 19 and body[5:9] == bytes.fromhex("00000100"):
                    experience.append((packet["timestamp_ns"], int.from_bytes(body[9:17], "little")))
                elif packet["opcode"] == 139 and len(body) == 13 and body[:10] == bytes.fromhex("8b0001ed030000010300") and body[10:].isdigit():
                    progress.append(int(body[10:]))
        matched = attacks & damaged & killed
        if not matched or not progress or max(progress) < 1:
            raise ValueError("fresh attack, nonlethal HP update, matching mob removal and quest progress are required")
        if quest_state:
            saved = json.loads(quest_state.read_text())
            if saved.get("tutorial_kills", 0) < max(progress):
                raise ValueError("quest kill progress was not persisted")
        combat_result = {"status": "passed", "killed_mob_ids": sorted(matched), "tutorial_progress": max(progress)}
        combat_result["respawned_mob_ids"] = sorted(identifier for identifier in matched
            if any(timestamp > kill_times[identifier] + 5_000_000_000 for timestamp in spawn_times.get(identifier, [])))
        combat_result["experience_after_kill"] = [value for timestamp, value in experience
            if any(0 <= timestamp - kill_times[identifier] < 1_000_000_000 for identifier in matched)]
        if not combat_result["respawned_mob_ids"] or not combat_result["experience_after_kill"]:
            raise ValueError("combat checkpoint also requires a live respawn and EXP award after the kill")
        if quest_state and saved.get("exp", 0) < max(combat_result["experience_after_kill"]):
            raise ValueError("experience was not persisted")
    evidence = directory / "gameplay"
    evidence.mkdir(exist_ok=True)
    # Logs are still growing; preserve immutable snapshots for hash validation.
    artifacts = []
    for path in [trace, login, world, client / "cw-rebuilt-build.json", *screenshots, *([quest_state] if quest_state else [])]:
        dest = evidence / path.name
        shutil.copyfile(path, dest)
        artifacts.append({"path": str(dest.resolve()), "sha256": digest(dest)})
    integration = {"status": "passed", "scope": "login, channel/character choice, field rendering, movement and heartbeat; local tutorial server",
                   "artifacts": artifacts, "runtime_pid": events[0]["pid"],
                   "function_call_lower_bounds": {str(i): max(r["calls"] for r in events if r["function"] == i) for i in range(5)},
                   "movement_packets": counts["world"][("client_to_server", 0x8111)],
                   "heartbeat_replies": counts["world"][("client_to_server", 0x43dd)]}
    if combat_result:
        integration["combat"] = combat_result
    target["run_status"] = "passed"
    target["runtime_evidence"] = str((evidence / trace.name).resolve())
    report["integration"] = integration
    for function in report["functions"]:
        function["integration_status"] = "passed"
    temporary = directory / "validation.json.partial"
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(report_path)
    if leaf_trace:
        leaf_directory = Path(leaf_manifest["validation"]).parent
        leaf_report = json.loads((leaf_directory / "validation.json").read_text())
        dll_target = next(r for r in leaf_report["results"] if r["target"] == "windows-x64-leaf-dll")
        if dll_target["executable_sha256"] != leaf_manifest["dll_sha256"]:
            raise ValueError("leaf runtime differs from tested DLL")
        leaf_events = rows(leaf_trace)
        if {r["pid"] for r in leaf_events} != {events[0]["pid"]} or any(r["event"] not in ("installed", "returned", "total") for r in leaf_events):
            raise ValueError("leaf runtime has mismatched process or installation errors")
        if {r["function"] for r in leaf_events if r["event"] == "installed"} != set(range(len(leaf_manifest["functions"]))):
            raise ValueError("leaf runtime did not install the complete verified batch")
        called = {r["function"] for r in leaf_events if r["event"] == "returned" and r["calls"] > 0}
        leaf_evidence = leaf_directory / "gameplay"
        leaf_evidence.mkdir(exist_ok=True)
        leaf_artifacts = list(artifacts)
        for path in [leaf_trace, client / "cw-leaf-build.json"]:
            copied = leaf_evidence / path.name
            shutil.copyfile(path, copied)
            leaf_artifacts.append({"path": str(copied.resolve()), "sha256": digest(copied)})
        ids = {leaf_report["binary_sha256"] + ":" + leaf_manifest["functions"][i]["rva"] for i in called}
        leaf_report["integration"] = {"status": "passed", "scope": integration["scope"], "artifacts": leaf_artifacts,
                                      "runtime_pid": events[0]["pid"], "installed": len(leaf_manifest["functions"]), "executed": len(ids)}
        for function in leaf_report["functions"]:
            function["integration_status"] = "passed" if function["id"] in ids else "pending"
        temp = leaf_directory / "validation.json.partial"
        temp.write_text(json.dumps(leaf_report, indent=2) + "\n")
        temp.replace(leaf_directory / "validation.json")
        integration["leaf_functions_executed"] = len(ids)
    print(json.dumps(integration, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=REPO / "downloads/cw_graph/validation/client-transport")
    parser.add_argument("--client", type=Path, default=REPO / "downloads/cw_wine/client")
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--login", type=Path, required=True)
    parser.add_argument("--world", type=Path, required=True)
    parser.add_argument("--screenshot", type=Path, action="append", required=True)
    parser.add_argument("--leaf-trace", type=Path)
    parser.add_argument("--combat", action="store_true")
    parser.add_argument("--quest-state", type=Path)
    args = parser.parse_args()
    verify(args.directory, args.client, args.trace, args.login, args.world, args.screenshot, args.leaf_trace, args.combat, args.quest_state)


if __name__ == "__main__":
    main()

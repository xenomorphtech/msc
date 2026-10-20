#!/usr/bin/env python3
"""Capture-specific, explicitly bounded correlations over exported plaintext."""
import argparse
from collections import Counter
import json
from pathlib import Path
import statistics
import struct


def analyze(rows):
    pending, probe = {}, None
    events, latencies, heartbeat_latencies = [], [], []
    replaced = reset_pending = orphan_acks = unmatched_responses = 0
    epoch = 0
    for row in rows:
        body = bytes.fromhex(row["plaintext_hex"])
        op, direction = row["opcode"], row["direction"]
        event = {key: row[key] for key in ["stream", "direction", "index",
                                          "timestamp_ns", "capture_frame", "opcode"]}
        event["evidence"] = "capture correlation; original client opcode mapping unresolved"
        if direction == "server_to_client" and op == 422:
            epoch += 1
            reset_pending += len(pending)
            pending.clear()
            event.update(kind="state_snapshot_candidate", epoch=epoch, length=len(body))
        elif direction == "client_to_server" and op == 0xb226:
            if len(body) < 8:
                raise ValueError("short object command prefix")
            key = struct.unpack_from("<IH", body, 2)
            replaced += key in pending
            pending[key] = row
            event.update(kind="object_command_candidate", epoch=epoch,
                         object_id=key[0], sequence=key[1], opaque_body_hex=body[8:].hex())
        elif direction == "server_to_client" and op == 996:
            if len(body) != 28:
                raise ValueError("unexpected object reply width")
            key = struct.unpack_from("<IH", body, 2)
            request = pending.pop(key, None)
            event.update(kind="object_command_reply_candidate", epoch=epoch,
                         object_id=key[0], sequence=key[1], opaque_body_hex=body[8:].hex())
            if request is None:
                orphan_acks += 1
            else:
                delay = (row["timestamp_ns"] - request["timestamp_ns"]) / 1e6
                latencies.append(delay)
                event.update(request_index=request["index"], latency_ms=delay)
        elif direction == "server_to_client" and op == 1579:
            if len(body) != 2:
                raise ValueError("nonempty periodic probe")
            probe = row
            event.update(kind="periodic_probe_candidate")
        elif direction == "client_to_server" and op == 0x43dd:
            if len(body) != 2:
                raise ValueError("nonempty periodic response")
            event.update(kind="periodic_response_candidate")
            if probe is None:
                unmatched_responses += 1
            else:
                delay = (row["timestamp_ns"] - probe["timestamp_ns"]) / 1e6
                event.update(probe_index=probe["index"], latency_ms=delay)
                heartbeat_latencies.append(delay)
                probe = None
        else:
            continue
        events.append(event)
    return events, {
        "scope": "Observed prefix/width correlations, with opaque tails retained; not full body semantics.",
        "event_counts": dict(Counter(e["kind"] for e in events)),
        "object_command_matching": {
            "matched": len(latencies), "unmatched_replies": orphan_acks,
            "same_key_replacements": replaced, "pending_at_snapshot_boundaries": reset_pending,
            "pending_at_capture_end": len(pending),
            "matching_rule": "most recent preceding identical u32/u16 prefix within snapshot epoch",
            "latency_ms": {"min": min(latencies), "median": statistics.median(latencies),
                           "max": max(latencies)} if latencies else {},
        },
        "periodic_probe_matching": {
            "matched": len(heartbeat_latencies), "unmatched_responses": unmatched_responses,
            "pending_probe": probe is not None,
            "latency_ms": {"min": min(heartbeat_latencies),
                           "median": statistics.median(heartbeat_latencies),
                           "max": max(heartbeat_latencies)} if heartbeat_latencies else {},
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text().splitlines()]
    events, summary = analyze(rows)
    args.output.mkdir(parents=True, exist_ok=True)
    args.output.chmod(0o700)
    path = args.output / "gameplay-events.jsonl"
    path.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in events))
    path.chmod(0o600)
    (args.output / "correlations.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()

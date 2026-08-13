from __future__ import annotations

import argparse
import asyncio
import functools
from ipaddress import IPv4Address
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.server import (  # noqa: E402
    build_parser,
    build_post_transcript_server_frames,
    CaptureProxyConfig,
    capture_proxy_connection,
    common_prefix_length,
    common_suffix_length,
    drop_normalized_client_frames,
    parse_client_opcode_reply,
    parse_client_opcode_reply_delays,
    parse_client_opcode_result_rewrite,
    parse_i16_position,
    parse_inventory_quantity_update,
    parse_mob_movement_auto_path_target,
    parse_mob_movement_broadcast_target,
    parse_mob_movement_composed_path_target,
    parse_mob_movement_path_target,
    parse_mob_movement_relative_policy,
    parse_server_opcode_byte_rewrite,
    parse_server_frame_patch,
    parse_plaintext_hex,
    parse_pcap_plaintext_reference,
    parse_zero_filled_frame,
    patch_server_event_data,
    patch_server_frames,
    post_transcript_server_cipher_state,
    replay_connection,
    rewrite_channel_transition_world_from_selection,
)
from maple_server.gameplay import (  # noqa: E402
    AbilityPointAllocationResponsePolicy,
    ClientRecoveryResponsePolicy,
    FieldDropEntity,
    InventoryItemEntity,
    InventoryMoveResponsePolicy,
    ItemAcquisitionResponsePolicy,
    ItemPickupResponsePolicy,
    ItemUseResponsePolicy,
    MobHealthResponsePolicy,
    MobMovementAcknowledgementPolicy,
    MobMovementBroadcastPlan,
    MobMovementBroadcastSequencePlan,
    MobMovementRelativeDecisionPolicy,
    NpcStateResponsePolicy,
    ReactiveMobHealth,
    SkillLevelChangeResponsePolicy,
    analyze_gameplay_transcript,
)
from maple_server.http_api import ServerPacketInjection  # noqa: E402
from maple_server.protocol import (  # noqa: E402
    crypt_payload,
    encode_frame_header,
    parse_encrypted_frames,
    parse_handshake,
    shuffle_iv,
)
from maple_server.packets import (  # noqa: E402
    AbilityPointAllocationEntry,
    ChannelTransitionResponse,
    CharacterStatUpdate,
    ClientAbilityPointAllocationRequest,
    ClientOpcode298ItemAcquisitionRequest,
    ClientNpcStateSubmission,
    ClientRecoveryRequest,
    ClientAttackAction,
    ClientAttackCommonState,
    ClientAttackTargetState,
    FieldDropRemoval,
    FieldDropSpawn,
    HeartbeatProbe,
    HeartbeatResponse,
    InitialInventoryItem,
    InventoryChangeSet,
    InventoryModification,
    InventoryMoveRequest,
    ItemPickupRequest,
    ItemUseRequest,
    MobControllerChange,
    MobEnterField,
    MobHealthPercentageUpdate,
    MobLeaveField,
    MobMovementAcknowledgement,
    MobMovementBroadcast,
    MobMovementCommand,
    MobMovementPath,
    MobMovementSubmission,
    MobSpawnData,
    MobSpawnTemporaryStatus,
    NpcSpawn,
    NpcStateUpdate,
    PlayerMovementCommand,
    PlayerMovementPath,
    PlayerMovementSubmission,
    PickupGainNotice,
    SkillLevelChangeRequest,
    SkillRecordUpdate,
    SkillRecordUpdateAcknowledgement,
    WorldHandoff,
    WorldSelection,
    VariableServerEntry,
    VariableServerRecord,
)
from maple_server.transcript import (  # noqa: E402
    Transcript,
    TranscriptEvent,
    TranscriptWriter,
)


def fixture_mob_movement_broadcast_plan(
    broadcast: MobMovementBroadcast,
    *,
    previous_x: int,
    previous_y: int,
    previous_foothold_id: int,
    previous_stance: int,
    target_x: int,
    target_y: int,
    target_foothold_id: int,
    target_stance: int,
    source_server_frame_index: int | None = None,
) -> MobMovementBroadcastPlan:
    return MobMovementBroadcastPlan(
        broadcast=broadcast,
        mode="test_captured_path",
        entity="mob:test:1",
        template_id=210_100,
        field_epoch=1,
        previous_x=previous_x,
        previous_y=previous_y,
        previous_foothold_id=previous_foothold_id,
        previous_stance=previous_stance,
        target_x=target_x,
        target_y=target_y,
        target_foothold_id=target_foothold_id,
        stance=target_stance,
        broadcast_evidence=1,
        exact_stationary_shape_evidence=0,
        source_server_frame_index=source_server_frame_index,
        exact_relative_motion_shape_evidence=1,
        matching_displacement_path_evidence=1,
        matching_displacement_shape_evidence=1,
    )


class TranscriptTest(unittest.TestCase):
    def test_rewrites_captured_channel_transition_to_live_world(self) -> None:
        replies = (
            ChannelTransitionResponse(
                stage=0,
                transition_values=(267_748, 267_744),
            ).to_bytes(),
            ChannelTransitionResponse(stage=1, world_id=4).to_bytes(),
        )

        rewritten = rewrite_channel_transition_world_from_selection(
            replies, WorldSelection(world_id=1).to_bytes()
        )

        self.assertEqual(
            ChannelTransitionResponse.parse(rewritten[0]),
            ChannelTransitionResponse(
                stage=0,
                transition_values=(267_748, 267_744),
            ),
        )
        self.assertEqual(
            ChannelTransitionResponse.parse(rewritten[1]).world_id, 1
        )

    def test_post_transcript_cli_frames_preserve_argument_order(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12082",
                "--transcript",
                "capture.jsonl",
                "--transcript-dir",
                "observed",
                "--send-after-transcript",
                "aa",
                "--send-zero-filled-after-transcript",
                "1:4:7",
                "--send-after-transcript",
                "bb",
                "--post-transcript-gap-delay-seconds",
                "0",
                "--post-transcript-gap-delay-seconds",
                "18",
                "--post-transcript-gap-delay-seconds",
                "1",
            ]
        )
        self.assertEqual(
            arguments.post_transcript_server_frames,
            [bytes.fromhex("aa"), bytes.fromhex("01000700"), bytes.fromhex("bb")],
        )
        self.assertEqual(
            arguments.post_transcript_gap_delays_seconds,
            [0.0, 18.0, 1.0],
        )

    def test_repeated_npc_state_update_cli_is_explicit(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--hold-open-seconds",
                "30",
                "--repeat-final-field-npc-state-update",
            ]
        )

        self.assertTrue(arguments.repeat_final_field_npc_state_update)

    def test_pcap_replay_accepts_explicit_launcher_frame_omission(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12082",
                "--pcap",
                "reference.pcapng",
                "--tcp-stream",
                "83",
                "--drop-client-frame",
                "0",
            ]
        )
        self.assertEqual(arguments.drop_client_frame, [0])

    def test_drops_only_selected_frame_aligned_client_event(self) -> None:
        transcript = Transcript(
            path=Path("fixture.pcapng"),
            events=(
                TranscriptEvent(event="connect", timestamp_ns=1),
                TranscriptEvent(
                    event="data",
                    timestamp_ns=2,
                    direction="client_to_server",
                    data=b"launcher",
                    metadata={"frame_index": 0},
                ),
                TranscriptEvent(
                    event="data",
                    timestamp_ns=3,
                    direction="client_to_server",
                    data=b"login",
                    metadata={"frame_index": 1},
                ),
            ),
        )

        filtered = drop_normalized_client_frames(transcript, {0})

        self.assertEqual(filtered.client_bytes, b"login")

    def test_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TranscriptWriter(
                directory,
                label="login:10282",
                metadata={"upstream_port": 10282},
                max_runtime_events=1,
            )
            writer.data("client_to_server", b"hello")
            writer.data("server_to_client", b"world")
            writer.runtime_event(
                "policy_decision",
                {"decision_index": 2, "outcome": "started"},
            )
            writer.runtime_event("policy_decision", {"decision_index": 3})
            with self.assertRaises(ValueError):
                writer.runtime_event("unsafe", {"raw": b"identifier"})
            writer.close()

            transcript = Transcript.load(writer.path)
            self.assertEqual(transcript.client_bytes, b"hello")
            self.assertEqual(transcript.server_bytes, b"world")
            self.assertEqual(transcript.events[3].event, "runtime_event")
            self.assertEqual(
                transcript.events[3].metadata,
                {
                    "kind": "policy_decision",
                    "details": {
                        "decision_index": 2,
                        "outcome": "started",
                    },
                },
            )
            self.assertEqual(
                transcript.events[-1].metadata["runtime_events_written"], 1
            )
            self.assertEqual(
                transcript.events[-1].metadata["runtime_events_dropped"], 1
            )
            self.assertEqual(writer.path.stat().st_mode & 0o777, 0o600)

    def test_common_edges(self) -> None:
        self.assertEqual(common_prefix_length(b"stable-one", b"stable-two"), 7)
        self.assertEqual(common_suffix_length(b"one-stable", b"two-stable"), 7)
        self.assertEqual(common_prefix_length(b"same", b"same"), 4)
        self.assertEqual(common_suffix_length(b"same", b"same"), 4)

    def test_server_frame_patch_reencrypts_plaintext_and_preserves_stream(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_iv = bytes.fromhex("6e3c795a")
            second_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + first_iv
                + second_iv
                + b"\x08"
            )
            plaintexts = (b"first", b"second")
            frames = []
            iv = second_iv
            for plaintext in plaintexts:
                frames.append(
                    encode_frame_header(len(plaintext), iv, ~300)
                    + crypt_payload(plaintext, iv)
                )
                iv = shuffle_iv(iv)

            writer = TranscriptWriter(directory, label="patch", metadata={})
            writer.data("server_to_client", greeting + frames[0][:3])
            writer.data("server_to_client", frames[0][3:] + frames[1])
            writer.close()
            transcript = Transcript.load(writer.path)

            patched = patch_server_frames(transcript, {1: b"change"})
            self.assertEqual(len(patched), len(transcript.server_bytes))
            self.assertEqual(patched[: len(greeting)], greeting)
            parsed_handshake = parse_handshake(patched)
            parsed_frames = parse_encrypted_frames(
                patched, offset=parsed_handshake.wire_length
            )
            self.assertEqual(crypt_payload(parsed_frames[0].payload, second_iv), b"first")
            self.assertEqual(
                crypt_payload(parsed_frames[1].payload, shuffle_iv(second_iv)),
                b"change",
            )

    def test_server_frame_patch_allows_length_change_and_remaps_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            iv = bytes.fromhex("885db958")
            greeting = struct.pack("<HHH", 13, 300, 0) + b"iv01" + iv + b"\x08"
            frame = encode_frame_header(4, iv, ~300) + crypt_payload(b"same", iv)
            writer = TranscriptWriter(directory, label="patch-length", metadata={})
            writer.data("server_to_client", greeting + frame[:3])
            writer.data("server_to_client", frame[3:])
            writer.close()
            transcript = Transcript.load(writer.path)
            patched = patch_server_frames(transcript, {0: b"longer"})
            self.assertEqual(len(patched), len(transcript.server_bytes) + 2)
            parsed = parse_encrypted_frames(patched, offset=len(greeting))
            self.assertEqual(len(parsed[0].payload), 6)
            self.assertEqual(crypt_payload(parsed[0].payload, iv), b"longer")

            event_payloads = patch_server_event_data(transcript, {0: b"longer"})
            self.assertEqual(len(event_payloads), 2)
            self.assertEqual(b"".join(event_payloads), patched)

    def test_server_frame_drop_reencrypts_later_frames_and_remaps_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_iv = bytes.fromhex("6e3c795a")
            second_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + first_iv
                + second_iv
                + b"\x08"
            )
            plaintexts = (b"first", b"drop-me", b"third")
            frames = []
            iv = second_iv
            for plaintext in plaintexts:
                frames.append(
                    encode_frame_header(len(plaintext), iv, ~300)
                    + crypt_payload(plaintext, iv)
                )
                iv = shuffle_iv(iv)

            writer = TranscriptWriter(directory, label="drop-server", metadata={})
            writer.data("server_to_client", greeting + frames[0] + frames[1][:2])
            writer.data("server_to_client", frames[1][2:] + frames[2][:3])
            writer.data("server_to_client", frames[2][3:])
            writer.close()
            transcript = Transcript.load(writer.path)

            edited = patch_server_frames(transcript, {}, {1})
            parsed_handshake = parse_handshake(edited)
            parsed_frames = parse_encrypted_frames(
                edited, offset=parsed_handshake.wire_length
            )
            self.assertEqual(len(parsed_frames), 2)
            self.assertEqual(
                crypt_payload(parsed_frames[0].payload, second_iv), b"first"
            )
            next_iv = shuffle_iv(second_iv)
            self.assertEqual(
                crypt_payload(parsed_frames[1].payload, next_iv), b"third"
            )
            self.assertEqual(
                post_transcript_server_cipher_state(transcript, {1})[0],
                shuffle_iv(next_iv),
            )

            event_payloads = patch_server_event_data(transcript, {}, {1})
            self.assertEqual(len(event_payloads), 3)
            self.assertEqual(b"".join(event_payloads), edited)

    def test_replay_parser_accepts_server_frame_omissions(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12082",
                "--transcript",
                "capture.jsonl",
                "--drop-server-frame",
                "4",
                "--drop-server-frame",
                "7",
            ]
        )
        self.assertEqual(arguments.drop_server_frame, [4, 7])

    def test_replay_parser_accepts_keep_world_open(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--hold-open-seconds",
                "600",
                "--keep-world-open",
            ]
        )

        self.assertTrue(arguments.keep_world_open)
        self.assertEqual(arguments.hold_open_seconds, 600)

    def test_replay_parser_accepts_typed_initial_hp_rewrite(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--rewrite-initial-current-hp",
                "1",
            ]
        )

        self.assertEqual(arguments.rewrite_initial_current_hp, 1)

    def test_replay_parser_accepts_typed_initial_field_emitter(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--generate-initial-field-snapshot",
            ]
        )

        self.assertTrue(arguments.generate_initial_field_snapshot)

    def test_replay_parser_accepts_typed_npc_spawn_emitter(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--generate-field-npc-spawns",
            ]
        )

        self.assertTrue(arguments.generate_field_npc_spawns)

    def test_replay_parser_accepts_typed_fixed_server_record_emitter(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--generate-fixed-server-records",
            ]
        )

        self.assertTrue(arguments.generate_fixed_server_records)

    def test_replay_parser_accepts_typed_variable_server_emitter(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--generate-variable-server-records",
            ]
        )

        self.assertTrue(arguments.generate_variable_server_records)

    def test_replay_parser_accepts_typed_post_transcript_hp_update(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--emit-current-hp-update",
                "1",
            ]
        )

        self.assertEqual(arguments.emit_current_hp_update, 1)

    def test_parser_accepts_live_typed_hp_injection_validation(self) -> None:
        arguments = build_parser().parse_args(
            [
                "inject-current-hp",
                "--transcript",
                "live-world.jsonl",
                "--current-hp",
                "49",
                "--http-api-url",
                "http://127.0.0.1:12858/api/v1/server-packets",
                "--verify-timeout-seconds",
                "3",
                "--json",
            ]
        )

        self.assertEqual(arguments.transcript, Path("live-world.jsonl"))
        self.assertEqual(arguments.current_hp, 49)
        self.assertEqual(arguments.verify_timeout_seconds, 3)
        self.assertTrue(arguments.json)

    def test_parser_accepts_live_skill_record_injection_validation(self) -> None:
        arguments = build_parser().parse_args(
            [
                "inject-skill-record",
                "--transcript",
                "live-world.jsonl",
                "--skill-id",
                "2001005",
                "--level",
                "6",
                "--verify-timeout-seconds",
                "3",
                "--json",
            ]
        )

        self.assertEqual(arguments.transcript, Path("live-world.jsonl"))
        self.assertEqual(arguments.skill_id, 2_001_005)
        self.assertEqual(arguments.level, 6)
        self.assertEqual(arguments.verify_timeout_seconds, 3)
        self.assertTrue(arguments.json)

    def test_replay_parser_accepts_typed_inventory_quantity_update(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--emit-inventory-quantity-update",
                "use:15:1",
            ]
        )

        self.assertEqual(
            arguments.emit_inventory_quantity_update,
            ("use", 15, 1),
        )
        self.assertEqual(
            parse_inventory_quantity_update("etc:0x12:0x2"),
            ("etc", 18, 2),
        )

    def test_replay_parser_accepts_reactive_item_use_responses(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--reactive-item-use-responses",
            ]
        )

        self.assertTrue(arguments.reactive_item_use_responses)

    def test_replay_parser_accepts_reactive_client_recovery_responses(
        self,
    ) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--reactive-client-recovery-responses",
            ]
        )

        self.assertTrue(arguments.reactive_client_recovery_responses)

    def test_replay_parser_accepts_reactive_inventory_move_responses(
        self,
    ) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--reactive-inventory-move-responses",
            ]
        )

        self.assertTrue(arguments.reactive_inventory_move_responses)

    def test_replay_parser_accepts_reactive_ability_point_responses(
        self,
    ) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--reactive-ability-point-allocation-responses",
            ]
        )

        self.assertTrue(
            arguments.reactive_ability_point_allocation_responses
        )

    def test_replay_parser_accepts_reactive_skill_level_responses(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--reactive-skill-level-change-responses",
            ]
        )

        self.assertTrue(arguments.reactive_skill_level_change_responses)

    def test_replay_parser_accepts_reactive_item_acquisition_responses(
        self,
    ) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--reactive-item-acquisition-responses",
            ]
        )

        self.assertTrue(arguments.reactive_item_acquisition_responses)

    def test_replay_parser_accepts_reactive_npc_state_responses(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--reactive-npc-state-responses",
            ]
        )

        self.assertTrue(arguments.reactive_npc_state_responses)

    def test_replay_parser_accepts_typed_item_pickup_options(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--pcap",
                "111.pcapng",
                "--tcp-stream",
                "114",
                "--rewrite-final-field-drop-position",
                "633:-2677",
                "--rewrite-final-field-drop-owner-to-player",
                "--reactive-item-pickup-responses",
                "--item-pickup-evidence-tcp-stream",
                "92",
            ]
        )

        self.assertEqual(
            arguments.rewrite_final_field_drop_position,
            (633, -2677),
        )
        self.assertTrue(arguments.rewrite_final_field_drop_owner_to_player)
        self.assertTrue(arguments.reactive_item_pickup_responses)
        self.assertEqual(arguments.item_pickup_evidence_tcp_stream, 92)
        self.assertEqual(parse_i16_position("0x10:-0x20"), (16, -32))

    def test_parser_accepts_latest_position_item_pickup_injection(self) -> None:
        arguments = build_parser().parse_args(
            [
                "inject-item-pickup",
                "--transcript",
                "world.jsonl",
                "--evidence-pcap",
                "111.pcapng",
                "--wayland-display",
                "wayland-3",
            ]
        )

        self.assertEqual(arguments.evidence_tcp_stream, 92)
        self.assertEqual(arguments.item_id, 4_000_004)
        self.assertEqual(arguments.admission_index, 1)
        self.assertEqual(arguments.pickup_key, "z")
        self.assertEqual(arguments.pickup_key_hold_ms, 100)
        self.assertEqual(arguments.verify_timeout_seconds, 10.0)

    def test_replay_parser_accepts_world_heartbeat_interval(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--hold-open-seconds",
                "600",
                "--keep-world-open",
                "--world-heartbeat-interval-seconds",
                "10",
                "--world-readiness-heartbeat-responses",
                "5",
            ]
        )

        self.assertEqual(arguments.world_heartbeat_interval_seconds, 10)
        self.assertEqual(arguments.world_readiness_heartbeat_responses, 5)

    def test_replay_parser_accepts_opt_in_http_packet_injection(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--http-api-port",
                "12858",
                "--enable-http-packet-injection",
                "--transcript",
                "world.jsonl",
            ]
        )

        self.assertTrue(arguments.enable_http_packet_injection)

    def test_replay_parser_accepts_reactive_mob_acknowledgements(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--hold-open-seconds",
                "600",
                "--keep-world-open",
                "--reactive-mob-movement-acknowledgements",
            ]
        )

        self.assertTrue(arguments.reactive_mob_movement_acknowledgements)

    def test_replay_parser_accepts_separate_mob_movement_evidence(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--pcap",
                "world.pcapng",
                "--tcp-stream",
                "114",
                "--keep-world-open",
                "--hold-open-seconds",
                "600",
                "--reactive-mob-movement-acknowledgements",
                "--mob-movement-evidence-tcp-stream",
                "92",
            ]
        )

        self.assertEqual(arguments.mob_movement_evidence_tcp_stream, 92)

    def test_replay_parser_accepts_mob_movement_broadcast(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--hold-open-seconds",
                "600",
                "--emit-mob-movement-broadcast",
                "733:-2677:635:5",
            ]
        )

        self.assertEqual(
            arguments.emit_mob_movement_broadcast,
            (733, -2677, 635, 5),
        )
        self.assertEqual(
            parse_mob_movement_broadcast_target("733:-2677:635"),
            (733, -2677, 635, 4),
        )

    def test_replay_parser_accepts_captured_mob_movement_path(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--hold-open-seconds",
                "600",
                "--emit-mob-movement-path",
                "18818:833:-2677:635",
            ]
        )

        self.assertEqual(
            arguments.emit_mob_movement_path,
            (18_818, 833, -2677, 635),
        )
        self.assertEqual(
            parse_mob_movement_path_target("0:150:-200:7"),
            (0, 150, -200, 7),
        )

    def test_replay_parser_accepts_automatic_mob_movement_path(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--hold-open-seconds",
                "600",
                "--emit-mob-movement-auto-path",
                "833:-2677:635",
            ]
        )

        self.assertEqual(
            arguments.emit_mob_movement_auto_path,
            (833, -2677, 635),
        )
        self.assertEqual(
            parse_mob_movement_auto_path_target("150:-200:7"),
            (150, -200, 7),
        )

    def test_replay_parser_accepts_composed_mob_movement_path(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--hold-open-seconds",
                "600",
                "--emit-mob-movement-composed-path",
                "4:881:-2677:635",
                "--mob-movement-step-delay-seconds",
                "0.25",
                "--queue-mob-movement-composed-path",
                "2:929:-2677:635",
                "--queue-mob-movement-composed-path",
                "2:1025:-2677:635",
            ]
        )

        self.assertEqual(
            arguments.emit_mob_movement_composed_path,
            (4, 881, -2677, 635),
        )
        self.assertEqual(arguments.mob_movement_step_delay_seconds, 0.25)
        self.assertEqual(
            arguments.queue_mob_movement_composed_path,
            [(2, 929, -2677, 635), (2, 1025, -2677, 635)],
        )
        self.assertEqual(
            parse_mob_movement_composed_path_target("2:300:-200:8"),
            (2, 300, -200, 8),
        )

    def test_replay_parser_accepts_relative_mob_movement_policy(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--emit-mob-movement-auto-path",
                "833:-2677:635",
                "--mob-movement-relative-policy",
                "2:2:96:0:635",
                "--world-heartbeat-interval-seconds",
                "10",
                "--mob-movement-policy-trigger",
                "matched-heartbeat",
                "--mob-movement-policy-cooldown-seconds",
                "5",
                "--mob-movement-policy-event-budget",
                "1",
            ]
        )

        self.assertEqual(
            arguments.mob_movement_relative_policy.safe_dict(),
            {
                "decision_count": 2,
                "max_steps": 2,
                "displacement_x": 96,
                "displacement_y": 0,
                "foothold_id": 635,
            },
        )
        self.assertEqual(
            arguments.mob_movement_policy_trigger, "matched-heartbeat"
        )
        self.assertEqual(arguments.mob_movement_policy_cooldown_seconds, 5)
        self.assertEqual(arguments.mob_movement_policy_event_budget, 1)
        served_arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--reactive-mob-movement-acknowledgements",
                "--emit-mob-movement-auto-path",
                "833:-2677:635",
                "--mob-movement-relative-policy",
                "1:2:96:0:635",
                "--mob-movement-policy-trigger",
                "served-mob-movement",
            ]
        )
        self.assertEqual(
            served_arguments.mob_movement_policy_trigger,
            "served-mob-movement",
        )
        proximity_arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--keep-world-open",
                "--emit-mob-movement-auto-path",
                "833:-2677:635",
                "--mob-movement-relative-policy",
                "1:2:96:0:635",
                "--mob-movement-policy-trigger",
                "player-proximity",
                "--mob-movement-proximity-radius",
                "64",
            ]
        )
        self.assertEqual(
            proximity_arguments.mob_movement_policy_trigger,
            "player-proximity",
        )
        self.assertEqual(
            proximity_arguments.mob_movement_proximity_radius,
            64,
        )
        self.assertEqual(
            parse_mob_movement_relative_policy("1:4:-32:16:7").safe_dict(),
            {
                "decision_count": 1,
                "max_steps": 4,
                "displacement_x": -32,
                "displacement_y": 16,
                "foothold_id": 7,
            },
        )

    def test_replay_parser_accepts_reactive_mob_health_responses(self) -> None:
        arguments = build_parser().parse_args(
            [
                "replay",
                "--listen-port",
                "12857",
                "--transcript",
                "world.jsonl",
                "--hold-open-seconds",
                "600",
                "--keep-world-open",
                "--reactive-mob-health-responses",
            ]
        )

        self.assertTrue(arguments.reactive_mob_health_responses)

    def test_parse_server_frame_patch(self) -> None:
        self.assertEqual(parse_server_frame_patch("3=0000ff"), (3, b"\x00\x00\xff"))

    def test_build_post_transcript_server_frames_advances_server_iv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_iv = bytes.fromhex("6e3c795a")
            second_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + first_iv
                + second_iv
                + b"\x08"
            )
            first_plaintext = b"captured"
            first_frame = (
                encode_frame_header(len(first_plaintext), second_iv, ~300)
                + crypt_payload(first_plaintext, second_iv)
            )
            writer = TranscriptWriter(directory, label="post-reply", metadata={})
            writer.data("server_to_client", greeting + first_frame)
            writer.close()
            transcript = Transcript.load(writer.path)

            plaintexts = (b"first reply", b"second reply")
            replies = build_post_transcript_server_frames(transcript, plaintexts)
            iv = shuffle_iv(second_iv)
            self.assertEqual(crypt_payload(replies[0][4:], iv), plaintexts[0])
            iv = shuffle_iv(iv)
            self.assertEqual(crypt_payload(replies[1][4:], iv), plaintexts[1])

    def test_parse_plaintext_hex(self) -> None:
        self.assertEqual(parse_plaintext_hex("0d0000"), b"\x0d\x00\x00")

    def test_pcap_plaintext_reference_can_rewrite_only_opcode(self) -> None:
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(b"\x00\x00private",),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@83:0?opcode=1"
            )
        self.assertEqual(payload, b"\x01\x00private")

    def test_pcap_plaintext_reference_can_rewrite_validated_handoff(self) -> None:
        original = WorldHandoff(
            result=0,
            address=IPv4Address("203.0.113.10"),
            port=8587,
            character_id=1234,
        ).to_bytes()
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@83:0?handoff=127.0.0.1:12857"
            )
        parsed = WorldHandoff.parse(payload)
        self.assertEqual(str(parsed.address), "127.0.0.1")
        self.assertEqual(parsed.port, 12857)
        self.assertEqual(parsed.character_id, 1234)

    def test_pcap_plaintext_reference_can_reencode_typed_character_list(
        self,
    ) -> None:
        original = bytes.fromhex("040000000000000000000000000103000000")
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@116:0?character-list"
            )

        self.assertEqual(payload, original)

    def test_pcap_plaintext_reference_can_rebind_one_keyboard_skill(
        self,
    ) -> None:
        bindings = [
            VariableServerEntry(selector=0, value=0) for _ in range(89)
        ]
        bindings[29] = VariableServerEntry(selector=1, value=2_001_005)
        original = VariableServerRecord(
            opcode=385,
            variant=0,
            entries=tuple(bindings),
        ).to_bytes()
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@114:0?"
                "keyboard-skill=29:2001004"
            )

        parsed = VariableServerRecord.parse(payload)
        self.assertEqual(parsed.left_ctrl_skill_id, 2_001_004)
        self.assertEqual(parsed.entries[29].selector, 1)
        self.assertEqual(parsed.entries[:29], tuple(bindings[:29]))
        self.assertEqual(parsed.entries[30:], tuple(bindings[30:]))

        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            with self.assertRaisesRegex(
                argparse.ArgumentTypeError, "not a captured skill binding"
            ):
                parse_pcap_plaintext_reference(
                    "/private/reference.pcapng@114:0?"
                    "keyboard-skill=28:2001004"
                )

    def test_pcap_plaintext_reference_can_zero_one_skill_selector(
        self,
    ) -> None:
        bindings = [
            VariableServerEntry(selector=0, value=0) for _ in range(89)
        ]
        bindings[71] = VariableServerEntry(selector=1, value=2_001_002)
        original = VariableServerRecord(
            opcode=385,
            variant=0,
            entries=tuple(bindings),
        ).to_bytes()
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@114:0?"
                "keyboard-selector-zero=71"
            )

        parsed = VariableServerRecord.parse(payload)
        self.assertEqual(parsed.entries[71].selector, 0)
        self.assertEqual(parsed.entries[71].value, 2_001_002)
        self.assertEqual(parsed.keyboard_skill_bindings.get(71), None)
        self.assertEqual(parsed.entries[:71], tuple(bindings[:71]))
        self.assertEqual(parsed.entries[72:], tuple(bindings[72:]))

    def test_pcap_plaintext_reference_can_rewrite_one_captured_stat(
        self,
    ) -> None:
        original = CharacterStatUpdate(
            request_flag=False,
            stat_mask=CharacterStatUpdate.EXPERIENCE,
            experience=1_615,
        ).to_bytes()
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@92:0?"
                "character-stat=experience:1474"
            )

        parsed = CharacterStatUpdate.parse(payload)
        self.assertEqual(parsed.experience, 1_474)
        self.assertEqual(parsed.stat_mask, CharacterStatUpdate.EXPERIENCE)
        self.assertFalse(parsed.request_flag)
        self.assertFalse(parsed.trailing_flag)
        self.assertIsNone(parsed.trailing_value)

        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            with self.assertRaisesRegex(
                argparse.ArgumentTypeError, "only captured stat field"
            ):
                parse_pcap_plaintext_reference(
                    "/private/reference.pcapng@92:0?"
                    "character-stat=current_mp:86"
                )

    def test_pcap_plaintext_reference_can_rewrite_drop_positions(
        self,
    ) -> None:
        original_record = FieldDropSpawn(
            spawn_mode=1,
            drop_object_id=40_004,
            drop_kind=FieldDropSpawn.ITEM,
            value=4_000_004,
            owner_value_1=300_001,
            owner_value_2=300_001,
            ownership_flag=0,
            position_x=516,
            position_y=1_006,
            source_mob_object_id=20_001,
            source_x=526,
            source_y=1_058,
            animation_duration_ms=450,
            expiration_ticks=150_842_304_000_000_000,
            final_flag=1,
        )
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original_record.to_bytes(),),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@92:0?"
                "field-drop-position=633:-2677:633:-2677"
            )

        parsed = FieldDropSpawn.parse(payload)
        self.assertEqual((parsed.position_x, parsed.position_y), (633, -2677))
        self.assertEqual((parsed.source_x, parsed.source_y), (633, -2677))
        self.assertEqual(parsed.drop_object_id, original_record.drop_object_id)
        self.assertEqual(parsed.value, original_record.value)
        self.assertEqual(parsed.owner_value_1, original_record.owner_value_1)
        self.assertEqual(parsed.owner_value_2, original_record.owner_value_2)
        self.assertEqual(
            parsed.source_mob_object_id,
            original_record.source_mob_object_id,
        )

    def test_pcap_plaintext_reference_can_rewrite_typed_mob_spawn(self) -> None:
        original = MobEnterField(
            object_id=20_001,
            spawn=MobSpawnData(
                spawn_marker=1,
                template_id=100_100,
                temporary_status=MobSpawnTemporaryStatus(),
                x=82,
                y=234,
                stance=3,
                foothold_id=258,
                origin_foothold_id=213,
                appear_type=-1,
                team=0xFF,
                effect_item_id=0,
            ),
        ).to_bytes()
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(original,),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@92:0?mob-spawn=633:-2677:0:0"
            )
        parsed = MobEnterField.parse(payload)
        self.assertEqual(parsed.object_id, 20_001)
        self.assertEqual(parsed.spawn.template_id, 100_100)
        self.assertEqual((parsed.spawn.x, parsed.spawn.y), (633, -2677))
        self.assertEqual(parsed.spawn.foothold_id, 0)
        self.assertEqual(parsed.spawn.origin_foothold_id, 0)

        controlled = MobControllerChange(
            control_level=1,
            object_id=20_001,
            spawn=MobEnterField.parse(original).spawn,
        ).to_bytes()
        with patch(
            "maple_server.server._load_pcap_plaintexts",
            return_value=(controlled,),
        ):
            payload = parse_pcap_plaintext_reference(
                "/private/reference.pcapng@92:0?mob-spawn=600:-2600:7:8"
            )
        controller = MobControllerChange.parse(payload)
        assert controller.spawn is not None
        self.assertEqual((controller.spawn.x, controller.spawn.y), (600, -2600))
        self.assertEqual(controller.spawn.foothold_id, 7)
        self.assertEqual(controller.spawn.origin_foothold_id, 8)

    def test_parse_zero_filled_frame_with_selector(self) -> None:
        self.assertEqual(
            parse_zero_filled_frame("1:6:1"),
            b"\x01\x00\x01\x00\x00\x00",
        )

    def test_parse_client_opcode_reply(self) -> None:
        self.assertEqual(
            parse_client_opcode_reply("13=0d0000"),
            (13, b"\x0d\x00\x00"),
        )

    def test_parse_client_opcode_reply_delays(self) -> None:
        self.assertEqual(
            parse_client_opcode_reply_delays("4=0,2.5"),
            (4, (0.0, 2.5)),
        )

    def test_parse_client_opcode_result_rewrite(self) -> None:
        self.assertEqual(
            parse_client_opcode_result_rewrite("13=0"),
            (13, 0),
        )

    def test_parse_server_opcode_byte_rewrite(self) -> None:
        self.assertEqual(
            parse_server_opcode_byte_rewrite("0:2=0"),
            (0, 2, 0),
        )


class ServerTest(unittest.IsolatedAsyncioTestCase):
    async def test_replay_matches_client_and_returns_server_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TranscriptWriter(directory, label="replay", metadata={})
            writer.data("client_to_server", b"request")
            writer.data("server_to_client", b"response")
            writer.close()
            transcript = Transcript.load(writer.path)

            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, stream_writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(reader, stream_writer, transcript)
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, stream_writer = await asyncio.open_connection("127.0.0.1", port)
            stream_writer.write(b"request")
            await stream_writer.drain()
            self.assertEqual(await reader.readexactly(8), b"response")
            stream_writer.close()
            await stream_writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_can_record_observed_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory:
            source_writer = TranscriptWriter(
                source_directory, label="source", metadata={}
            )
            source_writer.data("client_to_server", b"request")
            source_writer.data("server_to_client", b"response")
            source_writer.close()
            source = Transcript.load(source_writer.path)

            with tempfile.TemporaryDirectory() as observed_directory:
                tasks: set[asyncio.Task[None]] = set()

                def accept(reader, writer) -> None:
                    tasks.add(
                        asyncio.create_task(
                            replay_connection(
                                reader,
                                writer,
                                source,
                                transcript_directory=Path(observed_directory),
                                listen_port=10282,
                            )
                        )
                    )

                server = await asyncio.start_server(accept, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(b"request")
                await writer.drain()
                self.assertEqual(await reader.readexactly(8), b"response")
                writer.close()
                await writer.wait_closed()
                await asyncio.gather(*tasks)

                observed_path = next(Path(observed_directory).glob("*.jsonl"))
                observed = Transcript.load(observed_path)
                self.assertEqual(observed.client_bytes, b"request")
                self.assertEqual(observed.server_bytes, b"response")

                server.close()
                await server.wait_closed()

    async def test_replay_records_partial_client_event_before_disconnect(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory:
            source_writer = TranscriptWriter(
                source_directory, label="source", metadata={}
            )
            source_writer.data("server_to_client", b"greeting")
            source_writer.data("client_to_server", b"expected-long-request")
            source_writer.close()
            source = Transcript.load(source_writer.path)

            with tempfile.TemporaryDirectory() as observed_directory:
                tasks: set[asyncio.Task[None]] = set()

                def accept(reader, writer) -> None:
                    tasks.add(
                        asyncio.create_task(
                            replay_connection(
                                reader,
                                writer,
                                source,
                                transcript_directory=Path(observed_directory),
                                listen_port=10282,
                            )
                        )
                    )

                server = await asyncio.start_server(accept, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                self.assertEqual(await reader.readexactly(8), b"greeting")
                writer.write(b"partial")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                self.assertEqual(len(results), 1)
                self.assertIsInstance(results[0], asyncio.IncompleteReadError)

                observed_path = next(Path(observed_directory).glob("*.jsonl"))
                observed = Transcript.load(observed_path)
                self.assertEqual(observed.client_bytes, b"partial")
                self.assertEqual(observed.server_bytes, b"greeting")

                server.close()
                await server.wait_closed()

    async def test_non_strict_replay_accepts_a_different_complete_frame(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_writer = TranscriptWriter(directory, label="framed", metadata={})
            source_writer.data(
                "client_to_server", b"\x34\x12\x3c\x12expected"
            )
            source_writer.data("server_to_client", b"response")
            source_writer.close()
            source = Transcript.load(source_writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(reader, writer, source, strict=False)
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"\x00\x20\x04\x20live")
            await writer.drain()
            self.assertEqual(await reader.readexactly(8), b"response")
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_can_hold_connection_open_after_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TranscriptWriter(directory, label="hold-open", metadata={})
            writer.data("client_to_server", b"request")
            writer.data("server_to_client", b"response")
            writer.close()
            transcript = Transcript.load(writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, stream_writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            stream_writer,
                            transcript,
                            hold_open_seconds=0.1,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, stream_writer = await asyncio.open_connection("127.0.0.1", port)
            stream_writer.write(b"request")
            await stream_writer.drain()
            self.assertEqual(await reader.readexactly(8), b"response")
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(reader.read(1), timeout=0.02)
            self.assertEqual(await reader.read(), b"")
            stream_writer.close()
            await stream_writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_injects_plaintext_through_active_cipher_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"\x34\x12captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="injection-source", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            injection = ServerPacketInjection(enabled=True)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=1,
                            server_packet_injection=injection,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            for _ in range(100):
                if injection.safe_dict()["ready"]:
                    break
                await asyncio.sleep(0.001)
            self.assertTrue(injection.safe_dict()["ready"])

            injected_plaintext = VariableServerRecord(
                opcode=385, variant=1, opaque_tail=b""
            ).to_bytes()
            result = await injection.inject(injected_plaintext)
            encrypted = await reader.readexactly(4 + len(injected_plaintext))
            self.assertEqual(
                crypt_payload(encrypted[4:], shuffle_iv(server_iv)),
                injected_plaintext,
            )
            self.assertEqual(result["opcode"], 385)
            self.assertEqual(result["plaintext_length"], 3)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()
            self.assertFalse(injection.safe_dict()["ready"])

            observed_paths = tuple(observed_directory.glob("*.jsonl"))
            self.assertEqual(len(observed_paths), 1)
            analysis = analyze_gameplay_transcript(
                Transcript.load(observed_paths[0])
            )
            self.assertTrue(analysis.valid)
            self.assertEqual(analysis.state.variable_server_records, 1)

    async def test_replay_periodically_probes_and_folds_heartbeat_responses(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"\x34\x12captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="heartbeat-source", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            runtime_protocol = {
                "world_heartbeat": {
                    "probes_sent": 0,
                    "responses_observed": 0,
                    "pending": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.13,
                            world_heartbeat_interval_seconds=0.05,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )

            next_server_iv = shuffle_iv(server_iv)
            next_client_iv = client_iv
            for response_value in (1, 2):
                encrypted_probe = await reader.readexactly(6)
                probe_plaintext = crypt_payload(
                    encrypted_probe[4:], next_server_iv
                )
                self.assertEqual(
                    HeartbeatProbe.parse(probe_plaintext), HeartbeatProbe()
                )
                next_server_iv = shuffle_iv(next_server_iv)

                response = HeartbeatResponse(
                    response_value=response_value
                ).to_bytes()
                writer.write(
                    encode_frame_header(len(response), next_client_iv, 300)
                    + crypt_payload(response, next_client_iv)
                )
                await writer.drain()
                next_client_iv = shuffle_iv(next_client_iv)

            self.assertEqual(await reader.read(), b"")
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

            observed_paths = tuple(observed_directory.glob("*.jsonl"))
            self.assertEqual(len(observed_paths), 1)
            analysis = analyze_gameplay_transcript(
                Transcript.load(observed_paths[0])
            )
            self.assertTrue(analysis.valid)
            self.assertEqual(analysis.state.heartbeat_probes, 2)
            self.assertEqual(analysis.state.heartbeat_responses, 2)
            self.assertEqual(analysis.state.matched_heartbeat_responses, 2)
            self.assertEqual(analysis.state.pending_heartbeat_probes, 0)
            heartbeat_metrics = runtime_protocol["world_heartbeat"]
            self.assertEqual(heartbeat_metrics["probes_sent"], 2)
            self.assertEqual(heartbeat_metrics["responses_observed"], 2)
            self.assertEqual(heartbeat_metrics["pending"], 0)
            self.assertGreater(heartbeat_metrics["last_round_trip_ms"], 0)

    async def test_replay_replies_after_one_new_client_frame(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_iv = bytes.fromhex("6e3c795a")
            second_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + first_iv
                + second_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), second_iv, ~300)
                + crypt_payload(captured_plaintext, second_iv)
            )
            source_writer = TranscriptWriter(directory, label="reactive", metadata={})
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            post_transcript_replies=(b"ack",),
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            writer.write(b"\x00\x20\x04\x20live")
            await writer.drain()
            reply = await reader.readexactly(7)
            self.assertEqual(
                crypt_payload(reply[4:], shuffle_iv(second_iv)), b"ack"
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_sends_new_server_frame_immediately_after_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_iv = bytes.fromhex("6e3c795a")
            second_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + first_iv
                + second_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), second_iv, ~300)
                + crypt_payload(captured_plaintext, second_iv)
            )
            source_writer = TranscriptWriter(directory, label="append", metadata={})
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            post_transcript_server_frames=(b"appended",),
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            appended = await reader.readexactly(12)
            self.assertEqual(
                crypt_payload(appended[4:], shuffle_iv(second_iv)), b"appended"
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_reports_modeled_npc_state_packet_sent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"\x34\x12captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="npc-state-source", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            update = NpcStateUpdate(
                object_id=1234,
                action=255,
                parameter=1,
            ).to_bytes()
            runtime_protocol = {
                "npc_state_replay": {
                    "packets_planned": 1,
                    "packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            post_transcript_server_frames=(update,),
                            npc_state_replay_plaintext=update,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            encrypted_update = await reader.readexactly(len(update) + 4)
            plaintext = crypt_payload(
                encrypted_update[4:], shuffle_iv(server_iv)
            )
            self.assertEqual(NpcStateUpdate.parse(plaintext).to_bytes(), update)
            self.assertEqual(
                runtime_protocol["npc_state_replay"]["packets_sent"], 1
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_reports_modeled_player_stat_packet_sent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"\x34\x12captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="player-stat-source", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            update = CharacterStatUpdate(
                request_flag=False,
                stat_mask=CharacterStatUpdate.CURRENT_HP,
                current_hp=1,
            ).to_bytes()
            runtime_protocol = {
                "player_stat_update": {
                    "packets_planned": 1,
                    "packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            post_transcript_server_frames=(update,),
                            player_stat_update_plaintext=update,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            encrypted_update = await reader.readexactly(len(update) + 4)
            plaintext = crypt_payload(
                encrypted_update[4:], shuffle_iv(server_iv)
            )
            self.assertEqual(
                CharacterStatUpdate.parse(plaintext).to_bytes(), update
            )
            self.assertEqual(
                runtime_protocol["player_stat_update"]["packets_sent"], 1
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_reports_inventory_quantity_packet_sent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"\x34\x12captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="inventory-quantity-source", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            update = InventoryChangeSet(
                update_flag=0,
                modifications=(
                    InventoryModification(
                        operation=InventoryModification.UPDATE_QUANTITY,
                        inventory_type=2,
                        slot=15,
                        quantity=1,
                    ),
                ),
            ).to_bytes()
            runtime_protocol = {
                "inventory_quantity_update": {
                    "packets_planned": 1,
                    "packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            post_transcript_server_frames=(update,),
                            inventory_quantity_update_plaintext=update,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            encrypted_update = await reader.readexactly(len(update) + 4)
            plaintext = crypt_payload(
                encrypted_update[4:], shuffle_iv(server_iv)
            )
            self.assertEqual(
                InventoryChangeSet.parse(plaintext).to_bytes(), update
            )
            self.assertEqual(
                runtime_protocol["inventory_quantity_update"]["packets_sent"],
                1,
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_responds_to_modeled_item_use_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-item-use", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            policy = ItemUseResponsePolicy(
                use_items={
                    15: InventoryItemEntity(
                        slot=15,
                        record_type=2,
                        item_id=2_000_000,
                        cash_item=False,
                        expires_at_ticks=150_842_304_000_000_000,
                        quantity=2,
                    )
                },
                current_hp=50,
                max_hp=222,
                current_mp=97,
                max_mp=342,
                field_epoch=1,
            )
            runtime_protocol = {
                "item_use_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            item_use_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = ItemUseRequest(
                client_tick=502_038,
                slot=15,
                item_id=2_000_000,
            ).to_bytes()
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()
            first_server_iv = shuffle_iv(server_iv)
            inventory_wire = await reader.readexactly(14)
            inventory_update = InventoryChangeSet.parse(
                crypt_payload(inventory_wire[4:], first_server_iv)
            )
            self.assertEqual(inventory_update.modifications[0].quantity, 1)
            second_server_iv = shuffle_iv(first_server_iv)
            stat_wire = await reader.readexactly(14)
            stat_update = CharacterStatUpdate.parse(
                crypt_payload(stat_wire[4:], second_server_iv)
            )
            self.assertEqual(stat_update.current_hp, 100)

            next_client_iv = shuffle_iv(client_iv)
            writer.write(
                encode_frame_header(len(request), next_client_iv, 300)
                + crypt_payload(request, next_client_iv)
            )
            await writer.drain()
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(reader.read(1), timeout=0.02)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()
            metrics = runtime_protocol["item_use_responses"]
            self.assertEqual(metrics["requests_observed"], 2)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 1)
            self.assertEqual(metrics["response_packets_sent"], 2)
            self.assertEqual(
                metrics["last_rejection"],
                "item-use last-item removal response shape is not validated",
            )
            self.assertEqual(policy.use_items[15].quantity, 1)
            self.assertEqual(policy.current_hp, 100)
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid)
            self.assertFalse(
                any(
                    "item-use requests had no complete" in warning
                    for warning in analysis.warnings
                )
            )
            self.assertEqual(analysis.state.pending_item_uses, 0)
            self.assertEqual(analysis.state.item_use_policy_rejections, 1)
            item_use_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("item_use_")
            ]
            self.assertEqual(
                [event.kind for event in item_use_events],
                [
                    "item_use_request_observed",
                    "item_use_response_completed",
                    "item_use_request_observed",
                    "item_use_request_rejected",
                ],
            )
            self.assertEqual(item_use_events[1].details["quantity_after"], 1)
            self.assertEqual(item_use_events[1].details["effect_after"], 100)
            self.assertEqual(
                item_use_events[1].details["server_opcodes"], [39, 41]
            )
            self.assertEqual(
                item_use_events[-1].details["reason"],
                "item-use last-item removal response shape is not validated",
            )

    async def test_replay_responds_to_client_recovery_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = CharacterStatUpdate(
                request_flag=False,
                stat_mask=(
                    CharacterStatUpdate.CURRENT_HP
                    | CharacterStatUpdate.MAX_HP
                ),
                current_hp=218,
                max_hp=222,
            ).to_bytes()
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-client-recovery", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            policy = ClientRecoveryResponsePolicy(
                current_hp=218,
                max_hp=222,
                current_mp=97,
                max_mp=342,
                field_epoch=1,
            )
            runtime_protocol = {
                "client_recovery_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            client_recovery_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = ClientRecoveryRequest(
                hp_recovery=10,
                mp_recovery=0,
            ).to_bytes()
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()
            first_server_iv = shuffle_iv(server_iv)
            stat_wire = await reader.readexactly(14)
            stat_update = CharacterStatUpdate.parse(
                crypt_payload(stat_wire[4:], first_server_iv)
            )
            self.assertEqual(stat_update.current_hp, 222)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()
            metrics = runtime_protocol["client_recovery_responses"]
            self.assertEqual(metrics["requests_observed"], 1)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["response_packets_sent"], 1)
            self.assertEqual(metrics["last_response"]["actual_increment"], 4)
            self.assertTrue(
                metrics["last_response"]["maximum_cap_applied"]
            )
            self.assertEqual(policy.current_hp, 222)
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid, analysis.issues)
            self.assertEqual(
                analysis.state.pending_client_recovery_requests, 0
            )
            self.assertEqual(
                analysis.state.client_recovery_capped_amount_matches, 1
            )
            recovery_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("client_recovery_")
            ]
            self.assertEqual(
                [event.kind for event in recovery_events],
                [
                    "client_recovery_request_observed",
                    "client_recovery_response_completed",
                ],
            )
            self.assertEqual(
                recovery_events[-1].details["server_opcodes"], [41]
            )

    async def test_replay_responds_to_inventory_move_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"\x18\x00"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-inventory-move", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            policy = InventoryMoveResponsePolicy(
                equip_items={
                    2: InventoryItemEntity(
                        slot=2,
                        record_type=1,
                        item_id=1_332_066,
                        cash_item=False,
                        expires_at_ticks=150_842_304_000_000_000,
                        quantity=None,
                    )
                },
                field_epoch=1,
            )
            runtime_protocol = {
                "inventory_move_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            inventory_move_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = InventoryMoveRequest(
                client_tick=1_640_184,
                inventory_type=1,
                source_slot=2,
                destination_slot=-11,
                quantity=-1,
            ).to_bytes()
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()
            response_wire = await reader.readexactly(15)
            response = InventoryChangeSet.parse(
                crypt_payload(response_wire[4:], shuffle_iv(server_iv))
            )
            self.assertEqual(response.update_flag, 1)
            self.assertEqual(response.modifications[0].move_flag, 2)
            self.assertEqual(response.modifications[0].slot, 2)
            self.assertEqual(response.modifications[0].destination_slot, -11)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()
            metrics = runtime_protocol["inventory_move_responses"]
            self.assertEqual(metrics["requests_observed"], 1)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 0)
            self.assertEqual(metrics["response_packets_sent"], 1)
            self.assertEqual(metrics["last_response"]["item_id"], 1_332_066)
            self.assertNotIn(2, policy.equip_items)
            self.assertEqual(policy.equip_items[-11].item_id, 1_332_066)
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid, analysis.issues)
            self.assertEqual(analysis.state.inventory_move_request_matches, 1)
            self.assertEqual(analysis.state.pending_inventory_move_requests, 0)
            move_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("inventory_move_")
            ]
            self.assertEqual(
                [event.kind for event in move_events],
                [
                    "inventory_move_request_observed",
                    "inventory_move_response_completed",
                ],
            )
            self.assertEqual(move_events[-1].details["server_opcodes"], [39])

    async def test_replay_responds_to_ability_point_allocation_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = CharacterStatUpdate(
                request_flag=False,
                stat_mask=(
                    CharacterStatUpdate.INTELLIGENCE
                    | CharacterStatUpdate.LUCK
                    | CharacterStatUpdate.ABILITY_POINTS
                ),
                intelligence=57,
                luck=15,
                ability_points=5,
            ).to_bytes()
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-ability-points", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            policy = AbilityPointAllocationResponsePolicy(
                strength=4,
                dexterity=4,
                intelligence=57,
                luck=15,
                ability_points=5,
                field_epoch=1,
            )
            runtime_protocol = {
                "ability_point_allocation_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            ability_point_allocation_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = ClientAbilityPointAllocationRequest(
                client_tick=564_468,
                allocations=(
                    AbilityPointAllocationEntry(
                        stat_mask=CharacterStatUpdate.LUCK,
                        increment=0,
                    ),
                    AbilityPointAllocationEntry(
                        stat_mask=CharacterStatUpdate.INTELLIGENCE,
                        increment=1,
                    ),
                ),
            ).to_bytes()
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()
            response_wire = await reader.readexactly(18)
            response = CharacterStatUpdate.parse(
                crypt_payload(response_wire[4:], shuffle_iv(server_iv))
            )
            self.assertEqual(response.request_flag, 1)
            self.assertEqual(response.stat_mask, 0x0000_4300)
            self.assertEqual(response.intelligence, 58)
            self.assertEqual(response.luck, 15)
            self.assertEqual(response.ability_points, 4)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()
            metrics = runtime_protocol[
                "ability_point_allocation_responses"
            ]
            self.assertEqual(metrics["requests_observed"], 1)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 0)
            self.assertEqual(metrics["response_packets_sent"], 1)
            self.assertEqual(metrics["last_response"]["ability_points_after"], 4)
            self.assertEqual(policy.intelligence, 58)
            self.assertEqual(policy.luck, 15)
            self.assertEqual(policy.ability_points, 4)
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid, analysis.issues)
            self.assertEqual(
                analysis.state.ability_point_allocation_response_matches, 1
            )
            self.assertEqual(
                analysis.state.pending_ability_point_allocations, 0
            )
            allocation_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("ability_point_allocation_")
            ]
            self.assertEqual(
                [event.kind for event in allocation_events],
                [
                    "ability_point_allocation_request_observed",
                    "ability_point_allocation_response_completed",
                ],
            )
            self.assertEqual(
                allocation_events[-1].details["server_opcodes"], [41]
            )

    async def test_replay_responds_to_skill_level_change_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = CharacterStatUpdate(
                request_flag=False,
                stat_mask=CharacterStatUpdate.SKILL_POINTS,
                skill_points=1,
            ).to_bytes()
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-skill-points", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            policy = SkillLevelChangeResponsePolicy(
                skill_points=1,
                skill_levels={},
                field_epoch=1,
            )
            runtime_protocol = {
                "skill_level_change_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            skill_level_change_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = SkillLevelChangeRequest(
                client_tick=200_000,
                skill_id=2_001_005,
            ).to_bytes()
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()

            first_response_iv = shuffle_iv(server_iv)
            stat_wire = await reader.readexactly(14)
            stat_update = CharacterStatUpdate.parse(
                crypt_payload(stat_wire[4:], first_response_iv)
            )
            skill_wire = await reader.readexactly(23)
            skill_update = SkillRecordUpdate.parse(
                crypt_payload(skill_wire[4:], shuffle_iv(first_response_iv))
            )
            self.assertEqual(stat_update.skill_points, 0)
            self.assertEqual(skill_update.records[0].skill_id, 2_001_005)
            self.assertEqual(skill_update.records[0].level, 1)
            self.assertEqual(skill_update.trailing_value, 2)

            acknowledgement = SkillRecordUpdateAcknowledgement(
                control_value=346,
                client_tick=200_450,
                trailing_value=0,
            ).to_bytes()
            next_client_iv = shuffle_iv(client_iv)
            writer.write(
                encode_frame_header(len(acknowledgement), next_client_iv, 300)
                + crypt_payload(acknowledgement, next_client_iv)
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

            metrics = runtime_protocol["skill_level_change_responses"]
            self.assertEqual(metrics["requests_observed"], 1)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 0)
            self.assertEqual(metrics["response_packets_sent"], 2)
            self.assertEqual(metrics["last_response"]["server_opcodes"], [41, 46])
            self.assertEqual(policy.skill_points, 0)
            self.assertEqual(policy.skill_levels, {2_001_005: 1})
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid, analysis.issues)
            self.assertEqual(analysis.state.skill_record_request_matches, 1)
            self.assertEqual(
                analysis.state.matched_skill_record_update_acknowledgements,
                1,
            )
            skill_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("skill_level_change_")
            ]
            self.assertEqual(
                [event.kind for event in skill_events],
                [
                    "skill_level_change_request_observed",
                    "skill_level_change_response_completed",
                ],
            )

    async def test_replay_responds_to_npc_state_during_hold_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            npc = NpcSpawn(
                object_id=23_549,
                template_id=1_001_000,
                x=69,
                cy=65,
                facing_value=1,
                foothold_id=89,
                range_left=40,
                range_right=120,
                hidden=False,
            )
            captured_plaintext = npc.to_bytes()
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-npc-state", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            policy = NpcStateResponsePolicy(
                active_npc_ids={npc.object_id},
                field_epoch=1,
            )
            runtime_protocol = {
                "npc_state_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            npc_state_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = bytes.fromhex(
                "d900fd5b000005ff3d004100020200000000040000003d00410000"
                "0000005900048813003d0041003d004100"
            )
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()

            expected = b"\x2f\x01" + request[2:-9]
            response_iv = shuffle_iv(server_iv)
            response_wire = await reader.readexactly(4 + len(expected))
            response = crypt_payload(response_wire[4:], response_iv)
            self.assertEqual(response, expected)
            self.assertEqual(
                NpcStateUpdate.parse(response),
                ClientNpcStateSubmission.parse(request).to_state_update(),
            )

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

            metrics = runtime_protocol["npc_state_responses"]
            self.assertEqual(metrics["requests_observed"], 1)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 0)
            self.assertEqual(metrics["response_packets_sent"], 1)
            self.assertEqual(metrics["last_response"]["server_opcodes"], [303])
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid, analysis.issues)
            self.assertEqual(analysis.state.npc_state_submission_matches, 1)
            self.assertEqual(analysis.state.pending_npc_state_submissions, 0)
            npc_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("npc_state_")
            ]
            self.assertEqual(
                [event.kind for event in npc_events],
                [
                    "npc_state_request_observed",
                    "npc_state_response_completed",
                ],
            )

    async def test_replay_responds_to_item_acquisition_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = InventoryChangeSet(
                update_flag=0,
                modifications=(),
            ).to_bytes()
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-item-acquisition", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            policy = ItemAcquisitionResponsePolicy(
                use_items={
                    1: InventoryItemEntity(
                        slot=1,
                        record_type=2,
                        item_id=2_000_000,
                        cash_item=False,
                        expires_at_ticks=150_842_304_000_000_000,
                        quantity=1,
                    )
                },
                field_epoch=1,
            )
            runtime_protocol = {
                "item_acquisition_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            item_acquisition_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = ClientOpcode298ItemAcquisitionRequest(
                control_value=0,
                selection_index=10,
                request_kind=1,
                item_id=2_030_059,
                quantity=10,
                duration_value=0,
                expires_at_ticks=150_842_304_000_000_000,
                serial_value=0,
                reserved_values=(0, 0, 0, 0, 0),
                signed_sentinel_values=(-99, -99),
                trailing_values=(0, 0),
                flag_1=0,
                flag_2=1,
            ).to_bytes()
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()

            response_iv = shuffle_iv(server_iv)
            response_length = len(
                InventoryChangeSet(
                    update_flag=0,
                    modifications=(
                        InventoryModification(
                            operation=InventoryModification.ADD,
                            inventory_type=2,
                            slot=2,
                            item=(
                                InitialInventoryItem.captured_permanent_stack(
                                    slot=2,
                                    item_id=2_030_059,
                                    quantity=10,
                                )
                            ),
                        ),
                    ),
                ).to_bytes()
            )
            response_wire = await reader.readexactly(4 + response_length)
            response = InventoryChangeSet.parse(
                crypt_payload(response_wire[4:], response_iv)
            )
            self.assertEqual(response.update_flag, 0)
            self.assertEqual(len(response.modifications), 1)
            modification = response.modifications[0]
            self.assertEqual(modification.operation, InventoryModification.ADD)
            self.assertEqual(modification.inventory_type, 2)
            self.assertEqual(modification.slot, 2)
            self.assertIsNotNone(modification.item)
            assert modification.item is not None
            self.assertEqual(modification.item.item_id, 2_030_059)
            self.assertEqual(modification.item.quantity, 10)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

            metrics = runtime_protocol["item_acquisition_responses"]
            self.assertEqual(metrics["requests_observed"], 1)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 0)
            self.assertEqual(metrics["response_packets_sent"], 1)
            self.assertEqual(metrics["last_response"]["destination_slot"], 2)
            self.assertEqual(policy.use_items[2].item_id, 2_030_059)
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid, analysis.issues)
            self.assertEqual(analysis.state.item_acquisition_matches, 1)
            self.assertEqual(
                analysis.state.item_acquisition_quantity_matches,
                1,
            )
            self.assertEqual(
                analysis.state.pending_item_acquisition_requests,
                0,
            )
            acquisition_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("item_acquisition_")
            ]
            self.assertEqual(
                [event.kind for event in acquisition_events],
                [
                    "item_acquisition_request_observed",
                    "item_acquisition_response_completed",
                ],
            )

    async def test_replay_responds_to_modeled_item_pickup_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-item-pickup", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            drop_object_id = 40_004
            spawn = FieldDropSpawn(
                spawn_mode=FieldDropSpawn.FIELD_LOAD_MODE,
                drop_object_id=drop_object_id,
                drop_kind=FieldDropSpawn.ITEM,
                value=4_010_003,
                owner_value_1=300_001,
                owner_value_2=300_001,
                ownership_flag=0,
                position_x=633,
                position_y=-2677,
                source_mob_object_id=0,
                expiration_ticks=150_842_304_000_000_000,
                final_flag=0,
            )
            policy = ItemPickupResponsePolicy(
                inventory_items={
                    "etc": {
                        7: InventoryItemEntity(
                            slot=7,
                            record_type=2,
                            item_id=4_010_003,
                            cash_item=False,
                            expires_at_ticks=150_842_304_000_000_000,
                            quantity=74,
                        )
                    }
                },
                active_drops={
                    drop_object_id: FieldDropEntity(
                        alias="drop:1",
                        spawn=spawn,
                    )
                },
                validated_item_effects={4_010_003: ("etc", 1)},
                field_epoch=1,
            )
            runtime_protocol = {
                "item_pickup_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            item_pickup_response_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            request = ItemPickupRequest(
                control_value=0,
                field_epoch=1,
                client_tick=502_040,
                position_x=633,
                position_y=-2677,
                drop_object_id=drop_object_id,
                item_validation_token=1_352_639_939,
            ).to_bytes()
            writer.write(
                encode_frame_header(len(request), client_iv, 300)
                + crypt_payload(request, client_iv)
            )
            await writer.drain()

            next_server_iv = shuffle_iv(server_iv)
            inventory_wire = await reader.readexactly(14)
            inventory_update = InventoryChangeSet.parse(
                crypt_payload(inventory_wire[4:], next_server_iv)
            )
            self.assertEqual(inventory_update.modifications[0].quantity, 75)
            next_server_iv = shuffle_iv(next_server_iv)
            notice_wire = await reader.readexactly(16)
            notice = PickupGainNotice.parse(
                crypt_payload(notice_wire[4:], next_server_iv)
            )
            self.assertEqual((notice.item_id, notice.quantity), (4_010_003, 1))
            next_server_iv = shuffle_iv(next_server_iv)
            removal_wire = await reader.readexactly(19)
            removal = FieldDropRemoval.parse(
                crypt_payload(removal_wire[4:], next_server_iv)
            )
            self.assertEqual(removal.reason, 5)
            self.assertEqual(removal.actor_id, 300_001)

            compact_request = ItemPickupRequest(
                control_value=None,
                field_epoch=1,
                client_tick=502_041,
                position_x=633,
                position_y=-2677,
                drop_object_id=drop_object_id,
                item_validation_token=0,
                opcode=222,
            ).to_bytes()
            next_client_iv = shuffle_iv(client_iv)
            writer.write(
                encode_frame_header(len(compact_request), next_client_iv, 300)
                + crypt_payload(compact_request, next_client_iv)
            )
            await writer.drain()
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(reader.read(1), timeout=0.02)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

            metrics = runtime_protocol["item_pickup_responses"]
            self.assertEqual(metrics["requests_observed"], 2)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 1)
            self.assertEqual(metrics["response_packets_sent"], 3)
            self.assertEqual(
                metrics["last_rejection"],
                "item-pickup request references an unknown active drop",
            )
            self.assertEqual(policy.inventory_items["etc"][7].quantity, 75)
            self.assertEqual(policy.active_drops, {})
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid)
            self.assertFalse(
                any(
                    "item-pickup requests had no complete" in warning
                    for warning in analysis.warnings
                )
            )
            self.assertEqual(analysis.state.pending_item_pickups, 0)
            self.assertEqual(analysis.state.item_pickup_policy_rejections, 1)
            self.assertEqual(analysis.state.item_pickup_compact_requests, 1)
            pickup_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("item_pickup_")
            ]
            self.assertEqual(
                [event.kind for event in pickup_events],
                [
                    "item_pickup_request_observed",
                    "item_pickup_response_completed",
                    "item_pickup_request_observed",
                    "item_pickup_request_rejected",
                ],
            )
            self.assertEqual(pickup_events[1].details["drop"], "drop:1")
            self.assertEqual(pickup_events[1].details["quantity_after"], 75)
            self.assertEqual(
                pickup_events[1].details["server_opcodes"], [39, 49, 312]
            )
            self.assertEqual(
                pickup_events[-1].details["reason"],
                "item-pickup request references an unknown active drop",
            )

    async def test_replay_delays_before_and_between_post_transcript_frames(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_iv = bytes.fromhex("6e3c795a")
            second_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + first_iv
                + second_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), second_iv, ~300)
                + crypt_payload(captured_plaintext, second_iv)
            )
            source_writer = TranscriptWriter(directory, label="delayed", metadata={})
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            post_transcript_server_frames=(b"first", b"second"),
                            post_transcript_start_delay_seconds=0.05,
                            post_transcript_gap_delays_seconds=(0.05,),
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            started = asyncio.get_running_loop().time()
            first = await reader.readexactly(9)
            self.assertGreaterEqual(
                asyncio.get_running_loop().time() - started,
                0.035,
            )
            first_appended_iv = shuffle_iv(second_iv)
            self.assertEqual(
                crypt_payload(first[4:], first_appended_iv), b"first"
            )
            started = asyncio.get_running_loop().time()
            second = await reader.readexactly(10)
            self.assertGreaterEqual(
                asyncio.get_running_loop().time() - started,
                0.035,
            )
            self.assertEqual(
                crypt_payload(second[4:], shuffle_iv(first_appended_iv)), b"second"
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_queues_reactive_opcode_reply_without_consuming_expected_frame(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_server_plaintext = b"captured"
            captured_server_frame = (
                encode_frame_header(
                    len(captured_server_plaintext), server_iv, ~300
                )
                + crypt_payload(captured_server_plaintext, server_iv)
            )
            captured_client_plaintext = b"\x1f\x00request"
            captured_client_frame = (
                encode_frame_header(
                    len(captured_client_plaintext), client_iv, 300
                )
                + crypt_payload(captured_client_plaintext, client_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="reactive-during-transcript", metadata={}
            )
            source_writer.data("server_to_client", greeting)
            source_writer.data("client_to_server", captured_client_frame)
            source_writer.data("server_to_client", captured_server_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            client_opcode_replies={13: b"\x0d\x00\x00"},
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(await reader.readexactly(len(greeting)), greeting)

            reactive_plaintext = b"\x0d\x00result"
            reactive_frame = (
                encode_frame_header(len(reactive_plaintext), client_iv, 300)
                + crypt_payload(reactive_plaintext, client_iv)
            )
            next_client_iv = shuffle_iv(client_iv)
            live_expected_frame = (
                encode_frame_header(
                    len(captured_client_plaintext), next_client_iv, 300
                )
                + crypt_payload(captured_client_plaintext, next_client_iv)
            )
            writer.write(reactive_frame + live_expected_frame)
            await writer.drain()

            self.assertEqual(
                await reader.readexactly(len(captured_server_frame)),
                captured_server_frame,
            )
            reply = await reader.readexactly(7)
            self.assertEqual(
                crypt_payload(reply[4:], shuffle_iv(server_iv)),
                b"\x0d\x00\x00",
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_replies_to_opcode_arriving_during_hold_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="reactive-hold-open", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            hold_open_seconds=0.2,
                            client_opcode_replies={13: b"ack"},
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            reactive_plaintext = b"\x0d\x00result"
            writer.write(
                encode_frame_header(len(reactive_plaintext), client_iv, 300)
                + crypt_payload(reactive_plaintext, client_iv)
            )
            await writer.drain()
            reply = await reader.readexactly(7)
            self.assertEqual(
                crypt_payload(reply[4:], shuffle_iv(server_iv)), b"ack"
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_responds_to_modeled_mob_damage_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-mob-health", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            object_id = 20_001
            policy = MobHealthResponsePolicy(
                mobs={
                    object_id: ReactiveMobHealth(
                        alias="mob:1",
                        template_id=210_100,
                        current_hp=50,
                        max_hp=50,
                    )
                },
                field_epoch=1,
            )
            movement_policy = MobMovementAcknowledgementPolicy(
                status_values_by_template={210_100: 35},
                observations_by_template={210_100: 4_728},
                known_mob_templates={object_id: 210_100},
                field_epoch=1,
                matched_pairs=11_949,
                known_template_pairs=11_949,
                unknown_template_pairs=0,
                flag_rule_matches=11_949,
                zero_auxiliary_pairs=11_949,
                pending_submissions=0,
                active_mob_object_ids={object_id},
            )
            runtime_protocol = {
                "mob_health_responses": {
                    "requests_observed": 0,
                    "requests_served": 0,
                    "requests_rejected": 0,
                    "response_packets_sent": 0,
                },
                "mob_movement_acknowledgements": {
                    "submissions_observed": 0,
                    "responses_sent": 0,
                    "submissions_rejected": 0,
                    "state": movement_policy.safe_dict(),
                },
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            mob_health_response_policy=policy,
                            mob_movement_acknowledgement_policy=movement_policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            attack = ClientAttackAction(
                opcode=52,
                local_object_index=1,
                variant=18,
                client_token=987_654_321,
                control_value=0,
                common_state=ClientAttackCommonState(0, 5, 0, 1, 4),
                value_1=3,
                value_2=object_id,
                target_state=ClientAttackTargetState(
                    value_1=6,
                    value_2=0,
                    value_3=0,
                    value_4=1,
                    position_1_x=10,
                    position_1_y=20,
                    position_2_x=11,
                    position_2_y=21,
                    trailing_value=393,
                    raw_damage_values=(40, 10),
                    reserved_zero=0,
                    final_position_x=12,
                    final_position_y=22,
                    opcode_52_reserved_zero=0,
                ),
                compact_reserved_zero=None,
            ).to_bytes()
            writer.write(
                encode_frame_header(len(attack), client_iv, 300)
                + crypt_payload(attack, client_iv)
            )
            await writer.drain()

            response_iv = shuffle_iv(server_iv)
            first_wire = await reader.readexactly(11)
            first_update = MobHealthPercentageUpdate.parse(
                crypt_payload(first_wire[4:], response_iv)
            )
            self.assertEqual(first_update.object_id, object_id)
            self.assertEqual(first_update.health_percentage, 20)
            response_iv = shuffle_iv(response_iv)
            second_wire = await reader.readexactly(11)
            second_update = MobHealthPercentageUpdate.parse(
                crypt_payload(second_wire[4:], response_iv)
            )
            self.assertEqual(second_update.health_percentage, 0)
            response_iv = shuffle_iv(response_iv)
            leave_wire = await reader.readexactly(11)
            leave = MobLeaveField.parse(
                crypt_payload(leave_wire[4:], response_iv)
            )
            self.assertEqual(leave.object_id, object_id)
            self.assertEqual(leave.reason, 1)

            untargeted_attack = ClientAttackAction(
                opcode=52,
                local_object_index=1,
                variant=2,
                client_token=987_654_322,
                control_value=0,
                common_state=ClientAttackCommonState(0, 5, 0, 1, 4),
                value_1=3,
                value_2=0,
                target_state=None,
                compact_reserved_zero=0,
            ).to_bytes()
            next_client_iv = shuffle_iv(client_iv)
            writer.write(
                encode_frame_header(len(untargeted_attack), next_client_iv, 300)
                + crypt_payload(untargeted_attack, next_client_iv)
            )
            await writer.drain()
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(reader.read(1), timeout=0.02)

            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()
            metrics = runtime_protocol["mob_health_responses"]
            self.assertEqual(metrics["requests_observed"], 2)
            self.assertEqual(metrics["requests_served"], 1)
            self.assertEqual(metrics["requests_rejected"], 1)
            self.assertEqual(metrics["response_packets_sent"], 3)
            self.assertEqual(
                metrics["last_response"]["server_opcodes"], [293, 293, 280]
            )
            self.assertEqual(
                metrics["last_rejection"],
                "client attack has no modeled mob target",
            )
            self.assertEqual(metrics["state"]["active_mobs"], [])
            self.assertNotIn(object_id, policy.mobs)
            movement_metrics = runtime_protocol[
                "mob_movement_acknowledgements"
            ]
            self.assertEqual(
                movement_metrics["state"]["active_known_mob_count"], 0
            )
            self.assertEqual(
                movement_policy.known_mob_templates[object_id], 210_100
            )
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid)
            health_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind.startswith("mob_health_")
            ]
            self.assertEqual(
                [event.kind for event in health_events],
                [
                    "mob_health_request_observed",
                    "mob_health_response_completed",
                    "mob_health_request_observed",
                    "mob_health_request_rejected",
                ],
            )
            response_event = health_events[1]
            self.assertEqual(response_event.direction, "runtime")
            self.assertEqual(response_event.details["target"], "mob:1")
            self.assertEqual(response_event.details["hp_after"], 0)
            self.assertTrue(response_event.details["removed"])
            self.assertEqual(
                response_event.details["server_opcodes"], [293, 293, 280]
            )
            self.assertEqual(
                health_events[-1].details["reason"],
                "client attack has no modeled mob target",
            )

    async def test_replay_paces_and_replans_queued_mob_decision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="paced-mob-schedule", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            object_id = 20_001

            def broadcast(
                reference_x: int,
                target_x: int,
                stance: int,
            ) -> MobMovementBroadcast:
                return MobMovementBroadcast(
                    object_id=object_id,
                    control_flag_1=False,
                    control_flag_2=False,
                    control_selector=0xFF,
                    control_value=0,
                    reference_x=reference_x,
                    reference_y=-200,
                    commands=(
                        MobMovementCommand.absolute(
                            position_x=target_x,
                            position_y=-200,
                            velocity_x=50,
                            velocity_y=0,
                            foothold_id=7,
                            stance=stance,
                            duration_ms=1_080,
                        ),
                    ),
                )

            first_broadcast = broadcast(100, 150, 2)
            second_broadcast = broadcast(150, 200, 4)
            first_plan = fixture_mob_movement_broadcast_plan(
                first_broadcast,
                previous_x=100,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=3,
                target_x=150,
                target_y=-200,
                target_foothold_id=7,
                target_stance=2,
                source_server_frame_index=10,
            )
            second_plan = fixture_mob_movement_broadcast_plan(
                second_broadcast,
                previous_x=150,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=2,
                target_x=200,
                target_y=-200,
                target_foothold_id=7,
                target_stance=4,
                source_server_frame_index=11,
            )
            runtime_protocol = {"mob_movement_broadcast": {}}
            tasks: set[asyncio.Task[None]] = set()
            follow_up_plan = MobMovementBroadcastSequencePlan(
                steps=(second_plan,),
                max_steps=2,
                usable_displacements=1,
                ambiguous_displacements=0,
                shortest_sequence_count=1,
            )
            planner_started = threading.Event()
            release_planner = threading.Event()

            def delayed_follow_up_plan(*args, **kwargs):
                planner_started.set()
                if not release_planner.wait(timeout=1):
                    raise TimeoutError("test did not release follow-up planner")
                return follow_up_plan

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            post_transcript_server_frames=(
                                first_broadcast.to_bytes(),
                            ),
                            mob_movement_broadcast_plans=(
                                first_plan,
                            ),
                            mob_movement_follow_up_targets=(
                                (2, 200, -200, 7),
                            ),
                            mob_movement_evidence_transcript=source,
                            mob_movement_step_delay_seconds=0.08,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            with patch(
                "maple_server.gameplay.plan_composed_mob_movement_broadcasts",
                side_effect=delayed_follow_up_plan,
            ) as planner:
                server = await asyncio.start_server(
                    accept, "127.0.0.1", 0
                )
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                self.assertEqual(
                    await reader.readexactly(len(greeting + captured_frame)),
                    greeting + captured_frame,
                )
                started = asyncio.get_running_loop().time()
                first_wire = await reader.readexactly(
                    len(first_broadcast.to_bytes()) + 4
                )
                first_iv = shuffle_iv(server_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(first_wire[4:], first_iv)
                    ),
                    first_broadcast,
                )
                self.assertTrue(
                    await asyncio.to_thread(planner_started.wait, 0.5)
                )
                await asyncio.sleep(0.01)
                planning = runtime_protocol["mob_movement_broadcast"]
                self.assertEqual(planning["packets_sent"], 1)
                self.assertEqual(planning["packets_remaining"], 0)
                self.assertEqual(planning["state"]["phase"], "planning")
                self.assertEqual(
                    planning["state"]["decision_queue"][
                        "planning_decision_index"
                    ],
                    2,
                )
                release_planner.set()
                for _ in range(10):
                    movement_runtime = runtime_protocol[
                        "mob_movement_broadcast"
                    ]
                    if movement_runtime.get("packets_planned") == 2:
                        break
                    await asyncio.sleep(0.005)
                in_progress = runtime_protocol["mob_movement_broadcast"]
                self.assertEqual(in_progress["packets_planned"], 2)
                self.assertEqual(in_progress["packets_sent"], 1)
                self.assertEqual(in_progress["packets_remaining"], 1)
                self.assertEqual(
                    in_progress["state"]["phase"], "in_progress"
                )
                self.assertEqual(
                    in_progress["state"]["current"],
                    {
                        "x": 150,
                        "y": -200,
                        "foothold_id": 7,
                        "stance": 2,
                    },
                )
                self.assertEqual(
                    in_progress["state"]["next_step"]["step_index"], 2
                )
                self.assertEqual(
                    in_progress["state"]["next_step"]["decision_index"],
                    2,
                )
                self.assertEqual(
                    in_progress["state"]["decision_queue"][
                        "decisions_planned"
                    ],
                    2,
                )
                planner.assert_called_once()
                self.assertEqual(
                    planner.call_args.kwargs[
                        "post_transcript_server_frames"
                    ],
                    (first_broadcast.to_bytes(),),
                )

                second_wire = await reader.readexactly(
                    len(second_broadcast.to_bytes()) + 4
                )
                self.assertGreaterEqual(
                    asyncio.get_running_loop().time() - started,
                    0.055,
                )
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(second_wire[4:], shuffle_iv(first_iv))
                    ),
                    second_broadcast,
                )
                writer.close()
                await writer.wait_closed()
                await asyncio.gather(*tasks)
                server.close()
                await server.wait_closed()
            complete = runtime_protocol["mob_movement_broadcast"]
            self.assertEqual(complete["packets_sent"], 2)
            self.assertEqual(complete["packets_remaining"], 0)
            self.assertEqual(complete["state"]["phase"], "complete")
            self.assertEqual(
                complete["state"]["current"],
                {
                    "x": 200,
                    "y": -200,
                    "foothold_id": 7,
                    "stance": 4,
                },
            )
            self.assertEqual(complete["state"]["next_step"], None)

    async def test_relative_mob_policy_enforces_heartbeat_event_budget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="heartbeat-gated-mob", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            object_id = 20_001

            def broadcast(reference_x: int, target_x: int, stance: int):
                return MobMovementBroadcast(
                    object_id=object_id,
                    control_flag_1=False,
                    control_flag_2=False,
                    control_selector=0xFF,
                    control_value=0,
                    reference_x=reference_x,
                    reference_y=-200,
                    commands=(
                        MobMovementCommand.absolute(
                            position_x=target_x,
                            position_y=-200,
                            velocity_x=50,
                            velocity_y=0,
                            foothold_id=7,
                            stance=stance,
                            duration_ms=1_080,
                        ),
                    ),
                )

            first_broadcast = broadcast(100, 150, 2)
            second_broadcast = broadcast(150, 200, 4)
            first_plan = fixture_mob_movement_broadcast_plan(
                first_broadcast,
                previous_x=100,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=3,
                target_x=150,
                target_y=-200,
                target_foothold_id=7,
                target_stance=2,
                source_server_frame_index=10,
            )
            second_plan = fixture_mob_movement_broadcast_plan(
                second_broadcast,
                previous_x=150,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=2,
                target_x=200,
                target_y=-200,
                target_foothold_id=7,
                target_stance=4,
                source_server_frame_index=11,
            )
            follow_up_plan = MobMovementBroadcastSequencePlan(
                steps=(second_plan,),
                max_steps=2,
                usable_displacements=1,
                ambiguous_displacements=0,
                shortest_sequence_count=1,
            )
            relative_policy = MobMovementRelativeDecisionPolicy(
                decision_count=2,
                max_steps=2,
                displacement_x=50,
                displacement_y=0,
                foothold_id=7,
            )
            runtime_protocol = {
                "world_heartbeat": {
                    "probes_sent": 0,
                    "responses_observed": 0,
                    "pending": 0,
                },
                "mob_movement_broadcast": {
                    "policy_trigger": {
                        "mode": "matched_heartbeat",
                        "awaiting_event": False,
                        "matched_events_observed": 0,
                        "decisions_started": 0,
                        "decisions_completed": 0,
                        "events_ignored_after_completion": 0,
                    }
                },
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            post_transcript_server_frames=(
                                first_broadcast.to_bytes(),
                            ),
                            mob_movement_broadcast_plans=(first_plan,),
                            mob_movement_follow_up_policy=relative_policy,
                            mob_movement_evidence_transcript=source,
                            mob_movement_policy_trigger="matched_heartbeat",
                            mob_movement_policy_event_budget=1,
                            hold_open_seconds=0.2,
                            world_heartbeat_interval_seconds=0.05,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            with patch(
                "maple_server.gameplay.plan_composed_mob_movement_broadcasts",
                return_value=follow_up_plan,
            ) as planner:
                server = await asyncio.start_server(
                    accept, "127.0.0.1", 0
                )
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                self.assertEqual(
                    await reader.readexactly(len(greeting + captured_frame)),
                    greeting + captured_frame,
                )
                first_wire = await reader.readexactly(
                    len(first_broadcast.to_bytes()) + 4
                )
                first_iv = shuffle_iv(server_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(first_wire[4:], first_iv)
                    ),
                    first_broadcast,
                )
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(reader.read(1), timeout=0.02)
                self.assertEqual(
                    runtime_protocol["mob_movement_broadcast"][
                        "packets_sent"
                    ],
                    1,
                )
                self.assertTrue(
                    runtime_protocol["mob_movement_broadcast"][
                        "policy_trigger"
                    ]["awaiting_event"]
                )
                planner.assert_not_called()

                heartbeat_wire = await reader.readexactly(6)
                heartbeat_iv = shuffle_iv(first_iv)
                self.assertEqual(
                    HeartbeatProbe.parse(
                        crypt_payload(heartbeat_wire[4:], heartbeat_iv)
                    ),
                    HeartbeatProbe(),
                )
                response = HeartbeatResponse(
                    response_value=int.from_bytes(b"policy!!", "little")
                ).to_bytes()
                writer.write(
                    encode_frame_header(len(response), client_iv, 300)
                    + crypt_payload(response, client_iv)
                )
                await writer.drain()

                follow_wire = await reader.readexactly(
                    len(second_broadcast.to_bytes()) + 4
                )
                follow_iv = shuffle_iv(heartbeat_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(follow_wire[4:], follow_iv)
                    ),
                    second_broadcast,
                )
                planner.assert_called_once()

                second_heartbeat_wire = await reader.readexactly(6)
                second_heartbeat_iv = shuffle_iv(follow_iv)
                self.assertEqual(
                    HeartbeatProbe.parse(
                        crypt_payload(
                            second_heartbeat_wire[4:],
                            second_heartbeat_iv,
                        )
                    ),
                    HeartbeatProbe(),
                )
                second_response_iv = shuffle_iv(client_iv)
                writer.write(
                    encode_frame_header(
                        len(response), second_response_iv, 300
                    )
                    + crypt_payload(response, second_response_iv)
                )
                await writer.drain()
                await asyncio.sleep(0.01)
                trigger_metrics = runtime_protocol[
                    "mob_movement_broadcast"
                ]["policy_trigger"]
                self.assertEqual(trigger_metrics["matched_events_observed"], 2)
                self.assertFalse(trigger_metrics["awaiting_event"])
                self.assertEqual(
                    trigger_metrics["last_event_outcome"],
                    "rejected_by_event_budget",
                )
                planner.assert_called_once()
                writer.close()
                await writer.wait_closed()
                await asyncio.gather(*tasks)
                server.close()
                await server.wait_closed()

            movement_metrics = runtime_protocol["mob_movement_broadcast"]
            self.assertEqual(movement_metrics["packets_sent"], 2)
            self.assertEqual(movement_metrics["state"]["phase"], "planning")
            trigger_metrics = movement_metrics["policy_trigger"]
            self.assertFalse(trigger_metrics["awaiting_event"])
            self.assertEqual(trigger_metrics["matched_events_observed"], 2)
            self.assertEqual(trigger_metrics["decisions_started"], 1)
            self.assertEqual(trigger_metrics["decisions_completed"], 1)
            self.assertEqual(trigger_metrics["event_budget"], 1)
            self.assertEqual(trigger_metrics["event_budget_used"], 1)
            self.assertEqual(trigger_metrics["event_budget_remaining"], 0)
            self.assertEqual(trigger_metrics["events_rejected_by_budget"], 1)
            self.assertEqual(
                trigger_metrics["last_event_outcome"],
                "rejected_by_event_budget",
            )
            self.assertEqual(
                trigger_metrics["events_ignored_after_completion"], 0
            )
            observed_path = next(observed_directory.glob("*.jsonl"))
            analysis = analyze_gameplay_transcript(
                Transcript.load(observed_path)
            )
            budget_rejection = next(
                event
                for event in analysis.events
                if event.kind == "mob_movement_policy_trigger_rejected"
            )
            self.assertEqual(
                budget_rejection.details,
                {
                    "trigger": "matched_heartbeat",
                    "reason": "event_budget",
                    "event_budget": 1,
                    "event_budget_remaining": 0,
                    "cooldown_remaining_seconds": 0.0,
                },
            )

    async def test_relative_mob_policy_waits_for_served_mob_movement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="served-mob-trigger", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            object_id = 20_001
            template_id = 210_100
            controller = MobControllerChange(
                control_level=1,
                object_id=object_id,
                spawn=MobSpawnData(
                    spawn_marker=1,
                    template_id=template_id,
                    temporary_status=MobSpawnTemporaryStatus(),
                    x=100,
                    y=-200,
                    stance=3,
                    foothold_id=7,
                    origin_foothold_id=7,
                    appear_type=-1,
                    team=0xFF,
                    effect_item_id=0,
                ),
            ).to_bytes()

            def broadcast(reference_x: int, target_x: int, stance: int):
                return MobMovementBroadcast(
                    object_id=object_id,
                    control_flag_1=False,
                    control_flag_2=False,
                    control_selector=0xFF,
                    control_value=0,
                    reference_x=reference_x,
                    reference_y=-200,
                    commands=(
                        MobMovementCommand.absolute(
                            position_x=target_x,
                            position_y=-200,
                            velocity_x=50,
                            velocity_y=0,
                            foothold_id=7,
                            stance=stance,
                            duration_ms=1_080,
                        ),
                    ),
                )

            first_broadcast = broadcast(100, 150, 2)
            second_broadcast = broadcast(150, 200, 4)
            first_plan = fixture_mob_movement_broadcast_plan(
                first_broadcast,
                previous_x=100,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=3,
                target_x=150,
                target_y=-200,
                target_foothold_id=7,
                target_stance=2,
                source_server_frame_index=10,
            )
            second_plan = fixture_mob_movement_broadcast_plan(
                second_broadcast,
                previous_x=150,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=2,
                target_x=200,
                target_y=-200,
                target_foothold_id=7,
                target_stance=4,
                source_server_frame_index=11,
            )
            follow_up_plan = MobMovementBroadcastSequencePlan(
                steps=(second_plan,),
                max_steps=2,
                usable_displacements=1,
                ambiguous_displacements=0,
                shortest_sequence_count=1,
            )
            relative_policy = MobMovementRelativeDecisionPolicy(
                decision_count=1,
                max_steps=2,
                displacement_x=50,
                displacement_y=0,
                foothold_id=7,
            )
            acknowledgement_policy = MobMovementAcknowledgementPolicy(
                status_values_by_template={template_id: 35},
                observations_by_template={template_id: 4_728},
                known_mob_templates={},
                field_epoch=1,
                matched_pairs=11_949,
                known_template_pairs=11_949,
                unknown_template_pairs=0,
                flag_rule_matches=11_949,
                zero_auxiliary_pairs=11_949,
                pending_submissions=0,
            )
            runtime_protocol = {
                "mob_movement_acknowledgements": {
                    "submissions_observed": 0,
                    "responses_sent": 0,
                    "submissions_rejected": 0,
                },
                "mob_movement_broadcast": {
                    "policy_trigger": {
                        "mode": "served_mob_movement",
                        "awaiting_event": False,
                        "matched_events_observed": 0,
                        "decisions_started": 0,
                        "decisions_completed": 0,
                        "events_ignored_after_completion": 0,
                    }
                },
            }
            tasks: set[asyncio.Task[None]] = set()
            third_broadcast = broadcast(200, 250, 2)
            third_plan = fixture_mob_movement_broadcast_plan(
                third_broadcast,
                previous_x=200,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=4,
                target_x=250,
                target_y=-200,
                target_foothold_id=7,
                target_stance=2,
                source_server_frame_index=12,
            )
            second_follow_up_plan = MobMovementBroadcastSequencePlan(
                steps=(third_plan,),
                max_steps=2,
                usable_displacements=1,
                ambiguous_displacements=0,
                shortest_sequence_count=1,
            )
            relative_policy = MobMovementRelativeDecisionPolicy(
                decision_count=2,
                max_steps=2,
                displacement_x=50,
                displacement_y=0,
                foothold_id=7,
            )

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            post_transcript_server_frames=(
                                controller,
                                first_broadcast.to_bytes(),
                            ),
                            mob_movement_broadcast_plans=(first_plan,),
                            mob_movement_baseline_server_frames=(controller,),
                            mob_movement_follow_up_policy=relative_policy,
                            mob_movement_policy_trigger=(
                                "served_mob_movement"
                            ),
                            mob_movement_policy_cooldown_seconds=0.05,
                            mob_movement_evidence_transcript=source,
                            mob_movement_acknowledgement_policy=(
                                acknowledgement_policy
                            ),
                            hold_open_seconds=0.4,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            with patch(
                "maple_server.gameplay.plan_composed_mob_movement_broadcasts",
                side_effect=(follow_up_plan, second_follow_up_plan),
            ) as planner:
                server = await asyncio.start_server(
                    accept, "127.0.0.1", 0
                )
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                self.assertEqual(
                    await reader.readexactly(len(greeting + captured_frame)),
                    greeting + captured_frame,
                )
                controller_wire = await reader.readexactly(len(controller) + 4)
                controller_iv = shuffle_iv(server_iv)
                self.assertEqual(
                    MobControllerChange.parse(
                        crypt_payload(controller_wire[4:], controller_iv)
                    ).object_id,
                    object_id,
                )
                first_wire = await reader.readexactly(
                    len(first_broadcast.to_bytes()) + 4
                )
                first_iv = shuffle_iv(controller_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(first_wire[4:], first_iv)
                    ),
                    first_broadcast,
                )
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(reader.read(1), timeout=0.02)
                planner.assert_not_called()
                self.assertTrue(
                    runtime_protocol["mob_movement_broadcast"][
                        "policy_trigger"
                    ]["awaiting_event"]
                )

                movement_path = MobMovementPath(
                    opaque_control=b"\x01" + b"\x00" * 18,
                    reference_x=100,
                    reference_y=-200,
                    commands=(
                        MobMovementCommand.absolute(
                            position_x=110,
                            position_y=-200,
                            velocity_x=10,
                            velocity_y=0,
                            foothold_id=7,
                            stance=2,
                            duration_ms=90,
                        ),
                    ),
                    trailer_marker=0,
                    path_start_x=90,
                    path_start_y=-200,
                    path_end_x=110,
                    path_end_y=-200,
                )
                rejected_submission = MobMovementSubmission(
                    object_id=object_id + 1,
                    sequence=41,
                    opaque_movement=movement_path.to_bytes(),
                ).to_bytes()
                writer.write(
                    encode_frame_header(
                        len(rejected_submission), client_iv, 300
                    )
                    + crypt_payload(rejected_submission, client_iv)
                )
                await writer.drain()
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(reader.read(1), timeout=0.02)
                planner.assert_not_called()
                self.assertEqual(
                    runtime_protocol["mob_movement_broadcast"][
                        "policy_trigger"
                    ]["matched_events_observed"],
                    0,
                )

                submission = MobMovementSubmission(
                    object_id=object_id,
                    sequence=42,
                    opaque_movement=movement_path.to_bytes(),
                ).to_bytes()
                accepted_client_iv = shuffle_iv(client_iv)
                writer.write(
                    encode_frame_header(
                        len(submission), accepted_client_iv, 300
                    )
                    + crypt_payload(submission, accepted_client_iv)
                )
                await writer.drain()

                acknowledgement_wire = await reader.readexactly(17)
                acknowledgement_iv = shuffle_iv(first_iv)
                acknowledgement = MobMovementAcknowledgement.parse(
                    crypt_payload(
                        acknowledgement_wire[4:], acknowledgement_iv
                    )
                )
                self.assertEqual(acknowledgement.object_id, object_id)
                self.assertEqual(acknowledgement.sequence, 42)
                follow_wire = await reader.readexactly(
                    len(second_broadcast.to_bytes()) + 4
                )
                follow_iv = shuffle_iv(acknowledgement_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(follow_wire[4:], follow_iv)
                    ),
                    second_broadcast,
                )
                planner.assert_called_once()

                cooldown_submission = MobMovementSubmission(
                    object_id=object_id,
                    sequence=43,
                    opaque_movement=movement_path.to_bytes(),
                ).to_bytes()
                cooldown_client_iv = shuffle_iv(accepted_client_iv)
                writer.write(
                    encode_frame_header(
                        len(cooldown_submission), cooldown_client_iv, 300
                    )
                    + crypt_payload(cooldown_submission, cooldown_client_iv)
                )
                await writer.drain()
                cooldown_ack_wire = await reader.readexactly(17)
                cooldown_ack_iv = shuffle_iv(follow_iv)
                self.assertEqual(
                    MobMovementAcknowledgement.parse(
                        crypt_payload(
                            cooldown_ack_wire[4:], cooldown_ack_iv
                        )
                    ).sequence,
                    43,
                )
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(reader.read(1), timeout=0.02)
                planner.assert_called_once()
                trigger_metrics = runtime_protocol[
                    "mob_movement_broadcast"
                ]["policy_trigger"]
                self.assertTrue(trigger_metrics["awaiting_event"])
                self.assertEqual(
                    trigger_metrics["events_rejected_by_cooldown"], 1
                )
                self.assertEqual(
                    trigger_metrics["last_event_outcome"],
                    "rejected_by_cooldown",
                )
                self.assertGreater(
                    trigger_metrics["last_cooldown_remaining_seconds"], 0
                )

                await asyncio.sleep(0.06)
                rearmed_submission = MobMovementSubmission(
                    object_id=object_id,
                    sequence=44,
                    opaque_movement=movement_path.to_bytes(),
                ).to_bytes()
                rearmed_client_iv = shuffle_iv(cooldown_client_iv)
                writer.write(
                    encode_frame_header(
                        len(rearmed_submission), rearmed_client_iv, 300
                    )
                    + crypt_payload(rearmed_submission, rearmed_client_iv)
                )
                await writer.drain()
                rearmed_ack_wire = await reader.readexactly(17)
                rearmed_ack_iv = shuffle_iv(cooldown_ack_iv)
                self.assertEqual(
                    MobMovementAcknowledgement.parse(
                        crypt_payload(rearmed_ack_wire[4:], rearmed_ack_iv)
                    ).sequence,
                    44,
                )
                third_wire = await reader.readexactly(
                    len(third_broadcast.to_bytes()) + 4
                )
                third_iv = shuffle_iv(rearmed_ack_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(third_wire[4:], third_iv)
                    ),
                    third_broadcast,
                )
                self.assertEqual(planner.call_count, 2)
                writer.close()
                await writer.wait_closed()
                await asyncio.gather(*tasks)
                server.close()
                await server.wait_closed()

            acknowledgement_metrics = runtime_protocol[
                "mob_movement_acknowledgements"
            ]
            self.assertEqual(
                acknowledgement_metrics["submissions_observed"], 4
            )
            self.assertEqual(acknowledgement_metrics["responses_sent"], 3)
            self.assertEqual(
                acknowledgement_metrics["submissions_rejected"], 1
            )
            movement_metrics = runtime_protocol["mob_movement_broadcast"]
            self.assertEqual(movement_metrics["packets_sent"], 3)
            self.assertEqual(movement_metrics["state"]["phase"], "complete")
            trigger_metrics = movement_metrics["policy_trigger"]
            self.assertFalse(trigger_metrics["awaiting_event"])
            self.assertEqual(trigger_metrics["matched_events_observed"], 3)
            self.assertEqual(trigger_metrics["decisions_started"], 2)
            self.assertEqual(trigger_metrics["decisions_completed"], 2)
            self.assertEqual(trigger_metrics["cooldown_seconds"], 0.05)
            self.assertEqual(
                trigger_metrics["events_rejected_by_cooldown"], 1
            )
            self.assertEqual(
                trigger_metrics["last_event_outcome"],
                "decision_completed",
            )
            self.assertEqual(
                trigger_metrics["events_ignored_after_completion"], 0
            )
            observed_path = next(observed_directory.glob("*.jsonl"))
            analysis = analyze_gameplay_transcript(
                Transcript.load(observed_path)
            )
            policy_events = [
                event
                for event in analysis.events
                if event.kind.startswith("mob_movement_policy_")
            ]
            self.assertEqual(
                [event.kind for event in policy_events],
                [
                    "mob_movement_policy_trigger_observed",
                    "mob_movement_policy_decision_started",
                    "mob_movement_policy_decision_completed",
                    "mob_movement_policy_trigger_observed",
                    "mob_movement_policy_trigger_rejected",
                    "mob_movement_policy_trigger_observed",
                    "mob_movement_policy_decision_started",
                    "mob_movement_policy_decision_completed",
                ],
            )
            self.assertTrue(
                all(event.direction == "runtime" for event in policy_events)
            )
            self.assertEqual(
                [
                    event.details["decision_index"]
                    for event in policy_events
                    if event.kind
                    == "mob_movement_policy_decision_completed"
                ],
                [2, 3],
            )
            rejected_event = next(
                event
                for event in policy_events
                if event.kind == "mob_movement_policy_trigger_rejected"
            )
            self.assertEqual(rejected_event.details["reason"], "cooldown")
            self.assertGreater(
                rejected_event.details["cooldown_remaining_seconds"], 0
            )
            acknowledgement_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind
                in {
                    "mob_movement_submission_observed",
                    "mob_movement_acknowledgement_completed",
                    "mob_movement_submission_rejected",
                }
            ]
            self.assertEqual(
                [event.kind for event in acknowledgement_events],
                [
                    "mob_movement_submission_observed",
                    "mob_movement_submission_rejected",
                    "mob_movement_submission_observed",
                    "mob_movement_acknowledgement_completed",
                    "mob_movement_submission_observed",
                    "mob_movement_acknowledgement_completed",
                    "mob_movement_submission_observed",
                    "mob_movement_acknowledgement_completed",
                ],
            )
            self.assertFalse(
                acknowledgement_events[0].details["target_known"]
            )
            self.assertEqual(
                acknowledgement_events[1].details["reason"],
                "movement submission has no explicit field-local "
                "mob-template state",
            )
            self.assertEqual(
                [
                    event.details["sequence"]
                    for event in acknowledgement_events
                    if event.kind
                    == "mob_movement_acknowledgement_completed"
                ],
                [42, 43, 44],
            )

    async def test_relative_mob_policy_waits_for_player_proximity_entry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="player-proximity-trigger", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            object_id = 20_001

            def broadcast(reference_x: int, target_x: int, stance: int):
                return MobMovementBroadcast(
                    object_id=object_id,
                    control_flag_1=False,
                    control_flag_2=False,
                    control_selector=0xFF,
                    control_value=0,
                    reference_x=reference_x,
                    reference_y=-200,
                    commands=(
                        MobMovementCommand.absolute(
                            position_x=target_x,
                            position_y=-200,
                            velocity_x=50,
                            velocity_y=0,
                            foothold_id=7,
                            stance=stance,
                            duration_ms=1_080,
                        ),
                    ),
                )

            def player_submission(path_end_x: int) -> bytes:
                return PlayerMovementSubmission(
                    control_value=0,
                    movement=PlayerMovementPath(
                        reference_x=path_end_x,
                        reference_y=-200,
                        commands=(
                            PlayerMovementCommand.absolute(
                                position_x=path_end_x,
                                position_y=-200,
                                velocity_x=0,
                                velocity_y=0,
                                foothold_id=7,
                                stance=4,
                                duration_ms=100,
                            ),
                        ),
                    ),
                    trailer_marker=0,
                    path_start_x=path_end_x,
                    path_start_y=-200,
                    path_end_x=path_end_x,
                    path_end_y=-200,
                ).to_bytes()

            first_broadcast = broadcast(100, 150, 2)
            second_broadcast = broadcast(150, 200, 4)
            first_plan = fixture_mob_movement_broadcast_plan(
                first_broadcast,
                previous_x=100,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=3,
                target_x=150,
                target_y=-200,
                target_foothold_id=7,
                target_stance=2,
                source_server_frame_index=10,
            )
            second_plan = fixture_mob_movement_broadcast_plan(
                second_broadcast,
                previous_x=150,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=2,
                target_x=200,
                target_y=-200,
                target_foothold_id=7,
                target_stance=4,
                source_server_frame_index=11,
            )
            follow_up_plan = MobMovementBroadcastSequencePlan(
                steps=(second_plan,),
                max_steps=2,
                usable_displacements=1,
                ambiguous_displacements=0,
                shortest_sequence_count=1,
            )
            relative_policy = MobMovementRelativeDecisionPolicy(
                decision_count=1,
                max_steps=2,
                displacement_x=50,
                displacement_y=0,
                foothold_id=7,
            )
            runtime_protocol = {
                "mob_movement_broadcast": {
                    "policy_trigger": {
                        "mode": "player_proximity",
                        "awaiting_event": False,
                        "matched_events_observed": 0,
                        "decisions_started": 0,
                        "decisions_completed": 0,
                        "events_ignored_after_completion": 0,
                        "proximity": None,
                    }
                }
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            post_transcript_server_frames=(
                                first_broadcast.to_bytes(),
                            ),
                            mob_movement_broadcast_plans=(first_plan,),
                            mob_movement_follow_up_policy=relative_policy,
                            mob_movement_policy_trigger="player_proximity",
                            mob_movement_proximity_radius=10,
                            mob_movement_evidence_transcript=source,
                            hold_open_seconds=0.2,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            with patch(
                "maple_server.gameplay.plan_composed_mob_movement_broadcasts",
                return_value=follow_up_plan,
            ) as planner:
                server = await asyncio.start_server(
                    accept, "127.0.0.1", 0
                )
                port = server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", port
                )
                self.assertEqual(
                    await reader.readexactly(len(greeting + captured_frame)),
                    greeting + captured_frame,
                )
                first_wire = await reader.readexactly(
                    len(first_broadcast.to_bytes()) + 4
                )
                first_iv = shuffle_iv(server_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(first_wire[4:], first_iv)
                    ),
                    first_broadcast,
                )
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(reader.read(1), timeout=0.02)
                planner.assert_not_called()

                outside = player_submission(0)
                writer.write(
                    encode_frame_header(len(outside), client_iv, 300)
                    + crypt_payload(outside, client_iv)
                )
                await writer.drain()
                for _ in range(20):
                    if (
                        runtime_protocol["mob_movement_broadcast"][
                            "policy_trigger"
                        ]["proximity"]["events_observed"]
                        == 1
                    ):
                        break
                    await asyncio.sleep(0.005)
                completed_tasks = [task for task in tasks if task.done()]
                self.assertFalse(
                    completed_tasks,
                    [repr(task.exception()) for task in completed_tasks],
                )
                with self.assertRaises(TimeoutError):
                    await asyncio.wait_for(reader.read(1), timeout=0.02)
                planner.assert_not_called()
                trigger_metrics = runtime_protocol[
                    "mob_movement_broadcast"
                ]["policy_trigger"]
                self.assertTrue(trigger_metrics["awaiting_event"])
                self.assertEqual(trigger_metrics["matched_events_observed"], 0)
                self.assertEqual(
                    trigger_metrics["proximity"]["events_observed"],
                    1,
                )
                self.assertEqual(
                    trigger_metrics["proximity"]["entries_observed"], 0
                )
                self.assertEqual(
                    trigger_metrics["proximity"]["last_observation"][
                        "manhattan_distance"
                    ],
                    150,
                )

                inside = player_submission(145)
                next_client_iv = shuffle_iv(client_iv)
                writer.write(
                    encode_frame_header(len(inside), next_client_iv, 300)
                    + crypt_payload(inside, next_client_iv)
                )
                await writer.drain()
                follow_wire = await reader.readexactly(
                    len(second_broadcast.to_bytes()) + 4
                )
                follow_iv = shuffle_iv(first_iv)
                self.assertEqual(
                    MobMovementBroadcast.parse(
                        crypt_payload(follow_wire[4:], follow_iv)
                    ),
                    second_broadcast,
                )
                planner.assert_called_once()
                writer.close()
                await writer.wait_closed()
                await asyncio.gather(*tasks)
                server.close()
                await server.wait_closed()

            movement_metrics = runtime_protocol["mob_movement_broadcast"]
            self.assertEqual(movement_metrics["packets_sent"], 2)
            self.assertEqual(movement_metrics["state"]["phase"], "complete")
            trigger_metrics = movement_metrics["policy_trigger"]
            self.assertFalse(trigger_metrics["awaiting_event"])
            self.assertEqual(trigger_metrics["matched_events_observed"], 1)
            self.assertEqual(trigger_metrics["decisions_started"], 1)
            self.assertEqual(trigger_metrics["decisions_completed"], 1)
            self.assertEqual(
                trigger_metrics["events_ignored_after_completion"], 0
            )
            self.assertEqual(
                trigger_metrics["proximity"]["events_observed"], 2
            )
            self.assertEqual(
                trigger_metrics["proximity"]["entries_observed"], 1
            )
            self.assertTrue(
                trigger_metrics["proximity"]["last_observation"][
                    "entered_radius"
                ]
            )

    async def test_replay_generates_typed_mob_acknowledgement_during_hold_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="modeled-mob-ack", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            observed_directory = Path(directory) / "observed"
            object_id = 20_001
            policy = MobMovementAcknowledgementPolicy(
                status_values_by_template={210_100: 35},
                observations_by_template={210_100: 4_728},
                known_mob_templates={},
                field_epoch=1,
                matched_pairs=11_949,
                known_template_pairs=11_949,
                unknown_template_pairs=0,
                flag_rule_matches=11_949,
                zero_auxiliary_pairs=11_949,
                pending_submissions=0,
            )
            controller = MobControllerChange(
                control_level=1,
                object_id=object_id,
                spawn=MobSpawnData(
                    spawn_marker=1,
                    template_id=210_100,
                    temporary_status=MobSpawnTemporaryStatus(),
                    x=100,
                    y=-200,
                    stance=3,
                    foothold_id=7,
                    origin_foothold_id=7,
                    appear_type=-1,
                    team=0xFF,
                    effect_item_id=0,
                ),
            ).to_bytes()
            broadcast = MobMovementBroadcast(
                object_id=object_id,
                control_flag_1=False,
                control_flag_2=False,
                control_selector=0xFF,
                control_value=0,
                reference_x=200,
                reference_y=-200,
                commands=(
                    MobMovementCommand.absolute(
                        position_x=200,
                        position_y=-200,
                        velocity_x=0,
                        velocity_y=0,
                        foothold_id=8,
                        stance=4,
                        duration_ms=1_080,
                    ),
                ),
            ).to_bytes()
            broadcast_plan = fixture_mob_movement_broadcast_plan(
                MobMovementBroadcast.parse(broadcast),
                previous_x=100,
                previous_y=-200,
                previous_foothold_id=7,
                previous_stance=3,
                target_x=200,
                target_y=-200,
                target_foothold_id=8,
                target_stance=4,
            )
            runtime_protocol = {
                "mob_movement_acknowledgements": {
                    "submissions_observed": 0,
                    "responses_sent": 0,
                    "submissions_rejected": 0,
                },
                "mob_movement_broadcast": {
                    "packets_planned": 1,
                    "packets_sent": 0,
                },
            }
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            transcript_directory=observed_directory,
                            hold_open_seconds=0.2,
                            post_transcript_server_frames=(
                                controller,
                                broadcast,
                            ),
                            mob_movement_broadcast_plans=(broadcast_plan,),
                            mob_movement_baseline_server_frames=(controller,),
                            mob_movement_acknowledgement_policy=policy,
                            runtime_protocol=runtime_protocol,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            controller_wire = await reader.readexactly(len(controller) + 4)
            first_response_iv = shuffle_iv(server_iv)
            self.assertEqual(
                MobControllerChange.parse(
                    crypt_payload(controller_wire[4:], first_response_iv)
                ).object_id,
                object_id,
            )
            second_response_iv = shuffle_iv(first_response_iv)
            broadcast_wire = await reader.readexactly(len(broadcast) + 4)
            observed_broadcast = MobMovementBroadcast.parse(
                crypt_payload(broadcast_wire[4:], second_response_iv)
            )
            self.assertEqual(observed_broadcast.object_id, object_id)
            self.assertEqual(
                observed_broadcast.commands[0].position,
                (200, -200),
            )
            movement_path = MobMovementPath(
                opaque_control=b"\x01" + b"\x00" * 18,
                reference_x=100,
                reference_y=-200,
                commands=(
                    MobMovementCommand.absolute(
                        position_x=110,
                        position_y=-200,
                        velocity_x=10,
                        velocity_y=0,
                        foothold_id=7,
                        stance=2,
                        duration_ms=90,
                    ),
                ),
                trailer_marker=0,
                path_start_x=90,
                path_start_y=-200,
                path_end_x=110,
                path_end_y=-200,
            )
            submission = MobMovementSubmission(
                object_id=object_id,
                sequence=42,
                opaque_movement=movement_path.to_bytes(),
            ).to_bytes()
            writer.write(
                encode_frame_header(len(submission), client_iv, 300)
                + crypt_payload(submission, client_iv)
            )
            await writer.drain()
            encrypted_acknowledgement = await reader.readexactly(17)
            acknowledgement = MobMovementAcknowledgement.parse(
                crypt_payload(
                    encrypted_acknowledgement[4:],
                    shuffle_iv(second_response_iv),
                )
            )
            self.assertEqual(acknowledgement.object_id, object_id)
            self.assertEqual(acknowledgement.sequence, 42)
            self.assertEqual(acknowledgement.status_flag, 1)
            self.assertEqual(acknowledgement.status_value, 35)
            self.assertEqual(acknowledgement.status_auxiliary_1, 0)
            self.assertEqual(acknowledgement.status_auxiliary_2, 0)
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()
            metrics = runtime_protocol["mob_movement_acknowledgements"]
            self.assertEqual(metrics["submissions_observed"], 1)
            self.assertEqual(metrics["responses_sent"], 1)
            self.assertEqual(metrics["submissions_rejected"], 0)
            self.assertEqual(
                metrics["last_response"]["template_id"], 210_100
            )
            self.assertEqual(metrics["state"]["active_known_mob_count"], 1)
            self.assertEqual(
                runtime_protocol["mob_movement_broadcast"]["packets_sent"],
                1,
            )
            movement_state = runtime_protocol["mob_movement_broadcast"][
                "state"
            ]
            self.assertEqual(movement_state["phase"], "complete")
            self.assertEqual(
                movement_state["current"],
                {
                    "x": 200,
                    "y": -200,
                    "foothold_id": 8,
                    "stance": 4,
                },
            )
            analysis = analyze_gameplay_transcript(
                Transcript.load(next(observed_directory.glob("*.jsonl")))
            )
            self.assertTrue(analysis.valid)
            acknowledgement_events = [
                event
                for event in analysis.events
                if event.direction == "runtime"
                and event.kind
                in {
                    "mob_movement_submission_observed",
                    "mob_movement_acknowledgement_completed",
                    "mob_movement_submission_rejected",
                }
            ]
            self.assertEqual(
                [event.kind for event in acknowledgement_events],
                [
                    "mob_movement_submission_observed",
                    "mob_movement_acknowledgement_completed",
                ],
            )
            self.assertEqual(
                acknowledgement_events[0].details["path_end"], [110, -200]
            )
            self.assertEqual(
                acknowledgement_events[0].details["option_flags"], 1
            )
            self.assertEqual(
                acknowledgement_events[0].details["activity_code"], 0
            )
            self.assertEqual(
                acknowledgement_events[0].details["control_marker"], 0
            )
            self.assertEqual(
                acknowledgement_events[0].details["control_value_1"], 0
            )
            self.assertEqual(
                acknowledgement_events[0].details["control_value_2"], 0
            )
            self.assertEqual(
                acknowledgement_events[0].details["control_value_3"], 0
            )
            self.assertTrue(
                acknowledgement_events[0].details["target_known"]
            )
            self.assertEqual(
                acknowledgement_events[1].details["server_opcode"], 283
            )
            self.assertEqual(
                acknowledgement_events[1].details["status_value"], 35
            )

    async def test_replay_preserves_delays_inside_reactive_reply_sequence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            client_iv = bytes.fromhex("6e3c795a")
            server_iv = bytes.fromhex("885db958")
            greeting = (
                struct.pack("<HHH", 13, 300, 0)
                + client_iv
                + server_iv
                + b"\x08"
            )
            captured_plaintext = b"captured"
            captured_frame = (
                encode_frame_header(len(captured_plaintext), server_iv, ~300)
                + crypt_payload(captured_plaintext, server_iv)
            )
            source_writer = TranscriptWriter(
                directory, label="reactive-sequence-delay", metadata={}
            )
            source_writer.data("server_to_client", greeting + captured_frame)
            source_writer.close()
            source = Transcript.load(source_writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            writer,
                            source,
                            strict=False,
                            hold_open_seconds=0.2,
                            client_opcode_replies={4: (b"one", b"two")},
                            client_opcode_reply_delays={4: (0.0, 0.05)},
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            self.assertEqual(
                await reader.readexactly(len(greeting + captured_frame)),
                greeting + captured_frame,
            )
            reactive_plaintext = b"\x04\x00world"
            writer.write(
                encode_frame_header(len(reactive_plaintext), client_iv, 300)
                + crypt_payload(reactive_plaintext, client_iv)
            )
            await writer.drain()
            first = await reader.readexactly(7)
            first_iv = shuffle_iv(server_iv)
            self.assertEqual(crypt_payload(first[4:], first_iv), b"one")
            started = asyncio.get_running_loop().time()
            second = await reader.readexactly(7)
            self.assertGreaterEqual(
                asyncio.get_running_loop().time() - started, 0.035
            )
            self.assertEqual(
                crypt_payload(second[4:], shuffle_iv(first_iv)), b"two"
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_replay_can_delay_playback_for_debugger_attach(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TranscriptWriter(directory, label="delayed", metadata={})
            writer.data("client_to_server", b"request")
            writer.data("server_to_client", b"response")
            writer.close()
            transcript = Transcript.load(writer.path)
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, stream_writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        replay_connection(
                            reader,
                            stream_writer,
                            transcript,
                            initial_delay_seconds=0.05,
                        )
                    )
                )

            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            reader, stream_writer = await asyncio.open_connection("127.0.0.1", port)
            stream_writer.write(b"request")
            await stream_writer.drain()
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(reader.read(1), timeout=0.01)
            self.assertEqual(await reader.readexactly(8), b"response")
            stream_writer.close()
            await stream_writer.wait_closed()
            await asyncio.gather(*tasks)
            server.close()
            await server.wait_closed()

    async def test_capture_proxy_records_both_directions(self) -> None:
        async def upstream(reader, writer) -> None:
            self.assertEqual(await reader.readexactly(4), b"ping")
            writer.write(b"pong")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        upstream_port = upstream_server.sockets[0].getsockname()[1]

        with tempfile.TemporaryDirectory() as directory:
            config = CaptureProxyConfig(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                transcript_directory=Path(directory),
            )
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        capture_proxy_connection(reader, writer, config)
                    )
                )

            proxy_server = await asyncio.start_server(accept, "127.0.0.1", 0)
            proxy_port = proxy_server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(b"ping")
            await writer.drain()
            self.assertEqual(await reader.readexactly(4), b"pong")
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)

            transcript_path = next(Path(directory).glob("*.jsonl"))
            transcript = Transcript.load(transcript_path)
            self.assertEqual(transcript.client_bytes, b"ping")
            self.assertEqual(transcript.server_bytes, b"pong")

            proxy_server.close()
            upstream_server.close()
            await proxy_server.wait_closed()
            await upstream_server.wait_closed()

    async def test_capture_proxy_rewrites_selected_client_result_byte(self) -> None:
        first_iv = bytes.fromhex("6e3c795a")
        second_iv = bytes.fromhex("885db958")
        greeting = (
            struct.pack("<HHH", 13, 300, 0)
            + first_iv
            + second_iv
            + b"\x08"
        )
        original_plaintext = b"\x0d\x00\x0fresult"
        original_frame = (
            encode_frame_header(len(original_plaintext), first_iv, 300)
            + crypt_payload(original_plaintext, first_iv)
        )
        forwarded_plaintext: asyncio.Future[bytes] = (
            asyncio.get_running_loop().create_future()
        )
        server_plaintext = b"\x00\x00\x02challenge"
        server_frame = (
            encode_frame_header(len(server_plaintext), second_iv, ~300)
            + crypt_payload(server_plaintext, second_iv)
        )

        async def upstream(reader, writer) -> None:
            writer.write(greeting)
            await writer.drain()
            frame = await reader.readexactly(len(original_frame))
            forwarded_plaintext.set_result(
                crypt_payload(frame[4:], first_iv)
            )
            writer.write(server_frame)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        upstream_server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        upstream_port = upstream_server.sockets[0].getsockname()[1]

        with tempfile.TemporaryDirectory() as directory:
            config = CaptureProxyConfig(
                upstream_host="127.0.0.1",
                upstream_port=upstream_port,
                transcript_directory=Path(directory),
                client_opcode_result_rewrites=((13, 0),),
                server_opcode_byte_rewrites=((0, 2, 0),),
            )
            tasks: set[asyncio.Task[None]] = set()

            def accept(reader, writer) -> None:
                tasks.add(
                    asyncio.create_task(
                        capture_proxy_connection(reader, writer, config)
                    )
                )

            proxy_server = await asyncio.start_server(accept, "127.0.0.1", 0)
            proxy_port = proxy_server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            self.assertEqual(await reader.readexactly(len(greeting)), greeting)
            writer.write(original_frame)
            await writer.drain()
            rewritten_server_frame = await reader.readexactly(len(server_frame))
            self.assertEqual(
                crypt_payload(rewritten_server_frame[4:], second_iv),
                b"\x00\x00\x00challenge",
            )
            self.assertEqual(
                await forwarded_plaintext,
                b"\x0d\x00\x00result",
            )
            writer.close()
            await writer.wait_closed()
            await asyncio.gather(*tasks)

            transcript_path = next(Path(directory).glob("*.jsonl"))
            transcript = Transcript.load(transcript_path)
            self.assertEqual(
                crypt_payload(transcript.client_bytes[4:], first_iv),
                b"\x0d\x00\x00result",
            )

            proxy_server.close()
            upstream_server.close()
            await proxy_server.wait_closed()
            await upstream_server.wait_closed()


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import asyncio
import functools
from pathlib import Path
import struct
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.server import (  # noqa: E402
    build_parser,
    build_post_transcript_server_frames,
    CaptureProxyConfig,
    capture_proxy_connection,
    common_prefix_length,
    common_suffix_length,
    parse_client_opcode_reply,
    parse_client_opcode_result_rewrite,
    parse_server_opcode_byte_rewrite,
    parse_server_frame_patch,
    parse_plaintext_hex,
    parse_zero_filled_frame,
    patch_server_event_data,
    patch_server_frames,
    replay_connection,
)
from maple_server.protocol import (  # noqa: E402
    crypt_payload,
    encode_frame_header,
    parse_encrypted_frames,
    parse_handshake,
    shuffle_iv,
)
from maple_server.transcript import Transcript, TranscriptWriter  # noqa: E402


class TranscriptTest(unittest.TestCase):
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

    def test_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = TranscriptWriter(
                directory,
                label="login:10282",
                metadata={"upstream_port": 10282},
            )
            writer.data("client_to_server", b"hello")
            writer.data("server_to_client", b"world")
            writer.close()

            transcript = Transcript.load(writer.path)
            self.assertEqual(transcript.client_bytes, b"hello")
            self.assertEqual(transcript.server_bytes, b"world")
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

    async def test_replay_delays_between_post_transcript_server_frames(self) -> None:
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
            first = await reader.readexactly(9)
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

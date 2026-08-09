from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from maple_server.http_api import (  # noqa: E402
    ServerPacketInjection,
    ServerRuntime,
    start_runtime_http_api,
)


class RuntimeHttpApiTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.runtime = ServerRuntime(
            mode="replay_connection",
            listen_host="127.0.0.1",
            listen_port=12857,
            config={"keep_world_open": True},
            protocol={
                "world_heartbeat": {
                    "probes_sent": 2,
                    "responses_observed": 2,
                    "pending": 0,
                }
            },
        )
        self.server = await start_runtime_http_api(
            self.runtime, "127.0.0.1", 0
        )
        socket = (self.server.sockets or [])[0]
        self.port = socket.getsockname()[1]

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def request(self, request: bytes) -> tuple[str, dict[str, object]]:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(request)
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        header, body = response.split(b"\r\n\r\n", 1)
        status = header.split(b"\r\n", 1)[0].decode("ascii")
        return status, json.loads(body)

    async def test_health_and_status_are_safe_json(self) -> None:
        self.runtime.listener_addresses = ("('127.0.0.1', 12857)",)
        self.runtime.connection_started()
        health_status, health = await self.request(
            b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        status_status, status = await self.request(
            b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )

        self.assertEqual(health_status, "HTTP/1.1 200 OK")
        self.assertEqual(health, {"ok": True})
        self.assertEqual(status_status, "HTTP/1.1 200 OK")
        self.assertEqual(status["mode"], "replay_connection")
        self.assertEqual(status["config"]["keep_world_open"], True)
        self.assertEqual(status["connections"]["active"], 1)
        self.assertEqual(
            status["protocol"]["world_heartbeat"]["responses_observed"], 2
        )

    async def test_rejects_mutating_methods_and_unknown_routes(self) -> None:
        method_status, method = await self.request(
            b"POST /api/v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        route_status, route = await self.request(
            b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )

        self.assertEqual(method_status, "HTTP/1.1 405 Method Not Allowed")
        self.assertEqual(method, {"error": "method_not_allowed"})
        self.assertEqual(route_status, "HTTP/1.1 404 Not Found")
        self.assertEqual(route, {"error": "not_found"})

    async def test_injects_one_plaintext_packet_when_explicitly_enabled(
        self,
    ) -> None:
        received: list[bytes] = []

        async def inject(plaintext: bytes) -> dict[str, object]:
            received.append(plaintext)
            return {"connection": "test"}

        injection = ServerPacketInjection(enabled=True)
        token = injection.register(inject)
        self.runtime.server_packet_injection = injection
        body = json.dumps({"plaintext_hex": "810100"}).encode("utf-8")
        status_line, response = await self.request(
            b"POST /api/v1/server-packets HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Content-Type: application/json\r\n\r\n"
            + body
        )

        self.assertEqual(status_line, "HTTP/1.1 200 OK")
        self.assertEqual(received, [bytes.fromhex("810100")])
        self.assertEqual(
            response,
            {
                "accepted": True,
                "connection": "test",
                "opcode": 385,
                "plaintext_length": 3,
                "sent_at_ns": response["sent_at_ns"],
            },
        )
        self.assertIsInstance(response["sent_at_ns"], int)
        self.assertEqual(injection.safe_dict()["packets_sent"], 1)
        injection.unregister(token)

    async def test_packet_injection_requires_opt_in_and_one_connection(
        self,
    ) -> None:
        body = b'{"plaintext_hex":"810101"}'
        request = (
            b"POST /api/v1/server-packets HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        disabled_status, disabled = await self.request(request)
        self.assertEqual(disabled_status, "HTTP/1.1 403 Forbidden")
        self.assertEqual(disabled, {"error": "packet_injection_disabled"})

        self.runtime.server_packet_injection.enabled = True
        unavailable_status, unavailable = await self.request(request)
        self.assertEqual(unavailable_status, "HTTP/1.1 409 Conflict")
        self.assertEqual(
            unavailable, {"error": "packet_injection_unavailable"}
        )

    async def test_packet_injection_rejects_malformed_json_shape(self) -> None:
        self.runtime.server_packet_injection.enabled = True
        body = b'{"plaintext_hex":"8101","extra":true}'
        status_line, response = await self.request(
            b"POST /api/v1/server-packets HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )
        self.assertEqual(status_line, "HTTP/1.1 400 Bad Request")
        self.assertEqual(response, {"error": "bad_request"})

    async def test_refuses_non_loopback_binding(self) -> None:
        with self.assertRaisesRegex(ValueError, "restricted to loopback"):
            await start_runtime_http_api(self.runtime, "192.0.2.10", 8799)


if __name__ == "__main__":
    unittest.main()

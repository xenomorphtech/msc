from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from ipaddress import ip_address
import json
import time
from typing import Awaitable, Callable


MAX_HTTP_HEADER_BYTES = 16 * 1024
MAX_HTTP_BODY_BYTES = 128 * 1024
MAX_INJECTED_PACKET_BYTES = 64 * 1024


class PacketInjectionDisabledError(RuntimeError):
    pass


class PacketInjectionUnavailableError(RuntimeError):
    pass


PacketInjector = Callable[[bytes], Awaitable[dict[str, object]]]


@dataclass
class ServerPacketInjection:
    enabled: bool = False
    attempts: int = 0
    packets_sent: int = 0
    failures: int = 0
    last_packet: dict[str, object] | None = None
    last_error: str | None = None
    _next_token: int = field(default=1, init=False, repr=False)
    _injectors: dict[int, PacketInjector] = field(
        default_factory=dict, init=False, repr=False
    )

    def register(self, injector: PacketInjector) -> int:
        token = self._next_token
        self._next_token += 1
        self._injectors[token] = injector
        return token

    def unregister(self, token: int) -> None:
        self._injectors.pop(token, None)

    async def inject(self, plaintext: bytes) -> dict[str, object]:
        self.attempts += 1
        if len(plaintext) < 2:
            self.failures += 1
            self.last_error = "injected packet must contain an opcode"
            raise ValueError(self.last_error)
        if len(plaintext) > MAX_INJECTED_PACKET_BYTES:
            self.failures += 1
            self.last_error = "injected packet is too large"
            raise ValueError(self.last_error)
        if not self.enabled:
            self.failures += 1
            self.last_error = "packet injection is disabled"
            raise PacketInjectionDisabledError(self.last_error)
        if len(self._injectors) != 1:
            self.failures += 1
            self.last_error = (
                "no active replay connection"
                if not self._injectors
                else "multiple active replay connections are ambiguous"
            )
            raise PacketInjectionUnavailableError(self.last_error)
        injector = next(iter(self._injectors.values()))
        try:
            result = await injector(plaintext)
        except Exception as error:
            self.failures += 1
            self.last_error = f"{type(error).__name__}: {error}"
            raise
        self.packets_sent += 1
        self.last_error = None
        self.last_packet = {
            "opcode": int.from_bytes(plaintext[:2], "little"),
            "plaintext_length": len(plaintext),
            "sent_at_ns": time.time_ns(),
        }
        return {**self.last_packet, **result}

    def safe_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "ready": self.enabled and len(self._injectors) == 1,
            "active_replay_connections": len(self._injectors),
            "attempts": self.attempts,
            "packets_sent": self.packets_sent,
            "failures": self.failures,
            "last_packet": self.last_packet,
            "last_error": self.last_error,
        }


@dataclass
class ServerRuntime:
    mode: str
    listen_host: str
    listen_port: int
    config: dict[str, object] = field(default_factory=dict)
    protocol: dict[str, object] = field(default_factory=dict)
    server_packet_injection: ServerPacketInjection = field(
        default_factory=ServerPacketInjection
    )
    started_at_ns: int = field(default_factory=time.time_ns)
    listener_addresses: tuple[str, ...] = ()
    accepted_connections: int = 0
    active_connections: int = 0
    completed_connections: int = 0
    failed_connections: int = 0
    last_error: str | None = None
    _world_heartbeat_response_baseline: int = field(
        default=0, init=False, repr=False
    )
    _login_handoff_baselines: dict[int, tuple[int, int, int, int]] = field(
        default_factory=dict, init=False, repr=False
    )
    _last_completed_login_handoff: dict[str, object] | None = field(
        default=None, init=False, repr=False
    )

    def _login_handoff_counts(self) -> tuple[int, int, int, int]:
        handoff = self.protocol.get("login_handoff")
        if not isinstance(handoff, dict):
            return (0, 0, 0, 0)
        return (
            int(handoff.get("requests_observed", 0)),
            int(handoff.get("responses_sent", 0)),
            int(handoff.get("matching_transactions", 0)),
            int(handoff.get("invalid_requests", 0)),
        )

    def connection_started(self) -> int:
        self.accepted_connections += 1
        self.active_connections += 1
        connection_id = self.accepted_connections
        self._login_handoff_baselines[connection_id] = (
            self._login_handoff_counts()
        )
        heartbeat = self.protocol.get("world_heartbeat")
        if isinstance(heartbeat, dict):
            self._world_heartbeat_response_baseline = int(
                heartbeat.get("responses_observed", 0)
            )
        else:
            self._world_heartbeat_response_baseline = 0
        return connection_id

    def connection_finished(
        self,
        error: BaseException | None = None,
        *,
        connection_id: int | None = None,
    ) -> None:
        if connection_id is None and self._login_handoff_baselines:
            connection_id = max(self._login_handoff_baselines)
        baseline = self._login_handoff_baselines.pop(
            connection_id, (0, 0, 0, 0)
        )
        current = self._login_handoff_counts()
        self._last_completed_login_handoff = {
            "connection_id": connection_id,
            "requests_observed": max(0, current[0] - baseline[0]),
            "responses_sent": max(0, current[1] - baseline[1]),
            "matching_transactions": max(0, current[2] - baseline[2]),
            "invalid_requests": max(0, current[3] - baseline[3]),
            "failed": error is not None,
        }
        self.active_connections -= 1
        self.completed_connections += 1
        if self.active_connections == 0:
            heartbeat = self.protocol.get("world_heartbeat")
            if isinstance(heartbeat, dict):
                self._world_heartbeat_response_baseline = int(
                    heartbeat.get("responses_observed", 0)
                )
        if error is not None:
            self.failed_connections += 1
            self.last_error = f"{type(error).__name__}: {error}"

    def login_session_readiness(self) -> dict[str, object]:
        handoff = self.protocol.get("login_handoff")
        configured = isinstance(handoff, dict)
        expected_transactions = (
            int(handoff.get("expected_transactions", 1))
            if configured
            else None
        )
        request_opcode = (
            int(handoff.get("request_opcode", 7)) if configured else None
        )
        response_opcode = (
            int(handoff.get("response_opcode", 5)) if configured else None
        )
        session: dict[str, object] | None = None
        session_source: str | None = None
        if self.active_connections == 1 and len(
            self._login_handoff_baselines
        ) == 1:
            connection_id, baseline = next(
                iter(self._login_handoff_baselines.items())
            )
            current = self._login_handoff_counts()
            session = {
                "connection_id": connection_id,
                "requests_observed": max(0, current[0] - baseline[0]),
                "responses_sent": max(0, current[1] - baseline[1]),
                "matching_transactions": max(0, current[2] - baseline[2]),
                "invalid_requests": max(0, current[3] - baseline[3]),
                "failed": False,
            }
            session_source = "active_connection"
        elif self.active_connections == 0:
            session = self._last_completed_login_handoff
            if session is not None:
                session_source = "last_completed_connection"
        requests_observed = int(
            session.get("requests_observed", 0) if session is not None else 0
        )
        responses_sent = int(
            session.get("responses_sent", 0) if session is not None else 0
        )
        matching_transactions = int(
            session.get("matching_transactions", 0)
            if session is not None
            else 0
        )
        invalid_requests = int(
            session.get("invalid_requests", 0) if session is not None else 0
        )
        connection_failed = bool(
            session.get("failed", False) if session is not None else False
        )
        connection_scope_available = session is not None
        request_count_matches = (
            expected_transactions is not None
            and requests_observed == expected_transactions
        )
        response_count_matches = (
            expected_transactions is not None
            and responses_sent == expected_transactions
        )
        all_transactions_match = (
            expected_transactions is not None
            and matching_transactions == expected_transactions
        )
        no_invalid_requests = invalid_requests == 0
        connection_not_failed = connection_scope_available and not connection_failed
        ready = (
            configured
            and connection_scope_available
            and request_count_matches
            and response_count_matches
            and all_transactions_match
            and no_invalid_requests
            and connection_not_failed
        )
        return {
            "ready": ready,
            "requirements": {
                "login_handoff_configured": configured,
                "connection_scope_available": connection_scope_available,
                "request_count_matches": request_count_matches,
                "response_count_matches": response_count_matches,
                "all_character_ids_match": all_transactions_match,
                "no_invalid_requests": no_invalid_requests,
                "connection_not_failed": connection_not_failed,
            },
            "connections": {
                "active": self.active_connections,
                "session_source": session_source,
                "connection_id": (
                    session.get("connection_id")
                    if session is not None
                    else None
                ),
            },
            "login_handoff": {
                "request_opcode": request_opcode,
                "response_opcode": response_opcode,
                "expected_transactions": expected_transactions,
                "requests_observed": requests_observed,
                "responses_sent": responses_sent,
                "matching_transactions": matching_transactions,
                "invalid_requests": invalid_requests,
            },
        }

    def world_session_readiness(self) -> dict[str, object]:
        heartbeat = self.protocol.get("world_heartbeat")
        heartbeat_configured = isinstance(heartbeat, dict)
        response_threshold: int | None = None
        responses_observed = 0
        pending = 0
        last_round_trip_ms: object = None
        if heartbeat_configured:
            response_threshold = int(
                heartbeat.get("readiness_response_count", 1)
            )
            responses_observed = int(heartbeat.get("responses_observed", 0))
            pending = int(heartbeat.get("pending", 0))
            last_round_trip_ms = heartbeat.get("last_round_trip_ms")
        current_responses = (
            max(
                0,
                responses_observed - self._world_heartbeat_response_baseline,
            )
            if self.active_connections > 0
            else 0
        )
        single_active_connection = self.active_connections == 1
        response_threshold_met = (
            response_threshold is not None
            and current_responses >= response_threshold
        )
        heartbeat_backlog_healthy = heartbeat_configured and pending <= 1
        ready = (
            single_active_connection
            and heartbeat_configured
            and response_threshold_met
            and heartbeat_backlog_healthy
        )
        return {
            "ready": ready,
            "requirements": {
                "single_active_connection": single_active_connection,
                "heartbeat_configured": heartbeat_configured,
                "heartbeat_response_threshold_met": response_threshold_met,
                "heartbeat_backlog_healthy": heartbeat_backlog_healthy,
            },
            "connections": {"active": self.active_connections},
            "world_heartbeat": {
                "response_threshold": response_threshold,
                "responses_observed_current_connection": current_responses,
                "pending": pending,
                "last_round_trip_ms": last_round_trip_ms,
            },
        }

    def safe_dict(self) -> dict[str, object]:
        return {
            "service": "maplestory-classic-custom-server",
            "mode": self.mode,
            "started_at_ns": self.started_at_ns,
            "listener": {
                "host": self.listen_host,
                "port": self.listen_port,
                "addresses": list(self.listener_addresses),
            },
            "config": self.config,
            "protocol": self.protocol,
            "login_session_readiness": self.login_session_readiness(),
            "world_session_readiness": self.world_session_readiness(),
            "server_packet_injection": self.server_packet_injection.safe_dict(),
            "connections": {
                "accepted": self.accepted_connections,
                "active": self.active_connections,
                "completed": self.completed_connections,
                "failed": self.failed_connections,
                "last_error": self.last_error,
            },
        }


def _json_response(status: str, payload: dict[str, object]) -> bytes:
    body = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return b"".join(
        (
            f"HTTP/1.1 {status}\r\n".encode("ascii"),
            b"Content-Type: application/json; charset=utf-8\r\n",
            f"Content-Length: {len(body)}\r\n".encode("ascii"),
            b"Cache-Control: no-store\r\n",
            b"Connection: close\r\n",
            b"\r\n",
            body,
        )
    )


async def handle_runtime_http_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    runtime: ServerRuntime,
) -> None:
    response: bytes
    try:
        header = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=5
        )
        if len(header) > MAX_HTTP_HEADER_BYTES:
            raise ValueError("HTTP request header is too large")
        request_line = header.split(b"\r\n", 1)[0].decode("ascii")
        method, target, version = request_line.split(" ", 2)
        header_lines = header[:-4].split(b"\r\n")[1:]
        headers: dict[str, str] = {}
        for raw_line in header_lines:
            name, separator, value = raw_line.partition(b":")
            if not separator:
                raise ValueError("malformed HTTP header")
            normalized_name = name.decode("ascii").strip().lower()
            normalized_value = value.decode("ascii").strip()
            if normalized_name in headers:
                raise ValueError("duplicate HTTP header")
            headers[normalized_name] = normalized_value
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            response = _json_response(
                "505 HTTP Version Not Supported",
                {"error": "unsupported_http_version"},
            )
        elif method == "POST" and target == "/api/v1/server-packets":
            content_length_text = headers.get("content-length")
            if content_length_text is None:
                raise ValueError("Content-Length is required")
            content_length = int(content_length_text, 10)
            if not 0 <= content_length <= MAX_HTTP_BODY_BYTES:
                response = _json_response(
                    "413 Content Too Large", {"error": "request_body_too_large"}
                )
            else:
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=5
                )
                request = json.loads(body.decode("utf-8"))
                if not isinstance(request, dict) or set(request) != {
                    "plaintext_hex"
                }:
                    raise ValueError("expected only plaintext_hex")
                plaintext_hex = request["plaintext_hex"]
                if not isinstance(plaintext_hex, str):
                    raise ValueError("plaintext_hex must be a string")
                if len(plaintext_hex) % 2:
                    raise ValueError("plaintext_hex must have even length")
                plaintext = bytes.fromhex(plaintext_hex)
                if len(plaintext) < 2:
                    raise ValueError("injected packet must contain an opcode")
                if len(plaintext) > MAX_INJECTED_PACKET_BYTES:
                    response = _json_response(
                        "413 Content Too Large",
                        {"error": "packet_too_large"},
                    )
                else:
                    try:
                        result = await runtime.server_packet_injection.inject(
                            plaintext
                        )
                    except PacketInjectionDisabledError:
                        response = _json_response(
                            "403 Forbidden",
                            {"error": "packet_injection_disabled"},
                        )
                    except PacketInjectionUnavailableError:
                        response = _json_response(
                            "409 Conflict",
                            {"error": "packet_injection_unavailable"},
                        )
                    except Exception:
                        response = _json_response(
                            "500 Internal Server Error",
                            {"error": "packet_injection_failed"},
                        )
                    else:
                        response = _json_response(
                            "200 OK", {"accepted": True, **result}
                        )
        elif method != "GET":
            response = _json_response(
                "405 Method Not Allowed", {"error": "method_not_allowed"}
            )
        elif target == "/healthz":
            response = _json_response("200 OK", {"ok": True})
        elif target == "/api/v1/status":
            response = _json_response("200 OK", runtime.safe_dict())
        elif target == "/api/v1/login-session-readiness":
            readiness = runtime.login_session_readiness()
            response = _json_response(
                "200 OK" if readiness["ready"] else "503 Service Unavailable",
                readiness,
            )
        elif target == "/api/v1/world-session-readiness":
            readiness = runtime.world_session_readiness()
            response = _json_response(
                "200 OK" if readiness["ready"] else "503 Service Unavailable",
                readiness,
            )
        else:
            response = _json_response("404 Not Found", {"error": "not_found"})
    except (asyncio.IncompleteReadError, TimeoutError, UnicodeDecodeError, ValueError):
        response = _json_response("400 Bad Request", {"error": "bad_request"})
    except asyncio.LimitOverrunError:
        response = _json_response(
            "431 Request Header Fields Too Large",
            {"error": "request_header_too_large"},
        )
    try:
        writer.write(response)
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def start_runtime_http_api(
    runtime: ServerRuntime, host: str, port: int
) -> asyncio.AbstractServer:
    if host != "localhost":
        try:
            address = ip_address(host)
        except ValueError as error:
            raise ValueError(
                "HTTP API host must be localhost or a numeric loopback address"
            ) from error
        if not address.is_loopback:
            raise ValueError("HTTP API is intentionally restricted to loopback")
    return await asyncio.start_server(
        lambda reader, writer: handle_runtime_http_request(
            reader, writer, runtime=runtime
        ),
        host,
        port,
        limit=MAX_HTTP_HEADER_BYTES,
    )

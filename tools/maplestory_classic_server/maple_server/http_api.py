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

    def connection_started(self) -> None:
        self.accepted_connections += 1
        self.active_connections += 1

    def connection_finished(self, error: BaseException | None = None) -> None:
        self.active_connections -= 1
        self.completed_connections += 1
        if error is not None:
            self.failed_connections += 1
            self.last_error = f"{type(error).__name__}: {error}"

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

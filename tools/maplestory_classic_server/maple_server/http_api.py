from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from ipaddress import ip_address
import json
import time


MAX_HTTP_HEADER_BYTES = 16 * 1024


@dataclass
class ServerRuntime:
    mode: str
    listen_host: str
    listen_port: int
    config: dict[str, object] = field(default_factory=dict)
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
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            response = _json_response(
                "505 HTTP Version Not Supported",
                {"error": "unsupported_http_version"},
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

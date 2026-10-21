"""A WebSocket client for the repeater.

The repeater speaks to the origin as a WebSocket client, so a request that
upgrades the protocol can be completed and then used to exchange frames. The
frames that come back are kept, so they can be shown next to the ones that
were sent.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any

from intercept.core.models import Request, Response
from intercept.proxy.convert import prepare_upstream
from intercept.proxy.http1 import parse_head_block, read_head_block, serialize_request
from intercept.proxy.upstream import UpstreamError, UpstreamPool
from intercept.proxy.websocket import FrameParser, WebSocketFrame

__all__ = ["WebSocketSession", "accept_key", "is_websocket_request"]

#: The constant the handshake of RFC 6455 is built on.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_key(key: str) -> str:
    """The ``Sec-WebSocket-Accept`` value for a ``Sec-WebSocket-Key``."""
    digest = hashlib.sha1((key.strip() + _WS_GUID).encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def is_websocket_request(request: Request) -> bool:
    """Does this request ask for a WebSocket upgrade?"""
    upgrade = (request.headers.get("upgrade") or "").lower()
    connection = (request.headers.get("connection") or "").lower()
    return "websocket" in upgrade and "upgrade" in connection


@dataclass
class WebSocketSession:
    """A WebSocket connection that the repeater opened."""

    request: Request
    pool: UpstreamPool
    timeout: float = 30.0
    response: Response | None = None
    sent: list[WebSocketFrame] = field(default_factory=list)
    received: list[WebSocketFrame] = field(default_factory=list)
    closed: bool = False
    error: str = ""
    _stream: Any = None
    _writer: Any = None
    _parser: FrameParser = field(default_factory=lambda: FrameParser("server"))

    async def open(self) -> Response:
        """Do the handshake and keep the connection open."""
        scheme, host, port, _path, _query = self.request.parts
        if not host:
            self.error = "the request has no host"
            raise UpstreamError(self.error)

        headers, body = prepare_upstream(self.request, host, port, scheme)
        headers.set("Connection", "Upgrade")
        headers.set("Upgrade", "websocket")
        headers.set("Sec-WebSocket-Version", "13")
        if not headers.get("Sec-WebSocket-Key"):
            headers.set(
                "Sec-WebSocket-Key", base64.b64encode(os.urandom(16)).decode("ascii")
            )

        try:
            stream, writer = await self.pool.open_raw(scheme, host, port)
        except UpstreamError as exc:
            self.error = str(exc)
            raise

        head = serialize_request(
            self.request.method, self.request.origin_form, headers, body
        )
        try:
            writer.write(head)
            await writer.drain()
            block = await asyncio.wait_for(
                read_head_block(stream, self.pool.max_header_size), timeout=self.timeout
            )
        except (TimeoutError, OSError, asyncio.IncompleteReadError) as exc:
            self.error = str(exc) or "the handshake failed"
            writer.close()
            raise UpstreamError(self.error) from exc

        if not block:
            self.error = "the origin closed the connection during the handshake"
            writer.close()
            raise UpstreamError(self.error)

        start_line, version, response_headers = parse_head_block(block)
        parts = start_line.split(" ")
        try:
            status = int(parts[1])
        except (IndexError, ValueError):
            status = 0

        self._stream = stream
        self._writer = writer
        self.response = Response(
            status=status,
            reason=parts[2] if len(parts) > 2 else "",
            headers=response_headers,
            body=b"",
            http_version=version,
            raw=block,
            elapsed_ms=0.0,
            tls=scheme == "https",
        )
        return self.response

    async def send(self, payload: bytes, opcode: int = 0x1) -> WebSocketFrame:
        """Send one frame to the origin."""
        if self._writer is None:
            raise UpstreamError("the connection is not open")
        frame = WebSocketFrame(direction="client", opcode=opcode, payload=payload)
        self._writer.write(frame.serialize(mask=True))
        await self._writer.drain()
        self.sent.append(frame)
        return frame

    async def receive(self, timeout: float | None = None) -> list[WebSocketFrame]:
        """Read the frames the origin sent, until the timeout passes."""
        if self._stream is None:
            raise UpstreamError("the connection is not open")
        wait = self.timeout if timeout is None else timeout
        frames: list[WebSocketFrame] = []
        deadline = time.monotonic() + wait
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                data = await asyncio.wait_for(self._stream.read(65536), timeout=remaining)
            except TimeoutError:
                break
            if not data:
                self.closed = True
                break
            for frame in self._parser.feed(data):
                frames.append(frame)
                self.received.append(frame)
            if frames:
                break
        return frames

    async def close(self) -> None:
        """Close the connection."""
        if self._writer is None:
            return
        try:
            frame = WebSocketFrame(direction="client", opcode=0x8, payload=b"")
            self._writer.write(frame.serialize(mask=True))
            await self._writer.drain()
        except (OSError, ConnectionError):
            pass
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except (OSError, ConnectionError, asyncio.CancelledError):
            pass
        self._writer = None
        self._stream = None
        self.closed = True

    def to_dict(self) -> dict[str, Any]:
        """What the interface shows about this session."""
        return {
            "open": self._writer is not None,
            "closed": self.closed,
            "error": self.error,
            "status": self.response.status if self.response else 0,
            "reason": self.response.reason if self.response else "",
            "headers": self.response.headers.to_dict() if self.response else {},
            "sent": [frame.to_dict() for frame in self.sent],
            "received": [frame.to_dict() for frame in self.received],
        }

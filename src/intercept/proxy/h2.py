"""HTTP/2 support.

Two roles are implemented on top of ``hyper-h2``:

* :class:`H2ServerConnection` terminates the client side of a tunnelled
  connection. The browser speaks HTTP/2 to us over the TLS tunnel we opened.
* :class:`H2ClientConnection` speaks HTTP/2 to the origin, so the upstream leg
  stays HTTP/2 when the origin offers it.

Both expose the same shape: bytes go in, completed messages come out, and the
bytes that still have to reach the peer are collected by
:meth:`data_to_send`.
"""

from __future__ import annotations

import collections
import contextlib
from dataclasses import dataclass, field
from typing import Any

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    PushedStreamReceived,
    RequestReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
    TrailersReceived,
)
from h2.exceptions import H2Error, ProtocolError, StreamClosedError

from intercept.core.models import Headers, Request, Response
from intercept.core.protocols import HTTP_2

__all__ = [
    "ALPN_PROTOCOLS",
    "H2ClientConnection",
    "H2Request",
    "H2Response",
    "H2ServerConnection",
    "headers_to_model",
    "h2_request_to_model",
    "h2_response_to_model",
    "model_to_headers",
    "render_h2_request_raw",
    "render_h2_response_raw",
    "strip_connection_headers",
]

ALPN_PROTOCOLS = ["h2", "http/1.1"]

#: Headers that must never be forwarded over an HTTP/2 connection.
CONNECTION_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    }
)


def _decode(value: bytes) -> str:
    return value.decode("latin-1", "replace")


def headers_to_model(raw: list[tuple[bytes, bytes]]) -> Headers:
    """Convert a header list into the model, keeping pseudo-headers visible."""
    headers = Headers()
    for name, value in raw:
        headers.add(_decode(name), _decode(value))
    return headers


def model_to_headers(headers: Headers, *, drop_pseudo: bool = True) -> list[tuple[bytes, bytes]]:
    """Convert model headers into wire headers."""
    out: list[tuple[bytes, bytes]] = []
    for name, value in headers:
        if drop_pseudo and name.startswith(":"):
            continue
        out.append((name.encode("latin-1", "replace"), value.encode("latin-1", "replace")))
    return out


def strip_connection_headers(headers: Headers, *, drop_host: bool = False) -> Headers:
    """Remove headers that HTTP/2 forbids on the wire.

    ``drop_host`` is used for requests, where ``:authority`` already carries
    the authority and a stray ``Host`` header only confuses origin servers.
    """
    cleaned = Headers()
    for name, value in headers:
        lowered = name.lower()
        if lowered.startswith(":"):
            continue
        if lowered in CONNECTION_HEADERS:
            continue
        if lowered == "te" and value.lower() != "trailers":
            continue
        if drop_host and lowered == "host":
            continue
        cleaned.add(name, value)
    return cleaned


def _render(raw: list[tuple[str, str]], body: bytes) -> bytes:
    lines = [f"{name}: {value}" for name, value in raw]
    text = "\r\n".join(lines) + "\r\n"
    return text.encode("utf-8", "replace") + body


def render_h2_request_raw(request: H2Request) -> bytes:
    return _render(request.headers.items(), request.body)


def render_h2_response_raw(response: H2Response) -> bytes:
    raw = [(":status", str(response.status))]
    raw.extend(response.headers.items())
    return _render(raw, response.body)


@dataclass
class H2Request:
    """A request received over HTTP/2."""

    stream_id: int
    headers: Headers
    method: str = "GET"
    scheme: str = "https"
    authority: str = ""
    path: str = "/"
    body: bytes = b""

    @property
    def url(self) -> str:
        authority = self.authority
        default_port = 443 if self.scheme == "https" else 80
        if ":" in authority and authority.rsplit(":", 1)[-1].isdigit():
            host, _, port = authority.rpartition(":")
            if int(port) == default_port:
                authority = f"[{host}]" if ":" in host else host
        return f"{self.scheme}://{authority}{self.path}"


@dataclass
class H2Response:
    """A response received over HTTP/2."""

    stream_id: int
    status: int = 0
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    trailers: Headers = field(default_factory=Headers)


def _request_from_headers(stream_id: int, raw: list[tuple[bytes, bytes]]) -> H2Request:
    headers = headers_to_model(raw)
    method = (headers.get(":method") or "GET").upper()
    scheme = (headers.get(":scheme") or "https").lower()
    authority = headers.get(":authority") or ""
    path = headers.get(":path") or "/"
    return H2Request(
        stream_id=stream_id,
        headers=headers,
        method=method,
        scheme=scheme,
        authority=authority,
        path=path,
    )


def h2_request_to_model(request: H2Request, *, client: str = "") -> Request:
    """Convert an HTTP/2 request into the shared model."""
    return Request(
        method=request.method,
        url=request.url,
        headers=request.headers,
        body=request.body,
        http_version=HTTP_2,
        raw=render_h2_request_raw(request),
        tls=request.scheme == "https",
        client=client,
        origin="proxy",
    )


def h2_response_to_model(response: H2Response, elapsed: float = 0.0) -> Response:
    """Convert an HTTP/2 response into the shared model."""
    return Response(
        status=response.status,
        reason="",
        headers=response.headers,
        body=response.body,
        http_version=HTTP_2,
        raw=render_h2_response_raw(response),
        elapsed_ms=elapsed,
        tls=True,
    )


def _is_bodyless(status: int) -> bool:
    return status in (204, 304) or 100 <= status < 200


class _BaseConnection:
    """Shared flow control and error bookkeeping."""

    def __init__(self, client_side: bool) -> None:
        self.conn = H2Connection(config=H2Configuration(client_side=client_side))
        self.conn.initiate_connection()
        self.errors: list[str] = []

    def data_to_send(self) -> bytes:
        return self.conn.data_to_send()

    def receive(self, data: bytes) -> list[Any]:
        try:
            return list(self.conn.receive_data(data))
        except (ProtocolError, H2Error) as exc:
            self.errors.append(str(exc))
            return []

    def _acknowledge(self, event: DataReceived) -> None:
        length = event.flow_controlled_length
        with contextlib.suppress(ProtocolError, H2Error, StreamClosedError):
            self.conn.acknowledge_received_data(length, event.stream_id)
            self.conn.increment_flow_control_window(length, event.stream_id)
            self.conn.increment_flow_control_window(length)


class H2ServerConnection(_BaseConnection):
    """Terminates HTTP/2 coming from the client."""

    def __init__(self) -> None:
        super().__init__(client_side=False)
        self._requests: dict[int, H2Request] = {}
        self._bodies: dict[int, bytearray] = collections.defaultdict(bytearray)
        self._completed: list[H2Request] = []
        self.pushed: list[str] = []

    def receive(self, data: bytes) -> list[Any]:
        events = super().receive(data)
        for event in events:
            if isinstance(event, RequestReceived):
                request = _request_from_headers(event.stream_id, event.headers)
                self._requests[event.stream_id] = request
                if event.stream_ended:
                    self._finish_request(event.stream_id)
            elif isinstance(event, DataReceived):
                self._acknowledge(event)
                self._bodies[event.stream_id].extend(event.data)
            elif isinstance(event, TrailersReceived):
                self._acknowledge(event)
            elif isinstance(event, StreamEnded):
                if event.stream_id in self._requests:
                    self._finish_request(event.stream_id)
            elif isinstance(event, StreamReset):
                self._requests.pop(event.stream_id, None)
                self._bodies.pop(event.stream_id, None)
            elif isinstance(event, PushedStreamReceived):
                pushed = dict(event.headers)
                self.pushed.append(_decode(pushed.get(b":path", b"")))
            elif isinstance(event, ConnectionTerminated):
                self.errors.append(f"connection terminated: {event.error_code}")
        return events

    def _finish_request(self, stream_id: int) -> None:
        request = self._requests.pop(stream_id, None)
        if request is None:
            return
        request.body = bytes(self._bodies.pop(stream_id, b""))
        self._completed.append(request)

    def take_completed(self) -> list[H2Request]:
        """Return the requests whose body is complete."""
        completed = self._completed
        self._completed = []
        return completed

    def send_response(
        self,
        stream_id: int,
        status: int,
        headers: Headers,
        body: bytes = b"",
    ) -> None:
        """Send a response on *stream_id*."""
        raw: list[tuple[bytes, bytes]] = [(b":status", str(status).encode())]
        raw.extend(model_to_headers(strip_connection_headers(headers)))
        has_body = bool(body) or not _is_bodyless(status)
        try:
            self.conn.send_headers(stream_id, raw, end_stream=not has_body)
            if has_body:
                self.conn.send_data(stream_id, body, end_stream=True)
        except (ProtocolError, H2Error) as exc:
            self.errors.append(str(exc))

    def send_error(self, stream_id: int, status: int, message: str) -> None:
        body = message.encode()
        headers = Headers(
            [
                ("content-type", "text/plain; charset=utf-8"),
                ("content-length", str(len(body))),
            ]
        )
        self.send_response(stream_id, status, headers, body)

    def reset_stream(self, stream_id: int, code: int = ErrorCodes.CANCEL) -> None:
        with contextlib.suppress(ProtocolError, H2Error):
            self.conn.reset_stream(stream_id, code)


class H2ClientConnection(_BaseConnection):
    """Speaks HTTP/2 to the origin."""

    def __init__(self) -> None:
        super().__init__(client_side=True)
        self._next_stream_id = 1
        self._responses: dict[int, H2Response] = {}
        self._bodies: dict[int, bytearray] = collections.defaultdict(bytearray)
        self._completed: list[H2Response] = []

    def next_stream_id(self) -> int:
        """Reserve and return the next client stream identifier."""
        stream_id = self._next_stream_id
        self._next_stream_id += 2
        return stream_id

    def request(
        self,
        method: str,
        scheme: str,
        authority: str,
        path: str,
        headers: Headers,
        body: bytes = b"",
    ) -> int:
        """Start a request and return its stream identifier."""
        stream_id = self.next_stream_id()
        raw: list[tuple[bytes, bytes]] = [
            (b":method", method.encode("latin-1", "replace")),
            (b":path", path.encode("latin-1", "replace")),
            (b":scheme", scheme.encode("latin-1", "replace")),
            (b":authority", authority.encode("latin-1", "replace")),
        ]
        raw.extend(model_to_headers(strip_connection_headers(headers, drop_host=True)))
        has_body = bool(body)
        try:
            self.conn.send_headers(stream_id, raw, end_stream=not has_body)
            if has_body:
                self.conn.send_data(stream_id, body, end_stream=True)
        except (ProtocolError, H2Error) as exc:
            self.errors.append(str(exc))
        return stream_id

    def receive(self, data: bytes) -> list[Any]:
        events = super().receive(data)
        for event in events:
            if isinstance(event, ResponseReceived):
                raw = dict(event.headers)
                status_raw = raw.get(b":status", b"0")
                try:
                    status = int(status_raw)
                except (TypeError, ValueError):
                    status = 0
                response = H2Response(
                    stream_id=event.stream_id,
                    status=status,
                    headers=headers_to_model(
                        [(k, v) for k, v in event.headers if not k.startswith(b":")]
                    ),
                )
                self._responses[event.stream_id] = response
                if event.stream_ended:
                    self._finish(event.stream_id)
            elif isinstance(event, DataReceived):
                self._acknowledge(event)
                self._bodies[event.stream_id].extend(event.data)
            elif isinstance(event, TrailersReceived):
                self._acknowledge(event)
            elif isinstance(event, StreamEnded):
                self._finish(event.stream_id)
            elif isinstance(event, StreamReset):
                self._responses.pop(event.stream_id, None)
            elif isinstance(event, ConnectionTerminated):
                self.errors.append(f"connection terminated: {event.error_code}")
        return events

    def _finish(self, stream_id: int) -> None:
        response = self._responses.pop(stream_id, None)
        if response is None:
            return
        response.body = bytes(self._bodies.pop(stream_id, b""))
        self._completed.append(response)

    def take_completed(self) -> list[H2Response]:
        completed = self._completed
        self._completed = []
        return completed

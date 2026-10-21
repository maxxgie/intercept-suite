"""End to end tests for the HTTP/2 support."""

from __future__ import annotations

import asyncio
import collections
import contextlib
import ssl
from typing import Any

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded

from intercept.core.models import Headers
from intercept.proxy.h2 import (
    H2ClientConnection,
    H2ServerConnection,
    h2_request_to_model,
    strip_connection_headers,
)


def _server_context(ca, hostname: str = "localhost") -> ssl.SSLContext:
    leaf = ca.leaf(hostname)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context


class _H2Origin:
    """A minimal HTTP/2 origin server used as the target of the proxy tests."""

    def __init__(self, context: ssl.SSLContext) -> None:
        self.context = context
        self.server: asyncio.Server | None = None
        self.port = 0
        self.requests: list[dict[str, Any]] = []
        self.writers: list[asyncio.StreamWriter] = []

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=self.context)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for writer in self.writers:
            with contextlib.suppress(Exception):
                writer.close()
        self.writers.clear()
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.writers.append(writer)
        conn = H2Connection(config=H2Configuration(client_side=False))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()
        bodies: dict[int, bytearray] = collections.defaultdict(bytearray)
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, RequestReceived):
                        headers = {k.decode(): v.decode() for k, v in event.headers}
                        self.requests.append({"headers": headers, "body": b""})
                    elif isinstance(event, DataReceived):
                        bodies[event.stream_id].extend(event.data)
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, StreamEnded):
                        entry = self.requests[-1] if self.requests else None
                        if entry is not None:
                            entry["body"] = bytes(bodies.pop(event.stream_id, b""))
                        payload = f"hello {entry['headers'].get(':path', '/')}".encode()
                        conn.send_headers(
                            event.stream_id,
                            [
                                (b":status", b"200"),
                                (b"content-type", b"text/plain"),
                                (b"content-length", str(len(payload)).encode()),
                                (b"x-origin-server", b"intercept-h2"),
                            ],
                        )
                        conn.send_data(event.stream_id, payload, end_stream=True)
                outbound = conn.data_to_send()
                if outbound:
                    writer.write(outbound)
                    await writer.drain()
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            return
        finally:
            writer.close()


class _H2Client:
    """A tiny HTTP/2 client that tunnels through the proxy with CONNECT."""

    def __init__(self, proxy_host: str, proxy_port: int, ca_file: str) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.ca_file = ca_file
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.conn = H2ClientConnection()

    async def connect(self, host: str, port: int) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.proxy_host, self.proxy_port)
        self.writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        await self.writer.drain()
        head = await self.reader.readuntil(b"\r\n\r\n")
        assert b"200" in head, head
        context = ssl.create_default_context(cafile=self.ca_file)
        context.set_alpn_protocols(["h2"])
        await self.writer.start_tls(context, server_hostname=host)
        self.writer.write(self.conn.data_to_send())
        await self.writer.drain()

    async def request(
        self,
        method: str,
        authority: str,
        path: str,
        headers: list[tuple[bytes, bytes]] | None = None,
        body: bytes = b"",
    ) -> tuple[int, Headers, bytes]:
        raw: list[tuple[bytes, bytes]] = [
            (b":method", method.encode()),
            (b":path", path.encode()),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
        ]
        if headers:
            raw.extend(headers)
        stream_id = self.conn.next_stream_id()
        self.conn.conn.send_headers(stream_id, raw, end_stream=not body)
        if body:
            self.conn.conn.send_data(stream_id, body, end_stream=True)
        assert self.writer is not None
        self.writer.write(self.conn.data_to_send())
        await self.writer.drain()
        return await self._await_response(stream_id)

    async def _await_response(self, stream_id: int) -> tuple[int, Headers, bytes]:
        assert self.reader is not None
        while True:
            data = await self.reader.read(65536)
            if not data:
                raise AssertionError("connection closed before the response arrived")
            self.conn.receive(data)
            for response in self.conn.take_completed():
                if response.stream_id == stream_id:
                    return response.status, response.headers, response.body
            assert self.writer is not None
            self.writer.write(self.conn.data_to_send())
            await self.writer.drain()

    async def close(self) -> None:
        if self.writer is not None:
            self.writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await self.writer.wait_closed()


@pytest.fixture
async def h2_origin(app):
    origin = _H2Origin(_server_context(app.ca))
    await origin.start()
    try:
        yield origin
    finally:
        await origin.stop()


async def test_http2_request_is_forwarded_and_recorded(app, config, h2_origin):
    client = _H2Client(config.proxy.host, config.proxy.port, str(app.ca.root_cert_path))
    await client.connect("localhost", h2_origin.port)
    try:
        status, headers, body = await client.request(
            "GET", f"localhost:{h2_origin.port}", "/secure"
        )
    finally:
        await client.close()

    assert status == 200
    assert headers.get("x-origin-server") == "intercept-h2"
    assert body == b"hello /secure"

    await app.store.flush()
    items = await app.store.list()
    assert len(items) == 1
    assert items[0]["status"] == 200
    assert items[0]["http_version"] == "HTTP/2"
    assert items[0]["path"] == "/secure"

    stored = await app.store.get(items[0]["id"])
    assert stored["request"]["http_version"] == "HTTP/2"
    assert ":authority" in stored["request"]["raw"]


async def test_http2_request_body_reaches_the_origin(app, config, h2_origin):
    client = _H2Client(config.proxy.host, config.proxy.port, str(app.ca.root_cert_path))
    await client.connect("localhost", h2_origin.port)
    try:
        status, _headers, _body = await client.request(
            "POST",
            f"localhost:{h2_origin.port}",
            "/submit",
            headers=[(b"content-type", b"text/plain")],
            body=b"payload",
        )
    finally:
        await client.close()

    assert status == 200
    assert h2_origin.requests[-1]["body"] == b"payload"
    assert h2_origin.requests[-1]["headers"][":method"] == "POST"


async def test_multiple_streams_are_forwarded(app, config, h2_origin):
    client = _H2Client(config.proxy.host, config.proxy.port, str(app.ca.root_cert_path))
    await client.connect("localhost", h2_origin.port)
    try:
        first = await client.request("GET", f"localhost:{h2_origin.port}", "/one")
        second = await client.request("GET", f"localhost:{h2_origin.port}", "/two")
    finally:
        await client.close()

    assert first[2] == b"hello /one"
    assert second[2] == b"hello /two"


async def test_http2_falls_back_to_http1_when_the_origin_has_no_h2(app, config):
    """A client speaking HTTP/2 still works against an HTTP/1.x only origin."""
    import http.server
    import threading

    from conftest import _Handler

    leaf = app.ca.leaf("localhost")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        client = _H2Client(config.proxy.host, config.proxy.port, str(app.ca.root_cert_path))
        await client.connect("localhost", port)
        try:
            status, headers, body = await client.request(
                "GET", f"localhost:{port}", "/fallback"
            )
        finally:
            await client.close()
    finally:
        server.shutdown()
        server.server_close()

    assert status == 200
    assert headers.get("x-origin-server") == "intercept-tests"
    assert b"/fallback" in body


def test_pseudo_headers_are_stripped_before_the_wire():
    headers = Headers(
        [
            (":method", "GET"),
            (":path", "/x"),
            ("host", "example.com"),
            ("connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("accept", "*/*"),
        ]
    )
    cleaned = strip_connection_headers(headers, drop_host=True)
    names = [name for name, _ in cleaned]
    assert names == ["accept"]


def test_h2_server_connection_parses_a_request():
    server = H2ServerConnection()
    client = H2ClientConnection()
    client.request(
        method="GET",
        scheme="https",
        authority="example.com",
        path="/a",
        headers=Headers([("accept", "*/*")]),
    )
    server.receive(client.data_to_send())

    completed = server.take_completed()
    assert len(completed) == 1
    request = completed[0]
    assert request.method == "GET"
    assert request.path == "/a"
    assert request.authority == "example.com"
    assert request.url == "https://example.com/a"

    model = h2_request_to_model(request)
    assert model.http_version == "HTTP/2"
    assert model.headers.get(":method") == "GET"

"""Shared test fixtures."""

from __future__ import annotations

import http.server
import json
import socket
import threading
from typing import Any

import pytest

from intercept.app import InterceptApp
from intercept.core.config import Config


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "body": body.decode("utf-8", "replace"),
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Origin-Server", "intercept-tests")
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond

    def log_message(self, *args: Any) -> None:
        return


@pytest.fixture
def origin_server():
    """A tiny HTTP origin server used as the target of proxy tests."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def origin_url(origin_server) -> str:
    host, port = origin_server.server_address[:2]
    return f"http://{host}:{port}"


@pytest.fixture
def config(tmp_path) -> Config:
    config = Config(home=str(tmp_path))
    config.proxy.host = "127.0.0.1"
    config.proxy.port = free_port()
    config.api.host = "127.0.0.1"
    config.api.port = free_port()
    config.proxy.upstream_verify = False
    return config


@pytest.fixture
async def app(config):
    """A running daemon with the proxy enabled."""
    application = InterceptApp(config)
    await application.startup()
    try:
        yield application
    finally:
        await application.shutdown()


@pytest.fixture
def proxy_url(config) -> str:
    return f"http://{config.proxy.host}:{config.proxy.port}"


@pytest.fixture
async def client(app):
    """An HTTP client bound to the daemon API."""
    import httpx

    from intercept.api.app import create_api

    api = create_api(app)
    transport = httpx.ASGITransport(app=api)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client

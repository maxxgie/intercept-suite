"""Tests for the proxy features: response editing, SOCKS, chaining and frames."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.client
import http.server
import socket
import struct
import threading
from urllib.parse import urlsplit

import httpx
import pytest

from intercept.core.models import Headers, Response
from intercept.proxy.intercept import InterceptDecision
from intercept.proxy.rules import Rule

# --------------------------------------------------------------- fixtures


class _ForwardProxyHandler(http.server.BaseHTTPRequestHandler):
    """A minimal forward proxy, used as an upstream to chain through."""

    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - the name is set by the base class
        url = urlsplit(self.path)
        target = url.path + (f"?{url.query}" if url.query else "")
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in ("proxy-connection", "connection")
        }
        connection = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=10)
        try:
            connection.request("GET", target, headers=headers)
            upstream = connection.getresponse()
            body = upstream.read()
            self.send_response(upstream.status)
            for name, value in upstream.getheaders():
                if name.lower() in ("transfer-encoding", "content-length", "connection"):
                    continue
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Chained-Through", "yes")
            self.end_headers()
            self.wfile.write(body)
        finally:
            connection.close()

    def log_message(self, *args: object) -> None:
        return


@pytest.fixture
def upstream_proxy():
    """A plain forward proxy the origin traffic can be chained through."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ForwardProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------ response edits


async def test_a_response_can_be_edited_while_it_is_held(app, origin_url, proxy_url):
    await app.rule_store.create(Rule(id="", kind="intercept", phase="response"))
    await app.reload_rules()
    app.intercept.enabled = True

    async def decide_later() -> None:
        for _ in range(200):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        request_id = app.intercept.pending_ids()[0]
        item = app.intercept.item(request_id)
        assert item is not None
        assert item.phase == "response"
        edited = Response(
            status=418,
            reason="I'm a teapot",
            headers=Headers([("X-Edited", "yes")]),
            body=b"edited by the analyst",
        )
        app.intercept.resolve(request_id, InterceptDecision("forward", response=edited))

    task = asyncio.create_task(decide_later())
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/edited")
    await task

    assert response.status_code == 418
    assert response.text == "edited by the analyst"
    assert response.headers["x-edited"] == "yes"


async def test_a_held_response_can_be_dropped(app, origin_url, proxy_url):
    await app.rule_store.create(Rule(id="", kind="intercept", phase="response"))
    await app.reload_rules()
    app.intercept.enabled = True

    async def decide_later() -> None:
        for _ in range(200):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        app.intercept.resolve(
            app.intercept.pending_ids()[0], InterceptDecision("drop")
        )

    task = asyncio.create_task(decide_later())
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/dropped")
    await task

    assert response.status_code == 502
    assert "dropped" in response.text


async def test_the_api_can_answer_a_held_response(app, client, origin_url, proxy_url):
    await app.rule_store.create(Rule(id="", kind="intercept", phase="response"))
    await app.reload_rules()
    app.intercept.enabled = True

    async def answer() -> None:
        for _ in range(200):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        request_id = app.intercept.pending_ids()[0]
        answered = await client.post(
            f"/api/intercept/{request_id}",
            json={
                "action": "forward",
                "status": 203,
                "reason": "Edited",
                "response_headers": {"X-From-Api": ["yes"]},
                "response_body": "from the api",
            },
        )
        assert answered.status_code == 200

    task = asyncio.create_task(answer())
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as http_client:
        response = await http_client.get(f"{origin_url}/api")
    await task

    assert response.status_code == 203
    assert response.text == "from the api"
    assert response.headers["x-from-api"] == "yes"


async def test_the_intercept_state_names_what_is_held(app, client):
    app.intercept.enabled = True
    state = (await client.get("/api/intercept")).json()
    assert state["enabled"] is True
    assert state["pending_count"] == 0
    assert state["items"] == []
    assert state["frames"] == []


# ------------------------------------------------------------------- socks


async def socks_connect(
    host: str, port: int, destination: str, dport: int
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Speak the SOCKS5 handshake by hand, so the server is tested on its own."""
    reader, writer = await asyncio.open_connection(host, port)
    writer.write(bytes([0x05, 0x01, 0x00]))
    await writer.drain()
    assert await reader.readexactly(2) == bytes([0x05, 0x00])

    name = destination.encode()
    writer.write(
        bytes([0x05, 0x01, 0x00, 0x03, len(name)]) + name + struct.pack("!H", dport)
    )
    await writer.drain()
    reply = await reader.readexactly(4)
    assert reply[0] == 0x05
    assert reply[1] == 0x00, "the tunnel was refused"
    if reply[3] == 0x01:
        await reader.readexactly(4)
        await reader.readexactly(2)
    elif reply[3] == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    return reader, writer


async def test_the_socks_listener_serves_http(config, origin_url):
    """A client that speaks SOCKS reaches the origin through the proxy."""
    from intercept.app import InterceptApp
    from intercept.core.config import ListenerConfig

    socks_port = _free_port()
    config.proxy.listeners.append(
        ListenerConfig(name="socks", host="127.0.0.1", port=socks_port, mode="socks")
    )
    application = InterceptApp(config)
    await application.startup()
    try:
        host, origin_port = urlsplit(origin_url).hostname, urlsplit(origin_url).port
        reader, writer = await socks_connect("127.0.0.1", socks_port, host, origin_port)
        writer.write(
            f"GET /through-socks HTTP/1.1\r\nHost: {host}:{origin_port}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        await writer.drain()
        data = b""
        try:
            while b"\r\n\r\n" not in data or b"}" not in data.split(b"\r\n\r\n", 1)[-1]:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
                if not chunk:
                    break
                data += chunk
        except TimeoutError:
            pass
        writer.close()
    finally:
        await application.shutdown()

    assert b"200 OK" in data
    assert b"through-socks" in data


async def test_a_listener_added_at_runtime_is_opened(app, origin_url, config):
    """A listener that is added while the daemon runs takes effect at once."""
    from intercept.core.config import ListenerConfig

    socks_port = _free_port()
    config.proxy.listeners.append(
        ListenerConfig(name="socks", host="127.0.0.1", port=socks_port, mode="socks")
    )
    await app.proxy.sync_listeners()

    host, origin_port = urlsplit(origin_url).hostname, urlsplit(origin_url).port
    reader, writer = await socks_connect("127.0.0.1", socks_port, host, origin_port)
    writer.write(
        f"GET /added-at-runtime HTTP/1.1\r\nHost: {host}:{origin_port}\r\n"
        "Connection: close\r\n\r\n".encode()
    )
    await writer.drain()
    data = b""
    try:
        while b"\r\n\r\n" not in data or b"}" not in data.split(b"\r\n\r\n", 1)[-1]:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
            if not chunk:
                break
            data += chunk
    except TimeoutError:
        pass
    writer.close()

    assert b"200 OK" in data
    assert b"added-at-runtime" in data


async def test_a_listener_removed_at_runtime_is_closed(app, config):
    """A listener that is removed while the daemon runs stops accepting."""
    from intercept.core.config import ListenerConfig

    socks_port = _free_port()
    config.proxy.listeners.append(
        ListenerConfig(name="socks", host="127.0.0.1", port=socks_port, mode="socks")
    )
    await app.proxy.sync_listeners()

    config.proxy.listeners.clear()
    await app.proxy.sync_listeners()

    with pytest.raises((OSError, ConnectionError)):
        await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", socks_port), timeout=5
        )


async def test_the_socks_client_reaches_an_origin(app, origin_url, config):
    """The proxy reaches the origin through a SOCKS5 proxy when told to."""

    # A SOCKS proxy that simply connects to whatever it is asked for.
    async def socks_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            greeting = await reader.readexactly(2)
            await reader.readexactly(greeting[1])
            writer.write(bytes([0x05, 0x00]))
            await writer.drain()
            head = await reader.readexactly(4)
            atyp = head[3]
            if atyp == 0x03:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode()
                dport = struct.unpack("!H", await reader.readexactly(2))[0]
            else:
                host = socket.inet_ntoa(await reader.readexactly(4))
                dport = struct.unpack("!H", await reader.readexactly(2))[0]
            writer.write(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            remote_reader, remote_writer = await asyncio.open_connection(host, dport)
            await asyncio.gather(
                _pipe(reader, remote_writer),
                _pipe(remote_reader, writer),
            )
        except (ConnectionError, OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(socks_server, "127.0.0.1", 0)
    socks_port = server.sockets[0].getsockname()[1]
    try:
        config.proxy.upstream_proxy.enabled = True
        config.proxy.upstream_proxy.scheme = "socks5"
        config.proxy.upstream_proxy.host = "127.0.0.1"
        config.proxy.upstream_proxy.port = socks_port
        app.proxy.pool.upstream_proxy = config.proxy.upstream_proxy

        proxy = f"http://{config.proxy.host}:{config.proxy.port}"
        async with httpx.AsyncClient(proxy=proxy, timeout=10) as client:
            response = await client.get(
                f"{origin_url}/through-a-socks-chain",
                headers={"Connection": "close"},
            )
    finally:
        server.close()

    assert response.status_code == 200
    assert response.json()["path"] == "/through-a-socks-chain"


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------- chaining


async def test_the_origin_traffic_can_be_chained_through_a_proxy(
    app, config, origin_url, upstream_proxy
):
    """The request reaches the origin through the configured upstream proxy."""
    from intercept.core.config import UpstreamProxyConfig

    config.proxy.upstream_proxy = UpstreamProxyConfig(
        enabled=True,
        scheme="http",
        host=urlsplit(upstream_proxy).hostname,
        port=urlsplit(upstream_proxy).port,
    )
    app.proxy.pool.upstream_proxy = config.proxy.upstream_proxy

    proxy = f"http://{config.proxy.host}:{config.proxy.port}"
    async with httpx.AsyncClient(proxy=proxy, timeout=10) as client:
        response = await client.get(f"{origin_url}/chained")

    assert response.status_code == 200
    assert response.headers["x-chained-through"] == "yes"
    assert response.json()["path"] == "/chained"


# -------------------------------------------------------------- websockets


def _ws_accept(key: str) -> str:
    digest = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    return base64.b64encode(digest).decode()


def _ws_frame(payload: bytes, opcode: int = 0x1, mask: bool = False) -> bytes:
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append((0x80 if mask else 0x00) | length)
    else:
        header.append((0x80 if mask else 0x00) | 126)
        header.extend(length.to_bytes(2, "big"))
    if not mask:
        return bytes(header) + payload
    key = b"\x01\x02\x03\x04"
    header.extend(key)
    return bytes(header) + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def _ws_read_frame(data: bytes) -> tuple[int, bytes, int]:
    """Return the opcode, the payload and how many bytes the frame took."""
    opcode = data[0] & 0x0F
    masked = bool(data[1] & 0x80)
    length = data[1] & 0x7F
    offset = 2
    if length == 126:
        length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
    elif length == 127:
        length = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
    key = b""
    if masked:
        key = data[offset : offset + 4]
        offset += 4
    payload = data[offset : offset + length]
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return opcode, payload, offset + length


@pytest.fixture
def websocket_origin():
    """A WebSocket origin that echoes every frame it receives."""

    def serve(client: socket.socket) -> None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                return
            data += chunk
        headers = {}
        for line in data.split(b"\r\n"):
            if b":" in line:
                name, _, value = line.partition(b":")
                headers[name.decode().strip().lower()] = value.decode().strip()
        key = headers.get("sec-websocket-key", "")
        client.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {_ws_accept(key)}\r\n\r\n"
            ).encode()
        )
        buffer = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                return
            buffer += chunk
            while len(buffer) >= 2:
                _, payload, size = _ws_read_frame(buffer)
                if len(buffer) < size:
                    break
                buffer = buffer[size:]
                client.sendall(_ws_frame(payload))

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    thread = threading.Thread(target=_accept_loop, args=(server, serve), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.getsockname()[1]}"
    finally:
        server.close()


def _accept_loop(server: socket.socket, serve) -> None:
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=serve, args=(client,), daemon=True).start()


async def test_a_websocket_frame_can_be_edited(app, websocket_origin, config):
    """A held frame is replaced by the edited one before it goes on the wire."""
    config.proxy.intercept_websockets = True
    config.proxy.intercept_websocket_directions = ["client"]
    app.intercept.enabled = True

    async def decide_later() -> None:
        from intercept.proxy.websocket import WebSocketFrame

        # The upgrade request is held first, then the frame that follows it.
        for _ in range(300):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        assert app.intercept.pending_ids()
        app.intercept.resolve(app.intercept.pending_ids()[0], InterceptDecision("forward"))

        for _ in range(300):
            await asyncio.sleep(0.02)
            frames = app.intercept.frame_items()
            if not frames:
                continue
            frame = frames[0]
            replacement = WebSocketFrame(
                direction=frame["direction"], opcode=0x1, payload=b"edited frame"
            )
            app.intercept.resolve_frame(
                frame["id"], InterceptDecision("forward", frame=replacement)
            )
            return
        raise AssertionError("no frame was held")

    task = asyncio.create_task(decide_later())

    reader, writer = await asyncio.open_connection("127.0.0.1", config.proxy.port)
    writer.write(
        f"GET {websocket_origin}/ws HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    await writer.drain()
    head = await asyncio.wait_for(reader.read(4096), timeout=5)
    assert b"101" in head

    writer.write(_ws_frame(b"original frame", mask=True))
    await writer.drain()
    data = await asyncio.wait_for(reader.read(4096), timeout=5)
    writer.close()
    await task

    _, payload, _ = _ws_read_frame(data)
    assert payload == b"edited frame"


async def test_a_held_websocket_frame_can_be_dropped(app, websocket_origin, config):
    config.proxy.intercept_websockets = True
    config.proxy.intercept_websocket_directions = ["client"]
    app.intercept.enabled = True

    async def decide_later() -> None:
        for _ in range(300):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        assert app.intercept.pending_ids()
        app.intercept.resolve(app.intercept.pending_ids()[0], InterceptDecision("forward"))

        for _ in range(300):
            await asyncio.sleep(0.02)
            frames = app.intercept.frame_items()
            if not frames:
                continue
            app.intercept.resolve_frame(frames[0]["id"], InterceptDecision("drop"))
            return
        raise AssertionError("no frame was held")

    task = asyncio.create_task(decide_later())

    reader, writer = await asyncio.open_connection("127.0.0.1", config.proxy.port)
    writer.write(
        f"GET {websocket_origin}/ws HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    await writer.drain()
    await asyncio.wait_for(reader.read(4096), timeout=5)

    writer.write(_ws_frame(b"dropped frame", mask=True))
    await writer.drain()
    data = b""
    try:
        while b"dropped frame" not in data:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=2)
            if not chunk:
                break
            data += chunk
    except TimeoutError:
        pass
    writer.close()
    await task

    assert b"dropped frame" not in data


# -------------------------------------------------------------- annotation


async def test_a_response_can_be_annotated(app, client, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as http_client:
        await http_client.get(f"{origin_url}/annotated")
    await app.store.flush()

    items = await app.store.list()
    assert len(items) == 1
    exchange_id = items[0]["id"]

    annotated = await client.put(
        f"/api/traffic/{exchange_id}/annotation",
        json={"side": "response", "tags": ["interesting"], "notes": ["look at this"]},
    )
    assert annotated.status_code == 200

    detail = await app.store.get(exchange_id)
    assert detail["response"]["tags"] == ["interesting"]
    assert detail["response"]["notes"] == ["look at this"]


async def test_a_request_can_be_annotated(app, client, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as http_client:
        await http_client.get(f"{origin_url}/annotated")
    await app.store.flush()

    items = await app.store.list()
    exchange_id = items[0]["id"]

    await client.put(
        f"/api/traffic/{exchange_id}/annotation",
        json={"side": "request", "tags": ["replayed"]},
    )
    detail = await app.store.get(exchange_id)
    assert detail["request"]["tags"] == ["replayed"]
    assert detail["response"]["tags"] == []


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])

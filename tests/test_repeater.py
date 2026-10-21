"""Tests for the repeater: attempts, timing, comparison, HTTP/2 and WebSockets."""

from __future__ import annotations

import base64
import hashlib
import socket
import threading

import pytest

# --------------------------------------------------------------- fixtures


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


def _ws_read_frame(data: bytes) -> tuple[int, bytes]:
    """Return the opcode and the payload of the first frame in *data*."""
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
    return opcode, payload


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
                _, payload, size = _read_frame(buffer)
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


def _read_frame(data: bytes) -> tuple[int, bytes, int]:
    opcode, payload = _ws_read_frame(data)
    masked = bool(data[1] & 0x80)
    length = data[1] & 0x7F
    offset = 2
    if length == 126:
        length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
    elif length == 127:
        length = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
    if masked:
        offset += 4
    return opcode, payload, offset + length


def _accept_loop(server: socket.socket, serve) -> None:
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=serve, args=(client,), daemon=True).start()


# ------------------------------------------------------------------ attempts


async def test_every_attempt_is_kept_with_its_timing(client, origin_url):
    """The tab keeps the attempts, so two answers can be compared later."""
    created = await client.post(
        "/api/repeater/tabs",
        json={"method": "GET", "url": f"{origin_url}/attempted"},
    )
    assert created.status_code == 200
    tab = created.json()

    for _ in range(3):
        sent = await client.post(
            f"/api/repeater/tabs/{tab['id']}/send", json={"tab_id": tab["id"]}
        )
        assert sent.status_code == 200

    listed = await client.get(f"/api/repeater/tabs/{tab['id']}")
    body = listed.json()
    assert body["attempt_count"] == 3
    assert len(body["attempts"]) == 3
    for attempt in body["attempts"]:
        assert attempt["response"]["status"] == 200
        assert attempt["elapsed_ms"] >= 0
        # The attempt has to carry the time the request really took.
        assert attempt["elapsed_ms"] == attempt["response"]["elapsed_ms"]

    timing = body["timing"]
    assert timing["count"] == 3
    assert timing["fastest"] <= timing["slowest"]
    assert timing["average"] >= timing["fastest"]
    assert timing["last"] == body["attempts"][-1]["elapsed_ms"]


async def test_an_earlier_attempt_can_be_sent_again(client, origin_url):
    """An earlier attempt of the tab can be replayed."""
    created = await client.post(
        "/api/repeater/tabs",
        json={"method": "GET", "url": f"{origin_url}/replayed"},
    )
    tab = created.json()
    await client.post(f"/api/repeater/tabs/{tab['id']}/send", json={"tab_id": tab["id"]})

    resent = await client.post(
        f"/api/repeater/tabs/{tab['id']}/resend", json={"attempt": 0}
    )
    assert resent.status_code == 200
    assert resent.json()["response"]["status"] == 200

    listed = await client.get(f"/api/repeater/tabs/{tab['id']}")
    assert listed.json()["attempt_count"] == 2

    missing = await client.post(
        f"/api/repeater/tabs/{tab['id']}/resend", json={"attempt": 9}
    )
    assert missing.status_code == 404


async def test_the_attempts_can_be_compared(client, origin_url):
    """Two attempts of the tab are both there, with their own bodies."""
    created = await client.post(
        "/api/repeater/tabs",
        json={"method": "GET", "url": f"{origin_url}/compared"},
    )
    tab = created.json()
    await client.post(f"/api/repeater/tabs/{tab['id']}/send", json={"tab_id": tab["id"]})
    await client.post(f"/api/repeater/tabs/{tab['id']}/send", json={"tab_id": tab["id"]})

    listed = await client.get(f"/api/repeater/tabs/{tab['id']}")
    attempts = listed.json()["attempts"]
    assert len(attempts) == 2
    for attempt in attempts:
        assert attempt["response"]["body"]
        assert attempt["request"]["url"].endswith("/compared")


# --------------------------------------------------------------------- http2


async def test_a_request_can_be_sent_over_http2(client, origin_url):
    """The HTTP/2 switch falls back to HTTP/1.x when the origin has no h2."""
    created = await client.post(
        "/api/repeater/tabs",
        json={"method": "GET", "url": f"{origin_url}/over-h2"},
    )
    tab = created.json()
    sent = await client.post(
        f"/api/repeater/tabs/{tab['id']}/send", json={"tab_id": tab["id"], "http2": True}
    )
    assert sent.status_code == 200
    assert sent.json()["response"]["status"] == 200


# ---------------------------------------------------------------- websockets


async def test_a_websocket_connection_can_be_opened_and_used(client, websocket_origin):
    """The repeater completes the handshake and exchanges frames."""
    created = await client.post(
        "/api/repeater/tabs",
        json={
            "method": "GET",
            "url": f"{websocket_origin}/ws",
            "headers": {
                "Connection": ["Upgrade"],
                "Upgrade": ["websocket"],
                "Sec-WebSocket-Version": ["13"],
            },
        },
    )
    assert created.status_code == 200
    tab = created.json()

    opened = await client.post(f"/api/repeater/tabs/{tab['id']}/websocket/open")
    assert opened.status_code == 200
    assert opened.json()["status"] == 101
    assert opened.json()["open"] is True

    sent = await client.post(
        f"/api/repeater/tabs/{tab['id']}/websocket/send",
        json={"text": "hello", "opcode": "text"},
    )
    assert sent.status_code == 200
    assert sent.json()["text"] == "hello"

    received = await client.post(
        f"/api/repeater/tabs/{tab['id']}/websocket/receive", json={"timeout": 5}
    )
    assert received.status_code == 200
    frames = received.json()["frames"]
    assert frames
    assert frames[0]["text"] == "hello"
    assert frames[0]["direction"] == "server"

    state = await client.get(f"/api/repeater/tabs/{tab['id']}/websocket")
    assert state.status_code == 200
    body = state.json()
    assert len(body["sent"]) == 1
    assert len(body["received"]) == 1

    closed = await client.post(f"/api/repeater/tabs/{tab['id']}/websocket/close")
    assert closed.status_code == 200
    after = await client.get(f"/api/repeater/tabs/{tab['id']}/websocket")
    assert after.json()["open"] is False


async def test_a_frame_is_answered_with_an_error_when_nothing_is_open(client, origin_url):
    """Sending a frame without a connection is reported, not ignored."""
    created = await client.post(
        "/api/repeater/tabs",
        json={"method": "GET", "url": f"{origin_url}/not-open"},
    )
    tab = created.json()
    sent = await client.post(
        f"/api/repeater/tabs/{tab['id']}/websocket/send", json={"text": "hello"}
    )
    assert sent.status_code == 409


async def test_opening_a_websocket_on_a_tab_that_is_not_there_is_reported(client):
    """A tab that does not exist answers with a 404."""
    response = await client.post("/api/repeater/tabs/nope/websocket/open")
    assert response.status_code == 404


# --------------------------------------------------------------------- bodies


async def test_a_binary_body_keeps_its_bytes(client, origin_url):
    """A body that is not text travels as base64, so nothing is lost."""
    from intercept.core.models import Headers, Response

    payload = bytes(range(256))
    response = Response(
        status=200,
        headers=Headers([("Content-Type", "application/octet-stream")]),
        body=payload,
    )
    body, encoding = response.to_dict()["body"], response.to_dict()["body_encoding"]
    assert encoding == "base64"
    assert base64.b64decode(body) == payload


async def test_a_text_body_stays_text(client, origin_url):
    """A body that is text is not turned into base64."""
    from intercept.core.models import Response

    response = Response(status=200, body=b'{"a": 1}')
    assert response.to_dict()["body_encoding"] == "utf-8"
    assert response.to_dict()["body"] == '{"a": 1}'

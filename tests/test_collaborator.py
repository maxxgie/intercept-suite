"""Tests for the collaborator: the payloads, the calls and the check."""

from __future__ import annotations

import asyncio
import re
import struct
import time
from typing import Any
from urllib.parse import unquote

import httpx
import pytest
from conftest import free_port

from intercept.core.config import CollaboratorConfig
from intercept.scanner.checks import check_catalog
from intercept.scanner.engine import Scanner
from intercept.scanner.oob import CollaboratorCheck
from intercept.scanner.target import Endpoint
from intercept.tools.collaborator import (
    COLLABORATOR_KINDS,
    Collaborator,
    build_payload,
    new_token,
)

# ------------------------------------------------------------------- payloads


def test_a_token_is_hard_to_guess():
    first = new_token()
    second = new_token()
    assert first != second
    assert len(first) == 10


def test_the_http_payload_is_the_url():
    payload = build_payload("http", "", "tok", "http://127.0.0.1:9001", "d.local")
    assert payload["url"] == "http://127.0.0.1:9001/?id=tok"
    assert payload["payload"] == payload["url"]
    assert payload["token"] == "tok"


def test_the_xxe_payload_reads_the_url():
    payload = build_payload("xxe", "", "tok", "http://127.0.0.1:9001", "d.local")
    assert "<!ENTITY xxe SYSTEM" in payload["payload"]
    assert "http://127.0.0.1:9001/?id=tok" in payload["payload"]
    assert "&xxe;" in payload["payload"]


def test_the_ssrf_payload_goes_where_it_is_told():
    payload = build_payload(
        "ssrf", "http://target/?next={COLLAB}", "tok", "http://127.0.0.1:9001", "d.local"
    )
    assert payload["payload"] == "http://target/?next=http://127.0.0.1:9001/?id=tok"


def test_the_sql_payload_reads_the_url():
    payload = build_payload("sqli", "", "tok", "http://127.0.0.1:9001", "d.local")
    assert "http://127.0.0.1:9001/?id=tok" in payload["payload"]
    assert "UNION" in payload["payload"].upper()


def test_the_command_payload_calls_the_url():
    payload = build_payload("rce", "", "tok", "http://127.0.0.1:9001", "d.local")
    assert "http://127.0.0.1:9001/?id=tok" in payload["payload"]


def test_the_dns_payload_is_a_name_under_the_domain():
    payload = build_payload("dns", "", "tok", "http://127.0.0.1:9001", "d.local")
    assert payload["payload"] == "tok.d.local"
    assert payload["hostname"] == "tok.d.local"


def test_the_smtp_payload_is_an_address():
    payload = build_payload(
        "smtp", "", "tok", "http://127.0.0.1:9001", "d.local", "127.0.0.1"
    )
    assert payload["payload"] == "mailto:tok@127.0.0.1"


def test_the_extra_data_is_carried_along():
    payload = build_payload(
        "http", "", "tok", "http://127.0.0.1:9001", "d.local", "", "the id is 42"
    )
    assert "d=the%20id%20is%2042" in payload["url"]


def test_an_unknown_kind_is_refused():
    with pytest.raises(ValueError):
        build_payload("telepathy", "", "tok", "http://127.0.0.1:9001", "d.local")


def test_every_kind_the_interface_offers_can_be_built():
    for kind in COLLABORATOR_KINDS:
        payload = build_payload(kind, "", "tok", "http://127.0.0.1:9001", "tok.d.local")
        assert payload["payload"]
        assert payload["label"]


# -------------------------------------------------------------------- server


@pytest.fixture
async def collaborator():
    """A collaborator with its listeners on free ports."""
    config = CollaboratorConfig(host="127.0.0.1", port=0, dns_port=0, smtp_port=0)
    server = Collaborator(config)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


async def test_the_collaborator_listens(collaborator):
    status = collaborator.status()
    assert status["running"] is True
    assert status["port"] > 0
    assert status["url"].startswith("http://127.0.0.1:")


async def test_an_http_call_is_recorded(collaborator):
    token = "abc1234567"
    reader, writer = await asyncio.open_connection("127.0.0.1", collaborator.http_port)
    try:
        writer.write(
            (
                f"GET /?id={token} HTTP/1.1\r\n"
                "Host: collaborator\r\n"
                "X-Test: hello\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            ).encode()
        )
        await writer.drain()
        answer = await asyncio.wait_for(reader.read(200), timeout=5)
    finally:
        writer.close()

    assert b"200 OK" in answer
    assert b"collaborator" in answer

    await asyncio.sleep(0.1)
    assert len(collaborator.interactions) == 1
    interaction = collaborator.interactions[0]
    assert interaction.kind == "http"
    assert interaction.token == token
    assert interaction.headers.get("X-Test") == "hello"


async def test_the_body_of_the_call_is_kept(collaborator):
    token = "bodytoken1"
    reader, writer = await asyncio.open_connection("127.0.0.1", collaborator.http_port)
    try:
        body = b"the secret is 7"
        writer.write(
            (
                f"POST /?id={token} HTTP/1.1\r\n"
                "Host: collaborator\r\n"
                f"Content-Length: {len(body)}\r\n"
                "\r\n"
            ).encode()
            + body
        )
        await writer.drain()
        await asyncio.wait_for(reader.read(200), timeout=5)
    finally:
        writer.close()

    await asyncio.sleep(0.1)
    assert collaborator.interactions[0].body == "the secret is 7"


async def test_the_token_can_be_carried_in_a_header(collaborator):
    token = "headertoken"
    reader, writer = await asyncio.open_connection("127.0.0.1", collaborator.http_port)
    try:
        writer.write(
            (
                "GET / HTTP/1.1\r\n"
                "Host: collaborator\r\n"
                f"X-Collaborator-Token: {token}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            ).encode()
        )
        await writer.drain()
        await asyncio.wait_for(reader.read(200), timeout=5)
    finally:
        writer.close()

    await asyncio.sleep(0.1)
    assert collaborator.interactions[0].token == token


def _dns_query(name: str, qtype: int = 1) -> bytes:
    """A DNS query for a name."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    body = b""
    for part in name.split("."):
        body += bytes([len(part)]) + part.encode()
    body += b"\x00"
    return header + body + struct.pack("!HH", qtype, 1)


class _DatagramCollector(asyncio.DatagramProtocol):
    """A protocol that keeps the datagrams that arrive."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.queue.put_nowait(data)


async def test_a_dns_query_is_recorded(collaborator):
    if not collaborator.dns_port:
        pytest.skip("the DNS listener could not be opened")

    name = f"{new_token()}.{collaborator.domain}"
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _DatagramCollector, remote_addr=("127.0.0.1", collaborator.dns_port)
    )
    try:
        transport.sendto(_dns_query(name))
        answer = await asyncio.wait_for(protocol.queue.get(), timeout=5)
    finally:
        transport.close()

    assert answer
    await asyncio.sleep(0.1)
    assert len(collaborator.interactions) == 1
    interaction = collaborator.interactions[0]
    assert interaction.kind == "dns"
    assert interaction.token == name.split(".")[0]
    assert interaction.detail == name


async def test_an_smtp_call_is_recorded(collaborator):
    if not collaborator.smtp_port:
        pytest.skip("the SMTP listener could not be opened")

    token = "mailtoken12"
    reader, writer = await asyncio.open_connection("127.0.0.1", collaborator.smtp_port)
    try:
        greeting = await asyncio.wait_for(reader.readline(), timeout=5)
        assert greeting.startswith(b"220")
        # Every command but the body of the mail is answered.
        commands = [
            "EHLO tester",
            "MAIL FROM:<attacker@example.com>",
            f"RCPT TO:<{token}@{collaborator.public_host}>",
            "DATA",
        ]
        for command in commands:
            writer.write(f"{command}\r\n".encode())
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=5)

        writer.write(b"the body of the mail\r\n.\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5)

        writer.write(b"QUIT\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=5)
    finally:
        writer.close()

    await asyncio.sleep(0.1)
    assert len(collaborator.interactions) == 1
    interaction = collaborator.interactions[0]
    assert interaction.kind == "smtp"
    assert interaction.token == token
    assert "the body of the mail" in interaction.body


async def test_the_recorded_calls_can_be_thrown_away(collaborator):
    reader, writer = await asyncio.open_connection("127.0.0.1", collaborator.http_port)
    try:
        writer.write(b"GET /?id=abc HTTP/1.1\r\nHost: c\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(200), timeout=5)
    finally:
        writer.close()
    await asyncio.sleep(0.1)

    assert collaborator.clear() == 1
    assert collaborator.interactions == []


async def test_a_call_is_found_by_its_token(collaborator):
    reader, writer = await asyncio.open_connection("127.0.0.1", collaborator.http_port)
    try:
        writer.write(b"GET /?id=findme HTTP/1.1\r\nHost: c\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(200), timeout=5)
    finally:
        writer.close()
    await asyncio.sleep(0.1)

    assert collaborator.find(["findme"]) is not None
    assert collaborator.find(["nothing"]) is None
    found = await collaborator.wait_for(["findme"], timeout=1)
    assert found is not None
    assert await collaborator.wait_for(["nothing"], timeout=0.2) is None


# ----------------------------------------------------------------- the check


class _CallbackClient:
    """A client whose requests make the target call the collaborator."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, request: Any) -> Any:
        url = request.url
        self.sent.append(url)
        match = re.search(r"http://127\.0\.0\.1:\d+/\?id=[0-9a-f]+", unquote(url))
        if match:
            async with httpx.AsyncClient(timeout=5) as client:
                await client.get(match.group(0))
        return None


def test_the_check_is_part_of_the_catalog():
    assert any(entry["id"] == "oob-callback" for entry in check_catalog())


async def test_the_check_reports_a_callback(collaborator):
    check = CollaboratorCheck()
    check.collaborator = collaborator
    endpoint = Endpoint(url="http://target.test/page?q=hello")

    findings = await check.run(_CallbackClient(), endpoint)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "oob-callback"
    assert finding.severity == "high"
    assert "collaborator" in finding.title.lower()
    assert "q" in finding.title


class _QuietClient:
    """A client whose requests make nothing happen."""

    async def send(self, request: Any) -> Any:
        return None


async def test_the_check_says_nothing_when_nothing_calls_back(collaborator):
    check = CollaboratorCheck()
    check.collaborator = collaborator
    check.wait = 0.3
    findings = await check.run(_QuietClient(), Endpoint(url="http://target.test/?q=1"))
    assert findings == []


async def test_the_check_does_nothing_without_a_collaborator():
    check = CollaboratorCheck()
    findings = await check.run(_CallbackClient(), Endpoint(url="http://target.test/?q=1"))
    assert findings == []


async def test_the_scanner_hands_the_collaborator_over(collaborator):
    scanner = Scanner(_CallbackClient(), None, None, None, collaborator=collaborator)
    check = CollaboratorCheck()
    check.wait = 0.5
    endpoint = Endpoint(url="http://target.test/page?q=hello")

    findings = await scanner._call(check, endpoint)

    assert len(findings) == 1
    assert findings[0].check_id == "oob-callback"


async def test_the_scanner_hands_over_its_own_collaborator(collaborator):
    """The built in checks are shared, so a stale one must not be kept."""
    check = CollaboratorCheck()
    check.collaborator = object()
    scanner = Scanner(_CallbackClient(), None, None, None, collaborator=collaborator)

    await scanner._call(check, Endpoint(url="http://target.test/page?q=hello"))

    assert check.collaborator is collaborator


async def test_the_check_waits_for_the_time_that_is_configured(collaborator):
    """The length of the wait is a setting, not a fixed number."""
    collaborator.config.wait = 0.2
    check = CollaboratorCheck()
    check.collaborator = collaborator

    started = time.monotonic()
    findings = await check.run(_QuietClient(), Endpoint(url="http://target.test/?q=1"))
    elapsed = time.monotonic() - started

    assert findings == []
    assert elapsed < 2


async def test_the_payload_says_where_to_ask(collaborator):
    payload = collaborator.payload("dns")
    assert payload["dns_server"] == collaborator.status()["dns_server"]
    assert payload["smtp_server"] == collaborator.status()["smtp_server"]


# --------------------------------------------------------------------- the API


async def test_the_status_is_reported(client, app):
    response = await client.get("/api/collaborator")
    assert response.status_code == 200
    data = response.json()
    assert data["running"] is True
    assert data["url"].startswith("http://")
    assert {item["kind"] for item in data["kinds"]} == set(COLLABORATOR_KINDS)


async def test_a_payload_is_built(client):
    response = await client.post(
        "/api/collaborator/payload",
        json={"kind": "http", "target": "", "extra": ""},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["token"]
    assert data["url"].startswith("http://")


async def test_an_unknown_kind_is_refused_by_the_api(client):
    response = await client.post(
        "/api/collaborator/payload", json={"kind": "telepathy"}
    )
    assert response.status_code == 400


async def test_the_calls_are_listed(client, app):
    token = "listtoken1"
    reader, writer = await asyncio.open_connection("127.0.0.1", app.collaborator.http_port)
    try:
        writer.write(
            f"GET /?id={token} HTTP/1.1\r\nHost: c\r\nContent-Length: 0\r\n\r\n".encode()
        )
        await writer.drain()
        await asyncio.wait_for(reader.read(200), timeout=5)
    finally:
        writer.close()
    await asyncio.sleep(0.1)

    response = await client.get("/api/collaborator/interactions")
    assert response.status_code == 200
    items = response.json()["items"]
    assert items[0]["token"] == token

    filtered = await client.get(f"/api/collaborator/interactions?token={token}")
    assert len(filtered.json()["items"]) == 1

    other = await client.get("/api/collaborator/interactions?token=nothing")
    assert other.json()["items"] == []

    cleared = await client.delete("/api/collaborator/interactions")
    assert cleared.json()["removed"] == 1


async def test_the_collaborator_can_be_stopped_and_started(client):
    stopped = await client.post("/api/collaborator/stop", json={})
    assert stopped.status_code == 200
    assert stopped.json()["running"] is False

    started = await client.post("/api/collaborator/start", json={})
    assert started.status_code == 200
    assert started.json()["running"] is True


async def test_the_collaborator_follows_the_configuration(client, app):
    off = await client.put("/api/config", json={"collaborator": {"enabled": False}})
    assert off.status_code == 200
    assert off.json()["collaborator"]["enabled"] is False
    assert app.collaborator.status()["running"] is False

    on = await client.put("/api/config", json={"collaborator": {"enabled": True}})
    assert on.json()["collaborator"]["enabled"] is True
    assert app.collaborator.status()["running"] is True


async def test_the_public_address_can_be_changed(client):
    changed = await client.put(
        "/api/config", json={"collaborator": {"public_host": "10.0.0.5"}}
    )
    assert changed.status_code == 200
    assert changed.json()["collaborator"]["public_host"] == "10.0.0.5"

    status = (await client.get("/api/collaborator")).json()
    assert status["url"].startswith("http://10.0.0.5:")


async def test_a_new_port_takes_effect_at_once(client, app):
    """The listeners are opened again when the ports change."""
    before = app.collaborator.status()["port"]
    wanted = free_port()

    changed = await client.put(
        "/api/config", json={"collaborator": {"port": wanted}}
    )
    assert changed.status_code == 200

    status = app.collaborator.status()
    assert status["running"] is True
    assert status["port"] == wanted
    assert status["port"] != before


async def test_the_calls_are_kept_when_the_listeners_are_opened_again(client, app):
    """Opening the listeners again does not throw the calls away."""
    token = "kepttoken1"
    reader, writer = await asyncio.open_connection("127.0.0.1", app.collaborator.http_port)
    try:
        writer.write(
            f"GET /?id={token} HTTP/1.1\r\nHost: c\r\nContent-Length: 0\r\n\r\n".encode()
        )
        await writer.drain()
        await asyncio.wait_for(reader.read(200), timeout=5)
    finally:
        writer.close()
    await asyncio.sleep(0.1)

    await client.put("/api/config", json={"collaborator": {"port": free_port()}})

    assert app.collaborator.status()["interactions"] == 1

"""Tests for the REST and WebSocket API."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import uvicorn
import websockets
from conftest import free_port

from intercept.api.app import create_api
from intercept.core.models import Request
from intercept.proxy.intercept import InterceptDecision


@pytest.fixture
async def client(app):
    api = create_api(app)
    transport = httpx.ASGITransport(app=api)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


async def test_health(client):
    response = await client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_state_reports_the_ca(client, app):
    response = await client.get("/api/state")
    data = response.json()
    assert data["ca"]["fingerprint"] == app.ca.fingerprint()
    assert data["proxy"]["port"] == app.config.proxy.port


async def test_traffic_listing_and_detail(client, app, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as browser:
        await browser.get(f"{origin_url}/api-check")
    await app.store.flush()

    listing = await client.get("/api/traffic")
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert len(items) == 1
    assert items[0]["path"] == "/api-check"

    detail = await client.get(f"/api/traffic/{items[0]['id']}")
    assert detail.status_code == 200
    assert detail.json()["response"]["status"] == 200


async def test_traffic_detail_404(client):
    response = await client.get("/api/traffic/nope")
    assert response.status_code == 404


async def test_repeater_tab_lifecycle(client, origin_url):
    created = await client.post(
        "/api/repeater/tabs",
        json={"method": "GET", "url": f"{origin_url}/repeat", "name": "tab one"},
    )
    assert created.status_code == 200
    tab = created.json()
    assert tab["name"] == "tab one"

    sent = await client.post(f"/api/repeater/tabs/{tab['id']}/send", json={"tab_id": tab["id"]})
    assert sent.status_code == 200
    assert sent.json()["response"]["status"] == 200

    listed = await client.get("/api/repeater/tabs")
    assert len(listed.json()["tabs"]) == 1

    deleted = await client.delete(f"/api/repeater/tabs/{tab['id']}")
    assert deleted.status_code == 200
    assert (await client.get("/api/repeater/tabs")).json()["tabs"] == []


async def test_scope_rules_can_be_added(client):
    added = await client.post(
        "/api/scope/rules", json={"pattern": "example.com", "kind": "include", "target": "host"}
    )
    assert added.status_code == 200
    assert len(added.json()["rules"]) == 1

    removed = await client.request("DELETE", "/api/scope/rules", params={"pattern": "example.com"})
    assert removed.status_code == 200
    assert removed.json()["rules"] == []


async def test_scope_rule_with_a_slash_can_be_removed(client):
    """A regular expression scope rule carries slashes, so it is removed by
    query parameter; the desktop shell sends the rule the same way."""
    added = await client.post(
        "/api/scope/rules", json={"pattern": "re:^/admin", "kind": "include", "target": "url"}
    )
    assert added.status_code == 200

    removed = await client.request("DELETE", "/api/scope/rules", params={"pattern": "re:^/admin"})
    assert removed.status_code == 200
    assert removed.json()["rules"] == []


async def test_config_update_keeps_the_sections_dataclasses(client, app):
    """Updating the configuration must not turn its sections into plain
    dictionaries, or every later reader of ``config.proxy.host`` breaks."""
    original_port = app.config.proxy.port
    response = await client.put("/api/config", json={"scan": {"concurrency": 8}})
    assert response.status_code == 200
    assert response.json()["scan"]["concurrency"] == 8

    assert app.config.scan.concurrency == 8
    assert app.config.proxy.port == original_port

    # The daemon must still be able to describe itself.
    state = await client.get("/api/state")
    assert state.status_code == 200
    assert state.json()["proxy"]["port"] == original_port


async def test_config_update_keeps_the_unpatched_values(client, app):
    """A partial patch only changes the fields it mentions."""
    before = app.config.proxy.upstream_timeout
    response = await client.put("/api/config", json={"proxy": {"port": app.config.proxy.port}})
    assert response.status_code == 200
    assert app.config.proxy.upstream_timeout == before


async def test_intercept_toggle(client):
    response = await client.post("/api/intercept/toggle", json={"enabled": True})
    assert response.status_code == 200
    assert response.json()["enabled"] is True


async def test_plugin_tools_are_listed(client):
    response = await client.get("/api/plugins")
    assert response.status_code == 200
    assert response.json()["tools"]


async def test_ca_certificate_can_be_downloaded(client):
    response = await client.get("/api/ca/download")
    assert response.status_code == 200
    assert response.content.startswith(b"-----BEGIN CERTIFICATE-----")


async def test_websocket_streams_traffic_events(app, origin_url, proxy_url):
    """The event stream pushes new exchanges to a connected client."""
    port = free_port()
    api = create_api(app)
    server = uvicorn.Server(
        uvicorn.Config(api, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    )
    task = asyncio.create_task(server.serve())
    for _ in range(100):
        await asyncio.sleep(0.05)
        if server.started:
            break
    assert server.started

    try:
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws") as socket:
            hello = json.loads(await asyncio.wait_for(socket.recv(), timeout=5))
            assert hello["type"] == "hello"

            async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as browser:
                await browser.get(f"{origin_url}/streamed")

            seen = None
            for _ in range(20):
                message = json.loads(await asyncio.wait_for(socket.recv(), timeout=5))
                if message["type"] == "response":
                    seen = message
                    break
            assert seen is not None
            assert seen["data"]["exchange"]["path"] == "/streamed"
    finally:
        server.should_exit = True
        await task


# ------------------------------------------------------------------- rules


async def test_a_rule_can_be_created_changed_and_removed(client, app):
    """The rule endpoints manage the rules the proxy applies."""
    created = await client.post(
        "/api/rules",
        json={
            "name": "hold the admin calls",
            "kind": "intercept",
            "host": "*.example.com",
            "path": "/admin/*",
            "method": "POST",
            "phase": "request",
        },
    )
    assert created.status_code == 200
    rule = created.json()
    assert rule["name"] == "hold the admin calls"
    assert rule["enabled"] is True

    listed = await client.get("/api/rules")
    assert listed.status_code == 200
    assert [item["id"] for item in listed.json()["rules"]] == [rule["id"]]

    # The engine must know about the rule straight away.
    assert any(item.id == rule["id"] for item in app.rules.rules)

    updated = await client.put(
        f"/api/rules/{rule['id']}",
        json={
            "name": "let the admin calls through",
            "kind": "forward",
            "host": "*.example.com",
            "path": "/admin/*",
            "method": "POST",
            "phase": "request",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["kind"] == "forward"
    assert any(
        item.id == rule["id"] and item.kind == "forward" for item in app.rules.rules
    )

    removed = await client.delete(f"/api/rules/{rule['id']}")
    assert removed.status_code == 200
    listed = await client.get("/api/rules")
    assert listed.json()["rules"] == []


async def test_a_missing_rule_is_reported(client):
    """Changing a rule that is not there answers with a 404."""
    response = await client.put(
        "/api/rules/nope",
        json={"name": "nothing", "kind": "intercept"},
    )
    assert response.status_code == 404


# -------------------------------------------------------------- listeners


async def test_a_listener_can_be_added_and_removed(client, app):
    """A listener is opened next to the main one, in the mode that was asked for."""
    response = await client.put(
        "/api/config",
        json={
            "proxy": {
                "listeners": [
                    {
                        "name": "phone",
                        "host": "127.0.0.1",
                        "port": 0,
                        "mode": "socks",
                        "enabled": True,
                    }
                ]
            }
        },
    )
    assert response.status_code == 200
    assert response.json()["proxy"]["listeners"][0]["mode"] == "socks"

    # The section must stay a dataclass, or the proxy breaks.
    assert app.config.proxy.listeners[0].name == "phone"
    assert app.config.proxy.listeners[0].mode == "socks"

    cleared = await client.put("/api/config", json={"proxy": {"listeners": []}})
    assert cleared.status_code == 200
    assert app.config.proxy.listeners == []


async def test_the_upstream_proxy_can_be_set(client, app):
    """The traffic can be chained through an upstream proxy."""
    response = await client.put(
        "/api/config",
        json={
            "proxy": {
                "upstream_proxy": {
                    "enabled": True,
                    "scheme": "socks5",
                    "host": "127.0.0.1",
                    "port": 1080,
                    "username": "user",
                    "password": "secret",
                }
            }
        },
    )
    assert response.status_code == 200
    assert app.config.proxy.upstream_proxy.enabled is True
    assert app.config.proxy.upstream_proxy.scheme == "socks5"
    assert app.config.proxy.upstream_proxy.port == 1080
    # The values that were not mentioned stay as they were.
    assert app.config.proxy.host == "127.0.0.1"


# -------------------------------------------------------------- intercept


async def test_a_held_message_can_be_read(client, app):
    """The text of a held message is available, so it can be shown and changed."""
    request = Request(method="GET", url="http://example.com/held")
    app.intercept.enabled = True
    task = asyncio.create_task(app.intercept.hold(request))
    await asyncio.sleep(0.05)

    listed = await client.get("/api/intercept")
    assert listed.status_code == 200
    assert listed.json()["pending_count"] == 1

    held = await client.get(f"/api/intercept/{request.id}")
    assert held.status_code == 200
    body = held.json()
    assert body["phase"] == "request"
    assert body["request"]["url"] == "http://example.com/held"
    assert body["response"] is None

    missing = await client.get("/api/intercept/does-not-exist")
    assert missing.status_code == 404

    app.intercept.resolve(request.id, InterceptDecision("forward"))
    await task


async def test_an_unknown_held_message_is_reported(client):
    """Asking for a message that is not held answers with a 404."""
    response = await client.get("/api/intercept/nope")
    assert response.status_code == 404


async def test_a_held_response_can_be_edited(client, app):
    """The response that is held may be changed before it is let through."""
    from intercept.core.models import Headers, Response

    request = Request(method="GET", url="http://example.com/edited")
    response = Response(
        status=200,
        reason="OK",
        headers=Headers([("Content-Type", "text/plain")]),
        body=b"original",
    )
    app.intercept.enabled = True
    task = asyncio.create_task(app.intercept.hold_response(request, response))
    await asyncio.sleep(0.05)

    decided = await client.post(
        f"/api/intercept/{request.id}",
        json={
            "action": "forward",
            "status": 404,
            "response_headers": {"Content-Type": ["text/html"]},
            "response_body": "edited body",
        },
    )
    assert decided.status_code == 200

    decision = await task
    assert decision.action == "forward"
    assert decision.response is not None
    assert decision.response.status == 404
    assert decision.response.body == b"edited body"
    assert decision.response.headers.get("Content-Type") == "text/html"


async def test_a_held_request_can_be_edited(client, app):
    """The request that is held may be changed before it is let through."""
    request = Request(
        method="GET",
        url="http://example.com/edit-me",
        headers={"X-Test": "1"},
    )
    app.intercept.enabled = True
    task = asyncio.create_task(app.intercept.hold(request))
    await asyncio.sleep(0.05)

    decided = await client.post(
        f"/api/intercept/{request.id}",
        json={
            "action": "forward",
            "raw": "GET http://example.com/edit-me HTTP/1.1\r\nHost: example.com\r\n",
            "url": "http://example.com/edit-me",
            "method": "GET",
            "headers": {"X-Test": ["2"]},
            "body": "new body",
        },
    )
    assert decided.status_code == 200

    decision = await task
    assert decision.request is not None
    assert decision.request.headers.get("X-Test") == "2"
    assert decision.request.body == b"new body"


async def test_a_held_frame_can_be_edited(client, app):
    """A held WebSocket frame may be changed before it is let through."""
    from intercept.proxy.websocket import WebSocketFrame

    frame = WebSocketFrame(direction="client", opcode=0x1, payload=b"original")
    app.intercept.enabled = True
    task = asyncio.create_task(app.intercept.hold_frame(frame))
    await asyncio.sleep(0.05)

    listed = await client.get("/api/intercept")
    assert listed.json()["frames"][0]["text"] == "original"

    decided = await client.post(
        "/api/intercept/frames/ws-1", json={"action": "forward", "text": "edited"}
    )
    assert decided.status_code == 200

    decision = await task
    assert decision.frame is not None
    assert decision.frame.payload == b"edited"


async def test_a_held_frame_can_be_dropped(client, app):
    """A held WebSocket frame may be thrown away."""
    from intercept.proxy.websocket import WebSocketFrame

    frame = WebSocketFrame(direction="client", opcode=0x1, payload=b"throw away")
    app.intercept.enabled = True
    task = asyncio.create_task(app.intercept.hold_frame(frame))
    await asyncio.sleep(0.05)

    decided = await client.post("/api/intercept/frames/ws-1", json={"action": "drop"})
    assert decided.status_code == 200

    decision = await task
    assert decision.action == "drop"
    assert decision.frame is None


# ------------------------------------------------------------ annotations


async def test_a_request_and_a_response_can_be_annotated(client, app, origin_url, proxy_url):
    """Remarks are kept for the request and for the response on their own."""
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as browser:
        await browser.get(f"{origin_url}/annotated")
    await app.store.flush()

    items = await client.get("/api/traffic?limit=10")
    assert items.status_code == 200
    exchange = items.json()["items"][0]

    marked = await client.put(
        f"/api/traffic/{exchange['id']}/annotation",
        json={"side": "request", "tags": ["interesting"], "notes": ["look again"]},
    )
    assert marked.status_code == 200
    assert marked.json()["tags"] == ["interesting"]

    marked = await client.put(
        f"/api/traffic/{exchange['id']}/annotation",
        json={"side": "response", "tags": ["leaky"], "notes": ["it leaks"]},
    )
    assert marked.status_code == 200

    detail = await client.get(f"/api/traffic/{exchange['id']}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["request"]["tags"] == ["interesting"]
    assert body["request"]["notes"] == ["look again"]
    assert body["response"]["tags"] == ["leaky"]
    assert body["response"]["notes"] == ["it leaks"]


async def test_annotating_an_unknown_exchange_is_reported(client):
    """Annotating an exchange that is not there answers with a 404."""
    response = await client.put(
        "/api/traffic/nope/annotation", json={"side": "request", "tags": ["x"]}
    )
    assert response.status_code == 404

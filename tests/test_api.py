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

"""End to end tests for the proxy: plain forwarding, TLS interception and hold."""

from __future__ import annotations

import http.server
import ssl
import threading

import httpx
import pytest
from conftest import _Handler

from intercept.core.models import Request
from intercept.proxy.intercept import InterceptDecision


async def test_plain_request_is_forwarded_and_recorded(app, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/hello?x=1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["path"] == "/hello?x=1"
    assert payload["method"] == "GET"
    assert response.headers["x-origin-server"] == "intercept-tests"

    await app.store.flush()
    items = await app.store.list()
    assert len(items) == 1
    assert items[0]["method"] == "GET"
    assert items[0]["status"] == 200
    assert items[0]["host"] == "127.0.0.1"
    assert items[0]["origin"] == "proxy"


async def test_post_body_is_forwarded(app, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.post(f"{origin_url}/submit", json={"a": 1})

    assert response.status_code == 200
    assert response.json()["body"] == '{"a":1}'


async def test_request_headers_are_preserved(app, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/h", headers={"X-Custom": "yes"})

    assert response.json()["headers"]["x-custom"] == "yes"


async def test_upstream_failure_returns_bad_gateway(app, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get("http://127.0.0.1:1/nothing")

    assert response.status_code == 502


@pytest.fixture
def tls_origin(app):
    """An HTTPS origin whose certificate is issued by the proxy CA."""
    leaf = app.ca.leaf("localhost")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(leaf.cert_path), str(leaf.key_path))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


async def test_https_is_intercepted_and_decrypted(app, tls_origin, proxy_url):
    port = tls_origin.server_address[1]
    verify = str(app.ca.root_cert_path)

    async with httpx.AsyncClient(proxy=proxy_url, verify=verify, timeout=10) as client:
        response = await client.get(f"https://localhost:{port}/secure")

    assert response.status_code == 200
    assert response.json()["path"] == "/secure"

    await app.store.flush()
    items = await app.store.list()
    assert len(items) == 1
    assert items[0]["scheme"] == "https"
    assert items[0]["status"] == 200


async def test_intercept_holds_the_request_until_decided(app, origin_url, proxy_url):
    app.intercept.enabled = True

    async def decide_later() -> None:
        import asyncio

        for _ in range(100):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        request_id = app.intercept.pending_ids()[0]
        app.intercept.resolve(request_id, InterceptDecision("forward"))

    import asyncio

    task = asyncio.create_task(decide_later())
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/held")
    await task

    assert response.status_code == 200
    assert response.json()["path"] == "/held"


async def test_intercept_can_drop_a_request(app, origin_url, proxy_url):
    app.intercept.enabled = True

    import asyncio

    async def drop_later() -> None:
        for _ in range(100):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        app.intercept.resolve(app.intercept.pending_ids()[0], InterceptDecision("drop"))

    task = asyncio.create_task(drop_later())
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        with pytest.raises(httpx.RemoteProtocolError):
            await client.get(f"{origin_url}/dropped")
    await task


async def test_repeater_handles_absolute_form_requests(app, origin_url, proxy_url):
    """A request captured from a forward proxy keeps an absolute request target."""
    from intercept.tools.repeater import request_from_raw

    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        await client.get(f"{origin_url}/absolute")
    await app.store.flush()

    items = await app.store.list()
    raw = (await app.store.get(items[0]["id"]))["request"]["raw"]
    assert raw.startswith("GET http://")

    request = request_from_raw(raw)
    assert request.url.startswith("http://")
    assert request.origin_form == "/absolute"

    tab = app.repeater.create_tab(request)
    response = await app.repeater.send(tab.id)
    assert response is not None
    assert response.status == 200
    assert b"absolute" in response.body


async def test_repeater_sends_an_edited_request(app, origin_url):
    request = Request(
        method="POST",
        url=f"{origin_url}/repeater",
        headers={"Content-Type": "application/json"},
        body=b'{"edited": true}',
    )
    tab = app.repeater.create_tab(request, "test")
    response = await app.repeater.send(tab.id)

    assert response is not None
    assert response.status == 200
    assert response.body and b"edited" in response.body

    await app.store.flush()
    items = await app.store.list(origin="repeater")
    assert len(items) == 1
    assert items[0]["method"] == "POST"

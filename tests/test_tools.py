"""Tests for the spider and the plugin manager."""

from __future__ import annotations

import http.server
import threading

import pytest

from intercept.plugins.api import PluginAPI, Tool
from intercept.store.sitemap import ScopeRule
from intercept.tools.spider import LinkParser


class _SiteHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    pages = {
        "/": b'<html><a href="/one">one</a><a href="/two">two</a></html>',
        "/one": b'<html><a href="/deep">deep</a></html>',
        "/two": b'<html>no links</html>',
        "/deep": b'<html>bottom</html>',
    }

    def do_GET(self) -> None:
        body = self.pages.get(self.path, b"<html>missing</html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


@pytest.fixture
def site_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def test_link_parser_collects_links():
    parser = LinkParser()
    parser.feed('<html><a href="/a">a</a><script src="/b.js"></script></html>')
    assert "/a" in parser.links
    assert "/b.js" in parser.links


async def test_spider_crawls_in_scope_links(app, site_server):
    host, port = site_server.server_address[:2]
    app.scope.add(ScopeRule(pattern="127.0.0.1", kind="include", target="host"))

    job = await app.spider.start([f"http://{host}:{port}/"])
    for _ in range(200):
        await __import__("asyncio").sleep(0.05)
        if job.state in ("finished", "stopped"):
            break

    assert job.state == "finished"
    assert job.crawled >= 4
    assert any("/one" in url for url in job.found)
    assert any("/deep" in url for url in job.found)


async def test_spider_respects_scope(app, site_server):
    host, port = site_server.server_address[:2]
    # No include rule, so nothing is in scope and nothing is followed.
    job = await app.spider.start([f"http://{host}:{port}/"])
    for _ in range(100):
        await __import__("asyncio").sleep(0.05)
        if job.state in ("finished", "stopped"):
            break
    assert job.crawled == 1


async def test_example_plugin_loads_and_runs(app):
    tools = app.plugins.describe_tools()
    assert tools, "the bundled example plugin should register a tool"
    tool = next(t for t in tools if t["id"].endswith("convert"))

    result = await app.plugins.run_tool(
        tool["id"], {"value": "a b", "mode": "encode", "encoding": "url"}
    )
    assert result["output"] == "a%20b"

    decoded = await app.plugins.run_tool(
        tool["id"], {"value": "a%20b", "mode": "decode", "encoding": "url"}
    )
    assert decoded["output"] == "a b"


async def test_plugin_errors_are_reported_not_raised(app):
    class Broken(Tool):
        id = "broken"
        label = "Broken"

        async def run(self, context, values):
            raise RuntimeError("boom")

    api = PluginAPI(app.plugins, "test")
    api.add_tool(Broken())
    result = await app.plugins.run_tool("test.broken", {})
    assert "boom" in result["error"]

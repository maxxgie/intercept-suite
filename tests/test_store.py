"""Tests for the store, the site map and the scope rules."""

from __future__ import annotations

import pytest

from intercept.core.models import Exchange, Headers, Request, Response
from intercept.store.history import HistoryStore
from intercept.store.sitemap import Scope, ScopeRule


def make_exchange(url: str, method: str = "GET", status: int = 200) -> Exchange:
    request = Request(
        method=method,
        url=url,
        headers=Headers([("Host", "example.com")]),
    )
    response = Response(
        status=status,
        reason="OK",
        headers=Headers([("Content-Type", "text/html")]),
        body=b"<html><body>hi</body></html>",
    )
    return Exchange(request=request, response=response)


@pytest.fixture
async def store(tmp_path):
    store = HistoryStore(tmp_path / "history.db")
    await store.start()
    yield store
    await store.stop()


async def test_exchange_roundtrip(store):
    await store.add(make_exchange("http://example.com/a/b"))
    await store.flush()

    items = await store.list()
    assert len(items) == 1
    assert items[0]["url"] == "http://example.com/a/b"
    assert items[0]["status"] == 200
    assert items[0]["host"] == "example.com"

    detail = await store.get(items[0]["id"])
    assert detail is not None
    assert detail["request"]["method"] == "GET"
    assert detail["response"]["body"] == "<html><body>hi</body></html>"


async def test_filtering_by_host_and_origin(store):
    await store.add(make_exchange("http://a.test/1"))
    await store.add(make_exchange("http://b.test/2"))
    await store.flush()

    assert len(await store.list(host="a.test")) == 1
    assert len(await store.list()) == 2
    assert await store.count() == 2


async def test_clear_removes_everything(store):
    await store.add(make_exchange("http://a.test/1"))
    await store.flush()
    assert await store.clear() == 1
    assert await store.count() == 0


async def test_sitemap_tree_groups_paths_under_a_host(store):
    await store.add(make_exchange("http://example.com/api/users"))
    await store.add(make_exchange("http://example.com/api/orders"))
    await store.add(make_exchange("http://example.com/home"))
    await store.flush()

    from intercept.store.sitemap import SiteMap

    tree = await SiteMap(store).tree()
    assert len(tree) == 1
    root = tree[0]
    assert root["host"] == "example.com"
    names = {node["name"] for node in root["nodes"]}
    assert names == {"api", "home"}
    api = next(node for node in root["nodes"] if node["name"] == "api")
    assert {child["name"] for child in api["children"]} == {"users", "orders"}


def test_scope_defaults_to_excluding_everything():
    scope = Scope()
    assert scope.is_in_scope("http://example.com/") is False


def test_scope_include_and_exclude():
    scope = Scope(
        [
            ScopeRule(pattern="example.com", kind="include", target="host"),
            ScopeRule(pattern="admin", kind="exclude", target="url"),
        ]
    )
    assert scope.is_in_scope("http://example.com/page") is True
    assert scope.is_in_scope("http://example.com/admin/panel") is False
    assert scope.is_in_scope("http://other.test/page") is False


def test_scope_supports_regular_expressions():
    scope = Scope([ScopeRule(pattern="re:.*\\.internal$", kind="include", target="host")])
    assert scope.is_in_scope("http://svc.internal/") is True
    assert scope.is_in_scope("http://svc.public/") is False


def test_scope_roundtrips_through_a_file(tmp_path):
    scope = Scope([ScopeRule(pattern="example.com", kind="include", target="host")])
    path = tmp_path / "scope.json"
    scope.save(path)
    assert Scope.load(path).rules == scope.rules

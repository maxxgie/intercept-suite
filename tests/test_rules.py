"""Tests for the proxy rules: interception rules, auto-forwarding and replace."""

from __future__ import annotations

import asyncio

import httpx

from intercept.core.models import Headers, Request, Response
from intercept.proxy.intercept import InterceptDecision
from intercept.proxy.rules import Rule, RuleEngine, substitute, substitute_bytes


def make_request(
    method: str = "GET", url: str = "http://example.com/path", headers=None
) -> Request:
    return Request(
        method=method,
        url=url,
        headers=Headers(headers or [("User-Agent", "test/1.0")]),
    )


# ------------------------------------------------------------------ matching


def test_a_rule_matches_the_host_the_path_and_the_method():
    rule = Rule(id="1", host="*.example.com", path="/admin/*", method="POST")
    assert rule.matches(make_request("POST", "http://api.example.com/admin/users"))
    assert not rule.matches(make_request("GET", "http://api.example.com/admin/users"))
    assert not rule.matches(make_request("POST", "http://api.other.com/admin/users"))
    assert not rule.matches(make_request("POST", "http://api.example.com/public"))


def test_an_empty_match_field_matches_everything():
    rule = Rule(id="1")
    assert rule.matches(make_request("DELETE", "http://anything.test/x"))


def test_the_host_and_the_method_are_matched_case_insensitively():
    rule = Rule(id="1", host="EXAMPLE.com", method="get")
    assert rule.matches(make_request("GET", "http://example.com/"))


# -------------------------------------------------------------- interception


def test_without_a_rule_everything_is_held():
    engine = RuleEngine()
    assert engine.intercept_request(make_request())


def test_an_intercept_rule_narrows_what_is_held():
    engine = RuleEngine()
    engine.set_rules([Rule(id="1", kind="intercept", host="admin.test")])
    assert engine.intercept_request(make_request(url="http://admin.test/x"))
    assert not engine.intercept_request(make_request(url="http://other.test/x"))


def test_a_response_rule_only_holds_the_response():
    engine = RuleEngine()
    engine.set_rules([Rule(id="1", kind="intercept", phase="response")])
    assert not engine.intercept_request(make_request())
    assert engine.intercept_response(make_request())


def test_a_both_rule_holds_the_request_and_the_response():
    engine = RuleEngine()
    engine.set_rules([Rule(id="1", kind="intercept", phase="both")])
    assert engine.intercept_request(make_request())
    assert engine.intercept_response(make_request())


def test_a_disabled_rule_does_nothing():
    engine = RuleEngine()
    engine.set_rules([Rule(id="1", kind="intercept", enabled=False)])
    assert not engine.intercept_request(make_request())


# ------------------------------------------------------------ auto forwarding


def test_a_forward_rule_lets_a_request_through():
    engine = RuleEngine()
    engine.set_rules([Rule(id="1", kind="forward", host="static.test")])
    assert engine.auto_forward(make_request(url="http://static.test/a.png"))
    assert not engine.auto_forward(make_request(url="http://api.test/a"))


def test_a_forward_rule_wins_over_an_intercept_rule():
    engine = RuleEngine()
    engine.set_rules(
        [
            Rule(id="1", kind="intercept"),
            Rule(id="2", kind="forward", host="static.test"),
        ]
    )
    assert not engine.intercept_request(make_request(url="http://static.test/a.png"))
    assert engine.intercept_request(make_request(url="http://api.test/a"))


# ---------------------------------------------------------- match and replace


def test_a_replace_rule_rewrites_a_header():
    engine = RuleEngine()
    engine.set_rules(
        [
            Rule(
                id="1",
                kind="replace",
                target="request",
                place="header",
                field="User-Agent",
                match="test/1.0",
                replace="intercept/1.0",
                regex=False,
            )
        ]
    )
    request = engine.apply_request(make_request())
    assert request.headers.get("User-Agent") == "intercept/1.0"


def test_a_replace_rule_adds_a_header():
    engine = RuleEngine()
    engine.set_rules(
        [
            Rule(
                id="1",
                kind="replace",
                target="request",
                place="header-add",
                field="X-Added",
                replace="yes",
            )
        ]
    )
    request = engine.apply_request(make_request())
    assert request.headers.get("X-Added") == "yes"


def test_a_replace_rule_rewrites_the_body():
    engine = RuleEngine()
    engine.set_rules(
        [
            Rule(
                id="1",
                kind="replace",
                target="request",
                place="body",
                match=r"admin",
                replace="root",
            )
        ]
    )
    request = make_request()
    request.body = b"role=admin&x=1"
    request = engine.apply_request(request)
    assert request.body == b"role=root&x=1"


def test_a_replace_rule_rewrites_the_url():
    engine = RuleEngine()
    engine.set_rules(
        [Rule(id="1", kind="replace", target="request", place="url", match="v1", replace="v2")]
    )
    request = engine.apply_request(make_request(url="http://example.com/api/v1/users"))
    assert request.url == "http://example.com/api/v2/users"


def test_a_replace_rule_rewrites_the_response():
    engine = RuleEngine()
    engine.set_rules(
        [
            Rule(
                id="1",
                kind="replace",
                target="response",
                place="header",
                field="Server",
                match="nginx",
                replace="intercept",
                regex=False,
            )
        ]
    )
    response = Response(status=200, headers=Headers([("Server", "nginx")]))
    response = engine.apply_response(make_request(), response)
    assert response.headers.get("Server") == "intercept"


def test_a_replace_rule_only_touches_the_matching_traffic():
    engine = RuleEngine()
    engine.set_rules(
        [
            Rule(
                id="1",
                kind="replace",
                target="request",
                place="header",
                field="User-Agent",
                match="test",
                replace="changed",
                regex=False,
                host="only.test",
            )
        ]
    )
    request = engine.apply_request(make_request(url="http://other.test/x"))
    assert request.headers.get("User-Agent") == "test/1.0"


def test_substitution_supports_backreferences():
    assert substitute(r"(\d+)", r"[\1]", "id 42") == "id [42]"
    assert substitute_bytes(r"(\d+)", r"[\1]", b"id 42") == b"id [42]"


def test_a_broken_pattern_leaves_the_value_alone():
    assert substitute("(", "x", "value") == "value"
    assert substitute_bytes("(", "x", b"value") == b"value"


# -------------------------------------------------------------------- store


async def test_the_rules_survive_a_reload(app, client):
    created = await client.post(
        "/api/rules",
        json={
            "name": "hold the admin",
            "kind": "intercept",
            "host": "admin.test",
            "phase": "request",
        },
    )
    assert created.status_code == 200
    rule_id = created.json()["id"]

    listed = await client.get("/api/rules")
    assert [rule["id"] for rule in listed.json()["rules"]] == [rule_id]

    await app.reload_rules()
    assert any(rule.id == rule_id for rule in app.rules.rules)


async def test_a_rule_can_be_updated_and_deleted(app, client):
    created = await client.post("/api/rules", json={"name": "one", "kind": "forward"})
    rule_id = created.json()["id"]

    updated = await client.put(f"/api/rules/{rule_id}", json={"name": "two", "kind": "forward"})
    assert updated.status_code == 200
    assert updated.json()["name"] == "two"

    assert (await client.delete(f"/api/rules/{rule_id}")).status_code == 200
    assert (await client.get("/api/rules")).json()["rules"] == []
    assert app.rules.rules == []


async def test_deleting_a_rule_that_is_not_there_is_reported(client):
    assert (await client.delete("/api/rules/nope")).status_code == 404


# ------------------------------------------------------- through the proxy


async def test_an_intercept_rule_holds_only_the_matching_request(app, origin_url, proxy_url):
    await app.rule_store.create(
        Rule(id="", kind="intercept", host="127.0.0.1", path="/held*")
    )
    await app.reload_rules()
    app.intercept.enabled = True

    async def decide_later() -> None:
        for _ in range(200):
            await asyncio.sleep(0.02)
            if app.intercept.pending_ids():
                break
        assert app.intercept.pending_ids()
        app.intercept.resolve(app.intercept.pending_ids()[0], InterceptDecision("forward"))

    task = asyncio.create_task(decide_later())
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        held = await client.get(f"{origin_url}/held")
        free = await client.get(f"{origin_url}/free")
    await task

    assert held.status_code == 200
    assert free.status_code == 200


async def test_a_forward_rule_lets_a_request_through_while_interception_is_on(
    app, origin_url, proxy_url
):
    await app.rule_store.create(Rule(id="", kind="forward", host="127.0.0.1"))
    await app.reload_rules()
    app.intercept.enabled = True

    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/auto")

    assert response.status_code == 200
    assert app.intercept.pending_ids() == []


async def test_a_replace_rule_changes_what_the_origin_receives(app, origin_url, proxy_url):
    await app.rule_store.create(
        Rule(
            id="",
            kind="replace",
            target="request",
            place="header",
            field="X-Subject",
            match="original",
            replace="replaced-by-a-rule",
            regex=False,
        )
    )
    await app.reload_rules()

    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/replaced", headers={"X-Subject": "original"})

    assert response.json()["headers"]["x-subject"] == "replaced-by-a-rule"


async def test_a_replace_rule_changes_the_response_the_client_sees(
    app, origin_url, proxy_url
):
    await app.rule_store.create(
        Rule(
            id="",
            kind="replace",
            target="response",
            place="header",
            field="X-Origin-Server",
            match="intercept-tests",
            replace="rewritten",
            regex=False,
        )
    )
    await app.reload_rules()

    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as client:
        response = await client.get(f"{origin_url}/rewritten")

    assert response.headers["x-origin-server"] == "rewritten"

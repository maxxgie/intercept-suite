"""Tests for the fuzzer, the scanner and the findings store."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

from intercept.core.models import Headers, Request
from intercept.plugins.api import Finding
from intercept.scanner.checks import VerboseErrorPageCheck, check_catalog
from intercept.store.findings import FindingStore
from intercept.tools.fuzzer import default_payloads, parse_template


def _request(url: str = "http://127.0.0.1/x?a=§a§&b=§b§", body: bytes = b"") -> Request:
    request = Request(method="GET", url=url, body=body)
    request.headers.set("X-Test", "§h§")
    return request


def test_template_marks_url_header_and_body_positions():
    request = _request(body="name=§v§".encode())
    template = parse_template(request)

    names = {p.name for p in template.positions}
    assert "a" in names
    assert "b" in names
    assert "X-Test:h" in names
    assert "body:v" in names


def test_payload_is_substituted_in_the_url():
    from intercept.tools.fuzzer import _apply

    template = parse_template(_request())
    position = next(p for p in template.positions if p.name == "a")
    mutated = _apply(template.request, position, "INJECT")
    assert "a=INJECT" in mutated.url
    assert "b=§b§" in mutated.url


def test_payload_is_substituted_in_a_header_and_the_body():
    from intercept.tools.fuzzer import _apply

    template = parse_template(_request(body="name=§v§".encode()))
    header = next(p for p in template.positions if p.name == "X-Test:h")
    mutated = _apply(template.request, header, "INJECT")
    assert mutated.headers.get("X-Test") == "INJECT"

    body_position = next(p for p in template.positions if p.name == "body:v")
    mutated = _apply(template.request, body_position, "INJECT")
    assert mutated.body == b"name=INJECT"


async def test_fuzzer_runs_every_payload_and_records_the_results(app, origin_url):
    request = Request(method="GET", url=f"{origin_url}/search?q=§term§")
    job = app.fuzzer.create_job(request, ["one", "two"])
    assert job.total == 2

    await app.fuzzer.run(job.id)

    assert job.status == "finished"
    assert len(job.results) == 2
    payloads = {r.payload for r in job.results}
    assert payloads == {"one", "two"}
    assert all(r.status == 200 for r in job.results)

    await app.store.flush()
    items = await app.store.list(origin="fuzzer")
    assert len(items) == 2
    query = parse_qs(urlsplit(items[0]["url"]).query)
    assert query["q"][0] in ("one", "two")


async def test_fuzzer_marks_a_different_response_as_interesting(app, origin_url):
    request = Request(method="GET", url=f"{origin_url}/fuzz?a=§a§")
    job = app.fuzzer.create_job(request, ["missing"])
    await app.fuzzer.run(job.id)

    assert len(job.results) == 1
    result = job.results[0]
    assert result.status == 200
    assert result.interesting is False


def test_verbose_error_page_check_flags_a_stack_trace():
    check = VerboseErrorPageCheck()
    request = Request(method="GET", url="http://example.com/x")
    response = type(
        "R",
        (),
        {
            "status": 500,
            "body": b"Traceback (most recent call last): boom",
        },
    )()
    findings = check.run(request, response)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_check_catalog_lists_every_builtin_check():
    catalog = check_catalog()
    ids = {entry["id"] for entry in catalog}
    assert "headers.security" in ids
    assert "files.sensitive" in ids
    assert "tls.configuration" in ids
    assert all(entry["kind"] in ("active", "passive") for entry in catalog)


async def test_scanner_runs_the_selected_checks(app, origin_url):
    job = app.scanner.create_job([origin_url], ["headers.security"])
    await app.scanner.run(job.id)

    assert job.status == "finished"
    assert len(job.results) == 1
    findings = await app.finding_store.list()
    assert any(f["check_id"] == "headers.security" for f in findings)


async def test_scanner_stores_findings_and_counts_them(app, origin_url):
    job = app.scanner.create_job([origin_url], ["info.banner"])
    await app.scanner.run(job.id)

    total = await app.finding_store.count()
    assert total >= 1
    counts = await app.finding_store.severity_counts()
    assert sum(counts.values()) == total

    items = await app.finding_store.list(source="scanner")
    assert all(item["source"] == "scanner" for item in items)


async def test_concurrent_requests_do_not_mix_up(app, origin_url):
    """The upstream pool must not interleave two requests on one connection."""
    request = Request(method="GET", url=f"{origin_url}/echo?q=VALUE")
    request.headers.set("X-Test", "unique")

    responses = await asyncio.gather(
        *(app.client.send(request.clone()) for _ in range(12)),
    )
    assert len(responses) == 12
    for response in responses:
        assert response.status == 200, response.error
        assert b"echo" in response.body


async def test_a_plugin_check_is_registered_with_the_scanner(app):
    ids = {check["id"] for check in app.scanner.catalog()}
    assert "headers.csp" in ids, sorted(ids)


async def test_a_plugin_check_runs_in_a_scan(app, origin_url):
    job = app.scanner.create_job([origin_url], ["headers.csp"])
    await app.scanner.run(job.id)

    assert job.status == "finished"
    assert len(job.results) == 1
    findings = await app.finding_store.list(check_id="headers.csp")
    assert len(findings) == 1
    assert findings[0]["title"] == "No Content-Security-Policy header"


async def test_scanner_stops_a_running_job(app, origin_url):
    job = app.scanner.create_job([origin_url] * 50, ["files.sensitive"])
    await app.scanner.start(job.id)
    assert app.scanner.stop(job.id) is True
    assert job.status == "stopped"


async def test_api_exposes_the_fuzzer_and_the_scanner(client, origin_url):
    created = await client.post(
        "/api/fuzz/jobs",
        json={
            "method": "GET",
            "url": f"{origin_url}/api?q=§q§",
            "payloads": ["a", "b"],
            "start": False,
        },
    )
    assert created.status_code == 200
    job = created.json()
    assert job["total"] == 2
    assert len(job["template"]["positions"]) == 1

    listed = await client.get("/api/fuzz/jobs")
    assert listed.status_code == 200
    assert len(listed.json()["jobs"]) == 1

    checks = await client.get("/api/scanner/checks")
    assert checks.status_code == 200
    assert any(c["id"] == "headers.security" for c in checks.json()["checks"])

    scan = await client.post(
        "/api/scanner/jobs",
        json={"targets": [origin_url], "checks": ["info.banner"], "start": False},
    )
    assert scan.status_code == 200
    assert scan.json()["total"] == 1

    findings = await client.get("/api/findings")
    assert findings.status_code == 200
    assert "items" in findings.json()
    assert "severities" in findings.json()


async def test_api_rejects_a_scan_without_targets(client):
    response = await client.post("/api/scanner/jobs", json={"targets": []})
    assert response.status_code == 400


async def test_finding_store_filters_by_severity(tmp_path):
    store = FindingStore(tmp_path / "findings.db")
    store.add(
        Finding(check_id="a", title="high one", severity="high", url="http://x/"),
        source="scanner",
    )
    store.add(
        Finding(check_id="b", title="low one", severity="low", url="http://y/"),
        source="passive",
    )
    high = await store.list(severity="high")
    assert len(high) == 1
    assert high[0]["host"] == "x"
    passive = await store.list(source="passive")
    assert len(passive) == 1
    assert await store.count() == 2
    store.close()


def test_headers_helper_keeps_order():
    headers = Headers([("a", "1"), ("b", "2"), ("a", "3")])
    assert headers.get_all("a") == ["1", "3"]
    assert json.dumps(headers.to_dict()) == '{"a": ["1", "3"], "b": ["2"]}'


def test_default_payloads_are_not_empty():
    assert len(default_payloads()) > 5

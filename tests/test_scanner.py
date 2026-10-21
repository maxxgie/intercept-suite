"""Tests for the professional scanner.

The tests run against a small server that behaves like a vulnerable
application: it answers with a database error for a quote, echoes a script
back, evaluates a template expression and hands out objects that belong to
somebody else. The checks have to notice each of those.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest

from intercept.scanner.checks import BUILTIN_CHECKS, check_catalog
from intercept.scanner.engine import ScanOptions
from intercept.scanner.target import Endpoint, Parameter


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _AppHandler(http.server.BaseHTTPRequestHandler):
    """A server that answers like an application with holes in it."""

    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, content_type: str = "text/html") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - the name is fixed by http.server
        split = urlsplit(self.path)
        query = dict(parse_qsl(split.query, keep_blank_values=True))
        path = split.path

        if path == "/search":
            value = query.get("q", "")
            if "'" in value:
                self._send(
                    500,
                    b"You have an error in your SQL syntax near '" + value.encode() + b"'",
                )
                return
            if "<script>" in value:
                self._send(200, f"<html><body>{value}</body></html>".encode())
                return
            if "7*7" in value:
                self._send(200, b"<html><body>49</body></html>")
                return
            if "cat /etc/passwd" in value:
                self._send(200, b"<html><body>root:x:0:0:0:root:/root:/bin/bash</body></html>")
                return
            self._send(200, b"<html><body>the search</body></html>")
            return

        if path == "/file":
            value = query.get("name", "")
            if "etc/passwd" in value:
                self._send(200, b"root:x:0:0:0:root:/root:/bin/bash")
                return
            self._send(200, b"the file")
            return

        if path == "/redirect":
            target = query.get("url", "")
            if target:
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(200, b"no redirect")
            return

        if path == "/objects":
            value = query.get("id", "1")
            self._send(
                200,
                json.dumps(
                    {"id": value, "owner": "someone else", "email": "secret@example.com"}
                ).encode(),
                "application/json",
            )
            return

        if path == "/page":
            self._send(200, b"<html><body>the page</body></html>")
            return

        if path == "/admin":
            self._send(200, b"<html><body>the administration</body></html>")
            return

        if path == "/login":
            self._send(200, b"<html><body><form>please sign in</form></body></html>")
            return

        if path == "/graphql":
            self._send(
                200, b'{"data":{"__schema":{"types":[{"name":"User"}]}}}', "application/json"
            )
            return

        self._send(404, b"not found")

    do_POST = do_GET

    def log_message(self, *args) -> None:
        return


@pytest.fixture
def app_url():
    """A server that behaves like a vulnerable application."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()


def _endpoint(url: str, name: str = "q", value: str = "test") -> Endpoint:
    """An endpoint with one query parameter."""
    separator = "&" if "?" in url else "?"
    return Endpoint(
        url=f"{url}{separator}{urlencode({name: value})}",
        parameters=[Parameter(name, value, "query")],
    )


# ----------------------------------------------------------------- the catalog


def test_the_catalog_covers_the_whole_list():
    """Every kind of bug the scanner promises is in the catalog."""
    ids = {item["id"] for item in check_catalog()}
    for expected in (
        "injection.sql",
        "injection.xss",
        "injection.xxe",
        "injection.ssrf",
        "injection.ssti",
        "injection.command",
        "injection.ldap",
        "injection.nosql",
        "injection.traversal",
        "injection.redirect",
        "injection.prototype",
        "injection.deserialization",
        "graphql.configuration",
        "auth.authentication",
        "auth.jwt",
        "auth.oauth",
        "auth.idor",
        "web.clickjacking",
        "web.csp",
        "web.cache",
        "web.smuggling",
        "web.upload",
        "web.xml",
        "web.domxss",
        "web.headers",
        "web.cookies",
        "http.cors",
        "files.sensitive",
    ):
        assert expected in ids, expected


def test_every_check_tells_what_it_does():
    """A check without a description would be a mystery in the list."""
    for item in check_catalog():
        assert item["label"]
        assert item["description"]
        assert item["severity"] in {"info", "low", "medium", "high", "critical"}
        assert item["scope"] in {"host", "endpoint"}


def test_the_injection_checks_work_on_the_endpoints():
    """The checks that need input are marked as endpoint checks."""
    for check in BUILTIN_CHECKS:
        if check.id.startswith("injection."):
            assert check.scope == "endpoint", check.id


# ------------------------------------------------------------------- targets


def test_an_endpoint_replaces_one_parameter():
    """A copy of the endpoint with another value in one parameter."""
    endpoint = _endpoint("http://127.0.0.1/search", "q", "one")
    other = endpoint.with_parameter("q", "two")
    assert "q=two" in other.url
    assert "q=one" in endpoint.url
    assert other.parameters[0].value == "two"


def test_an_endpoint_replaces_one_form_field():
    """A copy of the endpoint with another value in one form field."""
    endpoint = Endpoint(url="http://127.0.0.1/login", method="POST", body_fields={"user": "one"})
    other = endpoint.with_body_field("user", "two")
    assert other.body_fields == {"user": "two"}
    assert endpoint.body_fields == {"user": "one"}


async def test_the_crawler_finds_the_endpoints(app, app_url):
    """The crawl finds the links and the parameters of a site."""
    from intercept.scanner.target import EndpointCrawler

    crawler = EndpointCrawler(app.client, max_pages=5, max_depth=1)
    endpoints = await crawler.crawl(f"{app_url}/page")
    assert endpoints
    assert all(endpoint.url.startswith(app_url) for endpoint in endpoints)


# ------------------------------------------------------------- the injection


async def test_the_sql_check_finds_the_database_error(app, app_url):
    """A quote that makes the database complain is an injection."""
    from intercept.scanner.injection import SqlInjectionCheck

    findings = await SqlInjectionCheck().run(app.client, _endpoint(f"{app_url}/search"))
    assert findings
    assert findings[0].check_id == "injection.sql"
    assert "SQL syntax" in findings[0].evidence


async def test_the_xss_check_finds_the_reflected_script(app, app_url):
    """A payload that comes back in the page is a cross site scripting hole."""
    from intercept.scanner.injection import XssCheck

    findings = await XssCheck().run(app.client, _endpoint(f"{app_url}/search"))
    assert findings
    assert findings[0].check_id == "injection.xss"
    assert "script" in findings[0].evidence.lower()


async def test_the_template_check_finds_the_evaluated_expression(app, app_url):
    """A template engine that calculates the input is a hole."""
    from intercept.scanner.injection import SstiCheck

    findings = await SstiCheck().run(app.client, _endpoint(f"{app_url}/search"))
    assert findings
    assert findings[0].check_id == "injection.ssti"


async def test_the_command_check_finds_the_output(app, app_url):
    """The output of a command in the answer proves a command injection."""
    from intercept.scanner.injection import CommandInjectionCheck

    findings = await CommandInjectionCheck().run(app.client, _endpoint(f"{app_url}/search"))
    assert findings
    assert findings[0].check_id == "injection.command"
    assert findings[0].severity == "critical"


async def test_the_traversal_check_finds_the_system_file(app, app_url):
    """A file outside of the web root in the answer is a traversal."""
    from intercept.scanner.injection import PathTraversalCheck

    findings = await PathTraversalCheck().run(
        app.client, _endpoint(f"{app_url}/file", "name", "index")
    )
    assert findings
    assert findings[0].check_id == "injection.traversal"


async def test_the_redirect_check_finds_the_foreign_host(app, app_url):
    """A redirect that accepts any host is an open redirect."""
    from intercept.scanner.injection import OpenRedirectCheck

    findings = await OpenRedirectCheck().run(
        app.client, _endpoint(f"{app_url}/redirect", "url", "start")
    )
    assert findings
    assert findings[0].check_id == "injection.redirect"


async def test_a_clean_answer_is_not_a_finding(app, app_url):
    """An endpoint that behaves itself is left alone."""
    from intercept.scanner.injection import SqlInjectionCheck

    findings = await SqlInjectionCheck().run(app.client, _endpoint(f"{app_url}/page"))
    assert findings == []


# --------------------------------------------------------------------- auth


async def test_the_jwt_check_finds_a_token_without_a_signature(app, app_url):
    """A token that says it is not signed can be forged."""
    import base64

    from intercept.scanner.authsec import JwtCheck

    def encode(value: dict) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
        return raw

    token = f"{encode({'alg': 'none'})}.{encode({'sub': 'admin'})}."
    endpoint = Endpoint(
        url=f"{app_url}/page?token={token}",
        parameters=[Parameter("token", token, "query")],
    )
    findings = await JwtCheck().run(app.client, endpoint)
    titles = [finding.title for finding in findings]
    assert any("alg=none" in title for title in titles)
    assert any("never expires" in title for title in titles)


async def test_the_jwt_check_finds_a_weak_secret(app, app_url):
    """A token signed with a well known secret can be forged."""
    import base64
    import hashlib
    import hmac

    from intercept.scanner.authsec import JwtCheck

    def encode(value: dict) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
        return raw

    header = encode({"alg": "HS256"})
    payload = encode({"sub": "admin", "exp": 9999999999})
    digest = hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    token = f"{header}.{payload}.{signature}"

    endpoint = Endpoint(
        url=f"{app_url}/page?token={token}",
        parameters=[Parameter("token", token, "query")],
    )
    findings = await JwtCheck().run(app.client, endpoint)
    assert any("secret" in finding.title for finding in findings)


async def test_the_idor_check_finds_another_object(app, app_url):
    """An identifier that can be changed hands out an object of somebody else."""
    from intercept.scanner.authsec import IdorCheck

    findings = await IdorCheck().run(app.client, _endpoint(f"{app_url}/objects", "id", "1"))
    assert findings
    assert findings[0].check_id == "auth.idor"


async def test_the_authentication_check_finds_an_open_area(app, app_url):
    """An area that should ask for a password and does not is a finding."""
    from intercept.scanner.authsec import AuthenticationCheck

    findings = await AuthenticationCheck().run(app.client, Endpoint(url=f"{app_url}/page"))
    titles = [finding.title for finding in findings]
    assert any("/admin" in title for title in titles)
    assert not any("/login" in title for title in titles)


# ---------------------------------------------------------------------- web


async def test_the_clickjacking_check_notices_a_page_without_a_frame_rule(app, app_url):
    """A page that can be framed can be used to click for the visitor."""
    from intercept.scanner.appsec import ClickjackingCheck

    findings = await ClickjackingCheck().run(app.client, Endpoint(url=f"{app_url}/page"))
    assert findings
    assert findings[0].check_id == "web.clickjacking"


async def test_the_graphql_check_finds_an_open_schema(app, app_url):
    """A GraphQL endpoint that hands out its schema gives away too much."""
    from intercept.scanner.graphql import GraphqlCheck

    findings = await GraphqlCheck().run(app.client, Endpoint(url=f"{app_url}/graphql"))
    assert findings
    assert findings[0].check_id == "graphql.configuration"


# ------------------------------------------------------------------ the engine


async def test_the_scan_runs_the_endpoint_checks_on_the_crawled_endpoints(app, app_url):
    """A scan finds the endpoints first and then probes them."""
    job = app.scanner.create_job(
        [f"{app_url}/page"],
        ["injection.sql", "injection.xss"],
        ScanOptions(crawl=True, max_pages=5, max_depth=1, max_endpoints=5),
    )
    await app.scanner.run(job.id)

    assert job.status == "finished"
    assert job.endpoints
    assert job.results
    assert all(result.error == "" for result in job.results)


async def test_the_scan_counts_the_work_it_will_do(app, app_url):
    """The number of runs the scan holds matches what it does."""
    job = app.scanner.create_job(
        [f"{app_url}/page"],
        ["web.clickjacking", "injection.sql"],
        ScanOptions(crawl=False),
    )
    await app.scanner.run(job.id)

    # One host check for the target and one endpoint check for the endpoint.
    assert job.planned == 2
    assert job.total == 2
    assert len(job.results) == 2


async def test_a_passive_check_is_not_run_against_the_target(app, app_url):
    """A passive check reads the traffic, it asks the server nothing."""
    job = app.scanner.create_job(
        [f"{app_url}/page"],
        ["passive.errorpage", "web.clickjacking"],
        ScanOptions(crawl=False),
    )
    await app.scanner.run(job.id)

    assert job.planned == 1
    assert all(result.error == "" for result in job.results)
    assert all(result.check_id != "passive.errorpage" for result in job.results)


async def test_the_scan_can_run_without_a_crawl(app, app_url):
    """Without a crawl the target itself is the only endpoint."""
    job = app.scanner.create_job(
        [f"{app_url}/search?q=test"], ["injection.sql"], ScanOptions(crawl=False)
    )
    await app.scanner.run(job.id)

    assert job.status == "finished"
    assert len(job.endpoints) == 1


async def test_the_scan_finds_the_injection(app, app_url):
    """A scan of a vulnerable endpoint reports the hole."""
    job = app.scanner.create_job(
        [f"{app_url}/search?q=test"], ["injection.sql"], ScanOptions(crawl=False)
    )
    await app.scanner.run(job.id)

    assert job.findings
    assert job.findings[0].check_id == "injection.sql"


async def test_the_findings_are_stored(app, app_url):
    """What the scan finds ends up in the finding store."""
    job = app.scanner.create_job(
        [f"{app_url}/search?q=test"], ["injection.sql"], ScanOptions(crawl=False)
    )
    await app.scanner.run(job.id)

    stored = await app.finding_store.list()
    assert any(finding["check_id"] == "injection.sql" for finding in stored)


# ---------------------------------------------------------------------- api


async def test_the_api_lists_the_checks(client):
    """The interface can ask what the scanner knows."""
    response = await client.get("/api/scanner/checks")
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()["checks"]}
    assert "injection.sql" in ids
    assert "web.clickjacking" in ids


async def test_the_api_starts_a_scan_with_the_options(client, app_url):
    """The options of a scan travel through the interface."""
    created = await client.post(
        "/api/scanner/jobs",
        json={
            "targets": [f"{app_url}/page"],
            "checks": ["web.clickjacking"],
            "crawl": False,
            "max_depth": 1,
            "start": False,
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["options"]["crawl"] is False
    assert body["options"]["max_depth"] == 1
    assert body["check_ids"] == ["web.clickjacking"]

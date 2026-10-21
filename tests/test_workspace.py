"""Tests for the workspace: filters, commands, the new stores and the API."""

from __future__ import annotations

import json

import httpx
import pytest

from intercept.core.commands import CommandError, CommandRegistry
from intercept.core.filters import FilterError, FilterState, parse
from intercept.core.reports import build_report, render_report
from intercept.proxy.websocket import FrameParser
from intercept.store.issues import IssueStore
from intercept.store.logger import EventLog
from intercept.store.notes import NoteStore
from intercept.store.project import ProjectStore
from intercept.store.sessions import SessionStore
from intercept.store.targets import TargetStore
from intercept.store.tasks import Scheduler, TaskStore

ROW = {
    "host": "example.com",
    "path": "/admin/login",
    "url": "https://example.com/admin/login",
    "method": "POST",
    "status": 404,
    "mime_type": "text/html",
    "response_length": 120,
    "request_length": 40,
    "elapsed_ms": 35.5,
    "tags": ["interesting", "auth"],
    "notes": ["looks odd"],
    "origin": "proxy",
    "scheme": "https",
    "port": 443,
    "query": "",
    "reason": "Not Found",
    "highlighted": True,
    "comment": "check this one",
    "extension": "html",
    "request_raw": b"POST /admin/login HTTP/1.1\r\nHost: example.com\r\n\r\npassword=hunter2",
    "response_raw": b"HTTP/1.1 404 Not Found\r\n\r\nnope",
    "body": b"password=hunter2",
}


# ------------------------------------------------------------------ filters


@pytest.mark.parametrize(
    "expression",
    [
        'host == "example.com"',
        "host == example.com",
        "status >= 400",
        "path contains admin",
        "not (status == 200)",
        "status >= 400 and method == POST",
        "status >= 400 or method == PUT",
        'path contains "/admin" or method == "POST"',
        'request =~ "password"',
        "tag == interesting",
        "tag contains rest",
        "mime == text/html",
        "size > 100",
        "time < 100",
        'comment contains "check"',
        "highlighted",
        "ext == html",
    ],
)
def test_a_filter_matches(expression):
    assert parse(expression).matches(ROW) is True


@pytest.mark.parametrize(
    "expression",
    [
        'host == "other.example"',
        "status < 400",
        "method == GET",
        'method == "post"',
        "not highlighted",
        "tag == other",
    ],
)
def test_a_filter_does_not_match(expression):
    assert parse(expression).matches(ROW) is False


@pytest.mark.parametrize(
    "expression",
    [
        "host ==",
        "nope == 1",
        'host == "x',
        '(host == "a"',
        "host",
        "and host == 1",
        "((host == 1)",
    ],
)
def test_a_broken_filter_is_rejected(expression):
    with pytest.raises(FilterError):
        parse(expression)


def test_an_empty_filter_matches_everything():
    assert parse("").matches(ROW) is True


def test_a_quoted_value_is_exact():
    assert parse('method == "post"').matches(ROW) is False
    assert parse('method == "POST"').matches(ROW) is True


def test_a_regular_expression_can_be_case_sensitive():
    assert parse('request =~ "PASSWORD"').matches(ROW) is False
    assert parse('request =~ "(?i)PASSWORD"').matches(ROW) is True


def test_the_filter_state_keeps_a_broken_expression():
    state = FilterState()
    assert state.set("host == 1") is True
    assert state.expression == "host == 1"
    assert state.set("nope == 1") is False
    assert state.error
    assert state.expression == "host == 1"
    state.clear()
    assert state.expression == ""


# ----------------------------------------------------------------- commands


def test_a_command_can_be_registered_and_run():
    registry = CommandRegistry()
    registry.register("test.run", "Run the test", handler=lambda args: {"ok": True})
    assert "test.run" in registry
    assert registry.get("test.run").title == "Run the test"
    assert registry.list()[0]["id"] == "test.run"


async def test_a_command_is_awaited_when_it_is_async():
    registry = CommandRegistry()

    async def handler(args):
        return args.get("value", 0) * 2

    registry.register("test.double", "Double", handler=handler)
    assert await registry.run("test.double", {"value": 21}) == 42


async def test_an_unknown_command_is_an_error():
    registry = CommandRegistry()
    with pytest.raises(CommandError):
        await registry.run("nope")


def test_the_command_search_finds_by_title():
    registry = CommandRegistry()
    registry.register("traffic.clear", "Clear HTTP history", category="Traffic")
    registry.register("note.create", "Add a note", category="Notes")
    found = registry.search("clear")
    assert found[0]["id"] == "traffic.clear"
    assert registry.search("note")[0]["id"] == "note.create"
    assert registry.search("nothing at all") == []


def test_the_command_search_is_forgiving():
    registry = CommandRegistry()
    registry.register("traffic.clear", "Clear HTTP history", category="Traffic")
    assert registry.search("cltr")[0]["id"] == "traffic.clear"


# --------------------------------------------------------------------- log


async def test_the_log_records_and_lists(tmp_path):
    log = EventLog(str(tmp_path / "events.db"))
    log.record("info", "proxy", "something happened", {"n": 1})
    log.record("error", "scanner", "it broke")

    entries = await log.list()
    assert len(entries) == 2
    assert entries[0]["message"] == "it broke"
    assert entries[1]["data"] == {"n": 1}

    assert await log.count() == 2
    assert (await log.levels())["info"] == 1
    assert await log.sources() == ["proxy", "scanner"]
    log.close()


async def test_the_log_can_be_filtered(tmp_path):
    log = EventLog(str(tmp_path / "events.db"))
    log.record("info", "proxy", "one")
    log.record("error", "scanner", "two")

    entries = await log.list(filter='level == "error"')
    assert len(entries) == 1
    assert entries[0]["message"] == "two"

    assert await log.clear() == 2
    log.close()


async def test_the_log_is_bounded(tmp_path):
    log = EventLog(str(tmp_path / "events.db"), limit=5)
    for index in range(20):
        log.record("info", "proxy", f"entry {index}")
    assert await log.count() == 5
    log.close()


# ------------------------------------------------------------------- notes


async def test_a_note_is_created_and_updated(tmp_path):
    notes = NoteStore(str(tmp_path / "notes.db"))
    note = await notes.create("exchange", "abc", "looks odd", "red", ["auth"])
    assert note.color == "red"
    assert note.tags == ["auth"]

    updated = await notes.update(note.id, text="still odd", color="orange")
    assert updated.text == "still odd"
    assert updated.color == "orange"

    listed = await notes.list(subject="exchange", subject_id="abc")
    assert len(listed) == 1
    assert await notes.count() == 1
    assert await notes.delete(note.id) is True
    assert await notes.count() == 0
    notes.close()


async def test_an_unknown_colour_is_dropped(tmp_path):
    notes = NoteStore(str(tmp_path / "notes.db"))
    note = await notes.create("exchange", "abc", "text", "chartreuse")
    assert note.color == ""
    notes.close()


# ------------------------------------------------------------------ issues


async def test_an_issue_is_raised_and_moved(tmp_path):
    issues = IssueStore(str(tmp_path / "issues.db"))
    issue = await issues.create(
        "Broken access control",
        description="admin page is open",
        severity="high",
        exchange_ids=["abc"],
    )
    assert issue.status == "open"
    assert issue.severity == "high"

    moved = await issues.update(issue.id, status="confirmed")
    assert moved.status == "confirmed"

    summary = await issues.summary()
    assert summary["total"] == 1
    assert summary["by_status"]["confirmed"] == 1

    listed = await issues.list(status="confirmed")
    assert len(listed) == 1
    assert await issues.delete(issue.id) is True
    issues.close()


async def test_an_issue_rejects_an_unknown_status(tmp_path):
    issues = IssueStore(str(tmp_path / "issues.db"))
    issue = await issues.create("Something", status="nonsense")
    assert issue.status == "open"
    issues.close()


# ---------------------------------------------------------------- sessions


async def test_a_session_holds_exchanges(tmp_path):
    sessions = SessionStore(str(tmp_path / "sessions.db"))
    listed = await sessions.list()
    assert any(session["live"] for session in listed)

    session = await sessions.create("Auth testing")
    assert session.name == "Auth testing"
    await sessions.add(session.id, ["one", "two"])
    assert await sessions.members(session.id) == ["one", "two"]
    await sessions.remove(session.id, ["one"])
    assert await sessions.members(session.id) == ["two"]

    renamed = await sessions.rename(session.id, "Renamed")
    assert renamed.name == "Renamed"
    assert await sessions.delete(session.id) is True
    sessions.close()


async def test_the_live_session_cannot_be_deleted(tmp_path):
    sessions = SessionStore(str(tmp_path / "sessions.db"))
    assert await sessions.delete("live") is False
    sessions.close()


# ----------------------------------------------------------------- targets


async def test_a_target_is_recorded(tmp_path):
    targets = TargetStore(str(tmp_path / "targets.db"))
    target = await targets.create("Example", host="example.com", port=443, notes="main site")
    assert target.url == "https://example.com:443"
    assert target.in_scope is True

    updated = await targets.update(target.id, in_scope=False)
    assert updated.in_scope is False

    assert len(await targets.list(in_scope=True)) == 0
    assert len(await targets.list()) == 1
    assert await targets.delete(target.id) is True
    targets.close()


# ------------------------------------------------------------------- tasks


async def test_a_task_is_created_and_run(tmp_path):
    store = TaskStore(str(tmp_path / "tasks.db"))
    ran: list[str] = []

    async def handler(command, args):
        ran.append(command)

    scheduler = Scheduler(store, handler)
    task = await store.create("Crawl", "spider.crawl", interval=5)
    assert task.enabled is True
    assert task.next_run > 0

    assert await scheduler.run_now(task.id) is True
    assert ran == ["spider.crawl"]
    assert (await store.get(task.id)).run_count == 1

    await scheduler.run_now("nope")
    store.close()


async def test_a_failing_task_is_recorded_but_does_not_raise(tmp_path):
    store = TaskStore(str(tmp_path / "tasks.db"))

    async def handler(command, args):
        raise RuntimeError("nope")

    scheduler = Scheduler(store, handler)
    task = await store.create("Broken", "spider.crawl", interval=5)
    await scheduler.run_now(task.id)
    assert "nope" in (await store.get(task.id)).last_error
    store.close()


async def test_a_task_interval_has_a_floor(tmp_path):
    store = TaskStore(str(tmp_path / "tasks.db"))
    task = await store.create("Too fast", "spider.crawl", interval=0.1)
    assert task.interval >= 5
    store.close()


# ----------------------------------------------------------------- projects


def test_a_project_is_created_and_saved(tmp_path):
    projects = ProjectStore(tmp_path)
    project = projects.create("Engagement one", description="the first one")
    assert project["name"] == "Engagement one"
    assert (tmp_path / "projects" / "engagement-one" / "project.json").exists()

    assert projects.current()["id"] == project["id"]
    assert len(projects.list()) == 1

    saved = projects.save(
        project["id"],
        notes=[{"text": "a note"}],
        issues=[{"title": "an issue"}],
    )
    assert saved is not None
    contents = projects.load(project["id"])
    assert contents["notes"] == [{"text": "a note"}]
    assert contents["issues"] == [{"title": "an issue"}]
    assert "project.json" in contents["files"]

    assert projects.open(project["id"])["id"] == project["id"]
    assert projects.delete(project["id"]) is True
    assert projects.list() == []


# ------------------------------------------------------------------ reports


def test_a_report_is_built_and_rendered():
    report = build_report(
        title="Engagement",
        findings=[
            {"title": "Missing headers", "severity": "medium", "url": "https://x/"},
            {"title": "Open redirect", "severity": "high", "url": "https://x/?u="},
        ],
        issues=[{"title": "Open redirect", "severity": "high", "status": "open"}],
        notes=[{"text": "interesting", "subject_id": "abc"}],
        targets=[{"name": "Example", "url": "https://example.com", "in_scope": True}],
        stats={"exchanges": 12},
    )
    assert report["summary"]["findings"] == 2
    assert report["summary"]["open_issues"] == 1
    assert report["findings"][0]["severity"] == "high"

    markdown = render_report(report, "markdown")
    assert "# Engagement" in markdown
    assert "Open redirect" in markdown
    assert "| Findings | 2 |" in markdown

    html = render_report(report, "html")
    assert "<!doctype html>" in html
    assert "Open redirect" in html

    payload = json.loads(render_report(report, "json"))
    assert payload["title"] == "Engagement"

    with pytest.raises(ValueError):
        render_report(report, "pdf")


# ---------------------------------------------------------------- websocket


def test_a_websocket_frame_is_parsed():
    parser = FrameParser("client")
    payload = b"hello"
    key = b"\x01\x02\x03\x04"
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    frame = bytes([0x81, 0x80 | len(payload)]) + key + masked
    frames = parser.feed(frame)
    assert len(frames) == 1
    assert frames[0].name == "text"
    assert frames[0].text == "hello"
    assert frames[0].direction == "client"


def test_a_websocket_frame_is_reassembled_from_parts():
    parser = FrameParser("server")
    payload = b"abcdef"
    frame = bytes([0x81, len(payload)]) + payload
    assert parser.feed(frame)[0].text == "abcdef"

    parser = FrameParser("server")
    first = bytes([0x01, 0x03]) + b"abc"
    second = bytes([0x80, 0x03]) + b"def"
    assert parser.feed(first) == []
    frames = parser.feed(second)
    assert frames[0].text == "abcdef"


def test_a_partial_websocket_frame_is_waited_for():
    parser = FrameParser("client")
    frame = bytes([0x81, 0x05]) + b"ab"
    assert parser.feed(frame) == []
    assert parser.feed(b"cde")[0].text == "abcde"


# ---------------------------------------------------------------------- api


@pytest.fixture
async def client(app):
    from intercept.api.app import create_api

    api = create_api(app)
    transport = httpx.ASGITransport(app=api)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client


async def test_the_api_lists_the_commands(client):
    response = await client.get("/api/commands")
    assert response.status_code == 200
    payload = response.json()
    assert payload["commands"]
    assert "Traffic" in payload["categories"]


async def test_the_api_searches_the_commands(client):
    response = await client.get("/api/commands/search", params={"q": "clear"})
    assert response.status_code == 200
    assert response.json()["commands"]


async def test_the_api_runs_a_command(client):
    response = await client.post("/api/commands/traffic.clear/run", json={"args": {}})
    assert response.status_code == 200
    assert "result" in response.json()


async def test_the_api_rejects_an_unknown_command(client):
    response = await client.post("/api/commands/nope/run", json={"args": {}})
    assert response.status_code == 404


async def test_the_api_sets_and_reads_the_filter(client):
    response = await client.put("/api/filter", json={"filter": "status >= 400"})
    assert response.status_code == 200
    assert response.json()["expression"] == "status >= 400"

    response = await client.get("/api/filter")
    assert response.json()["expression"] == "status >= 400"


async def test_the_api_rejects_a_broken_filter(client):
    response = await client.put("/api/filter", json={"filter": "nope == 1"})
    assert response.status_code == 400


async def test_the_api_filters_the_traffic(client, app, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as browser:
        await browser.get(f"{origin_url}/one")
    await app.store.flush()

    response = await client.get("/api/traffic", params={"filter": 'host == "127.0.0.1"'})
    assert response.status_code == 200
    assert len(response.json()["items"]) == 1

    response = await client.get("/api/traffic", params={"filter": 'host == "other"'})
    assert response.json()["items"] == []


async def test_the_api_searches_the_traffic(client, app, origin_url, proxy_url):
    async with httpx.AsyncClient(proxy=proxy_url, timeout=10) as browser:
        await browser.get(f"{origin_url}/findme")
    await app.store.flush()

    response = await client.get("/api/search", params={"q": "findme"})
    assert response.status_code == 200
    assert response.json()["total"] == 1


async def test_the_api_returns_the_dashboard(client):
    response = await client.get("/api/dashboard")
    assert response.status_code == 200
    payload = response.json()
    assert "traffic" in payload
    assert "issues" in payload
    assert "sessions" in payload


async def test_the_api_returns_the_organizer(client):
    response = await client.get("/api/organizer")
    assert response.status_code == 200
    assert "hosts" in response.json()


async def test_the_api_manages_notes(client):
    created = await client.post(
        "/api/notes", json={"subject": "exchange", "subject_id": "abc", "text": "look"}
    )
    assert created.status_code == 200
    note_id = created.json()["id"]

    listed = await client.get("/api/notes")
    assert listed.json()["total"] == 1

    updated = await client.put(f"/api/notes/{note_id}", json={"text": "looked", "color": "red"})
    assert updated.json()["text"] == "looked"

    assert (await client.delete(f"/api/notes/{note_id}")).status_code == 200
    assert (await client.get("/api/notes")).json()["total"] == 0


async def test_the_api_manages_issues(client):
    created = await client.post("/api/issues", json={"title": "A problem", "severity": "high"})
    assert created.status_code == 200
    issue_id = created.json()["id"]

    updated = await client.put(f"/api/issues/{issue_id}", json={"status": "resolved"})
    assert updated.json()["status"] == "resolved"
    # A partial update only touches the field it names.
    assert updated.json()["title"] == "A problem"
    assert updated.json()["severity"] == "high"

    assert (await client.delete(f"/api/issues/{issue_id}")).status_code == 200


async def test_the_api_manages_sessions(client):
    created = await client.post("/api/sessions", json={"name": "Testing"})
    assert created.status_code == 200
    session_id = created.json()["id"]

    members = await client.post(
        f"/api/sessions/{session_id}/members", json={"add": ["a", "b"]}
    )
    assert members.json()["count"] == 2

    assert (await client.delete(f"/api/sessions/{session_id}")).status_code == 200


async def test_the_api_manages_targets(client):
    created = await client.post(
        "/api/targets", json={"name": "Example", "host": "example.com", "port": 8443}
    )
    assert created.status_code == 200
    target_id = created.json()["id"]

    updated = await client.put(f"/api/targets/{target_id}", json={"in_scope": False})
    assert updated.json()["in_scope"] is False
    # A partial update only touches the field it names.
    assert updated.json()["port"] == 8443
    assert updated.json()["name"] == "Example"
    assert updated.json()["host"] == "example.com"

    assert (await client.delete(f"/api/targets/{target_id}")).status_code == 200


async def test_the_api_manages_tasks(client):
    created = await client.post(
        "/api/tasks", json={"name": "Crawl", "command": "spider.crawl", "interval": 30}
    )
    assert created.status_code == 200
    task_id = created.json()["id"]

    updated = await client.put(f"/api/tasks/{task_id}", json={"enabled": False})
    assert updated.json()["enabled"] is False
    # A partial update only touches the field it names.
    assert updated.json()["command"] == "spider.crawl"
    assert updated.json()["interval"] == 30

    assert (await client.post(f"/api/tasks/{task_id}/run")).status_code == 200
    assert (await client.delete(f"/api/tasks/{task_id}")).status_code == 200


async def test_the_api_rejects_a_task_without_a_command(client):
    response = await client.post("/api/tasks", json={"name": "Nothing"})
    assert response.status_code == 400


async def test_the_api_manages_projects(client):
    created = await client.post("/api/projects", json={"name": "Engagement"})
    assert created.status_code == 200
    project_id = created.json()["id"]

    saved = await client.post(f"/api/projects/{project_id}/save")
    assert saved.status_code == 200

    contents = await client.get(f"/api/projects/{project_id}")
    assert contents.status_code == 200
    assert contents.json()["project"]["name"] == "Engagement"

    assert (await client.delete(f"/api/projects/{project_id}")).status_code == 200


async def test_the_api_builds_and_renders_a_report(client):
    response = await client.get("/api/reports")
    assert response.status_code == 200
    assert response.json()["summary"]

    response = await client.get("/api/reports/render", params={"format": "markdown"})
    assert response.status_code == 200
    assert response.text.startswith("# ")


async def test_the_api_lists_the_websocket_history(client):
    response = await client.get("/api/websockets/connections")
    assert response.status_code == 200
    assert response.json()["connections"] == []

    response = await client.get("/api/websockets/messages")
    assert response.json()["messages"] == []


async def test_the_api_serves_the_event_log(client):
    response = await client.get("/api/log")
    assert response.status_code == 200
    assert "entries" in response.json()

    response = await client.get("/api/log/export")
    assert response.status_code == 200

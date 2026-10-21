"""HTTP and WebSocket API.

The desktop shell talks to the daemon exclusively through this API, which
means the same surface is available to scripts, to other tools and to remote
operators.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import uuid
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from intercept.app import InterceptApp
from intercept.core.models import Headers, Request, Response
from intercept.proxy.http1 import serialize_request, serialize_response
from intercept.proxy.intercept import InterceptDecision
from intercept.proxy.rules import Rule
from intercept.proxy.upstream import UpstreamError
from intercept.proxy.websocket import WebSocketFrame
from intercept.store.sitemap import ScopeRule
from intercept.tools.repeater import request_from_raw

log = logging.getLogger("intercept.api")

__all__ = ["create_api"]


# ----------------------------------------------------------------- schemas


class ConfigPatch(BaseModel):
    proxy: dict[str, Any] | None = None
    api: dict[str, Any] | None = None
    scan: dict[str, Any] | None = None
    log_level: str | None = None


class ScopeRulePayload(BaseModel):
    pattern: str
    kind: Literal["include", "exclude"] = "include"
    target: Literal["host", "url"] = "host"
    enabled: bool = True


class RepeatRequest(BaseModel):
    tab_id: str
    raw: str | None = None
    method: str | None = None
    url: str | None = None
    headers: dict[str, list[str]] | None = None
    body: str | None = None
    body_encoding: Literal["utf-8", "base64", "hex"] = "utf-8"
    #: Send the request over HTTP/2 when the origin offers it.
    http2: bool = False


class WebSocketFramePayload(BaseModel):
    """A frame to send over a WebSocket connection."""

    text: str = ""
    encoding: Literal["utf-8", "base64", "hex"] = "utf-8"
    opcode: Literal["text", "binary", "ping", "pong"] = "text"


class WebSocketReceivePayload(BaseModel):
    """How long to wait for the frames the origin sends."""

    timeout: float = 5.0


class ResendRequest(BaseModel):
    """Which of the earlier attempts to send again."""

    attempt: int = 0


class TabPayload(BaseModel):
    raw: str | None = None
    method: str | None = None
    url: str | None = None
    headers: dict[str, list[str]] | None = None
    body: str | None = None
    body_encoding: Literal["utf-8", "base64", "hex"] = "utf-8"
    name: str | None = None
    color: str = ""


class SpiderStart(BaseModel):
    seeds: list[str] = Field(default_factory=list)
    use_known_hosts: bool = True


class TagsPayload(BaseModel):
    tags: list[str] = Field(default_factory=list)


class AnnotationPayload(BaseModel):
    """Remarks attached to the request or to the response of an exchange."""

    side: Literal["request", "response"] = "request"
    tags: list[str] | None = None
    notes: list[str] | None = None


class InterceptToggle(BaseModel):
    enabled: bool


class InterceptDecisionPayload(BaseModel):
    action: Literal["forward", "drop"] = "forward"
    raw: str | None = None
    method: str | None = None
    url: str | None = None
    headers: dict[str, list[str]] | None = None
    body: str | None = None
    body_encoding: Literal["utf-8", "base64", "hex"] = "utf-8"
    #: The status of an edited response.
    status: int | None = None
    #: The reason phrase of an edited response.
    reason: str | None = None
    #: The headers of an edited response.
    response_headers: dict[str, list[str]] | None = None
    #: The body of an edited response.
    response_body: str | None = None
    response_body_encoding: Literal["utf-8", "base64", "hex"] = "utf-8"


class FrameDecisionPayload(BaseModel):
    action: Literal["forward", "drop"] = "forward"
    #: The replacement payload of an edited frame.
    text: str | None = None
    encoding: Literal["utf-8", "base64", "hex"] = "utf-8"


class RulePayload(BaseModel):
    name: str = ""
    kind: Literal["intercept", "forward", "replace"] = "intercept"
    enabled: bool = True
    host: str = ""
    path: str = ""
    method: str = ""
    phase: Literal["request", "response", "both"] = "request"
    target: Literal["request", "response"] = "request"
    place: Literal["header", "header-add", "body", "url"] = "header"
    field: str = ""
    match: str = ""
    replace: str = ""
    regex: bool = True


class ToolRun(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class FuzzJobPayload(BaseModel):
    raw: str | None = None
    method: str | None = None
    url: str | None = None
    headers: dict[str, list[str]] | None = None
    body: str | None = None
    body_encoding: Literal["utf-8", "base64", "hex"] = "utf-8"
    payloads: list[str] = Field(default_factory=list)
    positions: str = ""
    start: bool = True


class ScanJobPayload(BaseModel):
    targets: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    start: bool = True


class CommandRun(BaseModel):
    args: dict[str, Any] = Field(default_factory=dict)


class FilterPayload(BaseModel):
    filter: str = ""


class NotePayload(BaseModel):
    subject: str = "exchange"
    subject_id: str = ""
    text: str = ""
    color: str = ""
    tags: list[str] = Field(default_factory=list)


class IssuePayload(BaseModel):
    """Every field is optional so a partial update only touches what it names."""

    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    category: str | None = None
    exchange_ids: list[str] | None = None
    tags: list[str] | None = None


class SessionPayload(BaseModel):
    name: str = "Session"
    exchange_ids: list[str] = Field(default_factory=list)


class SessionMembersPayload(BaseModel):
    add: list[str] = Field(default_factory=list)
    remove: list[str] = Field(default_factory=list)


class TargetPayload(BaseModel):
    """Every field is optional so a partial update only touches what it names."""

    name: str | None = None
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    in_scope: bool | None = None
    notes: str | None = None
    tags: list[str] | None = None


class TaskPayload(BaseModel):
    """Every field is optional so a partial update only touches what it names."""

    name: str | None = None
    command: str | None = None
    args: dict[str, Any] | None = None
    interval: float | None = None
    enabled: bool | None = None


class ProjectPayload(BaseModel):
    name: str = "Project"
    description: str = ""
    path: str | None = None


# ------------------------------------------------------------------ helpers


def _decode_body(text: str | None, encoding: str) -> bytes:
    if not text:
        return b""
    if encoding == "base64":
        try:
            return base64.b64decode(text)
        except Exception:
            return b""
    if encoding == "hex":
        try:
            return bytes.fromhex(text.replace(" ", ""))
        except ValueError:
            return b""
    return text.encode("utf-8")


def _build_request(
    raw: str | None,
    method: str | None,
    url: str | None,
    headers: dict[str, list[str]] | None,
    body: str | None,
    body_encoding: str,
) -> Request:
    if raw:
        request = request_from_raw(raw, url)
        if body is not None:
            request.body = _decode_body(body, body_encoding)
        if headers:
            request.headers = Headers(
                [(k, v) for k, values in headers.items() for v in values]
            )
        return request
    if not url:
        raise HTTPException(status_code=400, detail="a url or raw request is required")
    header_list = [(k, v) for k, values in (headers or {}).items() for v in values]
    request = Request(
        method=(method or "GET").upper(),
        url=url,
        headers=Headers(header_list),
        body=_decode_body(body, body_encoding),
    )
    # Keep the raw form in sync so the editor always shows a full request.
    request.raw = serialize_request(
        request.method, request.origin_form, request.headers, request.body
    )
    return request


def _build_response(
    original: Response,
    status: int | None,
    reason: str | None,
    headers: dict[str, list[str]] | None,
    body: str | None,
    body_encoding: str,
) -> Response:
    """Build an edited copy of a response, keeping the fields that were not changed."""
    edited = Response(
        status=status if status is not None else original.status,
        reason=reason if reason is not None else original.reason,
        headers=original.headers.copy(),
        body=original.body,
        http_version=original.http_version,
        raw=original.raw,
        elapsed_ms=original.elapsed_ms,
        tls=original.tls,
    )
    if headers:
        edited.headers = Headers(
            [(k, v) for k, values in headers.items() for v in values]
        )
    if body is not None:
        edited.body = _decode_body(body, body_encoding)
    # Keep the raw form in sync so the editor always shows a full response.
    edited.raw = serialize_response(
        edited.status, edited.reason, edited.headers, edited.body, edited.http_version
    )
    return edited


# --------------------------------------------------------------------- API


def create_api(app: InterceptApp) -> FastAPI:
    """Build the FastAPI application for *app*."""
    # Origins may contain a wildcard for the port, which the middleware only
    # understands as a regular expression.
    exact_origins: list[str] = []
    wildcard_origins: list[str] = []
    for origin in app.config.api.cors_origins:
        (wildcard_origins if "*" in origin else exact_origins).append(origin)
    origin_regex = None
    if wildcard_origins:
        parts = [re.escape(origin).replace(r"\*", ".*") for origin in wildcard_origins]
        origin_regex = f"^({'|'.join(parts)})$"

    api = FastAPI(title="Intercept", version="0.1.0")
    api.add_middleware(
        CORSMiddleware,
        allow_origins=exact_origins,
        allow_origin_regex=origin_regex,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    router = APIRouter(prefix="/api")

    # ------------------------------------------------------------- meta

    @router.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": "0.1.0",
            "started": app._started,
            "stats": await app.store.stats(),
        }

    @router.get("/state")
    async def state() -> dict[str, Any]:
        return app.state()

    @router.get("/config")
    async def get_config() -> dict[str, Any]:
        return app.config.to_dict()

    @router.put("/config")
    async def put_config(patch: ConfigPatch) -> dict[str, Any]:
        current = app.config.to_dict()
        for section in ("proxy", "api", "scan"):
            value = getattr(patch, section)
            if value:
                current.setdefault(section, {}).update(value)
        if patch.log_level:
            current["log_level"] = patch.log_level
        app.config.apply(current)
        app.config.save()
        # A listener that was added or removed has to take effect now, and
        # not only after the next restart of the daemon.
        await app.proxy.sync_listeners()
        return app.config.to_dict()

    # ---------------------------------------------------------- traffic

    @router.get("/traffic")
    async def traffic(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        host: str | None = None,
        origin: str | None = None,
        search: str | None = None,
        status_min: int | None = None,
        status_max: int | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        items = await app.store.list(
            limit=limit,
            offset=offset,
            host=host,
            origin=origin,
            search=search,
            status_min=status_min,
            status_max=status_max,
            filter=filter,
        )
        return {
            "items": items,
            "total": await app.store.count(host),
            "limit": limit,
            "offset": offset,
        }

    @router.get("/traffic/{exchange_id}")
    async def traffic_detail(exchange_id: str) -> dict[str, Any]:
        item = await app.store.get(exchange_id)
        if item is None:
            raise HTTPException(status_code=404, detail="exchange not found")
        return item

    @router.delete("/traffic")
    async def clear_traffic() -> dict[str, Any]:
        return {"removed": await app.store.clear()}

    @router.put("/traffic/{exchange_id}/tags")
    async def set_tags(exchange_id: str, payload: TagsPayload) -> dict[str, Any]:
        ok = await app.store.set_tags(exchange_id, payload.tags)
        if not ok:
            raise HTTPException(status_code=404, detail="exchange not found")
        return {"id": exchange_id, "tags": payload.tags}

    @router.put("/traffic/{exchange_id}/annotation")
    async def set_annotation(
        exchange_id: str, payload: AnnotationPayload
    ) -> dict[str, Any]:
        side = payload.side
        ok = await app.store.set_annotation(
            exchange_id, side, payload.tags, payload.notes
        )
        if not ok:
            raise HTTPException(status_code=404, detail="exchange not found")
        return {"id": exchange_id, "side": side, "tags": payload.tags, "notes": payload.notes}

    # ----------------------------------------------------------- commands

    @router.get("/commands")
    async def list_commands() -> dict[str, Any]:
        return {
            "commands": app.commands.list(),
            "categories": app.commands.categories(),
        }

    @router.get("/commands/search")
    async def search_commands(q: str = "") -> dict[str, Any]:
        return {"commands": app.commands.search(q)}

    @router.post("/commands/{command_id}/run")
    async def run_command(command_id: str, payload: CommandRun) -> dict[str, Any]:
        from intercept.core.commands import CommandError

        try:
            result = await app.commands.run(command_id, payload.args)
        except CommandError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            app.log.record("error", "commands", "a command failed", {"id": command_id})
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"id": command_id, "result": result}

    # ------------------------------------------------------------- filter

    @router.get("/filter")
    async def get_filter() -> dict[str, Any]:
        return app.filters.to_dict()

    @router.put("/filter")
    async def put_filter(payload: FilterPayload) -> dict[str, Any]:
        if not app.filters.set(payload.filter):
            raise HTTPException(status_code=400, detail=app.filters.error)
        return app.filters.to_dict()

    # ------------------------------------------------------------- search

    @router.get("/search")
    async def search(
        q: str = "",
        limit: int = Query(100, ge=1, le=1000),
        in_body: bool = True,
    ) -> dict[str, Any]:
        """Search the history for a string, optionally in the bodies."""
        if not q:
            return {"items": [], "total": 0, "query": q}
        items = await app.store.search(q, limit=limit, in_body=in_body)
        return {"items": items, "total": len(items), "query": q}

    # --------------------------------------------------------- dashboard

    @router.get("/dashboard")
    async def dashboard() -> dict[str, Any]:
        stats = await app.store.stats()
        findings = await app.finding_store.list(limit=1000)
        severity: dict[str, int] = {}
        for finding in findings:
            key = str(finding.get("severity", "info"))
            severity[key] = severity.get(key, 0) + 1
        return {
            "traffic": stats,
            "findings": {"total": len(findings), "by_severity": severity},
            "issues": await app.issues.summary(),
            "notes": await app.notes.count(),
            "targets": await app.targets.list(),
            "sessions": await app.sessions.list(),
            "websockets": await app.websockets.count(),
            "log": {"total": await app.log.count(), "levels": await app.log.levels()},
            "tasks": await app.task_store.list(),
            "filter": app.filters.to_dict(),
        }

    # --------------------------------------------------------- organizer

    @router.get("/organizer")
    async def organizer(
        limit: int = Query(200, ge=1, le=2000),
        filter: str | None = None,
    ) -> dict[str, Any]:
        """The traffic grouped the way the organizer shows it."""
        items = await app.store.list(limit=limit, filter=filter)
        groups: dict[str, dict[str, Any]] = {}
        for item in items:
            host = item.get("host", "")
            group = groups.setdefault(
                host,
                {"host": host, "count": 0, "paths": {}, "statuses": {}, "size": 0},
            )
            group["count"] += 1
            group["size"] += int(item.get("response_length", 0))
            status = str(item.get("status", 0))
            group["statuses"][status] = group["statuses"].get(status, 0) + 1
            path = item.get("path", "")
            entry = group["paths"].setdefault(
                path, {"path": path, "count": 0, "statuses": {}, "methods": {}}
            )
            entry["count"] += 1
            entry["statuses"][status] = entry["statuses"].get(status, 0) + 1
            method = str(item.get("method", ""))
            entry["methods"][method] = entry["methods"].get(method, 0) + 1
        return {
            "hosts": sorted(groups.values(), key=lambda item: (-item["count"], item["host"])),
            "total": len(items),
        }

    # --------------------------------------------------------------- log

    @router.get("/log")
    async def log_entries(
        limit: int = Query(200, ge=1, le=2000),
        offset: int = Query(0, ge=0),
        level: str | None = None,
        source: str | None = None,
        search: str | None = None,
        filter: str | None = None,
    ) -> dict[str, Any]:
        entries = await app.log.list(
            limit=limit,
            offset=offset,
            level=level,
            source=source,
            search=search,
            filter=filter,
        )
        return {
            "entries": entries,
            "total": await app.log.count(),
            "levels": await app.log.levels(),
            "sources": await app.log.sources(),
        }

    @router.delete("/log")
    async def clear_log() -> dict[str, Any]:
        return {"removed": await app.log.clear()}

    @router.get("/log/export")
    async def export_log() -> Any:
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(await app.log.export())

    # ------------------------------------------------------------- notes

    @router.get("/notes")
    async def list_notes(
        subject: str | None = None,
        subject_id: str | None = None,
        search: str | None = None,
        limit: int = Query(200, ge=1, le=2000),
    ) -> dict[str, Any]:
        from intercept.store.notes import COLORS

        return {
            "notes": await app.notes.list(
                subject=subject, subject_id=subject_id, search=search, limit=limit
            ),
            "total": await app.notes.count(),
            "colors": list(COLORS),
        }

    @router.post("/notes")
    async def create_note(payload: NotePayload) -> dict[str, Any]:
        note = await app.notes.create(
            payload.subject,
            payload.subject_id,
            payload.text,
            payload.color,
            payload.tags,
        )
        app.log.record("info", "notes", "note added", {"subject": payload.subject})
        return note.to_dict()

    @router.put("/notes/{note_id}")
    async def update_note(note_id: str, payload: NotePayload) -> dict[str, Any]:
        note = await app.notes.update(
            note_id,
            text=payload.text or None,
            color=payload.color or None,
            tags=payload.tags or None,
        )
        if note is None:
            raise HTTPException(status_code=404, detail="note not found")
        return note.to_dict()

    @router.delete("/notes/{note_id}")
    async def delete_note(note_id: str) -> dict[str, Any]:
        if not await app.notes.delete(note_id):
            raise HTTPException(status_code=404, detail="note not found")
        return {"deleted": note_id}

    # ------------------------------------------------------------ issues

    @router.get("/issues")
    async def list_issues(
        status: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        limit: int = Query(200, ge=1, le=2000),
    ) -> dict[str, Any]:
        return {
            "issues": await app.issues.list(
                status=status, severity=severity, search=search, limit=limit
            ),
            "summary": await app.issues.summary(),
        }

    @router.post("/issues")
    async def create_issue(payload: IssuePayload) -> dict[str, Any]:
        issue = await app.issues.create(
            payload.title or "Untitled issue",
            description=payload.description or "",
            severity=payload.severity or "medium",
            status=payload.status or "open",
            category=payload.category or "",
            exchange_ids=payload.exchange_ids or [],
            tags=payload.tags or [],
        )
        app.log.record("info", "issues", "issue raised", {"title": issue.title})
        return issue.to_dict()

    @router.put("/issues/{issue_id}")
    async def update_issue(issue_id: str, payload: IssuePayload) -> dict[str, Any]:
        issue = await app.issues.update(
            issue_id,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            status=payload.status,
            category=payload.category,
            exchange_ids=payload.exchange_ids or None,
            tags=payload.tags or None,
        )
        if issue is None:
            raise HTTPException(status_code=404, detail="issue not found")
        return issue.to_dict()

    @router.delete("/issues/{issue_id}")
    async def delete_issue(issue_id: str) -> dict[str, Any]:
        if not await app.issues.delete(issue_id):
            raise HTTPException(status_code=404, detail="issue not found")
        return {"deleted": issue_id}

    # ---------------------------------------------------------- sessions

    @router.get("/sessions")
    async def list_sessions() -> dict[str, Any]:
        return {"sessions": await app.sessions.list()}

    @router.post("/sessions")
    async def create_session(payload: SessionPayload) -> dict[str, Any]:
        session = await app.sessions.create(payload.name, payload.exchange_ids)
        return session.to_dict()

    @router.put("/sessions/{session_id}")
    async def rename_session(session_id: str, payload: SessionPayload) -> dict[str, Any]:
        session = await app.sessions.rename(session_id, payload.name)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return session.to_dict()

    @router.post("/sessions/{session_id}/members")
    async def change_members(session_id: str, payload: SessionMembersPayload) -> dict[str, Any]:
        session = await app.sessions.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        if payload.add:
            session = await app.sessions.add(session_id, payload.add)
        if payload.remove:
            session = await app.sessions.remove(session_id, payload.remove)
        return session.to_dict() if session else {}

    @router.delete("/sessions/{session_id}")
    async def delete_session(session_id: str) -> dict[str, Any]:
        if not await app.sessions.delete(session_id):
            raise HTTPException(status_code=404, detail="session not found")
        return {"deleted": session_id}

    # ----------------------------------------------------------- targets

    @router.get("/targets")
    async def list_targets(in_scope: bool | None = None) -> dict[str, Any]:
        return {"targets": await app.targets.list(in_scope=in_scope)}

    @router.post("/targets")
    async def create_target(payload: TargetPayload) -> dict[str, Any]:
        host = payload.host or ""
        target = await app.targets.create(
            payload.name or host or "target",
            host=host,
            port=payload.port if payload.port is not None else 443,
            scheme=payload.scheme or "https",
            in_scope=True if payload.in_scope is None else payload.in_scope,
            notes=payload.notes or "",
            tags=payload.tags or [],
        )
        return target.to_dict()

    @router.put("/targets/{target_id}")
    async def update_target(target_id: str, payload: TargetPayload) -> dict[str, Any]:
        target = await app.targets.update(
            target_id,
            name=payload.name or None,
            host=payload.host or None,
            port=payload.port,
            scheme=payload.scheme,
            in_scope=payload.in_scope,
            notes=payload.notes,
            tags=payload.tags or None,
        )
        if target is None:
            raise HTTPException(status_code=404, detail="target not found")
        return target.to_dict()

    @router.delete("/targets/{target_id}")
    async def delete_target(target_id: str) -> dict[str, Any]:
        if not await app.targets.delete(target_id):
            raise HTTPException(status_code=404, detail="target not found")
        return {"deleted": target_id}

    # ------------------------------------------------------------- tasks

    @router.get("/tasks")
    async def list_tasks(enabled: bool | None = None) -> dict[str, Any]:
        return {"tasks": await app.task_store.list(enabled=enabled)}

    @router.post("/tasks")
    async def create_task(payload: TaskPayload) -> dict[str, Any]:
        if not payload.command:
            raise HTTPException(status_code=400, detail="a command is required")
        task = await app.task_store.create(
            payload.name or payload.command,
            payload.command,
            args=payload.args or {},
            interval=payload.interval if payload.interval is not None else 60.0,
            enabled=True if payload.enabled is None else payload.enabled,
        )
        return task.to_dict()

    @router.put("/tasks/{task_id}")
    async def update_task(task_id: str, payload: TaskPayload) -> dict[str, Any]:
        task = await app.task_store.update(
            task_id,
            name=payload.name or None,
            command=payload.command or None,
            args=payload.args or None,
            interval=payload.interval,
            enabled=payload.enabled,
        )
        if task is None:
            raise HTTPException(status_code=404, detail="task not found")
        return task.to_dict()

    @router.post("/tasks/{task_id}/run")
    async def run_task(task_id: str) -> dict[str, Any]:
        if not await app.scheduler.run_now(task_id):
            raise HTTPException(status_code=404, detail="task not found")
        task = await app.task_store.get(task_id)
        return task.to_dict() if task else {}

    @router.delete("/tasks/{task_id}")
    async def delete_task(task_id: str) -> dict[str, Any]:
        if not await app.task_store.delete(task_id):
            raise HTTPException(status_code=404, detail="task not found")
        return {"deleted": task_id}

    # ---------------------------------------------------------- projects

    @router.get("/projects")
    async def list_projects() -> dict[str, Any]:
        return {"projects": app.projects.list(), "current": app.projects.current()}

    @router.post("/projects")
    async def create_project(payload: ProjectPayload) -> dict[str, Any]:
        return app.projects.create(
            payload.name, path=payload.path, description=payload.description
        )

    @router.get("/projects/{project_id}")
    async def get_project(project_id: str) -> dict[str, Any]:
        contents = app.projects.load(project_id)
        if not contents:
            raise HTTPException(status_code=404, detail="project not found")
        return contents

    @router.post("/projects/{project_id}/save")
    async def save_project(project_id: str) -> dict[str, Any]:
        project = await app.save_project(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="project not found")
        return project

    @router.post("/projects/{project_id}/open")
    async def open_project(project_id: str) -> dict[str, Any]:
        project = app.projects.open(project_id)
        if project is None:
            raise HTTPException(status_code=404, detail="project not found")
        return project

    @router.delete("/projects/{project_id}")
    async def delete_project(project_id: str) -> dict[str, Any]:
        if not app.projects.delete(project_id):
            raise HTTPException(status_code=404, detail="project not found")
        return {"deleted": project_id}

    # ----------------------------------------------------------- reports

    @router.get("/reports")
    async def build_report(title: str = "Intercept report") -> dict[str, Any]:
        return await app.build_report(title)

    @router.get("/reports/render")
    async def render_report(
        title: str = "Intercept report",
        format: str = "markdown",
    ) -> Any:
        from fastapi.responses import PlainTextResponse

        from intercept.core.reports import render_report as render

        report = await app.build_report(title)
        body = render(report, format)
        if format == "html":
            return PlainTextResponse(body, media_type="text/html")
        if format == "json":
            return PlainTextResponse(body, media_type="application/json")
        return PlainTextResponse(body, media_type="text/markdown")

    # --------------------------------------------------------- websockets

    @router.get("/websockets/connections")
    async def websocket_connections() -> dict[str, Any]:
        return {"connections": await app.websockets.connections()}

    @router.get("/websockets/messages")
    async def websocket_messages(
        connection_id: str | None = None,
        direction: str | None = None,
        search: str | None = None,
        filter: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
    ) -> dict[str, Any]:
        return {
            "messages": await app.websockets.messages(
                connection_id=connection_id,
                direction=direction,
                search=search,
                filter=filter,
                limit=limit,
            ),
            "total": await app.websockets.count(),
        }

    @router.delete("/websockets")
    async def clear_websockets() -> dict[str, Any]:
        return {"removed": await app.websockets.clear()}

    # ------------------------------------------------------------ sites

    @router.get("/sites")
    async def sites() -> dict[str, Any]:
        return {"hosts": await app.sitemap.hosts(), "tree": await app.sitemap.tree()}

    @router.get("/sites/{host}/paths")
    async def site_paths(host: str) -> dict[str, Any]:
        return {"host": host, "paths": await app.store.distinct_paths(host)}

    @router.get("/scope")
    async def get_scope() -> dict[str, Any]:
        return app.scope.to_dict()

    @router.post("/scope/rules")
    async def add_scope_rule(payload: ScopeRulePayload) -> dict[str, Any]:
        app.scope.add(ScopeRule(**payload.model_dump()))
        app.scope.save(app.config.home + "/scope.json")
        return app.scope.to_dict()

    @router.delete("/scope/rules")
    async def remove_scope_rule(pattern: str) -> dict[str, Any]:
        app.scope.remove(pattern)
        app.scope.save(app.config.home + "/scope.json")
        return app.scope.to_dict()

    # --------------------------------------------------------- repeater

    @router.get("/repeater/tabs")
    async def list_tabs() -> dict[str, Any]:
        return {"tabs": [tab.to_dict() for tab in app.repeater.tabs()]}

    @router.post("/repeater/tabs")
    async def create_tab(payload: TabPayload) -> dict[str, Any]:
        request = _build_request(
            payload.raw, payload.method, payload.url, payload.headers, payload.body,
            payload.body_encoding,
        )
        tab = app.repeater.create_tab(request, payload.name, color=payload.color)
        return tab.to_dict()

    @router.get("/repeater/tabs/{tab_id}")
    async def get_tab(tab_id: str) -> dict[str, Any]:
        tab = app.repeater.get(tab_id)
        if tab is None:
            raise HTTPException(status_code=404, detail="tab not found")
        return tab.to_dict()

    @router.put("/repeater/tabs/{tab_id}")
    async def update_tab(tab_id: str, payload: TabPayload) -> dict[str, Any]:
        if app.repeater.get(tab_id) is None:
            raise HTTPException(status_code=404, detail="tab not found")
        request = _build_request(
            payload.raw, payload.method, payload.url, payload.headers, payload.body,
            payload.body_encoding,
        )
        tab = app.repeater.update_request(tab_id, request)
        return tab.to_dict() if tab else {}

    @router.delete("/repeater/tabs/{tab_id}")
    async def delete_tab(tab_id: str) -> dict[str, Any]:
        if not app.repeater.delete_tab(tab_id):
            raise HTTPException(status_code=404, detail="tab not found")
        return {"deleted": tab_id}

    @router.post("/repeater/tabs/{tab_id}/send")
    async def send_tab(tab_id: str, payload: RepeatRequest) -> dict[str, Any]:
        request = None
        if payload.raw or payload.url or payload.body is not None:
            request = _build_request(
                payload.raw, payload.method, payload.url, payload.headers, payload.body,
                payload.body_encoding,
            )
        response = await app.repeater.send(tab_id, request, http2=payload.http2)
        if response is None:
            raise HTTPException(status_code=404, detail="tab not found")
        tab = app.repeater.get(tab_id)
        return {
            "response": response.to_dict(),
            "tab": tab.to_dict() if tab else None,
        }

    @router.post("/repeater/tabs/{tab_id}/resend")
    async def resend_tab(tab_id: str, payload: ResendRequest) -> dict[str, Any]:
        """Send one of the earlier attempts of the tab again."""
        response = await app.repeater.resend(tab_id, payload.attempt)
        if response is None:
            raise HTTPException(status_code=404, detail="no such attempt")
        tab = app.repeater.get(tab_id)
        return {
            "response": response.to_dict(),
            "tab": tab.to_dict() if tab else None,
        }

    # ------------------------------------------------------ repeater sockets

    @router.post("/repeater/tabs/{tab_id}/websocket/open")
    async def open_websocket(tab_id: str) -> dict[str, Any]:
        """Open a WebSocket connection for the tab."""
        if app.repeater.get(tab_id) is None:
            raise HTTPException(status_code=404, detail="tab not found")
        try:
            session = await app.repeater.open_websocket(tab_id)
        except UpstreamError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return session.to_dict()

    @router.get("/repeater/tabs/{tab_id}/websocket")
    async def websocket_state(tab_id: str) -> dict[str, Any]:
        """The frames that were sent and received over the connection."""
        if app.repeater.get(tab_id) is None:
            raise HTTPException(status_code=404, detail="tab not found")
        session = app.repeater.websocket(tab_id)
        if session is None:
            return {"open": False, "closed": True, "sent": [], "received": []}
        return session.to_dict()

    @router.post("/repeater/tabs/{tab_id}/websocket/send")
    async def send_websocket_frame(
        tab_id: str, payload: WebSocketFramePayload
    ) -> dict[str, Any]:
        """Send a frame over the WebSocket connection of the tab."""
        if app.repeater.get(tab_id) is None:
            raise HTTPException(status_code=404, detail="tab not found")
        opcodes = {"text": 0x1, "binary": 0x2, "ping": 0x9, "pong": 0xA}
        try:
            frame = await app.repeater.send_websocket(
                tab_id, _decode_body(payload.text, payload.encoding), opcodes[payload.opcode]
            )
        except UpstreamError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return frame.to_dict()

    @router.post("/repeater/tabs/{tab_id}/websocket/receive")
    async def receive_websocket_frames(
        tab_id: str, payload: WebSocketReceivePayload
    ) -> dict[str, Any]:
        """Read the frames the origin sent."""
        if app.repeater.get(tab_id) is None:
            raise HTTPException(status_code=404, detail="tab not found")
        try:
            frames = await app.repeater.receive_websocket(tab_id, payload.timeout)
        except UpstreamError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"frames": [frame.to_dict() for frame in frames]}

    @router.post("/repeater/tabs/{tab_id}/websocket/close")
    async def close_websocket(tab_id: str) -> dict[str, Any]:
        """Close the WebSocket connection of the tab."""
        if app.repeater.get(tab_id) is None:
            raise HTTPException(status_code=404, detail="tab not found")
        await app.repeater.close_websocket(tab_id)
        return {"closed": tab_id}

    # ----------------------------------------------------------- spider

    @router.post("/spider/start")
    async def start_spider(payload: SpiderStart) -> dict[str, Any]:
        seeds = list(payload.seeds)
        if payload.use_known_hosts or not seeds:
            hosts = await app.store.distinct_hosts()
            known = app.spider.seed_from_hosts([h["host"] for h in hosts])
            seeds.extend(seed for seed in known if seed not in seeds)
        if not seeds:
            raise HTTPException(status_code=400, detail="no seeds available")
        job = await app.spider.start(seeds)
        return job.to_dict()

    @router.get("/spider/jobs")
    async def list_jobs() -> dict[str, Any]:
        return {"jobs": [job.to_dict() for job in app.spider.jobs()]}

    @router.post("/spider/jobs/{job_id}/stop")
    async def stop_spider(job_id: str) -> dict[str, Any]:
        if not await app.spider.stop(job_id):
            raise HTTPException(status_code=404, detail="job not found")
        return {"stopped": job_id}

    # -------------------------------------------------------- intercept

    @router.get("/intercept")
    async def intercept_state() -> dict[str, Any]:
        return app.intercept.state()

    @router.get("/intercept/{request_id}")
    async def held_message(request_id: str) -> dict[str, Any]:
        """The full text of a message that is being held."""
        item = app.intercept.item(request_id)
        if item is None:
            raise HTTPException(status_code=404, detail="no such pending request")
        return {
            "id": item.id,
            "phase": item.phase,
            "created_at": item.created_at,
            "request": item.request.to_dict(),
            "response": item.response.to_dict() if item.response is not None else None,
        }

    @router.post("/intercept/toggle")
    async def toggle_intercept(payload: InterceptToggle) -> dict[str, Any]:
        app.intercept.enabled = payload.enabled
        app.bus.emit("intercept.toggled", enabled=payload.enabled)
        return app.intercept.state()

    @router.post("/intercept/{request_id}")
    async def decide(request_id: str, payload: InterceptDecisionPayload) -> dict[str, Any]:
        item = app.intercept.item(request_id)
        request = None
        response = None
        if item is not None and item.phase == "response" and item.response is not None:
            if payload.action == "forward" and (
                payload.status is not None
                or payload.reason is not None
                or payload.response_headers
                or payload.response_body is not None
            ):
                response = _build_response(
                    item.response,
                    payload.status,
                    payload.reason,
                    payload.response_headers,
                    payload.response_body,
                    payload.response_body_encoding,
                )
        elif payload.action == "forward" and (
            payload.raw or payload.url or payload.body is not None
        ):
            request = _build_request(
                payload.raw, payload.method, payload.url, payload.headers, payload.body,
                payload.body_encoding,
            )
        decision = InterceptDecision(
            action=payload.action, request=request, response=response
        )
        if not app.intercept.resolve(request_id, decision):
            raise HTTPException(status_code=404, detail="no such pending request")
        return {"resolved": request_id, "action": payload.action}

    @router.post("/intercept/frames/{frame_id}")
    async def decide_frame(frame_id: str, payload: FrameDecisionPayload) -> dict[str, Any]:
        frame = app.intercept.frame(frame_id)
        edited = None
        if frame is not None and payload.action == "forward" and payload.text is not None:
            edited = WebSocketFrame(
                direction=frame.direction,
                opcode=frame.opcode,
                payload=_decode_body(payload.text, payload.encoding),
                fin=frame.fin,
            )
        decision = InterceptDecision(action=payload.action, frame=edited)
        if not app.intercept.resolve_frame(frame_id, decision):
            raise HTTPException(status_code=404, detail="no such pending frame")
        return {"resolved": frame_id, "action": payload.action}

    # -------------------------------------------------------------- rules

    @router.get("/rules")
    async def list_rules() -> dict[str, Any]:
        return {"rules": [rule.to_dict() for rule in await app.rule_store.list()]}

    @router.post("/rules")
    async def create_rule(payload: RulePayload) -> dict[str, Any]:
        rule = Rule.from_dict(payload.model_dump())
        rule.id = uuid.uuid4().hex[:12]
        await app.rule_store.create(rule)
        await app.reload_rules()
        return rule.to_dict()

    @router.put("/rules/{rule_id}")
    async def update_rule(rule_id: str, payload: RulePayload) -> dict[str, Any]:
        rule = Rule.from_dict(payload.model_dump())
        rule.id = rule_id
        updated = await app.rule_store.update(rule)
        if updated is None:
            raise HTTPException(status_code=404, detail="rule not found")
        await app.reload_rules()
        return updated.to_dict()

    @router.delete("/rules/{rule_id}")
    async def delete_rule(rule_id: str) -> dict[str, Any]:
        if not await app.rule_store.delete(rule_id):
            raise HTTPException(status_code=404, detail="rule not found")
        await app.reload_rules()
        return {"deleted": rule_id}

    # ------------------------------------------------------------- fuzzer

    @router.get("/fuzz/jobs")
    async def list_fuzz_jobs() -> dict[str, Any]:
        return {"jobs": [job.to_dict() for job in app.fuzzer.jobs()]}

    @router.post("/fuzz/jobs")
    async def create_fuzz_job(payload: FuzzJobPayload) -> dict[str, Any]:
        request = _build_request(
            payload.raw, payload.method, payload.url, payload.headers, payload.body,
            payload.body_encoding,
        )
        job = app.fuzzer.create_job(request, payload.payloads, payload.positions)
        if payload.start:
            await app.fuzzer.start(job.id)
            job = app.fuzzer.get(job.id) or job
        return job.to_dict()

    @router.get("/fuzz/jobs/{job_id}")
    async def get_fuzz_job(job_id: str) -> dict[str, Any]:
        job = app.fuzzer.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job.to_dict()

    @router.post("/fuzz/jobs/{job_id}/start")
    async def start_fuzz_job(job_id: str) -> dict[str, Any]:
        job = await app.fuzzer.start(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job.to_dict()

    @router.post("/fuzz/jobs/{job_id}/stop")
    async def stop_fuzz_job(job_id: str) -> dict[str, Any]:
        if not app.fuzzer.stop(job_id):
            raise HTTPException(status_code=404, detail="job not found")
        return {"stopped": job_id}

    @router.delete("/fuzz/jobs/{job_id}")
    async def delete_fuzz_job(job_id: str) -> dict[str, Any]:
        if not app.fuzzer.delete_job(job_id):
            raise HTTPException(status_code=404, detail="job not found")
        return {"deleted": job_id}

    # ------------------------------------------------------------- scanner

    @router.get("/scanner/checks")
    async def list_checks() -> dict[str, Any]:
        return {"checks": app.scanner.catalog()}

    @router.get("/scanner/jobs")
    async def list_scan_jobs() -> dict[str, Any]:
        return {"jobs": [job.to_dict() for job in app.scanner.jobs()]}

    @router.post("/scanner/jobs")
    async def create_scan_job(payload: ScanJobPayload) -> dict[str, Any]:
        targets = [t.strip() for t in payload.targets if t.strip()]
        if not targets:
            raise HTTPException(status_code=400, detail="at least one target is required")
        job = app.scanner.create_job(targets, payload.checks or None)
        if payload.start:
            await app.scanner.start(job.id)
            job = app.scanner.get(job.id) or job
        return job.to_dict()

    @router.get("/scanner/jobs/{job_id}")
    async def get_scan_job(job_id: str) -> dict[str, Any]:
        job = app.scanner.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job.to_dict()

    @router.post("/scanner/jobs/{job_id}/start")
    async def start_scan_job(job_id: str) -> dict[str, Any]:
        job = await app.scanner.start(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job.to_dict()

    @router.post("/scanner/jobs/{job_id}/stop")
    async def stop_scan_job(job_id: str) -> dict[str, Any]:
        if not app.scanner.stop(job_id):
            raise HTTPException(status_code=404, detail="job not found")
        return {"stopped": job_id}

    @router.delete("/scanner/jobs/{job_id}")
    async def delete_scan_job(job_id: str) -> dict[str, Any]:
        if not app.scanner.delete_job(job_id):
            raise HTTPException(status_code=404, detail="job not found")
        return {"deleted": job_id}

    # ------------------------------------------------------------ findings

    @router.get("/findings")
    async def list_findings(
        limit: int = Query(200, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        severity: str | None = None,
        host: str | None = None,
        check_id: str | None = None,
        source: str | None = None,
    ) -> dict[str, Any]:
        items = await app.finding_store.list(
            limit=limit,
            offset=offset,
            severity=severity,
            host=host,
            check_id=check_id,
            source=source,
        )
        return {
            "items": items,
            "total": await app.finding_store.count(),
            "severities": await app.finding_store.severity_counts(),
            "limit": limit,
            "offset": offset,
        }

    @router.delete("/findings")
    async def clear_findings() -> dict[str, Any]:
        return {"removed": await app.finding_store.clear()}

    @router.put("/findings/{finding_id}/acknowledge")
    async def acknowledge_finding(finding_id: str) -> dict[str, Any]:
        if not await app.finding_store.acknowledge(finding_id):
            raise HTTPException(status_code=404, detail="finding not found")
        return {"id": finding_id, "acknowledged": True}

    # ----------------------------------------------------------- plugins

    @router.get("/plugins")
    async def list_plugins() -> dict[str, Any]:
        return {
            "plugins": [info.to_dict() for info in app.plugins.plugins.values()],
            "tools": app.plugins.describe_tools(),
        }

    @router.post("/tools/{tool_id}/run")
    async def run_tool(tool_id: str, payload: ToolRun) -> dict[str, Any]:
        if tool_id not in app.plugins.tools:
            raise HTTPException(status_code=404, detail="unknown tool")
        return await app.plugins.run_tool(tool_id, payload.values)

    # --------------------------------------------------------------- CA

    @router.get("/ca")
    async def ca_info() -> dict[str, Any]:
        return {
            "subject": app.ca.subject(),
            "fingerprint": app.ca.fingerprint(),
            "path": str(app.ca.root_cert_path),
        }

    @router.get("/ca/download")
    async def ca_download() -> Any:
        from fastapi.responses import Response

        return Response(
            content=app.ca.root_pem(),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": 'attachment; filename="intercept-ca.crt"'},
        )

    @router.get("/ca/targets")
    async def ca_targets() -> dict[str, Any]:
        """The trust stores the browsers on this machine could use."""
        from intercept.crypto import install as trust

        return {"targets": [target.to_dict() for target in trust.targets()]}

    @router.post("/ca/install")
    async def ca_install(payload: dict[str, Any]) -> dict[str, Any]:
        """Trust the root CA in the local browsers."""
        from intercept.crypto import install as trust

        found = trust.targets()
        wanted = payload.get("target")
        if wanted:
            chosen = [target for target in found if target.name == wanted]
            if not chosen:
                raise HTTPException(status_code=400, detail=f"unknown target: {wanted}")
        else:
            chosen = [target for target in found if target.available]

        certificate = Path(app.ca.root_cert_path)
        results = []
        for target in chosen:
            try:
                detail = trust.install(target.name, certificate)
            except Exception as exc:  # noqa: BLE001
                results.append({"target": target.name, "ok": False, "detail": str(exc)})
                continue
            results.append({"target": target.name, "ok": True, "detail": detail})

        return {
            "certificate": str(certificate),
            "fingerprint": app.ca.fingerprint(),
            "results": results,
            "targets": [target.to_dict() for target in found],
        }

    @router.post("/ca/uninstall")
    async def ca_uninstall(payload: dict[str, Any]) -> dict[str, Any]:
        """Stop trusting the root CA."""
        from intercept.crypto import install as trust

        found = trust.targets()
        wanted = payload.get("target")
        chosen = (
            [target for target in found if target.name == wanted]
            if wanted
            else [target for target in found if target.available]
        )
        results = []
        for target in chosen:
            try:
                detail = trust.uninstall(target.name)
            except Exception as exc:  # noqa: BLE001
                results.append({"target": target.name, "ok": False, "detail": str(exc)})
                continue
            results.append({"target": target.name, "ok": True, "detail": detail})
        return {"results": results}

    api.include_router(router)

    # --------------------------------------------------------- websocket

    @api.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        queue = app.bus.subscribe()
        try:
            await websocket.send_json({"type": "hello", "data": app.state()})
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    await websocket.send_json({"type": "ping", "ts": 0})
                    continue
                await websocket.send_json(event.to_dict())
        except WebSocketDisconnect:
            pass
        except Exception:  # noqa: BLE001
            log.debug("websocket closed unexpectedly", exc_info=True)
        finally:
            app.bus.unsubscribe(queue)

    return api

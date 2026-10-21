"""The issue tracker.

Findings come from the scanner, but an issue is what a human decides to do
about them. An issue links back to the exchanges and findings it was raised
from, and carries a status, a severity and an owner.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from intercept.store.sqlite import SqliteStore

__all__ = ["IssueStore", "Issue"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS issues (
    id           TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'medium',
    status       TEXT NOT NULL DEFAULT 'open',
    category     TEXT NOT NULL DEFAULT '',
    source       TEXT NOT NULL DEFAULT '',
    source_id    TEXT NOT NULL DEFAULT '',
    exchange_ids TEXT NOT NULL DEFAULT '[]',
    tags         TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);
"""

STATUSES = ("open", "confirmed", "in-progress", "resolved", "ignored", "false-positive")
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass(slots=True)
class Issue:
    id: str
    created_at: float
    updated_at: float
    title: str
    description: str = ""
    severity: str = "medium"
    status: str = "open"
    category: str = ""
    source: str = ""
    source_id: str = ""
    exchange_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "category": self.category,
            "source": self.source,
            "source_id": self.source_id,
            "exchange_ids": list(self.exchange_ids),
            "tags": list(self.tags),
        }


class IssueStore(SqliteStore):
    """Issues raised by hand or promoted from a finding."""

    def __init__(self, path: str) -> None:
        super().__init__(path, _SCHEMA)

    async def create(
        self,
        title: str,
        *,
        description: str = "",
        severity: str = "medium",
        status: str = "open",
        category: str = "",
        source: str = "",
        source_id: str = "",
        exchange_ids: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> Issue:
        now = time.time()
        issue = Issue(
            id=uuid.uuid4().hex[:12],
            created_at=now,
            updated_at=now,
            title=title,
            description=description,
            severity=severity if severity in SEVERITIES else "medium",
            status=status if status in STATUSES else "open",
            category=category,
            source=source,
            source_id=source_id,
            exchange_ids=list(exchange_ids or []),
            tags=list(tags or []),
        )
        await self.run(
            """
            INSERT INTO issues (id, created_at, updated_at, title, description, severity,
                                status, category, source, source_id, exchange_ids, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                issue.id,
                issue.created_at,
                issue.updated_at,
                issue.title,
                issue.description,
                issue.severity,
                issue.status,
                issue.category,
                issue.source,
                issue.source_id,
                json.dumps(issue.exchange_ids),
                json.dumps(issue.tags),
            ),
        )
        return issue

    async def update(self, issue_id: str, **changes: Any) -> Issue | None:
        issue = await self.get(issue_id)
        if issue is None:
            return None
        if "title" in changes and changes["title"] is not None:
            issue.title = str(changes["title"])
        if "description" in changes and changes["description"] is not None:
            issue.description = str(changes["description"])
        if changes.get("severity") in SEVERITIES:
            issue.severity = changes["severity"]
        if changes.get("status") in STATUSES:
            issue.status = changes["status"]
        if "category" in changes and changes["category"] is not None:
            issue.category = str(changes["category"])
        if changes.get("exchange_ids") is not None:
            issue.exchange_ids = list(changes["exchange_ids"])
        if changes.get("tags") is not None:
            issue.tags = list(changes["tags"])
        issue.updated_at = time.time()
        await self.run(
            """
            UPDATE issues SET title = ?, description = ?, severity = ?, status = ?,
                             category = ?, exchange_ids = ?, tags = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                issue.title,
                issue.description,
                issue.severity,
                issue.status,
                issue.category,
                json.dumps(issue.exchange_ids),
                json.dumps(issue.tags),
                issue.updated_at,
                issue.id,
            ),
        )
        return issue

    async def get(self, issue_id: str) -> Issue | None:
        row = await self.fetch_one("SELECT * FROM issues WHERE id = ?", (issue_id,))
        return _issue(row) if row else None

    async def list(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        search: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(
            self._list_sync, status, severity, search, limit, offset
        )

    def _list_sync(
        self,
        status: str | None,
        severity: str | None,
        search: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if status:
            where.append("status = ?")
            params.append(status)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if search:
            where.append("(title LIKE ? OR description LIKE ?)")
            pattern = f"%{search}%"
            params.extend([pattern, pattern])
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM issues {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        return [issue.to_dict() for issue in (_issue(row) for row in rows)]

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM issues")
        return int(row["n"]) if row else 0

    async def summary(self) -> dict[str, Any]:
        rows = self._query(
            "SELECT status, COUNT(*) AS n FROM issues GROUP BY status ORDER BY n DESC"
        )
        by_status = {row["status"]: int(row["n"]) for row in rows}
        rows = self._query(
            "SELECT severity, COUNT(*) AS n FROM issues GROUP BY severity"
        )
        by_severity = {row["severity"]: int(row["n"]) for row in rows}
        return {
            "total": await self.count(),
            "by_status": by_status,
            "by_severity": by_severity,
        }

    async def delete(self, issue_id: str) -> bool:
        return await self.run("DELETE FROM issues WHERE id = ?", (issue_id,)) > 0


def _issue(row) -> Issue:
    def _list(value: Any) -> list[str]:
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return []
        return parsed if isinstance(parsed, list) else []

    return Issue(
        id=row["id"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
        title=row["title"],
        description=row["description"],
        severity=row["severity"],
        status=row["status"],
        category=row["category"],
        source=row["source"],
        source_id=row["source_id"],
        exchange_ids=_list(row["exchange_ids"]),
        tags=_list(row["tags"]),
    )

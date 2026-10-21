"""Finding storage.

Findings are the output of the scanner and of any plugin check. They are kept
in their own table so that a scan history survives a restart and can be
queried by severity, host or check.
"""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from intercept.plugins.api import Finding

__all__ = ["FindingStore", "StoredFinding"]

_SEVERITIES = ("critical", "high", "medium", "low", "info")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    check_id    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    description TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    host        TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    request_id  TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'scanner',
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
"""


@dataclass
class StoredFinding:
    """A finding plus the bookkeeping the daemon needs."""

    id: str
    created_at: float
    check_id: str
    title: str
    severity: str = "info"
    description: str = ""
    url: str = ""
    host: str = ""
    evidence: str = ""
    remediation: str = ""
    request_id: str = ""
    source: str = "scanner"
    acknowledged: bool = False
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "url": self.url,
            "host": self.host,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "request_id": self.request_id,
            "source": self.source,
            "acknowledged": self.acknowledged,
            "tags": list(self.tags),
        }


class FindingStore:
    """Persistent store for findings."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)
        self._db.commit()

    # ----------------------------------------------------------------- write

    def add(self, finding: Finding, *, source: str = "scanner") -> StoredFinding:
        from urllib.parse import urlsplit

        host = ""
        try:
            host = urlsplit(finding.url).hostname or ""
        except ValueError:
            host = ""
        stored = StoredFinding(
            id=finding.request_id
            or f"find-{abs(hash((finding.check_id, finding.url, finding.title)))}",
            created_at=time.time(),
            check_id=finding.check_id,
            title=finding.title,
            severity=finding.severity,
            description=finding.description,
            url=finding.url,
            host=host,
            evidence=finding.evidence,
            remediation=finding.remediation,
            request_id=finding.request_id,
            source=source,
        )
        self._db.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, created_at, check_id, title, severity, description, url, host,
                evidence, remediation, request_id, source, acknowledged
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored.id,
                stored.created_at,
                stored.check_id,
                stored.title,
                stored.severity,
                stored.description,
                stored.url,
                stored.host,
                stored.evidence,
                stored.remediation,
                stored.request_id,
                stored.source,
                int(stored.acknowledged),
            ),
        )
        self._db.commit()
        return stored

    async def add_async(self, finding: Finding, *, source: str = "scanner") -> StoredFinding:
        return await asyncio.to_thread(self.add, finding, source=source)

    # ------------------------------------------------------------------ read

    async def list(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        severity: str | None = None,
        host: str | None = None,
        check_id: str | None = None,
        source: str | None = None,
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(
            self._list_sync, limit, offset, severity, host, check_id, source
        )

    def _list_sync(
        self,
        limit: int,
        offset: int,
        severity: str | None,
        host: str | None,
        check_id: str | None,
        source: str | None,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if host:
            where.append("host = ?")
            params.append(host)
        if check_id:
            where.append("check_id = ?")
            params.append(check_id)
        if source:
            where.append("source = ?")
            params.append(source)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        query = (
            f"SELECT * FROM findings {clause} "
            "ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?"
        )
        cursor = self._db.execute(query, [*params, limit, offset])
        return [_row_to_dict(row) for row in cursor.fetchall()]

    async def count(self) -> int:
        return await asyncio.to_thread(self._count_sync)

    def _count_sync(self) -> int:
        return int(self._db.execute("SELECT COUNT(*) FROM findings").fetchone()[0])

    async def severity_counts(self) -> dict[str, int]:
        return await asyncio.to_thread(self._severity_counts_sync)

    def _severity_counts_sync(self) -> dict[str, int]:
        cursor = self._db.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        )
        return {row["severity"]: int(row["n"]) for row in cursor.fetchall()}

    async def clear(self) -> int:
        return await asyncio.to_thread(self._clear_sync)

    def _clear_sync(self) -> int:
        count = int(self._db.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
        self._db.execute("DELETE FROM findings")
        self._db.commit()
        return count

    async def acknowledge(self, finding_id: str, acknowledged: bool = True) -> bool:
        return await asyncio.to_thread(self._acknowledge_sync, finding_id, acknowledged)

    def _acknowledge_sync(self, finding_id: str, acknowledged: bool) -> bool:
        cursor = self._db.execute(
            "UPDATE findings SET acknowledged = ? WHERE id = ?", (int(acknowledged), finding_id)
        )
        self._db.commit()
        return cursor.rowcount > 0

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._db.close()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "check_id": row["check_id"],
        "title": row["title"],
        "severity": row["severity"],
        "description": row["description"],
        "url": row["url"],
        "host": row["host"],
        "evidence": row["evidence"],
        "remediation": row["remediation"],
        "request_id": row["request_id"],
        "source": row["source"],
        "acknowledged": bool(row["acknowledged"]),
        "tags": [],
    }

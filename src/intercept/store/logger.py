"""The event log.

Everything the daemon does that is worth remembering ends up here: proxy
activity, tool runs, scanner results, configuration changes and errors. The log
is bounded so it can never fill the disk, and it is searchable with the same
filter language the traffic history uses.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from intercept.core.filters import parse as parse_filter
from intercept.store.sqlite import SqliteStore

__all__ = ["EventLog", "LogEntry"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS log_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  REAL NOT NULL,
    level       TEXT NOT NULL,
    source      TEXT NOT NULL,
    message     TEXT NOT NULL,
    data        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_log_created ON log_entries(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_level ON log_entries(level);
"""

#: Levels from the quietest to the loudest.
LEVELS = ("debug", "info", "warning", "error", "critical")

#: How many entries are kept before the oldest are dropped.
MAX_ENTRIES = 20000


@dataclass(slots=True)
class LogEntry:
    id: int
    created_at: float
    level: str
    source: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "data": self.data,
        }


class EventLog(SqliteStore):
    """A searchable, bounded log of everything that happened."""

    def __init__(self, path: str, limit: int = MAX_ENTRIES) -> None:
        super().__init__(path, _SCHEMA)
        self.limit = limit

    def record(
        self,
        level: str,
        source: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Write an entry. Never raises, never blocks."""
        import json

        try:
            self._write(
                """
                INSERT INTO log_entries (created_at, level, source, message, data)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    level if level in LEVELS else "info",
                    source,
                    message,
                    json.dumps(data or {}, default=str),
                ),
            )
            self._trim()
        except Exception:  # noqa: BLE001 - logging must never break the app
            pass

    def _trim(self) -> None:
        count = int(self._one("SELECT COUNT(*) AS n FROM log_entries")["n"])
        if count > self.limit:
            self._write(
                """
                DELETE FROM log_entries WHERE id IN (
                    SELECT id FROM log_entries ORDER BY id ASC LIMIT ?
                )
                """,
                (count - self.limit,),
            )

    async def list(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        level: str | None = None,
        source: str | None = None,
        search: str | None = None,
        filter: str | None = None,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if level:
            where.append("level = ?")
            params.append(level)
        if source:
            where.append("source = ?")
            params.append(source)
        if search:
            where.append("(message LIKE ? OR source LIKE ?)")
            pattern = f"%{search}%"
            params.extend([pattern, pattern])
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = await self.fetch(
            f"""
            SELECT id, created_at, level, source, message, data
            FROM log_entries {clause}
            ORDER BY id DESC LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        entries = [_entry(row).to_dict() for row in rows]
        if filter:
            compiled = parse_filter(filter)
            entries = [entry for entry in entries if compiled.matches(_filter_row(entry))]
        return entries

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM log_entries")
        return int(row["n"]) if row else 0

    async def levels(self) -> dict[str, int]:
        rows = await self.fetch(
            "SELECT level, COUNT(*) AS n FROM log_entries GROUP BY level ORDER BY n DESC"
        )
        return {row["level"]: int(row["n"]) for row in rows}

    async def sources(self) -> list[str]:
        rows = await self.fetch("SELECT DISTINCT source FROM log_entries ORDER BY source")
        return [row["source"] for row in rows]

    async def clear(self) -> int:
        count = await self.count()
        await self.run("DELETE FROM log_entries")
        return count

    async def export(self) -> str:
        """The whole log as text, one line per entry."""
        rows = await self.fetch(
            "SELECT created_at, level, source, message FROM log_entries ORDER BY id ASC"
        )
        return "\n".join(
            f"{row['created_at']:.3f} {row['level'].upper():<8} {row['source']:<16} "
            f"{row['message']}"
            for row in rows
        )


def _entry(row) -> LogEntry:
    import json

    try:
        data = json.loads(row["data"])
    except (ValueError, TypeError):
        data = {}
    return LogEntry(
        id=int(row["id"]),
        created_at=float(row["created_at"]),
        level=row["level"],
        source=row["source"],
        message=row["message"],
        data=data if isinstance(data, dict) else {},
    )


def _filter_row(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "level": entry.get("level", ""),
        "source": entry.get("source", ""),
        "message": entry.get("message", ""),
        "created_at": entry.get("created_at", 0),
        "data": entry.get("data", {}),
    }

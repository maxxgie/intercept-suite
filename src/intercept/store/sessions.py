"""Session handling.

A session is a named set of exchanges. The live session always exists and
holds everything the proxy has seen, but an analyst can split an engagement
into sessions per host, per bug or per test, and switch between them.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from intercept.store.sqlite import SqliteStore

__all__ = ["SessionStore", "Session"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    live        INTEGER NOT NULL DEFAULT 0,
    members     TEXT NOT NULL DEFAULT '[]',
    meta        TEXT NOT NULL DEFAULT '{}'
);
"""

LIVE_ID = "live"


@dataclass(slots=True)
class Session:
    id: str
    name: str
    created_at: float
    updated_at: float
    live: bool = False
    members: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "live": self.live,
            "members": list(self.members),
            "count": len(self.members),
            "meta": dict(self.meta),
        }


class SessionStore(SqliteStore):
    """Named collections of exchanges."""

    def __init__(self, path: str) -> None:
        super().__init__(path, _SCHEMA)
        self._ensure_live()

    def _ensure_live(self) -> None:
        if self._one("SELECT id FROM sessions WHERE id = ?", (LIVE_ID,)) is None:
            now = time.time()
            self._write(
                """
                INSERT INTO sessions (id, name, created_at, updated_at, live, members, meta)
                VALUES (?, ?, ?, ?, 1, '[]', '{}')
                """,
                (LIVE_ID, "Live traffic", now, now),
            )

    async def create(self, name: str, members: list[str] | None = None) -> Session:
        now = time.time()
        session = Session(
            id=uuid.uuid4().hex[:12],
            name=name,
            created_at=now,
            updated_at=now,
            members=list(members or []),
        )
        await self.run(
            """
            INSERT INTO sessions (id, name, created_at, updated_at, live, members, meta)
            VALUES (?, ?, ?, ?, 0, ?, '{}')
            """,
            (session.id, session.name, now, now, json.dumps(session.members)),
        )
        return session

    async def list(self) -> list[dict[str, Any]]:
        rows = await self.fetch(
            "SELECT * FROM sessions ORDER BY live DESC, updated_at DESC"
        )
        return [session.to_dict() for session in (_session(row) for row in rows)]

    async def get(self, session_id: str) -> Session | None:
        row = await self.fetch_one("SELECT * FROM sessions WHERE id = ?", (session_id,))
        return _session(row) if row else None

    async def rename(self, session_id: str, name: str) -> Session | None:
        session = await self.get(session_id)
        if session is None:
            return None
        session.name = name
        session.updated_at = time.time()
        await self.run(
            "UPDATE sessions SET name = ?, updated_at = ? WHERE id = ?",
            (name, session.updated_at, session_id),
        )
        return session

    async def add(self, session_id: str, exchange_ids: list[str]) -> Session | None:
        session = await self.get(session_id)
        if session is None:
            return None
        known = set(session.members)
        known.update(exchange_ids)
        session.members = sorted(known)
        session.updated_at = time.time()
        await self.run(
            "UPDATE sessions SET members = ?, updated_at = ? WHERE id = ?",
            (json.dumps(session.members), session.updated_at, session_id),
        )
        return session

    async def remove(self, session_id: str, exchange_ids: list[str]) -> Session | None:
        session = await self.get(session_id)
        if session is None:
            return None
        drop = set(exchange_ids)
        session.members = [item for item in session.members if item not in drop]
        session.updated_at = time.time()
        await self.run(
            "UPDATE sessions SET members = ?, updated_at = ? WHERE id = ?",
            (json.dumps(session.members), session.updated_at, session_id),
        )
        return session

    async def delete(self, session_id: str) -> bool:
        if session_id == LIVE_ID:
            return False
        return await self.run("DELETE FROM sessions WHERE id = ?", (session_id,)) > 0

    async def members(self, session_id: str) -> list[str]:
        session = await self.get(session_id)
        return list(session.members) if session else []

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM sessions")
        return int(row["n"]) if row else 0


def _session(row) -> Session:
    def _list(value: Any) -> list[str]:
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return []
        return parsed if isinstance(parsed, list) else []

    def _dict(value: Any) -> dict[str, Any]:
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    return Session(
        id=row["id"],
        name=row["name"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
        live=bool(row["live"]),
        members=_list(row["members"]),
        meta=_dict(row["meta"]),
    )

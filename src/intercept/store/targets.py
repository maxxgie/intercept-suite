"""Targets.

A target is a host the engagement is about. Targets carry the scope decision
(in or out), the ports that matter and any notes the analyst wrote about
them, so the whole engagement has one place that says what is being tested.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from intercept.store.sqlite import SqliteStore

__all__ = ["TargetStore", "Target"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    name        TEXT NOT NULL,
    host        TEXT NOT NULL DEFAULT '',
    port        INTEGER NOT NULL DEFAULT 443,
    scheme      TEXT NOT NULL DEFAULT 'https',
    in_scope    INTEGER NOT NULL DEFAULT 1,
    notes       TEXT NOT NULL DEFAULT '',
    tags        TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_targets_host ON targets(host);
"""


@dataclass(slots=True)
class Target:
    id: str
    created_at: float
    updated_at: float
    name: str
    host: str = ""
    port: int = 443
    scheme: str = "https"
    in_scope: bool = True
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}" if self.host else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "in_scope": self.in_scope,
            "notes": self.notes,
            "tags": list(self.tags),
            "url": self.url,
        }


class TargetStore(SqliteStore):
    """The hosts under test."""

    def __init__(self, path: str) -> None:
        super().__init__(path, _SCHEMA)

    async def create(
        self,
        name: str,
        *,
        host: str = "",
        port: int = 443,
        scheme: str = "https",
        in_scope: bool = True,
        notes: str = "",
        tags: list[str] | None = None,
    ) -> Target:
        now = time.time()
        target = Target(
            id=uuid.uuid4().hex[:12],
            created_at=now,
            updated_at=now,
            name=name,
            host=host,
            port=port,
            scheme=scheme,
            in_scope=in_scope,
            notes=notes,
            tags=list(tags or []),
        )
        await self.run(
            """
            INSERT INTO targets (id, created_at, updated_at, name, host, port, scheme,
                                 in_scope, notes, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target.id,
                target.created_at,
                target.updated_at,
                target.name,
                target.host,
                target.port,
                target.scheme,
                int(target.in_scope),
                target.notes,
                json.dumps(target.tags),
            ),
        )
        return target

    async def update(self, target_id: str, **changes: Any) -> Target | None:
        target = await self.get(target_id)
        if target is None:
            return None
        if changes.get("name") is not None:
            target.name = str(changes["name"])
        if changes.get("host") is not None:
            target.host = str(changes["host"])
        if changes.get("port") is not None:
            target.port = int(changes["port"])
        if changes.get("scheme") is not None:
            target.scheme = str(changes["scheme"])
        if changes.get("in_scope") is not None:
            target.in_scope = bool(changes["in_scope"])
        if changes.get("notes") is not None:
            target.notes = str(changes["notes"])
        if changes.get("tags") is not None:
            target.tags = list(changes["tags"])
        target.updated_at = time.time()
        await self.run(
            """
            UPDATE targets SET name = ?, host = ?, port = ?, scheme = ?, in_scope = ?,
                               notes = ?, tags = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                target.name,
                target.host,
                target.port,
                target.scheme,
                int(target.in_scope),
                target.notes,
                json.dumps(target.tags),
                target.updated_at,
                target.id,
            ),
        )
        return target

    async def get(self, target_id: str) -> Target | None:
        row = await self.fetch_one("SELECT * FROM targets WHERE id = ?", (target_id,))
        return _target(row) if row else None

    async def list(self, *, in_scope: bool | None = None) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_sync, in_scope)

    def _list_sync(self, in_scope: bool | None) -> list[dict[str, Any]]:
        if in_scope is None:
            rows = self._query("SELECT * FROM targets ORDER BY name")
        else:
            rows = self._query(
                "SELECT * FROM targets WHERE in_scope = ? ORDER BY name",
                (int(in_scope),),
            )
        return [target.to_dict() for target in (_target(row) for row in rows)]

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM targets")
        return int(row["n"]) if row else 0

    async def delete(self, target_id: str) -> bool:
        return await self.run("DELETE FROM targets WHERE id = ?", (target_id,)) > 0

    async def for_host(self, host: str) -> list[dict[str, Any]]:
        rows = self._query("SELECT * FROM targets WHERE host = ? ORDER BY name", (host,))
        return [target.to_dict() for target in (_target(row) for row in rows)]


def _target(row) -> Target:
    try:
        tags = json.loads(row["tags"])
    except (ValueError, TypeError):
        tags = []
    return Target(
        id=row["id"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
        name=row["name"],
        host=row["host"],
        port=int(row["port"]),
        scheme=row["scheme"],
        in_scope=bool(row["in_scope"]),
        notes=row["notes"],
        tags=tags if isinstance(tags, list) else [],
    )

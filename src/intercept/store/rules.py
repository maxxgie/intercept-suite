"""The rules store.

Rules are kept in their own table so they survive a restart and can be edited
without touching the traffic history. The store is the source of truth; the
engine in :mod:`intercept.proxy.rules` holds a copy that the proxy hot path
reads without touching the disk.
"""

from __future__ import annotations

import asyncio
import time
import uuid

from intercept.proxy.rules import Rule
from intercept.store.sqlite import SqliteStore

__all__ = ["RuleStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT 'intercept',
    enabled     INTEGER NOT NULL DEFAULT 1,
    host        TEXT NOT NULL DEFAULT '',
    path        TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT '',
    phase       TEXT NOT NULL DEFAULT 'request',
    target      TEXT NOT NULL DEFAULT 'request',
    place       TEXT NOT NULL DEFAULT 'header',
    field       TEXT NOT NULL DEFAULT '',
    match       TEXT NOT NULL DEFAULT '',
    replace     TEXT NOT NULL DEFAULT '',
    regex       INTEGER NOT NULL DEFAULT 1
);
"""

_COLUMNS = (
    "id, created_at, updated_at, name, kind, enabled, host, path, method, "
    "phase, target, place, field, match, replace, regex"
)


class RuleStore(SqliteStore):
    """The proxy rules."""

    def __init__(self, path: str) -> None:
        super().__init__(path, _SCHEMA)

    async def list(self) -> list[Rule]:
        rows = await self.fetch(f"SELECT {_COLUMNS} FROM rules ORDER BY created_at ASC")
        return [_rule(row) for row in rows]

    async def get(self, rule_id: str) -> Rule | None:
        row = await self.fetch_one(
            f"SELECT {_COLUMNS} FROM rules WHERE id = ?", (rule_id,)
        )
        return _rule(row) if row else None

    async def create(self, rule: Rule) -> Rule:
        now = time.time()
        rule.id = rule.id or uuid.uuid4().hex[:12]
        rule.created_at = rule.created_at or now
        rule.updated_at = now
        await self.run(
            """
            INSERT INTO rules (
                id, created_at, updated_at, name, kind, enabled, host, path,
                method, phase, target, place, field, match, replace, regex
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rule.id,
                rule.created_at,
                rule.updated_at,
                rule.name,
                rule.kind,
                1 if rule.enabled else 0,
                rule.host,
                rule.path,
                rule.method,
                rule.phase,
                rule.target,
                rule.place,
                rule.field,
                rule.match,
                rule.replace,
                1 if rule.regex else 0,
            ),
        )
        return rule

    async def update(self, rule: Rule) -> Rule | None:
        existing = await self.get(rule.id)
        if existing is None:
            return None
        rule.created_at = existing.created_at
        rule.updated_at = time.time()
        await self.run(
            """
            UPDATE rules SET updated_at = ?, name = ?, kind = ?, enabled = ?,
                host = ?, path = ?, method = ?, phase = ?, target = ?, place = ?,
                field = ?, match = ?, replace = ?, regex = ?
            WHERE id = ?
            """,
            (
                rule.updated_at,
                rule.name,
                rule.kind,
                1 if rule.enabled else 0,
                rule.host,
                rule.path,
                rule.method,
                rule.phase,
                rule.target,
                rule.place,
                rule.field,
                rule.match,
                rule.replace,
                1 if rule.regex else 0,
                rule.id,
            ),
        )
        return rule

    async def delete(self, rule_id: str) -> bool:
        return await self.run("DELETE FROM rules WHERE id = ?", (rule_id,)) > 0

    async def clear(self) -> int:
        count = await self.count()
        await self.run("DELETE FROM rules")
        return count

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM rules")
        return int(row["n"]) if row else 0

    async def list_sync(self) -> list[Rule]:
        """Read the rules without an event loop, for start-up."""
        return await asyncio.to_thread(self._list_sync)

    def _list_sync(self) -> list[Rule]:
        rows = self._query(f"SELECT {_COLUMNS} FROM rules ORDER BY created_at ASC")
        return [_rule(row) for row in rows]


def _rule(row) -> Rule:
    return Rule(
        id=row["id"],
        name=row["name"],
        kind=row["kind"],
        enabled=bool(row["enabled"]),
        host=row["host"],
        path=row["path"],
        method=row["method"],
        phase=row["phase"],
        target=row["target"],
        place=row["place"],
        field=row["field"],
        match=row["match"],
        replace=row["replace"],
        regex=bool(row["regex"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )

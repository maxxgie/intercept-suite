"""A very small base for the SQLite backed stores.

Every store in this package keeps its data in one table, is written to from
the event loop and read from request handlers, and never blocks the proxy hot
path. The base class only takes care of the plumbing.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

__all__ = ["SqliteStore"]


class SqliteStore:
    """A table backed store with a background writer."""

    def __init__(self, path: Path | str, schema: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(schema)
        self._db.commit()

    # ------------------------------------------------------------- execution

    def _query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return self._db.execute(sql, params).fetchall()

    def _one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return self._db.execute(sql, params).fetchone()

    def _write(self, sql: str, params: Sequence[Any] = ()) -> int:
        cursor = self._db.execute(sql, params)
        self._db.commit()
        return cursor.rowcount

    # ------------------------------------------------------------- async api

    async def run(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Run a write without blocking the event loop."""
        return await asyncio.to_thread(self._write, sql, params)

    async def fetch(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        return await asyncio.to_thread(self._query, sql, params)

    async def fetch_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        return await asyncio.to_thread(self._one, sql, params)

    def close(self) -> None:
        try:
            self._db.commit()
        finally:
            self._db.close()

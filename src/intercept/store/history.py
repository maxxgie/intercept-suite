"""Traffic history.

Every exchange the proxy observes is written to a SQLite database. Writes are
queued and performed by a background task so the proxy hot path never blocks
on disk IO.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from intercept.core.filters import parse as parse_filter
from intercept.core.models import Exchange, Headers, Request, Response

__all__ = ["HistoryStore"]

_FLUSH = "_flush"


@dataclass
class _Flush:
    """Queue item that asks the writer to commit and acknowledge."""

    future: asyncio.Future[bool]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS exchanges (
    id                  TEXT PRIMARY KEY,
    created_at          REAL NOT NULL,
    elapsed_ms          REAL NOT NULL DEFAULT 0,
    origin              TEXT NOT NULL DEFAULT 'proxy',
    method              TEXT NOT NULL,
    url                 TEXT NOT NULL,
    scheme              TEXT NOT NULL,
    host                TEXT NOT NULL,
    port                INTEGER NOT NULL,
    path                TEXT NOT NULL,
    query               TEXT NOT NULL DEFAULT '',
    request_version     TEXT NOT NULL DEFAULT 'HTTP/1.1',
    request_headers     TEXT NOT NULL DEFAULT '{}',
    request_body        BLOB,
    request_raw         BLOB,
    request_length      INTEGER NOT NULL DEFAULT 0,
    request_mime        TEXT NOT NULL DEFAULT '',
    client              TEXT NOT NULL DEFAULT '',
    tls                 INTEGER NOT NULL DEFAULT 1,
    status              INTEGER NOT NULL DEFAULT 0,
    reason              TEXT NOT NULL DEFAULT '',
    response_version    TEXT NOT NULL DEFAULT 'HTTP/1.1',
    response_headers    TEXT NOT NULL DEFAULT '{}',
    response_body       BLOB,
    response_raw        BLOB,
    response_mime       TEXT NOT NULL DEFAULT '',
    response_length     INTEGER NOT NULL DEFAULT 0,
    error               TEXT NOT NULL DEFAULT '',
    tags                TEXT NOT NULL DEFAULT '[]',
    notes               TEXT NOT NULL DEFAULT '[]',
    highlighted         INTEGER NOT NULL DEFAULT 0,
    request_tags        TEXT NOT NULL DEFAULT '[]',
    request_notes       TEXT NOT NULL DEFAULT '[]',
    response_tags       TEXT NOT NULL DEFAULT '[]',
    response_notes      TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_exchanges_created ON exchanges(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exchanges_host ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_exchanges_origin ON exchanges(origin);
"""

#: The columns that were added after the first release. An existing database
#: is given them one at a time when the store is opened.
_ADDED_COLUMNS = (
    ("request_tags", "TEXT NOT NULL DEFAULT '[]'"),
    ("request_notes", "TEXT NOT NULL DEFAULT '[]'"),
    ("response_tags", "TEXT NOT NULL DEFAULT '[]'"),
    ("response_notes", "TEXT NOT NULL DEFAULT '[]'"),
)


class HistoryStore:
    """Persistent store for observed exchanges."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)
        self._migrate()
        self._db.commit()
        self._queue: asyncio.Queue[Exchange | _Flush | None] = asyncio.Queue(maxsize=20000)
        self._writer: asyncio.Task | None = None
        self._dropped = 0

    # ------------------------------------------------------------- lifecycle

    def _migrate(self) -> None:
        """Give an older database the columns that were added later."""
        existing = {row["name"] for row in self._db.execute("PRAGMA table_info(exchanges)")}
        for name, definition in _ADDED_COLUMNS:
            if name not in existing:
                self._db.execute(f"ALTER TABLE exchanges ADD COLUMN {name} {definition}")

    async def start(self) -> None:
        if self._writer is None:
            self._writer = asyncio.create_task(self._writer_loop(), name="history-writer")

    async def stop(self) -> None:
        if self._writer is not None:
            await self._queue.put(None)
            with_suppress = self._writer
            try:
                await asyncio.wait_for(with_suppress, timeout=5)
            except (TimeoutError, asyncio.CancelledError):
                self._writer.cancel()
            self._writer = None

    async def _writer_loop(self) -> None:
        batch: list[Exchange] = []
        while True:
            item = await self._queue.get()
            if item is None:
                break
            if isinstance(item, _Flush):
                if batch:
                    await asyncio.to_thread(self._write_batch, batch)
                    batch = []
                await asyncio.to_thread(self._db.commit)
                if not item.future.done():
                    item.future.set_result(True)
                continue
            batch.append(item)
            # Commit as soon as the queue drains so the UI sees traffic
            # immediately, and in batches while traffic is heavy.
            if len(batch) >= 50 or self._queue.empty():
                await asyncio.to_thread(self._write_batch, batch)
                batch = []
        if batch:
            await asyncio.to_thread(self._write_batch, batch)
            await asyncio.to_thread(self._db.commit)

    # ----------------------------------------------------------------- write

    def _write_batch(self, batch: list[Exchange]) -> None:
        rows = [_to_row(e) for e in batch]
        self._db.executemany(
            """
            INSERT OR REPLACE INTO exchanges (
                id, created_at, elapsed_ms, origin, method, url, scheme, host, port, path,
                query, request_version, request_headers, request_body, request_raw,
                request_length, request_mime, client, tls, status, reason, response_version,
                response_headers, response_body, response_raw, response_mime,
                response_length, error, tags, notes, highlighted,
                request_tags, request_notes, response_tags, response_notes
            ) VALUES (
                :id, :created_at, :elapsed_ms, :origin, :method, :url, :scheme, :host, :port,
                :path, :query, :request_version, :request_headers, :request_body, :request_raw,
                :request_length, :request_mime, :client, :tls, :status, :reason,
                :response_version, :response_headers, :response_body, :response_raw,
                :response_mime, :response_length, :error, :tags, :notes, :highlighted,
                :request_tags, :request_notes, :response_tags, :response_notes
            )
            """,
            rows,
        )
        self._db.commit()

    async def add(self, exchange: Exchange) -> None:
        try:
            self._queue.put_nowait(exchange)
        except asyncio.QueueFull:
            self._dropped += 1

    async def flush(self) -> None:
        """Wait until every queued exchange has hit the disk."""
        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        await self._queue.put(_Flush(future))
        await future

    # ------------------------------------------------------------------ read

    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        host: str | None = None,
        origin: str | None = None,
        search: str | None = None,
        status_min: int | None = None,
        status_max: int | None = None,
        filter: str | None = None,
    ) -> list[dict[str, Any]]:
        if not filter:
            return await asyncio.to_thread(
                self._list_sync,
                limit,
                offset,
                host,
                origin,
                search,
                status_min,
                status_max,
                None,
            )

        # A filter expression can look at anything, including the raw bytes, so
        # it is evaluated in Python over a wider window.
        compiled = parse_filter(filter)
        window = min(max(limit + offset, 200) * 20, 20000)
        rows = await asyncio.to_thread(
            self._list_sync, window, 0, host, origin, search, status_min, status_max, True
        )
        matched = [row for row in rows if compiled.matches(row)]
        return matched[offset : offset + limit]

    def _list_sync(
        self,
        limit: int,
        offset: int,
        host: str | None,
        origin: str | None,
        search: str | None,
        status_min: int | None,
        status_max: int | None,
        with_raw: bool | None,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if host:
            where.append("host = ?")
            params.append(host)
        if origin:
            where.append("origin = ?")
            params.append(origin)
        if status_min is not None:
            where.append("status >= ?")
            params.append(status_min)
        if status_max is not None:
            where.append("status <= ?")
            params.append(status_max)
        if search:
            where.append("(url LIKE ? OR method LIKE ?)")
            pattern = f"%{search}%"
            params.extend([pattern, pattern])
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        if with_raw:
            columns = (
                "id, created_at, elapsed_ms, origin, method, url, scheme, host, port, path, "
                "query, request_version, response_version, status, reason, response_mime, "
                "response_length, request_length, request_mime, error, tags, notes, highlighted, "
                "request_raw, response_raw, request_body, response_body"
            )
        else:
            columns = (
                "id, created_at, elapsed_ms, origin, method, url, scheme, host, port, path, "
                "query, request_version, response_version, status, reason, response_mime, "
                "response_length, request_length, request_mime, error, tags, notes, highlighted"
            )
        cursor = self._db.execute(
            f"""
            SELECT {columns}
            FROM exchanges {clause}
            ORDER BY created_at DESC, rowid DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        return [_summary_row(row, bool(with_raw)) for row in cursor.fetchall()]

    async def search(
        self,
        text: str,
        *,
        limit: int = 100,
        in_body: bool = True,
    ) -> list[dict[str, Any]]:
        """Search the history for a string."""
        return await asyncio.to_thread(self._search_sync, text, limit, in_body)

    def _search_sync(self, text: str, limit: int, in_body: bool) -> list[dict[str, Any]]:
        pattern = f"%{text}%"
        where = ["(url LIKE ? OR method LIKE ? OR path LIKE ? OR request_raw LIKE ?)"]
        params: list[Any] = [pattern, pattern, pattern, pattern]
        if in_body:
            where.append("(request_body LIKE ? OR response_body LIKE ?)")
            params.extend([pattern, pattern])
        clause = f"WHERE {' OR '.join(where)}"
        cursor = self._db.execute(
            f"""
            SELECT id, created_at, elapsed_ms, origin, method, url, scheme, host, port, path,
                   query, request_version, response_version, status, reason, response_mime,
                   response_length, request_length, request_mime, error, tags, notes, highlighted
            FROM exchanges {clause}
            ORDER BY created_at DESC, rowid DESC
            LIMIT ?
            """,
            [*params, limit],
        )
        return [_summary_row(row) for row in cursor.fetchall()]

    async def get(self, exchange_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._get_sync, exchange_id)

    def _get_sync(self, exchange_id: str) -> dict[str, Any] | None:
        cursor = self._db.execute("SELECT * FROM exchanges WHERE id = ?", (exchange_id,))
        row = cursor.fetchone()
        if row is None:
            return None
        return _full_row(row)

    async def count(self, host: str | None = None) -> int:
        return await asyncio.to_thread(self._count_sync, host)

    def _count_sync(self, host: str | None) -> int:
        if host:
            cursor = self._db.execute("SELECT COUNT(*) FROM exchanges WHERE host = ?", (host,))
        else:
            cursor = self._db.execute("SELECT COUNT(*) FROM exchanges")
        return int(cursor.fetchone()[0])

    async def clear(self) -> int:
        return await asyncio.to_thread(self._clear_sync)

    def _clear_sync(self) -> int:
        count = int(self._db.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0])
        self._db.execute("DELETE FROM exchanges")
        self._db.commit()
        return count

    async def set_tags(self, exchange_id: str, tags: list[str]) -> bool:
        return await asyncio.to_thread(self._set_tags_sync, exchange_id, tags)

    def _set_tags_sync(self, exchange_id: str, tags: list[str]) -> bool:
        cursor = self._db.execute(
            "UPDATE exchanges SET tags = ? WHERE id = ?", (json.dumps(tags), exchange_id)
        )
        self._db.commit()
        return cursor.rowcount > 0

    async def set_annotation(
        self,
        exchange_id: str,
        side: str,
        tags: list[str] | None = None,
        notes: list[str] | None = None,
    ) -> bool:
        """Attach remarks to the request or to the response of an exchange."""
        return await asyncio.to_thread(
            self._set_annotation_sync, exchange_id, side, tags, notes
        )

    def _set_annotation_sync(
        self,
        exchange_id: str,
        side: str,
        tags: list[str] | None,
        notes: list[str] | None,
    ) -> bool:
        assignments: list[str] = []
        params: list[Any] = []
        if tags is not None:
            assignments.append(f"{side}_tags = ?")
            params.append(json.dumps(tags))
        if notes is not None:
            assignments.append(f"{side}_notes = ?")
            params.append(json.dumps(notes))
        if not assignments:
            return False
        params.append(exchange_id)
        cursor = self._db.execute(
            f"UPDATE exchanges SET {', '.join(assignments)} WHERE id = ?", params
        )
        self._db.commit()
        return cursor.rowcount > 0

    async def distinct_hosts(self) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._distinct_hosts_sync)

    def _distinct_hosts_sync(self) -> list[dict[str, Any]]:
        cursor = self._db.execute(
            """
            SELECT host, scheme, COUNT(*) AS hits, MAX(created_at) AS last_seen,
                   SUM(status) AS status_sum, MAX(status) AS status_max
            FROM exchanges GROUP BY host, scheme ORDER BY hits DESC
            """
        )
        return [dict(row) for row in cursor.fetchall()]

    async def distinct_paths(self, host: str) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._distinct_paths_sync, host)

    def _distinct_paths_sync(self, host: str) -> list[dict[str, Any]]:
        cursor = self._db.execute(
            """
            SELECT path, method, COUNT(*) AS hits, MAX(status) AS status,
                   MAX(created_at) AS last_seen
            FROM exchanges WHERE host = ? GROUP BY path, method ORDER BY path
            """,
            (host,),
        )
        return [dict(row) for row in cursor.fetchall()]

    async def stats(self) -> dict[str, Any]:
        return await asyncio.to_thread(self._stats_sync)

    def _stats_sync(self) -> dict[str, Any]:
        total = int(self._db.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0])
        hosts = int(
            self._db.execute("SELECT COUNT(DISTINCT host) FROM exchanges").fetchone()[0]
        )
        return {
            "exchanges": total,
            "hosts": hosts,
            "dropped": self._dropped,
            "database": str(self.path),
        }


# --------------------------------------------------------------------- rows


def _to_row(exchange: Exchange) -> dict[str, Any]:
    request = exchange.request
    response = exchange.response
    scheme, host, port, path, query = request.parts
    return {
        "id": exchange.id,
        "created_at": exchange.created_at,
        "elapsed_ms": exchange.elapsed_ms,
        "origin": request.origin,
        "method": request.method,
        "url": request.url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "request_version": request.http_version,
        "request_headers": json.dumps(request.headers.to_dict()),
        "request_body": request.body,
        "request_raw": request.raw,
        "request_length": request.content_length,
        "request_mime": request.mime_type,
        "client": request.client,
        "tls": int(request.tls),
        "status": response.status if response else 0,
        "reason": response.reason if response else "",
        "response_version": response.http_version if response else "HTTP/1.1",
        "response_headers": json.dumps(response.headers.to_dict()) if response else "{}",
        "response_body": response.body if response else b"",
        "response_raw": response.raw if response else b"",
        "response_mime": response.mime_type if response else "",
        "response_length": response.content_length if response else 0,
        "error": response.error if response else "",
        "tags": json.dumps(exchange.tags),
        "notes": json.dumps(exchange.notes),
        "highlighted": int(exchange.highlighted),
        "request_tags": json.dumps(request.tags),
        "request_notes": json.dumps(request.notes),
        "response_tags": json.dumps(response.tags if response else []),
        "response_notes": json.dumps(response.notes if response else []),
    }


def _summary_row(row: sqlite3.Row, with_raw: bool = False) -> dict[str, Any]:
    path = row["path"] or ""
    extension = ""
    if "." in path.rsplit("/", 1)[-1]:
        extension = path.rsplit(".", 1)[-1].lower()
    summary = {
        "id": row["id"],
        "created_at": row["created_at"],
        "elapsed_ms": row["elapsed_ms"],
        "origin": row["origin"],
        "method": row["method"],
        "url": row["url"],
        "scheme": row["scheme"],
        "host": row["host"],
        "port": row["port"],
        "path": path,
        "query": row["query"],
        "http_version": row["request_version"],
        "response_version": row["response_version"],
        "status": row["status"],
        "reason": row["reason"],
        "mime_type": row["response_mime"] or row["request_mime"],
        "request_length": row["request_length"],
        "response_length": row["response_length"],
        "error": row["error"],
        "tags": json.loads(row["tags"]),
        "notes": json.loads(row["notes"]),
        "highlighted": bool(row["highlighted"]),
        "extension": extension,
    }
    if with_raw:
        summary["request_raw"] = row["request_raw"] or b""
        summary["response_raw"] = row["response_raw"] or b""
        summary["body"] = (row["response_body"] or b"") + (row["request_body"] or b"")
    return summary


def _full_row(row: sqlite3.Row) -> dict[str, Any]:
    request = Request(
        method=row["method"],
        url=row["url"],
        headers=Headers(_expand(json.loads(row["request_headers"]))),
        body=row["request_body"] or b"",
        http_version=row["request_version"],
        origin=row["origin"],
        created_at=row["created_at"],
        raw=row["request_raw"] or b"",
        tls=bool(row["tls"]),
        client=row["client"],
        tags=_list(row["request_tags"]),
        notes=_list(row["request_notes"]),
    )
    response = None
    if row["status"] or row["response_raw"] or row["response_body"]:
        response = Response(
            status=row["status"],
            reason=row["reason"],
            headers=Headers(_expand(json.loads(row["response_headers"]))),
            body=row["response_body"] or b"",
            http_version=row["response_version"],
            raw=row["response_raw"] or b"",
            elapsed_ms=row["elapsed_ms"],
            tls=bool(row["tls"]),
            error=row["error"],
            tags=_list(row["response_tags"]),
            notes=_list(row["response_notes"]),
        )
    exchange = Exchange(
        request=request,
        response=response,
        id=row["id"],
        created_at=row["created_at"],
        elapsed_ms=row["elapsed_ms"],
        tags=json.loads(row["tags"]),
        notes=json.loads(row["notes"]),
        highlighted=bool(row["highlighted"]),
    )
    return exchange.to_dict()


def _expand(headers: dict[str, list[str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, values in headers.items():
        for value in values:
            out.append((name, value))
    return out


def _list(value: Any) -> list[str]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []

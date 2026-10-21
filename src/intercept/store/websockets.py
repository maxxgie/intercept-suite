"""WebSocket message history.

Every frame that passes through a tunnelled WebSocket is recorded here, so
the interface can show what was said in either direction.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from intercept.core.filters import parse as parse_filter
from intercept.store.sqlite import SqliteStore

__all__ = ["WebSocketStore", "WebSocketConnection", "WebSocketMessage"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS websocket_connections (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    url         TEXT NOT NULL,
    host        TEXT NOT NULL DEFAULT '',
    method      TEXT NOT NULL DEFAULT 'GET',
    headers     TEXT NOT NULL DEFAULT '{}',
    closed      INTEGER NOT NULL DEFAULT 0,
    closed_at   REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS websocket_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    created_at    REAL NOT NULL,
    direction     TEXT NOT NULL,
    opcode        TEXT NOT NULL,
    payload       TEXT NOT NULL DEFAULT '',
    size          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ws_messages_connection
    ON websocket_messages(connection_id, id);
"""


@dataclass(slots=True)
class WebSocketConnection:
    id: str
    created_at: float
    url: str
    host: str = ""
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    closed: bool = False
    closed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "url": self.url,
            "host": self.host,
            "method": self.method,
            "headers": dict(self.headers),
            "closed": self.closed,
            "closed_at": self.closed_at,
        }


@dataclass(slots=True)
class WebSocketMessage:
    id: int
    connection_id: str
    created_at: float
    direction: str
    opcode: str
    payload: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "connection_id": self.connection_id,
            "created_at": self.created_at,
            "direction": self.direction,
            "opcode": self.opcode,
            "payload": self.payload,
            "size": self.size,
        }


class WebSocketStore(SqliteStore):
    """The tunnelled WebSocket conversations."""

    def __init__(self, path: str) -> None:
        super().__init__(path, _SCHEMA)

    def open_connection(
        self,
        url: str,
        *,
        host: str = "",
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> WebSocketConnection:
        connection = WebSocketConnection(
            id=uuid.uuid4().hex[:12],
            created_at=time.time(),
            url=url,
            host=host,
            method=method,
            headers=dict(headers or {}),
        )
        self._write(
            """
            INSERT INTO websocket_connections (id, created_at, url, host, method, headers)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                connection.id,
                connection.created_at,
                connection.url,
                connection.host,
                connection.method,
                json.dumps(connection.headers),
            ),
        )
        return connection

    def close_connection(self, connection_id: str) -> None:
        self._write(
            "UPDATE websocket_connections SET closed = 1, closed_at = ? WHERE id = ?",
            (time.time(), connection_id),
        )

    def record_message(
        self,
        connection_id: str,
        direction: str,
        opcode: str,
        payload: str,
        size: int,
    ) -> None:
        self._write(
            """
            INSERT INTO websocket_messages (connection_id, created_at, direction, opcode,
                                           payload, size)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (connection_id, time.time(), direction, opcode, payload, size),
        )

    async def connections(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = await self.fetch(
            "SELECT * FROM websocket_connections ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        return [connection.to_dict() for connection in (_connection(row) for row in rows)]

    async def messages(
        self,
        *,
        connection_id: str | None = None,
        direction: str | None = None,
        search: str | None = None,
        filter: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(
            self._messages_sync,
            connection_id,
            direction,
            search,
            filter,
            limit,
            offset,
        )

    def _messages_sync(
        self,
        connection_id: str | None,
        direction: str | None,
        search: str | None,
        filter: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if connection_id:
            where.append("connection_id = ?")
            params.append(connection_id)
        if direction:
            where.append("direction = ?")
            params.append(direction)
        if search:
            where.append("payload LIKE ?")
            params.append(f"%{search}%")
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"""
            SELECT id, connection_id, created_at, direction, opcode, payload, size
            FROM websocket_messages {clause}
            ORDER BY id ASC LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        )
        messages = [message.to_dict() for message in (_message(row) for row in rows)]
        if filter:
            compiled = parse_filter(filter)
            messages = [
                message for message in messages if compiled.matches(_filter_row(message))
            ]
        return messages

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM websocket_messages")
        return int(row["n"]) if row else 0

    async def clear(self) -> int:
        count = await self.count()
        await self.run("DELETE FROM websocket_messages")
        await self.run("DELETE FROM websocket_connections")
        return count


def _connection(row) -> WebSocketConnection:
    try:
        headers = json.loads(row["headers"])
    except (ValueError, TypeError):
        headers = {}
    return WebSocketConnection(
        id=row["id"],
        created_at=float(row["created_at"]),
        url=row["url"],
        host=row["host"],
        method=row["method"],
        headers=headers if isinstance(headers, dict) else {},
        closed=bool(row["closed"]),
        closed_at=float(row["closed_at"]),
    )


def _message(row) -> WebSocketMessage:
    return WebSocketMessage(
        id=int(row["id"]),
        connection_id=row["connection_id"],
        created_at=float(row["created_at"]),
        direction=row["direction"],
        opcode=row["opcode"],
        payload=row["payload"],
        size=int(row["size"]),
    )


def _filter_row(message: dict[str, Any]) -> dict[str, Any]:
    return {
        "direction": message.get("direction"),
        "opcode": message.get("opcode"),
        "payload": message.get("payload"),
        "size": message.get("size"),
        "created_at": message.get("created_at"),
    }

"""Notes and highlights.

A note is a remark an analyst writes about an exchange, a finding or a site.
A highlight is the same thing with a colour, which is how a row in the traffic
list gets marked without changing anything else.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

from intercept.store.sqlite import SqliteStore

__all__ = ["NoteStore", "Note"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    subject_id  TEXT NOT NULL DEFAULT '',
    text        TEXT NOT NULL DEFAULT '',
    color       TEXT NOT NULL DEFAULT '',
    tags        TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_notes_subject ON notes(subject, subject_id);
"""

#: The colours a highlight may use.
COLORS = ("red", "orange", "yellow", "green", "blue", "purple", "grey")


@dataclass(slots=True)
class Note:
    id: str
    created_at: float
    updated_at: float
    subject: str
    subject_id: str
    text: str
    color: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "subject": self.subject,
            "subject_id": self.subject_id,
            "text": self.text,
            "color": self.color,
            "tags": list(self.tags),
        }


class NoteStore(SqliteStore):
    """Notes about exchanges, findings and sites."""

    def __init__(self, path: str) -> None:
        super().__init__(path, _SCHEMA)

    async def create(
        self,
        subject: str,
        subject_id: str,
        text: str,
        color: str = "",
        tags: list[str] | None = None,
    ) -> Note:
        import uuid

        now = time.time()
        note = Note(
            id=uuid.uuid4().hex[:12],
            created_at=now,
            updated_at=now,
            subject=subject,
            subject_id=subject_id,
            text=text,
            color=color if color in COLORS else "",
            tags=list(tags or []),
        )
        await self.run(
            """
            INSERT INTO notes (id, created_at, updated_at, subject, subject_id, text, color, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                note.id,
                note.created_at,
                note.updated_at,
                note.subject,
                note.subject_id,
                note.text,
                note.color,
                json.dumps(note.tags),
            ),
        )
        return note

    async def update(
        self,
        note_id: str,
        *,
        text: str | None = None,
        color: str | None = None,
        tags: list[str] | None = None,
    ) -> Note | None:
        note = await self.get(note_id)
        if note is None:
            return None
        if text is not None:
            note.text = text
        if color is not None:
            note.color = color if color in COLORS else ""
        if tags is not None:
            note.tags = list(tags)
        note.updated_at = time.time()
        await self.run(
            "UPDATE notes SET text = ?, color = ?, tags = ?, updated_at = ? WHERE id = ?",
            (note.text, note.color, json.dumps(note.tags), note.updated_at, note.id),
        )
        return note

    async def get(self, note_id: str) -> Note | None:
        row = await self.fetch_one("SELECT * FROM notes WHERE id = ?", (note_id,))
        return _note(row) if row else None

    async def list(
        self,
        *,
        subject: str | None = None,
        subject_id: str | None = None,
        search: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(
            self._list_sync, subject, subject_id, search, limit, offset
        )

    def _list_sync(
        self,
        subject: str | None,
        subject_id: str | None,
        search: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if subject:
            where.append("subject = ?")
            params.append(subject)
        if subject_id:
            where.append("subject_id = ?")
            params.append(subject_id)
        if search:
            where.append("text LIKE ?")
            params.append(f"%{search}%")
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        rows = self._query(
            f"SELECT * FROM notes {clause} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        return [note.to_dict() for note in (_note(row) for row in rows)]

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM notes")
        return int(row["n"]) if row else 0

    async def delete(self, note_id: str) -> bool:
        return await self.run("DELETE FROM notes WHERE id = ?", (note_id,)) > 0

    async def clear(self) -> int:
        count = await self.count()
        await self.run("DELETE FROM notes")
        return count


def _note(row) -> Note:
    try:
        tags = json.loads(row["tags"])
    except (ValueError, TypeError):
        tags = []
    return Note(
        id=row["id"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
        subject=row["subject"],
        subject_id=row["subject_id"],
        text=row["text"],
        color=row["color"],
        tags=tags if isinstance(tags, list) else [],
    )

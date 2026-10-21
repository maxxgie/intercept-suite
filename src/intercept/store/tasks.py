"""The task scheduler.

A task is a named command that runs on an interval, for example crawling a
host every ten minutes or re-running a scan. The scheduler wakes up once a
second, runs whatever is due and records the outcome, so a failing task never
takes the daemon down.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from intercept.store.sqlite import SqliteStore

__all__ = ["TaskStore", "Task", "Scheduler"]

log = logging.getLogger("intercept.tasks")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id           TEXT PRIMARY KEY,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    name         TEXT NOT NULL,
    command      TEXT NOT NULL,
    args         TEXT NOT NULL DEFAULT '{}',
    interval     REAL NOT NULL DEFAULT 60,
    enabled      INTEGER NOT NULL DEFAULT 1,
    last_run     REAL NOT NULL DEFAULT 0,
    next_run     REAL NOT NULL DEFAULT 0,
    run_count    INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT NOT NULL DEFAULT ''
);
"""

#: The shortest interval a task may have, in seconds.
MIN_INTERVAL = 5.0


@dataclass(slots=True)
class Task:
    id: str
    created_at: float
    updated_at: float
    name: str
    command: str
    args: dict[str, Any] = field(default_factory=dict)
    interval: float = 60.0
    enabled: bool = True
    last_run: float = 0.0
    next_run: float = 0.0
    run_count: int = 0
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "name": self.name,
            "command": self.command,
            "args": dict(self.args),
            "interval": self.interval,
            "enabled": self.enabled,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "run_count": self.run_count,
            "last_error": self.last_error,
        }


class TaskStore(SqliteStore):
    """The persisted task list."""

    def __init__(self, path: str) -> None:
        super().__init__(path, _SCHEMA)

    async def create(
        self,
        name: str,
        command: str,
        *,
        args: dict[str, Any] | None = None,
        interval: float = 60.0,
        enabled: bool = True,
    ) -> Task:
        now = time.time()
        task = Task(
            id=uuid.uuid4().hex[:12],
            created_at=now,
            updated_at=now,
            name=name,
            command=command,
            args=dict(args or {}),
            interval=max(float(interval), MIN_INTERVAL),
            enabled=enabled,
            next_run=now + max(float(interval), MIN_INTERVAL),
        )
        await self.run(
            """
            INSERT INTO tasks (id, created_at, updated_at, name, command, args, interval,
                               enabled, last_run, next_run, run_count, last_error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
            """,
            (
                task.id,
                task.created_at,
                task.updated_at,
                task.name,
                task.command,
                json.dumps(task.args),
                task.interval,
                int(task.enabled),
                task.last_run,
                task.next_run,
                task.run_count,
            ),
        )
        return task

    async def update(self, task_id: str, **changes: Any) -> Task | None:
        task = await self.get(task_id)
        if task is None:
            return None
        if changes.get("name") is not None:
            task.name = str(changes["name"])
        if changes.get("command") is not None:
            task.command = str(changes["command"])
        if changes.get("args") is not None:
            task.args = dict(changes["args"])
        if changes.get("interval") is not None:
            task.interval = max(float(changes["interval"]), MIN_INTERVAL)
        if changes.get("enabled") is not None:
            task.enabled = bool(changes["enabled"])
        task.updated_at = time.time()
        await self.run(
            """
            UPDATE tasks SET name = ?, command = ?, args = ?, interval = ?, enabled = ?,
                             updated_at = ?
            WHERE id = ?
            """,
            (
                task.name,
                task.command,
                json.dumps(task.args),
                task.interval,
                int(task.enabled),
                task.updated_at,
                task.id,
            ),
        )
        return task

    async def record_run(self, task_id: str, error: str = "") -> None:
        task = await self.get(task_id)
        if task is None:
            return
        now = time.time()
        await self.run(
            """
            UPDATE tasks SET last_run = ?, next_run = ?, run_count = ?, last_error = ?
            WHERE id = ?
            """,
            (now, now + task.interval, task.run_count + 1, error[:500], task.id),
        )

    async def get(self, task_id: str) -> Task | None:
        row = await self.fetch_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
        return _task(row) if row else None

    async def list(self, *, enabled: bool | None = None) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_sync, enabled)

    def _list_sync(self, enabled: bool | None) -> list[dict[str, Any]]:
        if enabled is None:
            rows = self._query("SELECT * FROM tasks ORDER BY name")
        else:
            rows = self._query(
                "SELECT * FROM tasks WHERE enabled = ? ORDER BY name", (int(enabled),)
            )
        return [task.to_dict() for task in (_task(row) for row in rows)]

    async def due(self, now: float | None = None) -> list[Task]:
        moment = now if now is not None else time.time()
        rows = await self.fetch(
            "SELECT * FROM tasks WHERE enabled = 1 AND next_run <= ? ORDER BY next_run",
            (moment,),
        )
        return [_task(row) for row in rows]

    async def count(self) -> int:
        row = await self.fetch_one("SELECT COUNT(*) AS n FROM tasks")
        return int(row["n"]) if row else 0

    async def delete(self, task_id: str) -> bool:
        return await self.run("DELETE FROM tasks WHERE id = ?", (task_id,)) > 0


class Scheduler:
    """Runs the tasks that are due."""

    def __init__(
        self,
        store: TaskStore,
        handler: Callable[[str, dict[str, Any]], Awaitable[Any]],
    ) -> None:
        self.store = store
        self.handler = handler
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="task-scheduler")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def run_now(self, task_id: str) -> bool:
        """Run a task immediately, ignoring its schedule."""
        task = await self.store.get(task_id)
        if task is None:
            return False
        await self._execute(task)
        return True

    async def _loop(self) -> None:
        while True:
            try:
                for task in await self.store.due():
                    await self._execute(task)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a broken task must not stop the loop
                log.exception("the task scheduler failed")
            await asyncio.sleep(1)

    async def _execute(self, task: Task) -> None:
        error = ""
        try:
            await self.handler(task.command, dict(task.args))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            log.warning("task %s failed: %s", task.name, error)
        await self.store.record_run(task.id, error)


def _task(row) -> Task:
    try:
        args = json.loads(row["args"])
    except (ValueError, TypeError):
        args = {}
    return Task(
        id=row["id"],
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
        name=row["name"],
        command=row["command"],
        args=args if isinstance(args, dict) else {},
        interval=float(row["interval"]),
        enabled=bool(row["enabled"]),
        last_run=float(row["last_run"]),
        next_run=float(row["next_run"]),
        run_count=int(row["run_count"]),
        last_error=row["last_error"],
    )

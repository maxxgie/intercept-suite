"""A tiny publish/subscribe bus used to stream activity to the UI.

The bus is deliberately synchronous and non-blocking: the proxy hot path calls
``emit`` on every exchange and must never await a slow consumer.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Event", "EventBus"]


@dataclass(slots=True)
class Event:
    type: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "ts": self.ts, "data": self.data}


class EventBus:
    """Fan-out bus with a bounded replay buffer.

    Subscribers get a ``asyncio.Queue``. When a consumer falls behind, the
    oldest queued event is dropped rather than blocking the producer.
    """

    def __init__(self, replay: int = 200, queue_size: int = 2000) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._replay: deque[Event] = deque(maxlen=replay)
        self._queue_size = queue_size

    def emit(self, type: str, **data: Any) -> Event:
        event = Event(type=type, data=data)
        self._replay.append(event)
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass
        return event

    def subscribe(self) -> asyncio.Queue[Event]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Event]) -> None:
        self._subscribers.discard(queue)

    def replay(self) -> list[Event]:
        return list(self._replay)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

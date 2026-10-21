"""Interactive request and response interception.

When interception is enabled the proxy holds traffic instead of forwarding it.
The UI is notified over the event bus and answers with a decision: forward it,
forward an edited version, or drop it.

A request and its response are held in two separate phases. A rule decides
which phase a message is held in, and the answer to a held message may carry
an edited copy of it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from intercept.core.events import EventBus
from intercept.core.models import Request, Response
from intercept.proxy.websocket import WebSocketFrame

__all__ = ["InterceptController", "InterceptDecision", "PendingItem"]


@dataclass(slots=True)
class InterceptDecision:
    """The answer to a held message."""

    action: str  # "forward" | "drop"
    request: Request | None = None
    response: Response | None = None
    frame: WebSocketFrame | None = None


@dataclass(slots=True)
class PendingItem:
    """A message that is waiting for an answer."""

    id: str
    phase: str  # "request" | "response"
    request: Request
    response: Response | None = None
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "id": self.id,
            "phase": self.phase,
            "method": self.request.method,
            "url": self.request.url,
            "host": self.request.parts[1],
            "path": self.request.parts[3],
            "body_length": self.request.content_length,
            "mime_type": self.request.mime_type,
            "created_at": self.created_at,
        }
        if self.response is not None:
            item["status"] = self.response.status
            item["response_length"] = self.response.content_length
            item["response_mime_type"] = self.response.mime_type
        return item


class InterceptController:
    """Holds messages until the UI decides what happens to them."""

    def __init__(self, bus: EventBus, timeout: float = 60.0) -> None:
        self.bus = bus
        self.timeout = timeout
        self.enabled = False
        self._pending: dict[str, asyncio.Future[InterceptDecision]] = {}
        self._items: dict[str, PendingItem] = {}
        self._frames: dict[str, asyncio.Future[InterceptDecision]] = {}
        self._frame_items: dict[str, WebSocketFrame] = {}
        self._frame_counter = 0

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def pending_ids(self) -> list[str]:
        return list(self._pending)

    def items(self) -> list[dict[str, Any]]:
        """What is being held right now."""
        return [self._items[key].to_dict() for key in self._pending if key in self._items]

    def item(self, request_id: str) -> PendingItem | None:
        """The message that is being held under *request_id*, if any."""
        return self._items.get(request_id)

    def frame(self, frame_id: str) -> WebSocketFrame | None:
        """The WebSocket frame that is being held under *frame_id*, if any."""
        return self._frame_items.get(frame_id)

    def frame_items(self) -> list[dict[str, Any]]:
        """The WebSocket frames that are being held right now."""
        return [
            {
                "id": key,
                "direction": frame.direction,
                "type": frame.name,
                "text": frame.text,
                "size": len(frame.payload),
            }
            for key, frame in self._frame_items.items()
        ]

    async def hold_frame(self, frame: WebSocketFrame) -> InterceptDecision:
        """Suspend a WebSocket frame until a decision arrives."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[InterceptDecision] = loop.create_future()
        self._frame_counter += 1
        frame_id = f"ws-{self._frame_counter}"
        self._frames[frame_id] = future
        self._frame_items[frame_id] = frame
        self.bus.emit(
            "intercept.frame",
            id=frame_id,
            direction=frame.direction,
            type=frame.name,
            text=frame.text,
            size=len(frame.payload),
        )
        try:
            async with asyncio.timeout(self.timeout):
                decision = await future
        except TimeoutError:
            decision = InterceptDecision("forward")
            self.bus.emit("intercept.timeout", id=frame_id)
        finally:
            self._frames.pop(frame_id, None)
            self._frame_items.pop(frame_id, None)
        return decision

    def resolve_frame(self, frame_id: str, decision: InterceptDecision) -> bool:
        """Answer a held WebSocket frame."""
        future = self._frames.get(frame_id)
        if future is None or future.done():
            return False
        future.set_result(decision)
        return True

    async def hold(self, request: Request) -> InterceptDecision:
        """Suspend *request* until a decision arrives, or the timeout expires."""
        return await self._hold(request, None, "request")

    async def hold_response(
        self, request: Request, response: Response
    ) -> InterceptDecision:
        """Suspend the response to *request* until a decision arrives."""
        return await self._hold(request, response, "response")

    async def _hold(
        self, request: Request, response: Response | None, phase: str
    ) -> InterceptDecision:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[InterceptDecision] = loop.create_future()
        self._pending[request.id] = future
        self._items[request.id] = PendingItem(
            id=request.id, phase=phase, request=request, response=response
        )
        if phase == "request":
            self.bus.emit("intercept.request", request=request.summary(), id=request.id)
        else:
            self.bus.emit(
                "intercept.response",
                request=request.summary(),
                response=response.summary() if response else {},
                id=request.id,
            )
        try:
            async with asyncio.timeout(self.timeout):
                decision = await future
        except TimeoutError:
            decision = InterceptDecision("forward", request)
            self.bus.emit("intercept.timeout", id=request.id)
        finally:
            self._pending.pop(request.id, None)
            self._items.pop(request.id, None)
        return decision

    def resolve(self, request_id: str, decision: InterceptDecision) -> bool:
        """Answer a held message. Returns ``False`` if it is no longer pending."""
        future = self._pending.get(request_id)
        if future is None or future.done():
            return False
        future.set_result(decision)
        return True

    def resolve_all(self, decision: InterceptDecision) -> int:
        count = 0
        for request_id in list(self._pending):
            if self.resolve(request_id, decision):
                count += 1
        return count

    def state(self) -> dict:
        return {
            "enabled": self.enabled,
            "pending": list(self._pending),
            "pending_count": len(self._pending),
            "updated_at": time.time(),
            "items": self.items(),
            "frames": self.frame_items(),
        }

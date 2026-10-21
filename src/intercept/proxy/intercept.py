"""Interactive request interception.

When interception is enabled the proxy holds every request instead of
forwarding it. The UI is notified over the event bus and answers with a
decision: forward it, forward an edited version, or drop it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from intercept.core.events import EventBus
from intercept.core.models import Request

__all__ = ["InterceptController", "InterceptDecision"]


@dataclass(slots=True)
class InterceptDecision:
    action: str  # "forward" | "drop"
    request: Request | None = None


class InterceptController:
    """Holds requests until the UI decides what happens to them."""

    def __init__(self, bus: EventBus, timeout: float = 60.0) -> None:
        self.bus = bus
        self.timeout = timeout
        self.enabled = False
        self._pending: dict[str, asyncio.Future[InterceptDecision]] = {}

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def pending_ids(self) -> list[str]:
        return list(self._pending)

    async def hold(self, request: Request) -> InterceptDecision:
        """Suspend *request* until a decision arrives, or the timeout expires."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[InterceptDecision] = loop.create_future()
        self._pending[request.id] = future
        self.bus.emit("intercept.request", request=request.summary(), id=request.id)
        try:
            async with asyncio.timeout(self.timeout):
                decision = await future
        except TimeoutError:
            decision = InterceptDecision("forward", request)
            self.bus.emit("intercept.timeout", id=request.id)
        finally:
            self._pending.pop(request.id, None)
        return decision

    def resolve(self, request_id: str, decision: InterceptDecision) -> bool:
        """Answer a held request. Returns ``False`` if it is no longer pending."""
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
        }

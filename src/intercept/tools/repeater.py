"""The repeater.

The repeater takes a request, lets the user edit it, and sends it again. Each
tab keeps its own request, its latest response and the full list of attempts
so two responses can be compared later.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Any

from intercept.core.events import EventBus
from intercept.core.models import Exchange, Headers, Request, Response
from intercept.tools.client import ToolClient

__all__ = ["Repeater", "RepeaterTab"]


@dataclass
class RepeaterTab:
    """One repeater workspace."""

    id: str
    name: str
    request: Request
    response: Response | None = None
    attempts: list[Exchange] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    color: str = ""
    target: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "color": self.color,
            "target": self.target,
            "created_at": self.created_at,
            "request": self.request.to_dict(include_raw=True),
            "response": self.response.to_dict(include_raw=True) if self.response else None,
            "attempt_count": len(self.attempts),
        }


class Repeater:
    """Manages repeater tabs and dispatches their requests."""

    def __init__(self, client: ToolClient, bus: EventBus) -> None:
        self.client = client
        self.bus = bus
        self._tabs: dict[str, RepeaterTab] = {}
        self._counter = itertools.count(1)

    # ------------------------------------------------------------------ tabs

    def create_tab(
        self,
        request: Request,
        name: str | None = None,
        tab_id: str | None = None,
        color: str = "",
    ) -> RepeaterTab:
        identifier = tab_id or f"tab-{next(self._counter)}"
        tab = RepeaterTab(
            id=identifier,
            name=name or f"Tab {identifier.split('-')[-1]}",
            request=request.clone(),
            color=color,
            target=request.host,
        )
        self._tabs[identifier] = tab
        self.bus.emit("repeater.tab.created", tab=tab.to_dict())
        return tab

    def get(self, tab_id: str) -> RepeaterTab | None:
        return self._tabs.get(tab_id)

    def tabs(self) -> list[RepeaterTab]:
        return list(self._tabs.values())

    def delete_tab(self, tab_id: str) -> bool:
        removed = self._tabs.pop(tab_id, None)
        if removed is not None:
            self.bus.emit("repeater.tab.deleted", id=tab_id)
        return removed is not None

    def update_request(self, tab_id: str, request: Request) -> RepeaterTab | None:
        tab = self._tabs.get(tab_id)
        if tab is None:
            return None
        tab.request = request.clone()
        return tab

    # ----------------------------------------------------------------- send

    async def send(self, tab_id: str, request: Request | None = None) -> Response | None:
        """Send the tab's (optionally updated) request."""
        tab = self._tabs.get(tab_id)
        if tab is None:
            return None
        if request is not None:
            tab.request = request.clone()
        outgoing = tab.request.clone()
        outgoing.origin = "repeater"
        response = await self.client.send(outgoing)
        tab.response = response
        tab.attempts.append(Exchange(request=outgoing, response=response))
        self.bus.emit("repeater.sent", tab=tab.to_dict())
        return response

    async def resend(self, tab_id: str, attempt_index: int) -> Response | None:
        """Re-send a previous attempt of the tab."""
        tab = self._tabs.get(tab_id)
        if tab is None or attempt_index >= len(tab.attempts):
            return None
        previous = tab.attempts[attempt_index].request
        return await self.send(tab_id, previous.clone())


def request_from_raw(raw: str, url: str | None = None) -> Request:
    """Build a request from a raw HTTP/1.x message typed by the user."""
    text = raw.replace("\r\n", "\n")
    lines = text.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("request is empty")

    parts = lines[0].strip().split(" ")
    method = parts[0].upper()
    target = parts[1] if len(parts) > 1 else "/"
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers = Headers()
    body = b""
    index = 1
    while index < len(lines):
        line = lines[index].rstrip()
        index += 1
        if not line:
            break
        name, sep, value = line.partition(":")
        if sep:
            headers.add(name.strip(), value.strip())

    if index < len(lines):
        body = "\n".join(lines[index:]).encode("utf-8")

    if url is None:
        if target.lower().startswith(("http://", "https://")):
            # A request captured from a forward proxy keeps the absolute form.
            url = target
        else:
            host = headers.get("Host") or ""
            scheme = "https" if host.endswith(":443") else "http"
            url = f"{scheme}://{host}{target}" if host else target

    return Request(
        method=method,
        url=url,
        headers=headers,
        body=body,
        http_version=version,
        raw=raw.replace("\n", "\r\n").encode("utf-8", "replace"),
    )

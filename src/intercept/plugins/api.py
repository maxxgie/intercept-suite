"""The plugin API.

A plugin is a Python module that receives a :class:`PluginAPI` and registers
tools, checks and event hooks against it. The API is deliberately small so
that plugins stay easy to write and hard to break.

A plugin lives in a directory with a ``plugin.toml`` manifest and an entry
module that exposes ``register(api)``::

    # plugin.toml
    name = "jwt-tool"
    label = "JWT Decoder"
    version = "0.1.0"
    entry = "plugin.py"

    # plugin.py
    def register(api):
        api.add_tool(JwtTool())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "Field",
    "Tool",
    "Finding",
    "ActiveCheck",
    "PluginAPI",
    "PluginContext",
    "HookCallback",
]


@dataclass(slots=True)
class Field:
    """A single input in a tool form."""

    name: str
    label: str
    type: str = "text"  # text | textarea | number | select | boolean
    default: Any = ""
    options: list[str] = field(default_factory=list)
    placeholder: str = ""
    help: str = ""


class Tool:
    """Base class for a plugin provided tool.

    Subclasses set the class attributes and implement :meth:`run`.
    """

    id: str = ""
    label: str = ""
    description: str = ""
    icon: str = ""
    fields: list[Field] = []

    async def run(self, context: PluginContext, values: dict[str, Any]) -> dict[str, Any]:
        """Execute the tool and return a JSON-serialisable result."""
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "icon": self.icon,
            "fields": [
                {
                    "name": f.name,
                    "label": f.label,
                    "type": f.type,
                    "default": f.default,
                    "options": list(f.options),
                    "placeholder": f.placeholder,
                    "help": f.help,
                }
                for f in self.fields
            ],
        }


@dataclass(slots=True)
class Finding:
    """A single issue reported by a check."""

    check_id: str
    title: str
    severity: str = "info"  # info | low | medium | high | critical
    description: str = ""
    request_id: str = ""
    url: str = ""
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "request_id": self.request_id,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@runtime_checkable
class ActiveCheck(Protocol):
    """A check that sends its own requests to probe a target."""

    id: str
    label: str

    async def check(self, context: PluginContext, url: str) -> list[Finding]: ...


HookCallback = Any


@dataclass
class PluginContext:
    """Everything a plugin is allowed to touch."""

    config: Any
    bus: Any
    client: Any = None
    store: Any = None
    scope: Any = None
    data: dict[str, Any] = field(default_factory=dict)

    async def send(self, request: Any) -> Any:
        """Send a request through the shared tool client."""
        if self.client is None:
            raise RuntimeError("no HTTP client is available in this context")
        return await self.client.send(request)

    def log(self, message: str) -> None:
        if self.bus is not None:
            self.bus.emit("plugin.log", message=message)


class PluginAPI:
    """Handed to a plugin's ``register`` function."""

    def __init__(self, manager: Any, plugin_name: str) -> None:
        self._manager = manager
        self.plugin_name = plugin_name

    def add_tool(self, tool: Tool) -> None:
        """Register a tool that appears in the UI."""
        if not tool.id:
            tool.id = self.plugin_name
        self._manager.add_tool(self.plugin_name, tool)

    def add_check(self, check: ActiveCheck) -> None:
        """Register an active check."""
        self._manager.add_check(self.plugin_name, check)

    def on(self, event: str, callback: HookCallback) -> None:
        """Subscribe to a daemon event."""
        self._manager.add_hook(self.plugin_name, event, callback)

    def log(self, message: str) -> None:
        self._manager.log(self.plugin_name, message)

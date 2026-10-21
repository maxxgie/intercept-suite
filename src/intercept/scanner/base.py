"""The shape of a check.

A check is a small, self contained probe. Two kinds exist:

``ActiveCheck``
    sends its own requests to the target;
``PassiveCheck``
    looks at a request and response that were already observed.

Both produce :class:`~intercept.plugins.api.Finding` objects, so a plugin can
register checks that behave exactly like the built in ones.

A check also says where it belongs: a ``host`` check looks at the server as a
whole and runs once per target, while an ``endpoint`` check probes a place that
takes input and runs for every endpoint that was found.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from intercept.core.models import Request, Response
from intercept.plugins.api import Finding
from intercept.scanner.target import Endpoint
from intercept.tools.client import ToolClient

__all__ = ["CheckInfo", "ActiveCheck", "PassiveCheck"]


@dataclass(slots=True)
class CheckInfo:
    """Metadata describing a check."""

    id: str
    label: str
    description: str = ""
    severity: str = "info"
    category: str = "general"
    kind: str = "active"
    scope: str = "host"
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "kind": self.kind,
            "scope": self.scope,
            "enabled": self.enabled,
        }


class ActiveCheck:
    """A check that sends its own requests to the target."""

    id = ""
    label = ""
    description = ""
    severity = "info"
    category = "general"
    #: ``host`` runs once per target, ``endpoint`` runs for every endpoint.
    scope = "host"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        raise NotImplementedError

    def info(self) -> CheckInfo:
        return CheckInfo(
            id=self.id,
            label=self.label,
            description=self.description,
            severity=self.severity,
            category=self.category,
            kind="active",
            scope=self.scope,
        )


class PassiveCheck:
    """A check that inspects traffic that was already observed."""

    id = ""
    label = ""
    description = ""
    severity = "info"
    category = "general"
    scope = "host"

    def run(self, request: Request, response: Response) -> list[Finding]:
        raise NotImplementedError

    def info(self) -> CheckInfo:
        return CheckInfo(
            id=self.id,
            label=self.label,
            description=self.description,
            severity=self.severity,
            category=self.category,
            kind="passive",
            scope=self.scope,
        )

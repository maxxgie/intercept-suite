"""An example plugin that registers a scanner check.

The check looks for a ``Content-Security-Policy`` header, which is the smallest
useful example of a plugin contributed check. Copy this directory into
``<home>/plugins`` to install it.
"""

from __future__ import annotations

from intercept.core.models import Request
from intercept.plugins.api import Finding, PluginAPI
from intercept.scanner.checks import ActiveCheck


class ContentSecurityPolicyCheck(ActiveCheck):
    id = "csp"
    label = "Content-Security-Policy"
    description = "Reports targets that do not set a Content-Security-Policy."
    severity = "low"
    category = "headers"

    async def run(self, client, url: str) -> list[Finding]:
        response = await client.send(Request(method="GET", url=url))
        if response.status == 0:
            return []
        if response.headers.get("content-security-policy"):
            return []
        return [
            Finding(
                check_id=self.id,
                title="No Content-Security-Policy header",
                severity=self.severity,
                description=(
                    f"{url} answers without a Content-Security-Policy, so the browser "
                    "applies no restriction to the scripts the page loads."
                ),
                url=url,
                evidence=f"HTTP {response.status}",
                remediation="Set a Content-Security-Policy that lists the allowed sources.",
            )
        ]


def register(api: PluginAPI) -> None:
    api.add_check(ContentSecurityPolicyCheck())

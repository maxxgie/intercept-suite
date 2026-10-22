"""The out of band check.

A blind flaw does not answer in the request that caused it: the target takes
the payload, does something with it and only then reaches out. The
collaborator is the server that waits for that call, and this check is what
joins the two. It sends a payload that points at the collaborator, waits for
the callback and reports a finding when one arrives.

Three flavours of payload are tried, because a target reaches out in three
different ways:

* a plain **URL**, which is what a blind SSRF and a blind XXE make;
* a **SQL fragment**, which is what a blind SQL injection makes;
* a **command**, which is what a blind RCE makes.

An **XML entity** is tried as well, but only when the input is parsed as XML,
because an entity in something that is not XML is only noise.

The first callback that arrives ends the check for that endpoint, and the
finding says which flavour produced it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from intercept.plugins.api import Finding
from intercept.scanner.base import ActiveCheck
from intercept.scanner.target import Endpoint
from intercept.tools.client import ToolClient

__all__ = ["CollaboratorCheck"]


class CollaboratorCheck(ActiveCheck):
    """Blind flaws, found by waiting for the target to call back."""

    id = "oob-callback"
    label = "Out of band interaction"
    description = (
        "Sends a payload that points at the collaborator and waits for the "
        "target to call it, which is how a blind flaw gives itself away."
    )
    severity = "high"
    category = "oob"
    scope = "endpoint"

    #: The check cannot work without the collaborator, so the scanner hands it
    #: over before the check is run.
    needs_collaborator = True

    #: The collaborator, filled in by the scanner.
    collaborator: Any = None

    #: How many parameters of an endpoint are probed.
    max_parameters = 2
    #: How long the check waits for the callback, in seconds. ``None`` means
    #: the wait that the collaborator is configured with.
    wait: float | None = None
    #: The payloads that are tried, and what each of them is meant to prove.
    flavours: tuple[tuple[str, str], ...] = (
        ("http", "the target fetched a URL that was given to it"),
        ("sqli", "the database was made to read a URL"),
        ("rce", "the command that was run reached out"),
    )
    #: The XML entity is only tried when the input is parsed as XML.
    xml_flavour = ("xxe", "the input was parsed as XML and the entity was read")

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        """Probe the endpoint and wait for the target to call back."""
        collaborator = self.collaborator
        if collaborator is None:
            return []
        if not collaborator.status().get("running"):
            return []
        if not target.has_parameters:
            return []
        finding = await self._probe(client, target, collaborator)
        return [finding] if finding is not None else []

    # ------------------------------------------------------------- machinery

    def _flavours(self, endpoint: Endpoint) -> list[tuple[str, str]]:
        """The payloads that are tried against this endpoint."""
        flavours = list(self.flavours)
        content_type = (endpoint.content_type or "").lower()
        if "xml" in content_type:
            flavours.append(self.xml_flavour)
        return flavours

    async def _probe(
        self, client: ToolClient, endpoint: Endpoint, collaborator: Any
    ) -> Finding | None:
        """Send the payloads and wait for the callback."""
        parameters = endpoint.parameter_names[: self.max_parameters]
        if not parameters:
            return None

        tokens: list[str] = []
        origins: dict[str, tuple[str, str, str]] = {}
        for parameter in parameters:
            for flavour, reason in self._flavours(endpoint):
                payload = collaborator.payload(flavour)
                token = str(payload.get("token", ""))
                value = str(payload.get("payload", ""))
                if not token or not value:
                    continue
                probe = (
                    endpoint.with_body_field(parameter, value)
                    if parameter in endpoint.body_fields
                    else endpoint.with_parameter(parameter, value)
                )
                await self._send(client, probe)
                tokens.append(token)
                origins[token] = (flavour, parameter, reason)

        if not tokens:
            return None

        interaction = await collaborator.wait_for(tokens, timeout=self.wait)
        if interaction is None:
            return None
        return self._finding(endpoint, interaction, origins)

    async def _send(self, client: ToolClient, endpoint: Endpoint) -> None:
        """Send one probe. A failed probe is not a finding."""
        try:
            await client.send(endpoint.request())
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            return

    def _finding(
        self,
        endpoint: Endpoint,
        interaction: Any,
        origins: dict[str, tuple[str, str, str]],
    ) -> Finding:
        """The finding that a callback produces."""
        flavour, parameter, reason = origins.get(
            interaction.token, ("http", "", "the target reached out")
        )
        evidence = [
            f"the collaborator was called over {interaction.kind}",
            f"the call came from {interaction.peer}",
            f"the token was {interaction.token}",
        ]
        if interaction.detail:
            evidence.append(interaction.detail)
        if interaction.body:
            evidence.append(f"the body was: {interaction.body[:200]}")
        title = "The target called the collaborator"
        if parameter:
            title = f"The target called the collaborator through {parameter}"
        return Finding(
            check_id=self.id,
            title=title,
            severity=self.severity,
            description=(
                f"A payload of the kind '{flavour}' made the target reach out to "
                f"the collaborator: {reason}. The flaw is there even though the "
                "answer itself carries nothing."
            ),
            url=endpoint.url,
            evidence="\n".join(evidence),
            remediation=(
                "Do not let the input reach the network, the file system or the "
                "shell. Validate it against a list of allowed values, and keep "
                "the database, the parser and the command away from it."
            ),
        )

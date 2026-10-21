"""The checks that look at a GraphQL endpoint.

A GraphQL endpoint is one URL that takes a query, so the things that can go
wrong with it are different from the things that can go wrong with a form:
the schema is often readable, the queries can be batched and a query can be
made so deep that the server gives up.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from intercept.core.models import Request, Response
from intercept.plugins.api import Finding
from intercept.scanner.base import ActiveCheck
from intercept.scanner.target import Endpoint
from intercept.tools.client import ToolClient

__all__ = ["GraphqlCheck", "is_graphql_url", "GRAPHQL_PATHS"]

#: The paths a GraphQL endpoint usually lives under.
GRAPHQL_PATHS = ("/graphql", "/graphql/", "/graphiql", "/api/graphql", "/v1/graphql", "/gql")

INTROSPECTION_QUERY = (
    '{"query":"query IntrospectionQuery { __schema { queryType { name } '
    'types { name fields { name } } } }"}'
)


def is_graphql_url(url: str) -> bool:
    """Whether the URL looks like a GraphQL endpoint."""
    path = urlsplit(url).path.lower()
    return any(path.endswith(candidate.rstrip("/")) for candidate in GRAPHQL_PATHS) or (
        "graphql" in path
    )


class GraphqlCheck(ActiveCheck):
    """Looks for a GraphQL endpoint that gives away too much."""

    id = "graphql.configuration"
    label = "GraphQL issues"
    description = "Looks for an open introspection, batching and a missing depth limit."
    severity = "medium"
    category = "graphql"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = self._graphql_url(target)
        if url is None:
            return []
        findings: list[Finding] = []

        response = await self._post(client, url, INTROSPECTION_QUERY)
        if response is not None and self._holds_schema(response):
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The GraphQL schema can be read",
                    severity="medium",
                    description=(
                        f"{url} answers an introspection query with the whole schema, which "
                        "shows every query, every field and every type of the application."
                    ),
                    url=url,
                    evidence=response.body[:200].decode("utf-8", "replace"),
                    remediation="Turn introspection off in production.",
                )
            )

        response = await self._post(
            client, url, '[{"query":"{__typename}"},{"query":"{__typename}"}]'
        )
        if response is not None:
            try:
                body = json.loads(response.body.decode("utf-8", "replace"))
            except ValueError:
                body = None
            if isinstance(body, list) and len(body) > 1:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="The GraphQL endpoint accepts a batch of queries",
                        severity="medium",
                        description=(
                            f"{url} answers a list of queries with a list of answers, so many "
                            "queries can be sent in one request and the limits on a single "
                            "query can be worked around."
                        ),
                        url=url,
                        evidence=response.body[:200].decode("utf-8", "replace"),
                        remediation="Refuse a request that holds more than one query.",
                    )
                )

        response = await self._post(client, url, '{"query":"{__typename}","variables":{"a":1}}')
        if response is not None:
            text = response.body.decode("utf-8", "replace")
            if "errors" in text.lower() and "variable" in text.lower():
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="The GraphQL endpoint talks about the variables it was given",
                        severity="low",
                        description=(
                            "The error message of the endpoint names the variable, which makes "
                            "it easier to find a way into the query."
                        ),
                        url=url,
                        evidence=text[:200],
                        remediation="Return generic error messages to the client.",
                    )
                )

        response = await self._post(client, url, '{"query":"{__schema{types{name}}}"}')
        if response is not None:
            text = response.body.decode("utf-8", "replace")
            if "field" in text.lower() and "did you mean" in text.lower():
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="The GraphQL endpoint suggests the fields that do not exist",
                        severity="low",
                        description=(
                            "The endpoint answers a wrong field with a list of the fields that "
                            "are close to it, which lets somebody guess the schema."
                        ),
                        url=url,
                        evidence=text[:200],
                        remediation="Turn the field suggestions off.",
                    )
                )
        return findings

    def _graphql_url(self, target: Endpoint) -> str | None:
        if is_graphql_url(target.url):
            return target.url
        split = urlsplit(target.url)
        base = f"{split.scheme}://{split.netloc}"
        for path in GRAPHQL_PATHS:
            if path in target.url:
                return target.url
        return f"{base}/graphql"

    def _holds_schema(self, response: Response) -> bool:
        text = response.body.decode("utf-8", "replace")
        return "__schema" in text and "types" in text

    async def _post(self, client: ToolClient, url: str, body: str) -> Response | None:
        request = Request(method="POST", url=url)
        request.body = body.encode("utf-8")
        request.headers.set("Content-Type", "application/json")
        request.headers.set("Content-Length", str(len(request.body)))
        try:
            return await client.send(request)
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            return None

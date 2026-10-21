"""The injection checks.

Every check here replaces one parameter of an endpoint with a payload and
judges the answer that comes back. The judgement is what tells a real bug from
a curious answer, so each check brings its own rules:

* a payload that brings back a database error proves an injection;
* a payload that comes back unchanged in a page proves a cross site scripting
  hole;
* an answer that holds the output of a command proves a command injection.

The checks that need more than one request (the boolean and the time based
SQL injection ones) send them in pairs and compare.
"""

from __future__ import annotations

import asyncio

from intercept.core.models import Response
from intercept.plugins.api import Finding
from intercept.scanner.base import ActiveCheck
from intercept.scanner.probes import (
    COMMAND_OUTPUT_MARKERS,
    COMMAND_PAYLOADS,
    DESERIALIZATION_PAYLOADS,
    LDAP_PAYLOADS,
    NOSQL_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    PROTOTYPE_PAYLOADS,
    SQLI_BOOLEAN_PAYLOADS,
    SQLI_ERROR_PAYLOADS,
    SQLI_ERROR_SIGNATURES,
    SQLI_TIME_PAYLOADS,
    SSRF_PAYLOADS,
    SSTI_PAYLOADS,
    TRAVERSAL_MARKERS,
    TRAVERSAL_PAYLOADS,
    XSS_PAYLOADS,
    XXE_PAYLOADS,
    looks_like_error,
    reflected,
    stable_fingerprint,
)
from intercept.scanner.target import Endpoint
from intercept.tools.client import ToolClient

__all__ = [
    "InjectionCheck",
    "CommandInjectionCheck",
    "DeserializationCheck",
    "LdapInjectionCheck",
    "NoSqlInjectionCheck",
    "OpenRedirectCheck",
    "PathTraversalCheck",
    "PrototypePollutionCheck",
    "SsrfCheck",
    "SqlInjectionCheck",
    "SstiCheck",
    "XxeCheck",
    "XssCheck",
]


class InjectionCheck(ActiveCheck):
    """The base of every injection check.

    A check takes the endpoint as it is, sends it unchanged to get a baseline
    and then sends it again with one parameter replaced. The answer to the
    second request is compared with the baseline.
    """

    id = ""
    label = ""
    description = ""
    severity = "medium"
    category = "injection"
    scope = "endpoint"

    #: The payloads that are tried, one after the other.
    payloads: tuple[str, ...] = ()
    #: How many parameters of an endpoint are probed.
    max_parameters = 3
    #: How many endpoints are probed with this check.
    max_endpoints = 10
    #: The first finding ends the check for an endpoint.
    stop_at_first = True

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        """Probe the endpoint and report what was found."""
        findings: list[Finding] = []
        endpoints = [target] if target.has_parameters else []
        for endpoint in endpoints[: self.max_endpoints]:
            baseline = await self._baseline(client, endpoint)
            if baseline is None:
                continue
            for parameter in self._parameters(endpoint):
                finding = await self._probe(client, endpoint, parameter, baseline)
                if finding is None:
                    continue
                findings.append(finding)
                if self.stop_at_first:
                    break
            if findings and self.stop_at_first:
                break
        return findings

    # ------------------------------------------------------------- machinery

    def _parameters(self, endpoint: Endpoint) -> list[str]:
        names = endpoint.parameter_names
        return names[: self.max_parameters]

    async def _baseline(self, client: ToolClient, endpoint: Endpoint) -> Response | None:
        response = await self._send(client, endpoint)
        if response is None or response.status == 0:
            return None
        return response

    async def _send(
        self,
        client: ToolClient,
        endpoint: Endpoint,
        parameter: str | None = None,
        value: str | None = None,
    ) -> Response | None:
        probe = endpoint
        if parameter is not None and value is not None:
            if parameter in endpoint.body_fields:
                probe = endpoint.with_body_field(parameter, value)
            else:
                probe = endpoint.with_parameter(parameter, value)
        try:
            return await client.send(probe.request())
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            return None

    async def _probe(
        self,
        client: ToolClient,
        endpoint: Endpoint,
        parameter: str,
        baseline: Response,
    ) -> Finding | None:
        """Send one payload and judge the answer."""
        for payload in self.payloads:
            response = await self._send(client, endpoint, parameter, payload)
            if response is None or response.status == 0:
                continue
            evidence = self.detect(baseline, response, payload)
            if evidence:
                return self._finding(endpoint, parameter, payload, evidence, response)
        return None

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        """The evidence that the payload did something, if it did."""
        return ""

    def _finding(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        evidence: str,
        response: Response,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            title=self.title(parameter),
            severity=self.severity,
            description=self.explain(endpoint, parameter, payload, evidence),
            url=endpoint.url,
            evidence=evidence[:400],
            remediation=self.remediation,
        )

    def title(self, parameter: str) -> str:
        return f"{self.label} in the parameter {parameter!r}"

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} was given {payload!r} and the "
            f"answer shows that it was interpreted: {evidence[:200]}"
        )

    remediation = "Validate the input on the server and use parameterised queries."


class SqlInjectionCheck(InjectionCheck):
    """Looks for SQL injection in the parameters of an endpoint.

    Three things are tried: a payload that makes the database complain, a pair
    of payloads that should give the same answer when the input is injected
    and a payload that makes the database wait.
    """

    id = "injection.sql"
    label = "SQL injection"
    description = "Looks for SQL injection with error, boolean and time based probes."
    severity = "high"
    category = "injection"

    max_parameters = 3
    max_endpoints = 8

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in [target][: self.max_endpoints]:
            for parameter in self._parameters(endpoint):
                for strategy in (self._error_probe, self._boolean_probe, self._time_probe):
                    finding = await strategy(client, endpoint, parameter)
                    if finding is not None:
                        findings.append(finding)
                        break
            if findings:
                break
        return findings

    async def _error_probe(
        self, client: ToolClient, endpoint: Endpoint, parameter: str
    ) -> Finding | None:
        baseline = await self._baseline(client, endpoint)
        if baseline is None:
            return None
        for payload in SQLI_ERROR_PAYLOADS:
            response = await self._send(client, endpoint, parameter, payload)
            if response is None or response.status == 0:
                continue
            text = response.body.decode("utf-8", "replace")
            signature = looks_like_error(text, SQLI_ERROR_SIGNATURES)
            if signature:
                return self._finding(
                    endpoint,
                    parameter,
                    payload,
                    f"the answer holds the database error {signature!r}",
                    response,
                )
        return None

    async def _boolean_probe(
        self, client: ToolClient, endpoint: Endpoint, parameter: str
    ) -> Finding | None:
        baseline = await self._baseline(client, endpoint)
        if baseline is None:
            return None
        base_text = stable_fingerprint(baseline.body.decode("utf-8", "replace"))
        for true_payload, false_payload in SQLI_BOOLEAN_PAYLOADS:
            yes = await self._send(client, endpoint, parameter, true_payload)
            no = await self._send(client, endpoint, parameter, false_payload)
            if yes is None or no is None:
                continue
            if yes.status == 0 or no.status == 0:
                continue
            yes_text = stable_fingerprint(yes.body.decode("utf-8", "replace"))
            no_text = stable_fingerprint(no.body.decode("utf-8", "replace"))
            if yes_text == no_text:
                continue
            if yes_text != base_text and no_text == base_text:
                return self._finding(
                    endpoint,
                    parameter,
                    true_payload,
                    "the true and the false condition give different answers",
                    yes,
                )
        return None

    async def _time_probe(
        self, client: ToolClient, endpoint: Endpoint, parameter: str
    ) -> Finding | None:
        baseline = await self._baseline(client, endpoint)
        if baseline is None:
            return None
        base_ms = baseline.elapsed_ms
        for payload, marker in SQLI_TIME_PAYLOADS:
            response = await self._send(client, endpoint, parameter, payload)
            if response is None or response.status == 0:
                continue
            if response.elapsed_ms >= max(4000.0, base_ms + 3000.0):
                return self._finding(
                    endpoint,
                    parameter,
                    payload,
                    f"the answer took {response.elapsed_ms:.0f} ms, the {marker} payload waits",
                    response,
                )
        return None

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is not quoted properly: with "
            f"{payload!r} the answer changed ({evidence[:200]}). A crafted value can read, "
            "change or delete the data of the application."
        )

    remediation = (
        "Use parameterised queries or prepared statements and never build a query by "
        "joining strings."
    )


class XssCheck(InjectionCheck):
    """Looks for reflected cross site scripting."""

    id = "injection.xss"
    label = "Cross site scripting"
    description = "Looks for a payload that comes back unescaped in the answer."
    severity = "high"
    category = "injection"
    payloads = XSS_PAYLOADS

    max_parameters = 3
    max_endpoints = 8

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        content_type = (probe.headers.get("content-type") or "").lower()
        if "html" not in content_type and "json" not in content_type:
            return ""
        text = probe.body.decode("utf-8", "replace")
        marker = reflected(text, payload)
        if not marker:
            return ""
        base_text = baseline.body.decode("utf-8", "replace")
        if marker in base_text:
            return ""
        return f"the payload came back in the page as {marker!r}"

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is written into the page without "
            f"being escaped ({evidence[:200]}). An attacker can run script in the browser of "
            "every visitor who opens the link."
        )

    remediation = (
        "Encode the output for the context it is used in and set a Content-Security-Policy."
    )


class CommandInjectionCheck(InjectionCheck):
    """Looks for command injection."""

    id = "injection.command"
    label = "OS command injection"
    description = "Looks for a parameter that reaches a shell."
    severity = "critical"
    category = "injection"
    payloads = COMMAND_PAYLOADS

    max_parameters = 3
    max_endpoints = 8

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        for marker in COMMAND_OUTPUT_MARKERS:
            if marker in text and marker not in base_text:
                return f"the answer holds the output of the command ({marker!r})"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} reaches a shell: with {payload!r} "
            f"the server ran the command ({evidence[:200]}). This gives an attacker full "
            "control over the machine."
        )

    remediation = "Never pass user input to a shell; use an argument list and validate the input."


class SstiCheck(InjectionCheck):
    """Looks for server side template injection."""

    id = "injection.ssti"
    label = "Server side template injection"
    description = "Looks for a template engine that evaluates the input."
    severity = "critical"
    category = "injection"
    payloads = SSTI_PAYLOADS

    max_parameters = 3
    max_endpoints = 8

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        for evaluated in ("49", "7777777", "{}", "None", "True"):
            if evaluated in text and evaluated not in base_text:
                return f"the expression was evaluated and the answer holds {evaluated!r}"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is rendered by a template engine "
            f"that evaluates it ({evidence[:200]}). This usually leads to remote code "
            "execution."
        )

    remediation = "Never render user input as a template; use a context that escapes it."


class XxeCheck(InjectionCheck):
    """Looks for XML external entity processing."""

    id = "injection.xxe"
    label = "XML external entity"
    description = "Looks for an XML parser that resolves external entities."
    severity = "high"
    category = "injection"
    payloads = XXE_PAYLOADS

    max_parameters = 3
    max_endpoints = 6

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        for marker in ("root:x:0:0", "<?php", "SYSTEM", "entity"):
            if marker in text and marker not in base_text:
                return f"the answer holds {marker!r}, the entity was resolved"
        signature = looks_like_error(text, ("entity", "xml", "doctype", "external"))
        if signature and signature not in base_text:
            return f"the parser complained about the entity ({signature!r})"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is parsed as XML and the parser "
            f"resolves external entities ({evidence[:200]}). This reads local files and can "
            "reach internal services."
        )

    remediation = "Turn off external entity resolution and use a parser that does not support DTDs."


class SsrfCheck(InjectionCheck):
    """Looks for server side request forgery."""

    id = "injection.ssrf"
    label = "Server side request forgery"
    description = "Looks for a parameter that makes the server fetch a URL."
    severity = "high"
    category = "injection"
    payloads = SSRF_PAYLOADS

    max_parameters = 3
    max_endpoints = 6

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        if payload in text and payload not in base_text:
            return f"the URL came back in the answer ({payload!r})"
        for marker in ("connection refused", "no route to host", "could not resolve host"):
            if marker in text.lower() and marker not in base_text.lower():
                return f"the server tried to reach the address ({marker!r})"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is fetched by the server without "
            f"a check ({evidence[:200]}). An attacker can reach services that are only "
            "listening inside the network."
        )

    remediation = "Validate the URL against a list of allowed hosts and block the private ranges."


class LdapInjectionCheck(InjectionCheck):
    """Looks for LDAP injection."""

    id = "injection.ldap"
    label = "LDAP injection"
    description = "Looks for a parameter that reaches an LDAP filter."
    severity = "high"
    category = "injection"
    payloads = LDAP_PAYLOADS

    max_parameters = 3
    max_endpoints = 6

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        signature = looks_like_error(
            text, ("ldap", "invalid dn", "invalid search filter", "bad search filter")
        )
        if signature:
            return f"the directory complained about the filter ({signature!r})"
        if len(text) > len(base_text) * 2 and len(base_text) > 0:
            return "the answer grew a lot, the filter was widened"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is put into an LDAP filter without "
            f"being escaped ({evidence[:200]}). A wildcard can read the whole directory."
        )

    remediation = "Escape the input for LDAP (RFC 4515) or use a prepared filter."


class NoSqlInjectionCheck(InjectionCheck):
    """Looks for NoSQL injection."""

    id = "injection.nosql"
    label = "NoSQL injection"
    description = "Looks for a parameter that changes a document query."
    severity = "high"
    category = "injection"
    payloads = NOSQL_PAYLOADS

    max_parameters = 3
    max_endpoints = 6

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        signature = looks_like_error(
            text, ("mongodb", "duplicate key", "econnrefused", "com.mongodb", "bson")
        )
        if signature:
            return f"the database complained about the query ({signature!r})"
        if len(text) > len(base_text) * 2 and len(base_text) > 0:
            return "the answer grew a lot, the query was widened"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} reaches a document query as a "
            f"value ({evidence[:200]}). Operators such as $ne can be injected to read data "
            "that should stay hidden."
        )

    remediation = (
        "Check the type of every value before it reaches the query and keep the "
        "operators out of the input."
    )


class PathTraversalCheck(InjectionCheck):
    """Looks for directory traversal, local and remote file inclusion."""

    id = "injection.traversal"
    label = "Path traversal and file inclusion"
    description = "Looks for a parameter that reads a file outside of the web root."
    severity = "high"
    category = "injection"
    payloads = TRAVERSAL_PAYLOADS

    max_parameters = 3
    max_endpoints = 6

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        for marker in TRAVERSAL_MARKERS:
            if marker in text and marker not in base_text:
                return f"the answer holds the content of a system file ({marker!r})"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is used to build a path without "
            f"being checked ({evidence[:200]}). A file outside of the web root can be read."
        )

    remediation = (
        "Resolve the path and check that it stays inside the directory that may be served."
    )


class OpenRedirectCheck(InjectionCheck):
    """Looks for an open redirect."""

    id = "injection.redirect"
    label = "Open redirect"
    description = "Looks for a parameter that redirects to another host."
    severity = "medium"
    category = "injection"
    payloads = OPEN_REDIRECT_PAYLOADS

    max_parameters = 3
    max_endpoints = 6

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        if probe.status < 300 or probe.status >= 400:
            return ""
        location = probe.headers.get("location") or ""
        if "intercept.example" in location:
            return f"the server redirects to {location!r}"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} decides where the browser is sent "
            f"and accepts any host ({evidence[:200]}). A link like this is used to make "
            "victims trust a phishing page."
        )

    remediation = "Only redirect to a path or to a host from a list of allowed ones."


class PrototypePollutionCheck(InjectionCheck):
    """Looks for prototype pollution."""

    id = "injection.prototype"
    label = "Prototype pollution"
    description = "Looks for a parameter that reaches an object merge."
    severity = "high"
    category = "injection"

    max_parameters = 2
    max_endpoints = 5

    async def _probe(
        self,
        client: ToolClient,
        endpoint: Endpoint,
        parameter: str,
        baseline: Response,
    ) -> Finding | None:
        for payload in PROTOTYPE_PAYLOADS:
            response = await self._send(client, endpoint, parameter, payload)
            if response is None:
                continue
            text = response.body.decode("utf-8", "replace")
            if "polluted" in text:
                return self._finding(
                    endpoint, parameter, payload, "the answer holds 'polluted'", response
                )
            # The pollution shows up in the next request, not in this one.
            after = await self._send(client, endpoint)
            if after is not None and "polluted" in after.body.decode("utf-8", "replace"):
                return self._finding(
                    endpoint,
                    parameter,
                    payload,
                    "the next request holds 'polluted', the prototype was changed",
                    after,
                )
        return None


class DeserializationCheck(InjectionCheck):
    """Looks for unsafe deserialization."""

    id = "injection.deserialization"
    label = "Unsafe deserialization"
    description = "Looks for a parameter that is deserialized by the server."
    severity = "critical"
    category = "injection"
    payloads = DESERIALIZATION_PAYLOADS

    max_parameters = 2
    max_endpoints = 5

    def detect(self, baseline: Response, probe: Response, payload: str) -> str:
        text = probe.body.decode("utf-8", "replace")
        base_text = baseline.body.decode("utf-8", "replace")
        signature = looks_like_error(
            text,
            (
                "deserializ",
                "java.io.invalid",
                "unmarshal",
                "pickle",
                "yamlconstructor",
                "phpserialize",
                "gadget",
                "not a valid",
            ),
        )
        if signature and signature not in base_text:
            return f"the server complained about the object ({signature!r})"
        return ""

    def explain(self, endpoint: Endpoint, parameter: str, payload: str, evidence: str) -> str:
        return (
            f"The parameter {parameter!r} of {endpoint.url} is deserialized by the server "
            f"({evidence[:200]}). A crafted object can run code on the server."
        )

    remediation = (
        "Use a data format that only holds data and never deserialise objects of a foreign type."
    )


#: The injection checks, in the order they are shown.
INJECTION_CHECKS: list[InjectionCheck] = [
    SqlInjectionCheck(),
    XssCheck(),
    CommandInjectionCheck(),
    SstiCheck(),
    XxeCheck(),
    SsrfCheck(),
    LdapInjectionCheck(),
    NoSqlInjectionCheck(),
    PathTraversalCheck(),
    OpenRedirectCheck(),
    PrototypePollutionCheck(),
    DeserializationCheck(),
]

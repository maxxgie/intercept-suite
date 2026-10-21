"""The checks that look at how a target proves who you are.

Authentication, tokens and object references are three different ways of
letting a user in, and each of them can be broken in its own way. The checks
here look for an endpoint that lets a visitor in without proof, a token that
can be forged and an object that belongs to somebody else.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from intercept.core.models import Request, Response
from intercept.plugins.api import Finding
from intercept.scanner.base import ActiveCheck
from intercept.scanner.target import Endpoint
from intercept.tools.client import ToolClient

__all__ = [
    "AuthenticationCheck",
    "IdorCheck",
    "JwtCheck",
    "OAuthCheck",
]

#: The names that hold a token.
TOKEN_NAMES = (
    "token",
    "jwt",
    "access_token",
    "id_token",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "sid",
)

#: The names that hold the identifier of an object.
ID_NAMES = (
    "id",
    "uid",
    "user",
    "userid",
    "user_id",
    "account",
    "accountid",
    "order",
    "orderid",
    "no",
    "num",
    "ref",
    "doc",
    "docid",
)


class AuthenticationCheck(ActiveCheck):
    """Looks for a place that should ask for a password and does not."""

    id = "auth.authentication"
    label = "Authentication"
    description = "Looks for a protected area that answers without asking who you are."
    severity = "medium"
    category = "auth"

    #: The paths that usually belong to an account.
    PATHS = (
        "/admin",
        "/administrator",
        "/login",
        "/signin",
        "/account",
        "/profile",
        "/dashboard",
        "/wp-admin",
        "/manager",
        "/console",
        "/api/user",
        "/api/users",
        "/api/me",
        "/graphql",
    )

    #: The words that say the area is really protected.
    PROTECTED = (
        "login",
        "sign in",
        "signin",
        "log in",
        "password",
        "unauthorized",
        "authentication required",
        "please authenticate",
        "session expired",
        "401",
    )

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        split = urlsplit(target.url)
        base = f"{split.scheme}://{split.netloc}"
        findings: list[Finding] = []

        for path in self.PATHS:
            url = urljoin(base, path)
            response = await self._get(client, url)
            if response is None or response.status == 0:
                continue
            if response.status in (401, 403, 407):
                continue
            if response.status >= 500:
                continue
            text = response.body.decode("utf-8", "replace")[:4000]
            lowered = text.lower()
            if any(marker in lowered for marker in self.PROTECTED):
                continue
            # Only an area that looks like an account and answers with a page
            # is worth a finding.
            if (
                "<form" not in lowered
                and "login" not in lowered
                and "admin" not in path
                and "dashboard" not in path
            ):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"The area {path} answers without asking who you are",
                    severity="medium",
                    description=(
                        f"{url} answered with HTTP {response.status} and did not ask for "
                        "credentials, so the area may be reachable without an account."
                    ),
                    url=url,
                    evidence=f"HTTP {response.status}",
                    remediation="Put an authentication check in front of every private area.",
                )
            )
            if len(findings) >= 3:
                break
        return findings

    async def _get(self, client: ToolClient, url: str) -> Response | None:
        try:
            return await client.send(Request(method="GET", url=url))
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            return None


class JwtCheck(ActiveCheck):
    """Looks for a JSON web token that can be forged or that leaks."""

    id = "auth.jwt"
    label = "JWT issues"
    description = "Looks for a token that accepts alg=none, a weak secret or a token in a URL."
    severity = "high"
    category = "auth"

    #: The secrets that are used over and over again.
    WEAK_SECRETS = (
        "secret",
        "password",
        "changeme",
        "1234567890",
        "supersecret",
        "your-256-bit-secret",
        "jwtsecret",
        "key",
    )

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        token = self._find_token(target)
        if token:
            findings.extend(self._inspect_token(target.url, token))
        findings.extend(await self._look_for_tokens(client, target))
        return findings

    # ----------------------------------------------------------------- token

    def _find_token(self, target: Endpoint) -> str:
        for name, value in parse_qsl(urlsplit(target.url).query, keep_blank_values=True):
            if name.lower() in TOKEN_NAMES and value.count(".") == 2:
                return value
        for name, value in target.body_fields.items():
            if name.lower() in TOKEN_NAMES and value.count(".") == 2:
                return value
        return ""

    def _inspect_token(self, url: str, token: str) -> list[Finding]:
        findings: list[Finding] = []
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        algorithm = ""
        claims: dict[str, Any] = {}
        try:
            algorithm = str(json.loads(self._decode(parts[0])).get("alg", ""))
            claims = json.loads(self._decode(parts[1]))
        except (ValueError, TypeError):
            return findings

        if algorithm.lower() in ("none", "n one"):
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The token is signed with alg=none",
                    severity="critical",
                    description=(
                        "The token that was found says that it is not signed at all, so anyone "
                        "can write their own claims and be accepted."
                    ),
                    url=url,
                    evidence=f"alg: {algorithm}",
                    remediation="Only accept the algorithms you expect and refuse 'none'.",
                )
            )

        if "exp" not in claims and "nbf" not in claims:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The token never expires",
                    severity="medium",
                    description=(
                        "The claims of the token hold neither an expiry nor a not before date, "
                        "so a stolen token stays usable forever."
                    ),
                    url=url,
                    evidence=json.dumps(claims)[:200],
                    remediation="Give every token an expiry date.",
                )
            )

        sensitive = {
            key: value
            for key, value in claims.items()
            if key.lower()
            in ("password", "passwd", "secret", "token", "api_key", "apikey", "credit_card")
        }
        if sensitive:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The token carries secrets in its claims",
                    severity="medium",
                    description=(
                        "The claims of the token are readable by everybody who has it, so they "
                        "must not hold a password or another secret."
                    ),
                    url=url,
                    evidence=json.dumps(sensitive)[:200],
                    remediation="Keep secrets out of the claims of a token.",
                )
            )

        for secret in self.WEAK_SECRETS:
            if self._signs(parts, secret):
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"The token is signed with the secret {secret!r}",
                        severity="critical",
                        description=(
                            "The signature of the token can be made with a well known secret, so "
                            "anybody can forge a token for any user."
                        ),
                        url=url,
                        evidence=f"the signature matches the secret {secret!r}",
                        remediation="Use a long random secret and keep it out of the code.",
                    )
                )
                break
        return findings

    def _split(self, token: str) -> tuple[str, str, str]:
        parts = token.split(".")
        if len(parts) != 3:
            return "", "", ""
        return (self._decode(parts[0]), self._decode(parts[1]), parts[2])

    def _decode(self, part: str) -> str:
        padded = part + "=" * (-len(part) % 4)
        try:
            return base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return ""

    def _signs(self, parts: list[str], secret: str) -> bool:
        """Whether the signature of the token was made with the secret."""
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        signature = parts[2]
        for algorithm in ("sha256", "sha384", "sha512"):
            digest = hmac.new(secret.encode(), signing_input, getattr(hashlib, algorithm)).digest()
            expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            if hmac.compare_digest(expected, signature):
                return True
        return False

    # --------------------------------------------------------------- look out

    async def _look_for_tokens(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        response = await client.send(Request(method="GET", url=target.url))
        if response.status == 0:
            return findings
        text = response.body.decode("utf-8", "replace")
        for match in re.finditer(
            r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*", text
        ):
            token = match.group(0)
            url = target.url
            for finding in self._inspect_token(url, token):
                if finding.title not in {f.title for f in findings}:
                    findings.append(finding)
            break
        return findings


class OAuthCheck(ActiveCheck):
    """Looks for a broken OAuth or OpenID Connect flow."""

    id = "auth.oauth"
    label = "OAuth and OIDC"
    description = "Looks for a redirect that accepts any host, a missing state or a missing PKCE."
    severity = "medium"
    category = "auth"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        split = urlsplit(target.url)
        query = dict(parse_qsl(split.query, keep_blank_values=True))

        redirect_uri = (
            query.get("redirect_uri") or query.get("redirect_url") or query.get("return_url") or ""
        )
        if redirect_uri:
            request = Request(method="GET", url=target.url)
            request.headers.set("Host", "intercept.example")
            response = await client.send(request)
            location = (response.headers.get("location") or "") if response.status else ""
            if "intercept.example" in location:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="The OAuth redirect accepts any host",
                        severity="high",
                        description=(
                            "The authorisation answer sends the browser to a host that was taken "
                            "from the request, so the code or the token can be stolen."
                        ),
                        url=target.url,
                        evidence=f"Location: {location[:200]}",
                        remediation="Register the exact redirect URIs and compare them literally.",
                    )
                )
            if "state" not in query:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="The authorisation request carries no state",
                        severity="medium",
                        description=(
                            "Without a state parameter the answer cannot be tied to the request, "
                            "which allows a login CSRF."
                        ),
                        url=target.url,
                        evidence="no state parameter",
                        remediation="Send a random state and check it in the answer.",
                    )
                )
            if "code_challenge" not in query and "response_type=token" not in target.url:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="The authorisation request asks for no PKCE challenge",
                        severity="low",
                        description=(
                            "An authorisation code can be replayed without a proof key, which "
                            "matters for a public client."
                        ),
                        url=target.url,
                        evidence="no code_challenge parameter",
                        remediation="Use PKCE with S256 for every authorisation request.",
                    )
                )
        return findings


class IdorCheck(ActiveCheck):
    """Looks for an object that is handed out without checking who asks for it."""

    id = "auth.idor"
    label = "Insecure direct object reference"
    description = "Looks for an identifier that can be changed to reach another object."
    severity = "high"
    category = "auth"
    scope = "endpoint"

    #: The identifiers that are tried.
    CANDIDATES = ("1", "2", "3", "100", "1000", "0001", "0")

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        names = [
            name
            for name in target.parameter_names
            if name.lower() in ID_NAMES or name.lower().endswith("id")
        ]
        if not names:
            return []
        name = names[0]
        original = self._value_of(target, name)
        if not original:
            return []

        findings: list[Finding] = []
        baseline = await self._send(client, target)
        if baseline is None or baseline.status == 0:
            return []
        base_text = baseline.body.decode("utf-8", "replace")

        for candidate in self.CANDIDATES:
            if candidate == original:
                continue
            probe = self._with_value(target, name, candidate)
            response = await self._send(client, probe)
            if response is None or response.status == 0:
                continue
            if response.status in (401, 403, 404):
                continue
            text = response.body.decode("utf-8", "replace")
            if not text or text == base_text:
                continue
            if len(text) < 32:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"The object {candidate!r} was returned for another identifier",
                    severity="high",
                    description=(
                        f"The parameter {name!r} of {target.url} was changed from {original!r} to "
                        f"{candidate!r} and the server answered with an object that belongs to "
                        "somebody else."
                    ),
                    url=target.url,
                    evidence=text[:200],
                    remediation="Check that the session owns the object before it is returned.",
                )
            )
            break
        return findings

    def _value_of(self, target: Endpoint, name: str) -> str:
        for parameter in target.parameters:
            if parameter.name == name:
                return parameter.value
        return target.body_fields.get(name, "")

    def _with_value(self, target: Endpoint, name: str, value: str) -> Endpoint:
        if name in target.body_fields:
            return target.with_body_field(name, value)
        return target.with_parameter(name, value)

    async def _send(self, client: ToolClient, endpoint: Endpoint) -> Response | None:
        try:
            return await client.send(endpoint.request())
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            return None

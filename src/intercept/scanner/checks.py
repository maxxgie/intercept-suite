"""The checks that look at the server as a whole.

These checks ask a host about itself: the headers it sets, the cookies it
hands out, the files it should not serve and the methods it should not
accept. They run once per target, unlike the endpoint checks in
:mod:`intercept.scanner.injection` which probe the places that take input.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any
from urllib.parse import urljoin, urlsplit

from intercept.core.models import Request, Response
from intercept.plugins.api import Finding
from intercept.scanner.appsec import (
    CachePoisoningCheck,
    ClickjackingCheck,
    CookiePolicyCheck,
    CspWeaknessCheck,
    DomXssCheck,
    FileUploadCheck,
    HeaderMisconfigurationCheck,
    HttpRequestSmugglingCheck,
    XmlIssuesCheck,
)
from intercept.scanner.authsec import (
    AuthenticationCheck,
    IdorCheck,
    JwtCheck,
    OAuthCheck,
)
from intercept.scanner.base import ActiveCheck, CheckInfo, PassiveCheck
from intercept.scanner.graphql import GraphqlCheck
from intercept.scanner.injection import INJECTION_CHECKS
from intercept.scanner.oob import CollaboratorCheck
from intercept.scanner.target import Endpoint
from intercept.tools.client import ToolClient

__all__ = [
    "CheckInfo",
    "ActiveCheck",
    "PassiveCheck",
    "BUILTIN_CHECKS",
    "check_catalog",
]


# --------------------------------------------------------------------- active


class SecurityHeadersCheck(ActiveCheck):
    """Looks for missing response hardening headers."""

    id = "headers.security"
    label = "Security headers"
    description = "Checks for HSTS, CSP, X-Frame-Options and friends."
    severity = "medium"
    category = "headers"

    WANTED = {
        "strict-transport-security": ("high", "Enable HSTS to force TLS."),
        "content-security-policy": ("medium", "Set a Content-Security-Policy."),
        "x-frame-options": ("medium", "Set X-Frame-Options to stop framing."),
        "x-content-type-options": ("low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Set a Referrer-Policy."),
    }

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        response = await client.send(Request(method="GET", url=url))
        if response.status == 0:
            return []
        present = {name.lower() for name, _ in response.headers}
        findings: list[Finding] = []
        for header, (severity, remediation) in self.WANTED.items():
            if header in present:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Missing {header} header",
                    severity=severity,
                    description=(
                        f"The response for {url} does not set {header}, which leaves the "
                        "application exposed to a class of common attacks."
                    ),
                    url=url,
                    remediation=remediation,
                    evidence=f"HTTP {response.status}",
                )
            )
        return findings


class CookieFlagsCheck(ActiveCheck):
    """Looks for cookies without the usual protective flags."""

    id = "headers.cookies"
    label = "Cookie flags"
    description = "Checks Set-Cookie for Secure, HttpOnly and SameSite."
    severity = "low"
    category = "headers"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        response = await client.send(Request(method="GET", url=url))
        if response.status == 0:
            return []
        findings: list[Finding] = []
        for cookie in response.headers.get_all("set-cookie"):
            name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            problems = []
            if "secure" not in lowered:
                problems.append("Secure")
            if "httponly" not in lowered:
                problems.append("HttpOnly")
            if "samesite" not in lowered:
                problems.append("SameSite")
            if not problems:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Cookie {name} is missing {', '.join(problems)}",
                    severity="low",
                    description=(
                        f"The cookie {name!r} is set without {', '.join(problems)}, which "
                        "makes it easier to steal or to leak through a third party."
                    ),
                    url=url,
                    evidence=cookie,
                    remediation="Add the missing attributes to the cookie.",
                )
            )
        return findings


class DangerousMethodsCheck(ActiveCheck):
    """Probes for methods the server should not expose."""

    id = "http.methods"
    label = "Dangerous methods"
    description = "Tries TRACE, PUT and DELETE against the target."
    severity = "medium"
    category = "http"

    METHODS = ("TRACE", "PUT", "DELETE")

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        findings: list[Finding] = []
        for method in self.METHODS:
            request = Request(method=method, url=url)
            request.headers.set("Content-Length", "0")
            response = await client.send(request)
            if response.status == 0:
                continue
            if method == "TRACE" and response.status < 400:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="TRACE method is enabled",
                        severity="medium",
                        description=(
                            "The server answers TRACE requests, which can be used to "
                            "reflect cookies and authorization headers back to the client."
                        ),
                        url=url,
                        evidence=f"HTTP {response.status}",
                        remediation="Disable the TRACE method on the web server.",
                    )
                )
            elif method in ("PUT", "DELETE") and response.status < 400:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"{method} method is allowed",
                        severity="low",
                        description=(
                            f"The server accepts {method} requests on this path. Make sure "
                            "the route is protected by an authorization check."
                        ),
                        url=url,
                        evidence=f"HTTP {response.status}",
                        remediation="Restrict write methods to authenticated, authorised users.",
                    )
                )
        return findings


class SensitivePathsCheck(ActiveCheck):
    """Looks for files that should not be reachable."""

    id = "files.sensitive"
    label = "Sensitive files"
    description = "Probes for common configuration and secret files."
    severity = "high"
    category = "files"

    PATHS = (
        "/.env",
        "/.git/config",
        "/.git/HEAD",
        "/.svn/entries",
        "/config.php.bak",
        "/backup.sql",
        "/phpinfo.php",
        "/server-status",
        "/actuator/env",
        "/wp-config.php.bak",
        "/.DS_Store",
        "/debug",
    )

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        split = urlsplit(url)
        base = f"{split.scheme}://{split.netloc}"
        findings: list[Finding] = []
        for path in self.PATHS:
            response = await client.send(Request(method="GET", url=urljoin(base, path)))
            if response.status == 0 or response.status >= 400:
                continue
            body = response.body[:200].decode("utf-8", "replace")
            if _looks_like_not_found(response, body):
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Sensitive path is reachable: {path}",
                    severity="high",
                    description=(
                        f"The path {path} on {split.netloc} answered with HTTP "
                        f"{response.status} and looks like real content."
                    ),
                    url=urljoin(base, path),
                    evidence=body[:200],
                    remediation="Remove the file from the web root or deny access to it.",
                )
            )
        return findings


class DirectoryListingCheck(ActiveCheck):
    """Looks for directories that list their contents."""

    id = "files.listing"
    label = "Directory listing"
    description = "Probes for directory indexes."
    severity = "medium"
    category = "files"

    PATHS = ("/", "/uploads/", "/backup/", "/files/", "/assets/")

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        split = urlsplit(url)
        base = f"{split.scheme}://{split.netloc}"
        findings: list[Finding] = []
        for path in self.PATHS:
            response = await client.send(Request(method="GET", url=urljoin(base, path)))
            if response.status == 0 or response.status >= 400:
                continue
            body = response.body[:4000].decode("utf-8", "replace")
            if "Index of /" not in body and "<title>Index of" not in body:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Directory listing enabled on {path}",
                    severity="medium",
                    description=(
                        f"{urljoin(base, path)} returns a directory index, which exposes the "
                        "structure and the file names of the server."
                    ),
                    url=urljoin(base, path),
                    evidence=body[:200],
                    remediation="Disable directory indexing on the web server.",
                )
            )
        return findings


class CorsMisconfigurationCheck(ActiveCheck):
    """Looks for a CORS policy that reflects any origin."""

    id = "http.cors"
    label = "CORS misconfiguration"
    description = "Sends a foreign Origin header and inspects the answer."
    severity = "medium"
    category = "http"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        request = Request(method="GET", url=url)
        request.headers.set("Origin", "https://intercept.example")
        response = await client.send(request)
        if response.status == 0:
            return []
        allow_origin = response.headers.get("access-control-allow-origin") or ""
        if allow_origin != "*" and "intercept.example" not in allow_origin:
            return []
        credentials = (response.headers.get("access-control-allow-credentials") or "").lower()
        severity = "high" if credentials == "true" else "medium"
        findings = [
            Finding(
                check_id=self.id,
                title="CORS policy allows an arbitrary origin",
                severity=severity,
                description=(
                    "The response reflects a foreign Origin header, which lets any site "
                    "read the responses of this endpoint from a browser."
                ),
                url=url,
                evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                remediation="Restrict Access-Control-Allow-Origin to the trusted origins.",
            )
        ]
        if credentials == "true":
            findings.append(
                Finding(
                    check_id=self.id,
                    title="CORS policy allows credentials",
                    severity="high",
                    description=(
                        "The endpoint combines a permissive origin with "
                        "Access-Control-Allow-Credentials, so a third party site can read "
                        "authenticated responses."
                    ),
                    url=url,
                    evidence="Access-Control-Allow-Credentials: true",
                    remediation="Do not combine a wildcard origin with credentials.",
                )
            )
        return findings


class ServerBannerCheck(ActiveCheck):
    """Reports the server and framework banners."""

    id = "info.banner"
    label = "Server banner"
    description = "Reports the product and version banners of the response."
    severity = "info"
    category = "info"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        response = await client.send(Request(method="GET", url=url))
        if response.status == 0:
            return []
        findings: list[Finding] = []
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            value = response.headers.get(header)
            if not value:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"{header} discloses {value}",
                    severity="info",
                    description=(
                        f"The response sets {header}, which tells an attacker which software "
                        "and version is running."
                    ),
                    url=url,
                    evidence=f"{header}: {value}",
                    remediation="Remove or rewrite the banner header.",
                )
            )
        return findings


class TlsConfigurationCheck(ActiveCheck):
    """Reports the TLS version and cipher of the origin."""

    id = "tls.configuration"
    label = "TLS configuration"
    description = "Reports the negotiated TLS version and cipher suite."
    severity = "info"
    category = "tls"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        url = target.url
        split = urlsplit(url)
        if split.scheme != "https" or not split.hostname:
            return []
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection((split.hostname, split.port or 443), timeout=10) as sock,
                context.wrap_socket(sock, server_hostname=split.hostname) as tls,
            ):
                version = tls.version() or "unknown"
                cipher = tls.cipher()
        except OSError:
            return []
        cipher_name = cipher[0] if cipher else "unknown"
        findings = [
            Finding(
                check_id=self.id,
                title=f"TLS {version} with {cipher_name}",
                severity="info",
                description="The negotiated TLS parameters of the origin.",
                url=url,
                evidence=f"{version} {cipher_name}",
                remediation="Prefer TLS 1.2 or newer with a modern cipher suite.",
            )
        ]
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"Outdated TLS version in use ({version})",
                    severity="high",
                    description=(
                        f"The origin negotiated {version}, which is deprecated and known to "
                        "be broken."
                    ),
                    url=url,
                    evidence=version,
                    remediation="Disable TLS 1.0 and 1.1 on the server.",
                )
            )
        return findings


# -------------------------------------------------------------------- passive


class VerboseErrorPageCheck(PassiveCheck):
    """Looks for stack traces or debug output in an error page."""

    id = "passive.errorpage"
    label = "Verbose error page"
    description = "Looks for stack traces and debug output in responses."
    severity = "medium"
    category = "general"

    SIGNATURES = (
        "Traceback (most recent call last)",
        "java.lang.NullPointerException",
        "Fatal error:",
        "Microsoft VBScript runtime error",
        "ORA-00933",
        "SQLSTATE[",
        "Symfony\\Component\\HttpKernel\\Exception",
        "django.core.exceptions",
        "at java.",
        "org.apache.catalina",
    )

    def run(self, request: Request, response: Response) -> list[Finding]:
        if response.status < 400 or not response.body:
            return []
        text = response.body.decode("utf-8", "replace")
        for signature in self.SIGNATURES:
            if signature in text:
                return [
                    Finding(
                        check_id=self.id,
                        title="Error page leaks implementation details",
                        severity="medium",
                        description=(
                            f"The error response contains {signature!r}, which reveals the "
                            "technology stack and often file system paths."
                        ),
                        url=request.url,
                        evidence=text[:200],
                        remediation="Disable debug output and customise the error pages.",
                    )
                ]
        return []


class FormWithoutCsrfCheck(PassiveCheck):
    """Looks for state changing forms that have no CSRF token."""

    id = "passive.csrf"
    label = "Missing CSRF token"
    description = "Looks for forms that change state without a CSRF token."
    severity = "medium"
    category = "general"

    def run(self, request: Request, response: Response) -> list[Finding]:
        if request.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
            return []
        ctype = (response.headers.get("content-type") or "").lower()
        if "html" not in ctype:
            return []
        text = response.body.decode("utf-8", "replace")
        if "<form" not in text.lower():
            return []
        lowered = text.lower()
        if any(token in lowered for token in ("csrf", "xsrf", "_token", "authenticity_token")):
            return []
        return [
            Finding(
                check_id=self.id,
                title="Form submitted without a CSRF token",
                severity="medium",
                description=(
                    "A state changing request was sent and the response contains a form "
                    "without an anti-CSRF token, so the action may be forgeable."
                ),
                url=request.url,
                evidence=request.method,
                remediation="Add a per-session anti-CSRF token to every state changing form.",
            )
        ]


def _looks_like_not_found(response: Response, body: str) -> bool:
    """Heuristic that tells a real file apart from a soft 404 page."""
    if response.status == 404:
        return True
    lowered = body.lower()
    soft_404 = ("404", "not found", "no such file", "does not exist")
    return any(marker in lowered for marker in soft_404)


BUILTIN_CHECKS: list[Any] = [
    SecurityHeadersCheck(),
    CookieFlagsCheck(),
    DangerousMethodsCheck(),
    SensitivePathsCheck(),
    DirectoryListingCheck(),
    CorsMisconfigurationCheck(),
    ServerBannerCheck(),
    TlsConfigurationCheck(),
    VerboseErrorPageCheck(),
    FormWithoutCsrfCheck(),
    ClickjackingCheck(),
    CspWeaknessCheck(),
    CookiePolicyCheck(),
    HeaderMisconfigurationCheck(),
    CachePoisoningCheck(),
    HttpRequestSmugglingCheck(),
    FileUploadCheck(),
    XmlIssuesCheck(),
    DomXssCheck(),
    AuthenticationCheck(),
    JwtCheck(),
    OAuthCheck(),
    IdorCheck(),
    GraphqlCheck(),
    CollaboratorCheck(),
    *INJECTION_CHECKS,
]


def check_catalog() -> list[dict[str, Any]]:
    """Describe every built in check."""
    catalog: list[dict[str, Any]] = []
    for check in BUILTIN_CHECKS:
        catalog.append(check.info().to_dict())
    return catalog

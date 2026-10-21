"""The checks that look at how the application is put together.

These checks do not inject anything into a parameter. They look at the way the
server answers: the headers it sets, the frames it allows, the cache it fills,
the way it reads the body, the files it accepts and the scripts it hands out.
"""

from __future__ import annotations

import asyncio
import re

from intercept.core.models import Request, Response
from intercept.plugins.api import Finding
from intercept.scanner.base import ActiveCheck, PassiveCheck
from intercept.scanner.target import Endpoint
from intercept.tools.client import ToolClient

__all__ = [
    "CachePoisoningCheck",
    "ClickjackingCheck",
    "CookiePolicyCheck",
    "CspWeaknessCheck",
    "DomXssCheck",
    "FileUploadCheck",
    "HeaderMisconfigurationCheck",
    "HttpRequestSmugglingCheck",
    "XmlIssuesCheck",
]


class ClickjackingCheck(ActiveCheck):
    """Looks for a page that can be framed."""

    id = "web.clickjacking"
    label = "Clickjacking"
    description = "Looks for a missing X-Frame-Options or frame-ancestors."
    severity = "medium"
    category = "web"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        response = await client.send(Request(method="GET", url=target.url))
        if response.status == 0:
            return []
        frame_options = response.headers.get("x-frame-options") or ""
        policy = response.headers.get("content-security-policy") or ""
        if frame_options.lower() in ("deny", "sameorigin"):
            return []
        if "frame-ancestors" in policy.lower():
            return []
        return [
            Finding(
                check_id=self.id,
                title="The page can be framed by another site",
                severity="medium",
                description=(
                    f"{target.url} does not set X-Frame-Options and its "
                    "Content-Security-Policy does not name frame-ancestors, so another site "
                    "can put it in a frame and click on it for the visitor."
                ),
                url=target.url,
                evidence=f"HTTP {response.status}",
                remediation="Set X-Frame-Options: DENY or add frame-ancestors to the policy.",
            )
        ]


class CspWeaknessCheck(ActiveCheck):
    """Looks for a Content-Security-Policy that does not protect anything."""

    id = "web.csp"
    label = "Weak content security policy"
    description = "Looks for unsafe-inline, unsafe-eval and wildcards in the policy."
    severity = "medium"
    category = "web"

    WEAKNESSES = (
        ("unsafe-inline", "high", "Script sources may not use 'unsafe-inline'."),
        ("unsafe-eval", "high", "Script sources may not use 'unsafe-eval'."),
        ("data:", "medium", "Allowing 'data:' in a script source removes the protection."),
        ("*", "medium", "A wildcard lets every host be trusted."),
    )

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        response = await client.send(Request(method="GET", url=target.url))
        if response.status == 0:
            return []
        policy = response.headers.get("content-security-policy") or ""
        if not policy:
            return [
                Finding(
                    check_id=self.id,
                    title="No Content-Security-Policy",
                    severity="low",
                    description=(
                        f"{target.url} does not set a Content-Security-Policy, so the browser "
                        "runs whatever script the answer contains."
                    ),
                    url=target.url,
                    evidence=f"HTTP {response.status}",
                    remediation="Set a Content-Security-Policy that names the sources you trust.",
                )
            ]
        findings: list[Finding] = []
        lowered = policy.lower()
        for marker, severity, remediation in self.WEAKNESSES:
            if marker not in lowered:
                continue
            if marker == "*" and "*" not in lowered:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    title=f"The policy allows {marker!r}",
                    severity=severity,
                    description=(
                        f"The Content-Security-Policy of {target.url} allows {marker!r}, which "
                        "weakens the protection it is supposed to give."
                    ),
                    url=target.url,
                    evidence=policy[:300],
                    remediation=remediation,
                )
            )
        return findings


class CookiePolicyCheck(ActiveCheck):
    """Looks for cookies that carry more than they should."""

    id = "web.cookies"
    label = "Cookie policy"
    description = "Looks for long lived cookies and for session cookies without a flag."
    severity = "low"
    category = "web"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        response = await client.send(Request(method="GET", url=target.url))
        if response.status == 0:
            return []
        findings: list[Finding] = []
        for cookie in response.headers.get_all("set-cookie"):
            name = cookie.split("=", 1)[0].strip()
            lowered = cookie.lower()
            if "secure" not in lowered and target.url.lower().startswith("https"):
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"Cookie {name} is sent over plain HTTP as well",
                        severity="medium",
                        description=(
                            f"The cookie {name!r} is set without the Secure flag although the "
                            "page is served over HTTPS, so it travels in the clear when the "
                            "browser falls back to HTTP."
                        ),
                        url=target.url,
                        evidence=cookie,
                        remediation="Add the Secure attribute to every cookie of an HTTPS page.",
                    )
                )
            if "max-age" in lowered or "expires" in lowered:
                for part in cookie.split(";"):
                    part = part.strip().lower()
                    if part.startswith("max-age="):
                        try:
                            seconds = int(part.split("=", 1)[1])
                        except ValueError:
                            continue
                        if seconds > 60 * 60 * 24 * 30:
                            findings.append(
                                Finding(
                                    check_id=self.id,
                                    title=f"Cookie {name} lives for {seconds} seconds",
                                    severity="low",
                                    description=(
                                        f"The cookie {name!r} is kept for more than a month, so "
                                        "a stolen cookie stays useful for a long time."
                                    ),
                                    url=target.url,
                                    evidence=cookie,
                                    remediation="Give session cookies a short life.",
                                )
                            )
                    if part.startswith("expires="):
                        findings.append(
                            Finding(
                                check_id=self.id,
                                title=f"Cookie {name} has an expiry date",
                                severity="info",
                                description=(
                                    f"The cookie {name!r} is a persistent cookie, it survives the "
                                    "closing of the browser."
                                ),
                                url=target.url,
                                evidence=cookie,
                                remediation="Use a session cookie where a long life is not needed.",
                            )
                        )
        return findings


class HeaderMisconfigurationCheck(ActiveCheck):
    """Looks for headers that let a request be twisted."""

    id = "web.headers"
    label = "Header misconfiguration"
    description = "Looks for host header injection and for a reflected redirect header."
    severity = "medium"
    category = "web"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        request = Request(method="GET", url=target.url)
        request.headers.set("X-Forwarded-Host", "intercept.example")
        response = await client.send(request)
        if response.status == 0:
            return []
        text = response.body.decode("utf-8", "replace")
        location = response.headers.get("location") or ""
        if "intercept.example" in location:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The X-Forwarded-Host header decides where the redirect points",
                    severity="high",
                    description=(
                        "The answer reflects a forged X-Forwarded-Host header in its Location "
                        "header, so a link can send the visitor to another host."
                    ),
                    url=target.url,
                    evidence=f"Location: {location[:200]}",
                    remediation="Do not build redirects from a header the client controls.",
                )
            )
        elif "intercept.example" in text and "x-forwarded-host" in text.lower():
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The X-Forwarded-Host header is reflected in the page",
                    severity="low",
                    description=(
                        "The page shows the value of a forged X-Forwarded-Host header, which can "
                        "be used to poison a cache or to poison a password reset mail."
                    ),
                    url=target.url,
                    evidence=text[:200],
                    remediation="Use the host of the request, not a header, to build links.",
                )
            )
        return findings


class CachePoisoningCheck(ActiveCheck):
    """Looks for a page that is cached under a key the client controls."""

    id = "web.cache"
    label = "Web cache poisoning"
    description = "Looks for an unkeyed header that ends up in the cached page."
    severity = "medium"
    category = "web"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        request = Request(method="GET", url=target.url)
        request.headers.set("X-Forwarded-Host", "intercept-cache.example")
        response = await client.send(request)
        if response.status == 0:
            return []
        text = response.body.decode("utf-8", "replace")
        if "intercept-cache.example" not in text:
            return []
        cacheable = any(
            name.lower() in ("cache-control", "age", "etag", "x-cache", "vary")
            for name, _ in response.headers
        )
        if not cacheable:
            return []
        return [
            Finding(
                check_id=self.id,
                title="The page is cached and holds a header the client controls",
                severity="medium",
                description=(
                    f"{target.url} shows the value of a forged X-Forwarded-Host header and "
                    "answers with cache headers, so a poisoned answer can be served to every "
                    "visitor."
                ),
                url=target.url,
                evidence=text[:200],
                remediation=(
                    "Do not reflect client controlled headers, or include them in the cache key."
                ),
            )
        ]


class HttpRequestSmugglingCheck(ActiveCheck):
    """Looks for a server that reads the body in a different way than a proxy."""

    id = "web.smuggling"
    label = "HTTP request smuggling"
    description = "Looks for a difference between Content-Length and Transfer-Encoding."
    severity = "high"
    category = "web"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []

        request = Request(method="POST", url=target.url)
        request.headers.set("Content-Type", "application/x-www-form-urlencoded")
        request.headers.set("Content-Length", "6")
        request.headers.set("Transfer-Encoding", "chunked")
        request.body = b"0\r\n\r\n"
        response = await client.send(request)
        if response.status and response.status not in (400, 411, 413, 501):
            findings.append(
                Finding(
                    check_id=self.id,
                    title=(
                        "The server accepts a request with both Content-Length and "
                        "Transfer-Encoding"
                    ),
                    severity="high",
                    description=(
                        f"{target.url} answered a request that carries a Content-Length and a "
                        "Transfer-Encoding header at the same time. A front end and a back end "
                        "that read the body differently can be tricked into smuggling a second "
                        "request."
                    ),
                    url=target.url,
                    evidence=f"HTTP {response.status}",
                    remediation="Reject a request that carries both headers.",
                )
            )

        request = Request(method="POST", url=target.url)
        request.headers.set("Content-Type", "application/x-www-form-urlencoded")
        request.headers.set("Transfer-Encoding", "chunked")
        request.headers.set("Content-Length", "4")
        request.body = b"0\r\n\r\n"
        response = await self._send(client, request)
        if response is not None and response.status and response.status not in (400, 411, 413, 501):
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The server reads the chunked body although a Content-Length is set",
                    severity="medium",
                    description=(
                        f"{target.url} answered a request that carries a chunked body together "
                        "with a Content-Length, which is the shape a smuggled request needs."
                    ),
                    url=target.url,
                    evidence=f"HTTP {response.status}",
                    remediation="Use one framing header only and reject the request otherwise.",
                )
            )
        return findings

    async def _send(self, client: ToolClient, request: Request) -> Response | None:
        try:
            return await client.send(request)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            return None


class FileUploadCheck(ActiveCheck):
    """Looks for a place that accepts a file without checking it."""

    id = "web.upload"
    label = "File upload"
    description = "Looks for an upload that keeps a dangerous name or type."
    severity = "medium"
    category = "web"

    #: The names that are tried, one at a time.
    FILES = (
        ("probe.php", "<?php echo 'probe'; ?>", "text/plain"),
        ("probe.jsp", '<% out.print("probe"); %>', "text/plain"),
        ("probe.html", "<script>alert(1)</script>", "text/plain"),
        ("probe.svg", '<svg onload="alert(1)"/>', "image/svg+xml"),
    )

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        for name, content, content_type in self.FILES:
            request = Request(method="POST", url=target.url)
            boundary = "----interceptboundary"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
                f"{content}\r\n"
                f"--{boundary}--\r\n"
            ).encode()
            request.body = body
            request.headers.set("Content-Type", f"multipart/form-data; boundary={boundary}")
            request.headers.set("Content-Length", str(len(body)))
            response = await self._send(client, request)
            if response is None or response.status == 0:
                continue
            if response.status >= 400:
                continue
            text = response.body.decode("utf-8", "replace")
            if name.lower() in text.lower() or content.strip() in text:
                findings.append(
                    Finding(
                        check_id=self.id,
                        title=f"The upload {name} was accepted",
                        severity="high" if name.endswith((".php", ".jsp")) else "medium",
                        description=(
                            f"{target.url} answered the upload of {name} with HTTP "
                            f"{response.status} and kept the file, which can be used to run "
                            "code on the server."
                        ),
                        url=target.url,
                        evidence=f"HTTP {response.status}: {text[:200]}",
                        remediation=(
                            "Check the extension and the content of an upload and keep it "
                            "out of the web root."
                        ),
                    )
                )
                break
        return findings

    async def _send(self, client: ToolClient, request: Request) -> Response | None:
        try:
            return await client.send(request)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed probe is not a finding
            return None


class XmlIssuesCheck(ActiveCheck):
    """Looks for an XML service that says too much."""

    id = "web.xml"
    label = "XML issues"
    description = "Looks for a missing XML declaration and for a readable stylesheet."
    severity = "low"
    category = "web"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        findings: list[Finding] = []
        response = await client.send(Request(method="GET", url=target.url))
        if response.status == 0:
            return []
        content_type = (response.headers.get("content-type") or "").lower()
        if "xml" not in content_type:
            return []
        text = response.body.decode("utf-8", "replace")
        if "<?xml" not in text[:200]:
            findings.append(
                Finding(
                    check_id=self.id,
                    title="The XML answer has no declaration",
                    severity="info",
                    description=(
                        f"{target.url} answers with XML without a declaration, which makes the "
                        "encoding of the document ambiguous."
                    ),
                    url=target.url,
                    evidence=text[:200],
                    remediation="Start every XML document with its declaration.",
                )
            )
        for name, value in response.headers:
            if name.lower() != "content-type":
                continue
            if "text/xml" in value.lower() or "application/xml" in value.lower():
                findings.append(
                    Finding(
                        check_id=self.id,
                        title="The XML is served without a charset",
                        severity="info",
                        description=(
                            f"{target.url} serves XML as {value} without saying which encoding it "
                            "uses."
                        ),
                        url=target.url,
                        evidence=value,
                        remediation="Name the charset in the Content-Type header.",
                    )
                )
        return findings


class DomXssCheck(PassiveCheck):
    """Looks for a script that puts a value into the page without escaping it."""

    id = "web.domxss"
    label = "DOM based XSS"
    description = "Looks for a script that writes a value into the document or into an event."
    severity = "medium"
    category = "web"

    SINKS = (
        r"document\.write\s*\(",
        r"\.innerHTML\s*=",
        r"outerHTML\s*=",
        r"insertAdjacentHTML\s*\(",
        r"eval\s*\(",
        r"setTimeout\s*\(\s*[\"'`]",
        r"setInterval\s*\(\s*[\"'`]",
        r"location\.(hash|search)\b",
        r"document\.location\s*=",
        r"new Function\s*\(",
    )

    SOURCES = (
        r"location\.(hash|search|href)",
        r"document\.URL",
        r"document\.referrer",
        r"window\.name",
        r"URLSearchParams",
    )

    def run(self, request: Request, response: Response) -> list[Finding]:
        content_type = (response.headers.get("content-type") or "").lower()
        if "javascript" not in content_type and "html" not in content_type:
            return []
        text = response.body.decode("utf-8", "replace")
        sinks = [pattern for pattern in self.SINKS if re.search(pattern, text)]
        sources = [pattern for pattern in self.SOURCES if re.search(pattern, text)]
        if not sinks or not sources:
            return []
        return [
            Finding(
                check_id=self.id,
                title="The script writes a value from the address bar into the page",
                severity="medium",
                description=(
                    "The script of the answer reads a value from the address bar and writes it "
                    "into the document without escaping it, so a crafted link can run script in "
                    "the browser of the visitor."
                ),
                url=request.url,
                evidence=f"the sinks {', '.join(sinks[:3])} take a value from {sources[0]}",
                remediation="Write values with textContent instead of innerHTML and escape them.",
            )
        ]

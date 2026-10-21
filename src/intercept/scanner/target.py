"""The endpoints a scan works on.

A target URL on its own is not enough for a serious scan: the interesting
places are the pages that take input. This module holds the model of such a
place (:class:`Endpoint`) and a small crawler that finds them.

The crawler follows the links of the pages it reads, keeps the forms it finds
and notes the query parameters of every URL it comes across. The result is the
list of endpoints the checks are run against.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from intercept.core.models import Request
from intercept.tools.client import ToolClient

__all__ = [
    "Endpoint",
    "Parameter",
    "EndpointCrawler",
    "FormParser",
    "LinkParser",
    "extract_endpoints",
]


@dataclass
class Parameter:
    """One input of an endpoint."""

    name: str
    value: str = ""
    location: str = "query"  # query | body | header | cookie

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "location": self.location,
        }


@dataclass
class Endpoint:
    """A place that takes input.

    ``parameters`` holds the query parameters, ``body_fields`` the fields of a
    form and ``cookies`` the cookies that were set when the page was read.
    """

    url: str
    method: str = "GET"
    parameters: list[Parameter] = field(default_factory=list)
    body_fields: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    source: str = "seed"  # seed | link | form
    depth: int = 0

    def __post_init__(self) -> None:
        if not self.parameters:
            split = urlsplit(self.url)
            self.parameters = [
                Parameter(name, value, "query")
                for name, value in parse_qsl(split.query, keep_blank_values=True)
            ]

    @property
    def query_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == "query"]

    @property
    def has_parameters(self) -> bool:
        return bool(self.parameters or self.body_fields)

    @property
    def parameter_names(self) -> list[str]:
        names = [p.name for p in self.parameters]
        names.extend(self.body_fields)
        return names

    def with_parameter(self, name: str, value: str) -> Endpoint:
        """A copy of this endpoint with one parameter replaced."""
        split = urlsplit(self.url)
        pairs = parse_qsl(split.query, keep_blank_values=True)
        replaced = False
        new_pairs: list[tuple[str, str]] = []
        for key, current in pairs:
            if key == name:
                new_pairs.append((key, value))
                replaced = True
            else:
                new_pairs.append((key, current))
        if not replaced:
            new_pairs.append((name, value))
        query = urlencode(new_pairs)
        clone = Endpoint(
            url=urlunsplit((split.scheme, split.netloc, split.path, query, split.fragment)),
            method=self.method,
            parameters=[
                Parameter(p.name, value if p.name == name else p.value, p.location)
                for p in self.parameters
            ],
            body_fields=dict(self.body_fields),
            cookies=dict(self.cookies),
            content_type=self.content_type,
            source=self.source,
            depth=self.depth,
        )
        return clone

    def with_body_field(self, name: str, value: str) -> Endpoint:
        """A copy of this endpoint with one form field replaced."""
        clone = Endpoint(
            url=self.url,
            method=self.method,
            parameters=list(self.parameters),
            body_fields=dict(self.body_fields),
            cookies=dict(self.cookies),
            content_type=self.content_type,
            source=self.source,
            depth=self.depth,
        )
        clone.body_fields[name] = value
        return clone

    def request(self) -> Request:
        """The request that probes this endpoint."""
        request = Request(method=self.method, url=self.url)
        request.origin = "scanner"
        for name, value in self.cookies.items():
            request.headers.add("Cookie", f"{name}={value}")
        if self.body_fields:
            from urllib.parse import urlencode as encode

            body = encode(self.body_fields).encode("utf-8")
            request.body = body
            request.headers.set(
                "Content-Type",
                self.content_type or "application/x-www-form-urlencoded",
            )
            request.headers.set("Content-Length", str(len(body)))
        return request

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": [p.to_dict() for p in self.parameters],
            "body_fields": dict(self.body_fields),
            "cookies": dict(self.cookies),
            "content_type": self.content_type,
            "source": self.source,
            "depth": self.depth,
        }


class LinkParser(HTMLParser):
    """Collects the links and the forms of an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.base: str | None = None
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "base" and values.get("href"):
            self.base = values["href"]
        elif tag == "a" and values.get("href") or tag == "link" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "script" and values.get("src") or tag == "iframe" and values.get("src"):
            self.links.append(values["src"])
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "get").upper(),
                "fields": {},
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = values.get("name")
            if not name:
                return
            kind = values.get("type", "text").lower()
            if kind in ("submit", "button", "image", "reset", "file"):
                return
            self._form["fields"][name] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


class FormParser(LinkParser):
    """Kept as a name of its own for readability."""


def _same_host(left: str, right: str) -> bool:
    return urlsplit(left).netloc.lower() == urlsplit(right).netloc.lower()


def extract_endpoints(
    url: str, body: str, content_type: str = ""
) -> tuple[list[str], list[dict[str, Any]]]:
    """The links and the forms that a document holds."""
    if "html" not in content_type.lower() and "<" not in body[:200]:
        return [], []
    parser = FormParser()
    with contextlib.suppress(Exception):  # a broken document must not stop the crawl
        parser.feed(body)
    return parser.links, parser.forms


class EndpointCrawler:
    """Walks a target and collects the endpoints that take input."""

    def __init__(
        self,
        client: ToolClient,
        max_pages: int = 30,
        max_depth: int = 2,
        timeout: float = 10.0,
    ) -> None:
        self.client = client
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout

    async def crawl(self, url: str) -> list[Endpoint]:
        """The endpoints that were found under *url*."""
        split = urlsplit(url)
        base = f"{split.scheme}://{split.netloc}"
        seen: set[str] = set()
        endpoints: list[Endpoint] = []
        queue: list[tuple[str, int]] = [(url, 0)]
        pages = 0

        while queue and pages < self.max_pages:
            current, depth = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            pages += 1

            response = await self._get(current)
            if response is None:
                continue

            endpoint = self._endpoint(current, response)
            if endpoint is not None:
                endpoints.append(endpoint)

            if depth >= self.max_depth:
                continue

            text = response.body.decode("utf-8", "replace")
            links, forms = extract_endpoints(
                current, text, response.headers.get("content-type", "") or ""
            )
            for link in links:
                target = urljoin(current, link)
                if not target.startswith(("http://", "https://")):
                    continue
                if not _same_host(target, base):
                    continue
                if target not in seen:
                    queue.append((target, depth + 1))
            for form in forms:
                action = urljoin(current, form.get("action") or current)
                if not action.startswith(("http://", "https://")):
                    continue
                if not _same_host(action, base):
                    continue
                endpoints.append(
                    Endpoint(
                        url=action,
                        method=form.get("method", "GET"),
                        body_fields=dict(form.get("fields", {})),
                        cookies=self._cookies(response),
                        source="form",
                        depth=depth + 1,
                    )
                )
        return endpoints

    async def _get(self, url: str):
        try:
            return await asyncio.wait_for(
                self.client.send(Request(method="GET", url=url)), timeout=self.timeout
            )
        except (TimeoutError, asyncio.CancelledError):
            return None
        except Exception:  # noqa: BLE001 - a broken page must not stop the crawl
            return None

    def _cookies(self, response: Any) -> dict[str, str]:
        cookies: dict[str, str] = {}
        for raw in response.headers.get_all("set-cookie"):
            first = raw.split(";", 1)[0]
            name, _, value = first.partition("=")
            if name.strip():
                cookies[name.strip()] = value.strip()
        return cookies

    def _endpoint(self, url: str, response: Any) -> Endpoint | None:
        split = urlsplit(url)
        query = parse_qsl(split.query, keep_blank_values=True)
        parameters = [Parameter(name, value, "query") for name, value in query]
        return Endpoint(
            url=url,
            method="GET",
            parameters=parameters,
            cookies=self._cookies(response),
            content_type=response.headers.get("content-type", "") or "",
            source="seed" if not parameters else "link",
        )

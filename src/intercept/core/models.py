"""Core HTTP data model.

Everything that crosses a module boundary (proxy -> store -> api -> tool) is
expressed with these types, so the wire format, the storage format and the API
payload format all stay in sync.
"""

from __future__ import annotations

import base64
import time
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "Headers",
    "Request",
    "Response",
    "Exchange",
    "decode_body",
    "new_id",
]


def new_id() -> str:
    return uuid.uuid4().hex


def decode_body(body: bytes) -> tuple[str, str]:
    """Return a body as text and the encoding that text is in.

    A body that is not valid UTF-8 is sent as base64, so the bytes that were
    on the wire reach the interface unchanged and can be shown as a hex dump.
    """
    try:
        return body.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return base64.b64encode(body).decode("ascii"), "base64"


def _as_pairs(items: Any) -> list[tuple[str, str]]:
    """Accept tuples, a dict of name to value (or list of values), or Headers."""
    if items is None:
        return []
    if isinstance(items, Headers):
        return items.items()
    if isinstance(items, dict):
        pairs: list[tuple[str, str]] = []
        for key, value in items.items():
            if isinstance(value, (list, tuple, set)):
                pairs.extend((key, str(entry)) for entry in value)
            else:
                pairs.append((key, str(value)))
        return pairs
    return [(str(key), str(value)) for key, value in items]


class Headers:
    """Ordered, case-insensitive, multi-value HTTP header collection.

    Insertion order and duplicates are preserved because the tool shows the
    user exactly what went over the wire.
    """

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[tuple[str, str]] | None = None) -> None:
        self._items: list[list[str]] = [[k, v] for k, v in _as_pairs(items)]

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter((k, v) for k, v in self._items)

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        lowered = name.lower()
        return any(k.lower() == lowered for k, _ in self._items)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Headers):
            return NotImplemented
        return self._items == other._items

    def __repr__(self) -> str:
        return f"Headers({self._items!r})"

    def get(self, name: str, default: str | None = None) -> str | None:
        lowered = name.lower()
        for key, value in self._items:
            if key.lower() == lowered:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        lowered = name.lower()
        return [v for k, v in self._items if k.lower() == lowered]

    def set(self, name: str, value: str) -> None:
        """Replace every occurrence of *name* with a single header."""
        lowered = name.lower()
        out: list[list[str]] = []
        placed = False
        for key, existing in self._items:
            if key.lower() == lowered:
                if not placed:
                    out.append([name, value])
                    placed = True
                continue
            out.append([key, existing])
        if not placed:
            out.append([name, value])
        self._items = out

    def add(self, name: str, value: str) -> None:
        self._items.append([name, value])

    def remove(self, name: str) -> None:
        lowered = name.lower()
        self._items = [item for item in self._items if item[0].lower() != lowered]

    def items(self) -> list[tuple[str, str]]:
        return [(k, v) for k, v in self._items]

    def copy(self) -> Headers:
        return Headers(self.items())

    def to_dict(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for key, value in self._items:
            out.setdefault(key, []).append(value)
        return out

    def raw_bytes(self) -> bytes:
        return b"".join(
            k.encode("latin-1", "replace") + b": " + v.encode("latin-1", "replace") + b"\r\n"
            for k, v in self._items
        )


@dataclass(slots=True)
class Request:
    """A single HTTP request, either observed by the proxy or built by a tool."""

    method: str
    url: str
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    http_version: str = "HTTP/1.1"
    id: str = field(default_factory=new_id)
    origin: str = "proxy"
    created_at: float = field(default_factory=time.time)
    raw: bytes = b""
    tls: bool = True
    client: str = ""
    tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.headers, Headers):
            self.headers = Headers(self.headers)
        if isinstance(self.body, str):
            self.body = self.body.encode("utf-8")

    @property
    def parts(self) -> tuple[str, str, int, str, str]:
        """(scheme, host, port, path, query) for :attr:`url`."""
        scheme = "https" if self.tls else "http"
        host = ""
        port = 443 if scheme == "https" else 80
        path = "/"
        query = ""
        try:
            split = urlsplit(self.url)
            scheme = split.scheme or scheme
            host = split.hostname or ""
            port = split.port or (443 if scheme == "https" else 80)
            path = split.path or "/"
            query = split.query
        except ValueError:
            # A malformed URL must not take the proxy down; fall back to the
            # request line so the tool can still show and re-send it.
            path = self.url or "/"
        return scheme, host, port, path, query

    @property
    def host(self) -> str:
        return self.parts[1]

    @property
    def path(self) -> str:
        return self.parts[3]

    @property
    def query(self) -> str:
        return self.parts[4]

    @property
    def origin_form(self) -> str:
        """Request target in origin-form, as sent to the origin server."""
        path, query = self.path, self.query
        return f"{path}?{query}" if query else path

    @property
    def content_length(self) -> int:
        return len(self.body)

    @property
    def mime_type(self) -> str:
        ctype = self.headers.get("content-type", "") or ""
        return ctype.split(";")[0].strip().lower()

    def summary(self) -> dict[str, Any]:
        _, host, port, _, _ = self.parts
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "host": host,
            "port": port,
            "path": self.path,
            "http_version": self.http_version,
            "origin": self.origin,
            "created_at": self.created_at,
            "body_length": self.content_length,
            "mime_type": self.mime_type,
        }

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        data = self.summary()
        data["headers"] = self.headers.to_dict()
        body, encoding = decode_body(self.body)
        data["body"] = body
        data["body_encoding"] = encoding
        data["tls"] = self.tls
        data["client"] = self.client
        data["tags"] = list(self.tags)
        data["notes"] = list(self.notes)
        if include_raw:
            data["raw"] = self.raw.decode("utf-8", "replace")
        return data

    def clone(self) -> Request:
        return Request(
            method=self.method,
            url=self.url,
            headers=self.headers.copy(),
            body=self.body,
            http_version=self.http_version,
            id=self.id,
            origin=self.origin,
            created_at=self.created_at,
            raw=self.raw,
            tls=self.tls,
            client=self.client,
            tags=list(self.tags),
            notes=list(self.notes),
        )


@dataclass(slots=True)
class Response:
    """A single HTTP response."""

    status: int
    reason: str = ""
    headers: Headers = field(default_factory=Headers)
    body: bytes = b""
    http_version: str = "HTTP/1.1"
    id: str = field(default_factory=new_id)
    raw: bytes = b""
    elapsed_ms: float = 0.0
    tls: bool = True
    error: str = ""
    #: The remarks the analyst attached to this response.
    tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.headers, Headers):
            self.headers = Headers(self.headers)
        if isinstance(self.body, str):
            self.body = self.body.encode("utf-8")

    @property
    def mime_type(self) -> str:
        ctype = self.headers.get("content-type", "") or ""
        return ctype.split(";")[0].strip().lower()

    @property
    def content_length(self) -> int:
        return len(self.body)

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "reason": self.reason,
            "http_version": self.http_version,
            "mime_type": self.mime_type,
            "body_length": self.content_length,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        data = self.summary()
        data["headers"] = self.headers.to_dict()
        body, encoding = decode_body(self.body)
        data["body"] = body
        data["body_encoding"] = encoding
        data["tls"] = self.tls
        data["tags"] = list(self.tags)
        data["notes"] = list(self.notes)
        if include_raw:
            data["raw"] = self.raw.decode("utf-8", "replace")
        return data


@dataclass(slots=True)
class Exchange:
    """A request paired with its response - the unit stored in the history."""

    request: Request
    response: Response | None = None
    id: str = field(default_factory=new_id)
    created_at: float = field(default_factory=time.time)
    elapsed_ms: float = 0.0
    tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    highlighted: bool = False

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "elapsed_ms": self.elapsed_ms,
            "request": self.request.to_dict(include_raw=include_raw),
            "response": self.response.to_dict(include_raw=include_raw) if self.response else None,
            "tags": list(self.tags),
            "notes": list(self.notes),
            "highlighted": self.highlighted,
        }

    def summary(self) -> dict[str, Any]:
        base = self.request.summary()
        base["id"] = self.id
        base["created_at"] = self.created_at
        base["elapsed_ms"] = self.elapsed_ms
        base["status"] = self.response.status if self.response else 0
        base["response_mime_type"] = self.response.mime_type if self.response else ""
        base["response_length"] = self.response.content_length if self.response else 0
        base["error"] = self.response.error if self.response else ""
        base["tags"] = list(self.tags)
        base["highlighted"] = self.highlighted
        return base


def absolute_url(scheme: str, host: str, port: int, target: str) -> str:
    """Build an absolute URL from its parts."""
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    split = urlsplit(target)
    return urlunsplit((scheme, netloc, split.path or "/", split.query, ""))

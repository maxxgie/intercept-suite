"""Conversion between wire messages and the core model.

The proxy and the tools (repeater, spider) share these helpers so a request
produced by the repeater travels over the wire exactly like one the browser
sent.
"""

from __future__ import annotations

from intercept.core.models import Headers, Request, Response
from intercept.proxy.http1 import WireMessage, serialize_request

__all__ = [
    "wire_to_request",
    "wire_to_response",
    "request_to_wire",
    "upstream_headers",
    "prepare_upstream",
    "chunk_body",
    "netloc",
    "strip_proxy_headers",
]


def netloc(host: str, port: int, scheme: str) -> str:
    literal = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return literal if port == default else f"{literal}:{port}"


def strip_proxy_headers(headers: Headers) -> Headers:
    """Remove hop-by-hop proxy headers before forwarding upstream.

    HTTP/2 pseudo-headers are dropped as well: they only exist inside an
    HTTP/2 frame and must not be repeated on an HTTP/1.x connection.
    """
    cleaned = headers.copy()
    cleaned.remove("Proxy-Connection")
    cleaned.remove("Proxy-Authorization")
    pseudo = [name for name, _ in cleaned if name.startswith(":")]
    for name in pseudo:
        cleaned.remove(name)
    return cleaned


def wire_to_request(
    wire: WireMessage,
    scheme: str,
    host: str,
    port: int,
    client: str = "",
    origin: str = "proxy",
) -> Request:
    parts = wire.start_line.split(" ")
    method = parts[0].upper() if parts else "GET"
    target = parts[1] if len(parts) > 1 else "/"
    if target.lower().startswith(("http://", "https://")):
        url = target
    else:
        url = f"{scheme}://{netloc(host, port, scheme)}{target}"
    return Request(
        method=method,
        url=url,
        headers=wire.headers.copy(),
        body=wire.body,
        http_version=wire.version,
        raw=wire.raw,
        tls=scheme == "https",
        client=client,
        origin=origin,
    )


def wire_to_response(wire: WireMessage, elapsed: float = 0.0, tls: bool = True) -> Response:
    parts = wire.start_line.split(" ", 2)
    status = 0
    reason = ""
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0
        reason = parts[2] if len(parts) > 2 else ""
    return Response(
        status=status,
        reason=reason,
        headers=wire.headers.copy(),
        body=wire.body,
        http_version=wire.version,
        raw=wire.raw,
        elapsed_ms=elapsed,
        tls=tls,
    )


def request_to_wire(request: Request) -> WireMessage:
    """Rebuild a wire message from a (possibly edited) request."""
    scheme, host, port, _path, _query = request.parts
    headers, body = prepare_upstream(request, host, port, scheme)
    raw = serialize_request(
        request.method, request.origin_form, headers, body, request.http_version
    )
    return WireMessage(
        start_line=f"{request.method} {request.origin_form} {request.http_version}",
        version=request.http_version,
        headers=headers,
        body=request.body,
        raw=raw,
        raw_body=body,
    )


def upstream_headers(request: Request, host: str, port: int, scheme: str) -> Headers:
    """Prepare the headers sent to the origin server."""
    headers = strip_proxy_headers(request.headers)
    if "host" not in {key.lower() for key, _ in headers}:
        headers.set("Host", netloc(host, port, scheme))
    connection = (headers.get("connection") or "").lower()
    # A protocol upgrade has to keep the Connection header it came with,
    # because the origin only completes the handshake when it sees it.
    if (
        "close" not in connection
        and "upgrade" not in connection
        and request.http_version == "HTTP/1.1"
    ):
        headers.set("Connection", "keep-alive")
    return headers


def _is_chunked(headers: Headers) -> bool:
    return "chunked" in (headers.get("transfer-encoding") or "").lower()


def chunk_body(body: bytes, chunk_size: int = 8192) -> bytes:
    """Frame *body* with chunked transfer encoding."""
    if not body:
        return b"0\r\n\r\n"
    out = bytearray()
    for start in range(0, len(body), chunk_size):
        piece = body[start : start + chunk_size]
        out.extend(f"{len(piece):x}\r\n".encode("ascii"))
        out.extend(piece)
        out.extend(b"\r\n")
    out.extend(b"0\r\n\r\n")
    return bytes(out)


def prepare_upstream(
    request: Request, host: str, port: int, scheme: str
) -> tuple[Headers, bytes]:
    """Return the headers and the wire body to send to the origin.

    ``Content-Length`` is re-derived from the body so that a request edited in
    the repeater is sent with a length that matches what it now contains, and
    a chunked request is re-framed rather than silently de-chunked.
    """
    headers = upstream_headers(request, host, port, scheme)
    body = request.body
    if _is_chunked(headers):
        headers.remove("Content-Length")
        return headers, chunk_body(body)
    names = {key.lower() for key, _ in headers}
    if body or "content-length" in names:
        headers.set("Content-Length", str(len(body)))
    return headers, body

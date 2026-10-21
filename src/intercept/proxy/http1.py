"""A defensive HTTP/1.x message parser and serialiser.

The proxy needs byte level fidelity: what the user sees in the editor is what
went over the wire, including the original chunk framing. The parser therefore
keeps the raw header block and the raw body bytes alongside the decoded
values. It is also written to survive malformed input, because malformed input
is exactly what a security tool is pointed at.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from intercept.core.models import Headers
from intercept.proxy.stream import BufferedStream

__all__ = [
    "HTTPParseError",
    "WireMessage",
    "read_message",
    "read_head_block",
    "parse_head_block",
    "parse_headers",
    "serialize_request",
    "serialize_response",
]


class HTTPParseError(Exception):
    """Raised when a message cannot be framed."""


@dataclass(slots=True)
class WireMessage:
    """A framed HTTP message plus the metadata the proxy needs."""

    start_line: str
    version: str
    headers: Headers
    body: bytes
    raw: bytes
    raw_body: bytes = b""
    keep_alive: bool = True
    chunked: bool = False
    upgrade: bool = False
    body_until_eof: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def content_length(self) -> int:
        return len(self.body)


def _decode(raw: bytes) -> str:
    return raw.decode("latin-1", "replace")


async def read_head_block(
    reader: BufferedStream, max_size: int = 256 * 1024
) -> bytes | None:
    """Read up to and including the blank line that ends the header block.

    Any bytes read past the header block are pushed back onto the stream.
    """
    buf = bytearray()
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            if buf:
                raise HTTPParseError("connection closed inside header block")
            return None
        buf.extend(chunk)
        index = buf.find(b"\r\n\r\n")
        if index != -1:
            head = bytes(buf[: index + 4])
            reader.feed(bytes(buf[index + 4 :]))
            return head
        index = buf.find(b"\n\n")
        if index != -1:
            head = bytes(buf[: index + 2])
            reader.feed(bytes(buf[index + 2 :]))
            return head
        if len(buf) > max_size:
            raise HTTPParseError("header block too large")


def parse_headers(lines: list[str]) -> Headers:
    """Parse header lines, folding obsolete line continuations."""
    headers = Headers()
    last_name: str | None = None
    for line in lines:
        if not line:
            continue
        if line[0] in " \t":
            if last_name is not None:
                previous = headers.get(last_name) or ""
                headers.set(last_name, f"{previous} {line.strip()}")
            continue
        name, sep, value = line.partition(":")
        if not sep:
            continue
        headers.add(name.strip(), value.strip())
        last_name = name.strip()
    return headers


def parse_head_block(block: bytes) -> tuple[str, str, Headers]:
    """Split a head block into start line, version and headers."""
    text = _decode(block)
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise HTTPParseError("empty start line")
    start_line = lines[0].strip()
    parts = start_line.split(" ")
    version = parts[-1] if parts[-1].upper().startswith("HTTP/") else "HTTP/1.1"
    headers = parse_headers(lines[1:])
    return start_line, version, headers


def _transfer_encoding_is_chunked(headers: Headers) -> bool:
    values = headers.get_all("transfer-encoding")
    if not values:
        return False
    return values[-1].strip().lower().endswith("chunked")


def _content_length(headers: Headers) -> int | None:
    values = headers.get_all("content-length")
    if not values:
        return None
    try:
        return int(values[-1].strip())
    except ValueError:
        return None


def _expects_continue(headers: Headers) -> bool:
    return "100-continue" in (headers.get("expect") or "").lower()


async def _read_chunked(
    reader: BufferedStream, max_size: int, warnings: list[str]
) -> tuple[bytes, bytes]:
    """Read a chunked body, returning the decoded body and the original bytes."""
    body = bytearray()
    raw = bytearray()
    while True:
        line = await reader.readline()
        if not line:
            raise HTTPParseError("truncated chunked body")
        raw.extend(line)
        size_text = line.split(b";")[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise HTTPParseError(f"invalid chunk size: {size_text!r}") from exc
        if size == 0:
            while True:
                trailer = await reader.readline()
                raw.extend(trailer)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            break
        chunk = await reader.readexactly(size)
        body.extend(chunk)
        raw.extend(chunk)
        if len(body) > max_size:
            raise HTTPParseError("body exceeds configured maximum")
        terminator = await reader.readexactly(2)
        raw.extend(terminator)
        if terminator != b"\r\n":
            warnings.append("chunk not terminated by CRLF")
    return bytes(body), bytes(raw)


async def read_message(
    reader: BufferedStream,
    *,
    is_response: bool,
    max_header_size: int = 256 * 1024,
    max_body_size: int = 32 * 1024 * 1024,
    read_to_eof: bool = False,
    on_continue: Callable[[], Awaitable[None]] | None = None,
) -> WireMessage | None:
    """Read one HTTP message from *reader*.

    Returns ``None`` on a clean end of stream. When the request carries
    ``Expect: 100-continue`` and a body is expected, *on_continue* is awaited
    before the body is read, so clients that wait for the interim response do
    not deadlock.
    """
    block = await read_head_block(reader, max_header_size)
    if block is None:
        return None
    start_line, version, headers = parse_head_block(block)
    warnings: list[str] = []

    chunked = _transfer_encoding_is_chunked(headers)
    content_length = _content_length(headers)
    if chunked and content_length is not None:
        warnings.append("both Transfer-Encoding and Content-Length present")
    if len(headers.get_all("content-length")) > 1:
        warnings.append("duplicate Content-Length headers")
        values = {v.strip() for v in headers.get_all("content-length")}
        if len(values) > 1:
            warnings.append("conflicting Content-Length values")

    connection = (headers.get("connection") or "").lower()
    upgrade = "upgrade" in connection and "upgrade" in (headers.get("upgrade") or "").lower()
    keep_alive = "close" not in connection
    if version == "HTTP/1.0":
        keep_alive = "keep-alive" in connection

    body = b""
    raw_body = b""
    body_until_eof = False

    if is_response:
        status = _status_of(start_line)
        if status in (204, 304) or 100 <= status < 200:
            pass
        elif chunked:
            body, raw_body = await _read_chunked(reader, max_body_size, warnings)
        elif content_length is not None:
            if content_length > max_body_size:
                raise HTTPParseError("body exceeds configured maximum")
            raw_body = await reader.readexactly(content_length)
            body = raw_body
        elif read_to_eof:
            body_until_eof = True
            raw_body = await reader.read(-1)
            body = raw_body
        else:
            body_until_eof = True
            keep_alive = False
    else:
        method = start_line.split(" ")[0].upper() if start_line else ""
        if method == "CONNECT":
            pass
        elif chunked:
            if on_continue is not None and _expects_continue(headers):
                await on_continue()
            body, raw_body = await _read_chunked(reader, max_body_size, warnings)
        elif content_length is not None:
            if content_length > max_body_size:
                raise HTTPParseError("body exceeds configured maximum")
            if on_continue is not None and _expects_continue(headers):
                await on_continue()
            raw_body = await reader.readexactly(content_length)
            body = raw_body
        elif read_to_eof:
            body_until_eof = True
            raw_body = await reader.read(-1)
            body = raw_body

    return WireMessage(
        start_line=start_line,
        version=version,
        headers=headers,
        body=body,
        raw=block + raw_body,
        raw_body=raw_body,
        keep_alive=keep_alive,
        chunked=chunked,
        upgrade=upgrade,
        body_until_eof=body_until_eof,
        warnings=warnings,
    )


def _status_of(start_line: str) -> int:
    parts = start_line.split(" ", 2)
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0


def serialize_request(
    method: str,
    target: str,
    headers: Headers,
    body: bytes = b"",
    version: str = "HTTP/1.1",
) -> bytes:
    """Build the bytes for a request."""
    start_line = f"{method.upper()} {target} {version}"
    head = start_line.encode("latin-1", "replace") + b"\r\n"
    head += headers.raw_bytes()
    head += b"\r\n"
    return head + body


def serialize_response(
    status: int,
    reason: str,
    headers: Headers,
    body: bytes = b"",
    version: str = "HTTP/1.1",
) -> bytes:
    """Build the bytes for a response."""
    reason = reason or ""
    start_line = f"{version} {status} {reason}".rstrip()
    head = start_line.encode("latin-1", "replace") + b"\r\n"
    head += headers.raw_bytes()
    head += b"\r\n"
    return head + body

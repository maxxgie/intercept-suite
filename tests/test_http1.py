"""Tests for the HTTP/1.x parser."""

from __future__ import annotations

import asyncio

import pytest

from intercept.core.models import Headers
from intercept.proxy.http1 import (
    HTTPParseError,
    parse_headers,
    read_message,
    serialize_request,
)
from intercept.proxy.stream import BufferedStream


class _FakeReader(asyncio.StreamReader):
    pass


def _stream(data: bytes) -> BufferedStream:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return BufferedStream(reader)


async def test_parses_simple_request():
    raw = b"GET /a?b=c HTTP/1.1\r\nHost: example.com\r\nX-A: 1\r\n\r\n"
    message = await read_message(_stream(raw), is_response=False)
    assert message is not None
    assert message.start_line == "GET /a?b=c HTTP/1.1"
    assert message.version == "HTTP/1.1"
    assert message.headers.get("host") == "example.com"
    assert message.headers.get("X-A") == "1"
    assert message.body == b""
    assert message.keep_alive is True


async def test_parses_body_by_content_length():
    raw = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello"
    message = await read_message(_stream(raw), is_response=False)
    assert message is not None
    assert message.body == b"hello"
    assert message.raw == raw


async def test_parses_chunked_body_and_keeps_raw_framing():
    raw = (
        b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n3\r\nyou\r\n0\r\n\r\n"
    )
    message = await read_message(_stream(raw), is_response=False)
    assert message is not None
    assert message.body == b"helloyou"
    assert message.chunked is True
    # the raw bytes keep the original chunk framing
    assert b"5\r\nhello\r\n" in message.raw
    assert message.raw == raw


async def test_leftover_bytes_are_pushed_back():
    raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\nEXTRA"
    stream = _stream(raw)
    message = await read_message(stream, is_response=False)
    assert message is not None
    assert await stream.read(5) == b"EXTRA"


async def test_folded_header_is_joined():
    headers = parse_headers(["X-Long: part1", "  part2", "Other: v"])
    assert headers.get("X-Long") == "part1 part2"
    assert headers.get("Other") == "v"


async def test_conflicting_content_length_is_flagged():
    raw = (
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n"
        b"Content-Length: 5\r\n\r\nabcde"
    )
    message = await read_message(_stream(raw), is_response=False)
    assert message is not None
    assert any("Content-Length" in warning for warning in message.warnings)


async def test_truncated_body_raises():
    raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc"
    with pytest.raises((HTTPParseError, asyncio.IncompleteReadError)):
        await read_message(_stream(raw), is_response=False)


async def test_response_parsing():
    raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc"
    message = await read_message(_stream(raw), is_response=True)
    assert message is not None
    assert message.start_line == "HTTP/1.1 404 Not Found"
    assert message.body == b"abc"


def test_serialize_request_roundtrip():
    headers = Headers([("Host", "example.com"), ("Accept", "*/*")])
    raw = serialize_request("GET", "/x", headers)
    assert raw.startswith(b"GET /x HTTP/1.1\r\n")
    assert raw.endswith(b"\r\n\r\n")
    assert b"Host: example.com\r\n" in raw

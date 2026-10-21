"""A stream reader with pushback support.

The proxy needs to hand leftover bytes to the next protocol layer. ``CONNECT``
is the interesting case: the header block must be consumed without swallowing
the first bytes of the TLS handshake that follows it.
"""

from __future__ import annotations

import asyncio

__all__ = ["BufferedStream"]


class BufferedStream:
    """Wraps an :class:`asyncio.StreamReader` and allows pushing bytes back."""

    __slots__ = ("_reader", "_buffer")

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader
        self._buffer = bytearray()

    def feed(self, data: bytes) -> None:
        """Push *data* back to the front of the read buffer."""
        if data:
            self._buffer[:0] = data

    @property
    def reader(self) -> asyncio.StreamReader:
        return self._reader

    async def read(self, n: int = -1) -> bytes:
        if self._buffer:
            if n is None or n < 0:
                out = bytes(self._buffer)
                self._buffer.clear()
                return out
            out = bytes(self._buffer[:n])
            del self._buffer[: len(out)]
            return out
        return await self._reader.read(n)

    async def readexactly(self, n: int) -> bytes:
        if len(self._buffer) >= n:
            out = bytes(self._buffer[:n])
            del self._buffer[:n]
            return out
        chunks = [bytes(self._buffer)]
        self._buffer.clear()
        remaining = n - len(chunks[0])
        if remaining:
            chunks.append(await self._reader.readexactly(remaining))
        return b"".join(chunks)

    async def readline(self) -> bytes:
        while True:
            index = self._buffer.find(b"\n")
            if index != -1:
                out = bytes(self._buffer[: index + 1])
                del self._buffer[: index + 1]
                return out
            chunk = await self._reader.read(4096)
            if not chunk:
                out = bytes(self._buffer)
                self._buffer.clear()
                return out
            self._buffer.extend(chunk)

    async def readuntil(self, separator: bytes = b"\n") -> bytes:
        while True:
            index = self._buffer.find(separator)
            if index != -1:
                out = bytes(self._buffer[: index + len(separator)])
                del self._buffer[: index + len(separator)]
                return out
            chunk = await self._reader.read(4096)
            if not chunk:
                out = bytes(self._buffer)
                self._buffer.clear()
                return out
            self._buffer.extend(chunk)

    async def at_eof(self) -> bool:
        return not self._buffer and self._reader.at_eof()

    def __getattr__(self, name: str):  # pragma: no cover - passthrough
        return getattr(self._reader, name)

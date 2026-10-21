"""Upstream (origin server) connections.

A small connection pool keyed by ``scheme://host:port``. Connections are reused
when the origin allows keep-alive and are transparently re-established after a
stale connection is detected.

Two transports live side by side in the pool: HTTP/1.x connections for the
classic request/response path, and multiplexed HTTP/2 connections used when the
origin advertises ``h2`` through ALPN.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
from dataclasses import dataclass, field

from intercept.core.config import UpstreamProxyConfig
from intercept.core.models import Headers, absolute_url
from intercept.core.protocols import ALPN_PROTOCOLS
from intercept.proxy.h2 import H2ClientConnection, H2Response
from intercept.proxy.http1 import (
    WireMessage,
    parse_head_block,
    read_head_block,
    read_message,
    serialize_request,
)
from intercept.proxy.socks import SocksError, open_socks5
from intercept.proxy.stream import BufferedStream

log = logging.getLogger("intercept.proxy")

__all__ = ["UpstreamPool", "UpstreamError"]


class UpstreamError(Exception):
    """Raised when the origin server could not be reached."""


async def open_origin(
    host: str,
    port: int,
    scheme: str,
    ssl_context: ssl.SSLContext | None,
    upstream: UpstreamProxyConfig | None,
    timeout: float,
    max_header_size: int = 256 * 1024,
) -> tuple[BufferedStream, asyncio.StreamWriter]:
    """Open a connection to the origin, optionally through an upstream proxy.

    The upstream proxy is either a normal forward proxy or a SOCKS5 proxy. An
    encrypted origin is reached by opening a tunnel through the proxy first
    and then running the TLS handshake on top of it, so the origin still sees
    an ordinary client.
    """
    if upstream is None:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=host if ssl_context else None,
            ),
            timeout=timeout,
        )
        return BufferedStream(reader), writer

    if upstream.scheme == "socks5":
        reader, writer = await open_socks5(
            upstream.host,
            upstream.port,
            host,
            port,
            upstream.username,
            upstream.password,
            timeout,
        )
    else:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(upstream.host, upstream.port), timeout=timeout
        )

    stream = BufferedStream(reader)
    if scheme == "https" and ssl_context is not None:
        if upstream.scheme != "socks5":
            # A SOCKS tunnel already reaches the destination; a forward proxy
            # needs the tunnel opened first.
            await _connect_tunnel(stream, writer, host, port, max_header_size, timeout)
        await writer.start_tls(ssl_context, server_hostname=host)
    return stream, writer


async def _connect_tunnel(
    stream: BufferedStream,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    max_header_size: int,
    timeout: float,
) -> None:
    """Open a CONNECT tunnel through a forward proxy."""
    authority = f"{host}:{port}"
    writer.write(
        f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("latin-1")
    )
    await writer.drain()
    block = await asyncio.wait_for(
        read_head_block(stream, max_header_size), timeout=timeout
    )
    if block is None:
        raise UpstreamError("the upstream proxy closed the connection")
    start_line, _, _ = parse_head_block(block)
    parts = start_line.split(" ")
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        status = 0
    if status != 200:
        raise UpstreamError(f"the upstream proxy refused the tunnel: {start_line}")


@dataclass
class UpstreamPool:
    """Keeps a single reusable connection per origin."""

    verify: bool = True
    ca_file: str = ""
    timeout: float = 30.0
    max_header_size: int = 256 * 1024
    max_body_size: int = 32 * 1024 * 1024
    #: Try HTTP/2 with the origin when it advertises support.
    http2: bool = True
    #: The proxy the origin traffic is chained through, if any.
    upstream_proxy: UpstreamProxyConfig | None = None
    _connections: dict[tuple[str, str, int], _Connection] = field(default_factory=dict)
    _h2_connections: dict[tuple[str, str, int], _H2Connection] = field(default_factory=dict)
    _h2_unsupported: set[tuple[str, str, int]] = field(default_factory=set)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _ssl_context(self, alpn: list[str] | None = None) -> ssl.SSLContext | None:
        if self.ca_file:
            context = ssl.create_default_context(cafile=self.ca_file)
        elif not self.verify:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            return None
        if alpn:
            context.set_alpn_protocols(list(alpn))
        return context

    def _chain(self) -> UpstreamProxyConfig | None:
        """The upstream proxy to chain through, if one is configured."""
        proxy = self.upstream_proxy
        if proxy is not None and proxy.enabled and proxy.host and proxy.port:
            return proxy
        return None

    def _wire_target(self, scheme: str, host: str, port: int, target: str) -> str:
        """The request target as it goes on the wire.

        A forward proxy upstream expects the absolute form, a direct
        connection expects the origin form.
        """
        chain = self._chain()
        if chain is not None and chain.scheme != "socks5":
            return absolute_url(scheme, host, port, target)
        return target

    async def send(
        self,
        scheme: str,
        host: str,
        port: int,
        method: str,
        target: str,
        headers: Headers,
        body: bytes,
        http_version: str = "HTTP/1.1",
    ) -> tuple[WireMessage, float]:
        """Send a request to the origin and return the response and elapsed ms."""
        key = (scheme, host, port)
        connection = await self._acquire(key, scheme, host, port)

        started = time.perf_counter()
        try:
            message = await connection.request(
                method=method,
                target=self._wire_target(scheme, host, port, target),
                headers=headers,
                body=body,
                http_version=http_version,
            )
        except (TimeoutError, UpstreamError, OSError, ssl.SSLError) as exc:
            await connection.close()
            self._connections.pop(key, None)
            raise UpstreamError(str(exc)) from exc
        elapsed = (time.perf_counter() - started) * 1000

        if not message.keep_alive:
            await connection.close()
            self._connections.pop(key, None)
        return message, elapsed

    async def _acquire(
        self, key: tuple[str, str, int], scheme: str, host: str, port: int
    ) -> _Connection:
        """Return a usable connection for *key*, opening one when needed."""
        async with self._lock:
            connection = self._connections.get(key)
            if connection is not None and not connection.usable():
                await connection.close()
                connection = None
                self._connections.pop(key, None)
            if connection is None:
                connection = _Connection(
                    scheme=scheme,
                    host=host,
                    port=port,
                    ssl_context=(
                        self._ssl_context(["http/1.1"]) if scheme == "https" else None
                    ),
                    timeout=self.timeout,
                    max_header_size=self.max_header_size,
                    max_body_size=self.max_body_size,
                    upstream=self._chain(),
                )
                await connection.connect()
                self._connections[key] = connection
            return connection

    async def open_raw(
        self, scheme: str, host: str, port: int
    ) -> tuple[BufferedStream, asyncio.StreamWriter]:
        """Open a dedicated connection for protocol upgrades (WebSocket, h2c)."""
        context = self._ssl_context(["http/1.1"]) if scheme == "https" else None
        try:
            stream, writer = await open_origin(
                host,
                port,
                scheme,
                context,
                self._chain(),
                self.timeout,
                self.max_header_size,
            )
        except (SocksError, UpstreamError) as exc:
            raise UpstreamError(str(exc)) from exc
        except (TimeoutError, OSError) as exc:
            raise UpstreamError(f"cannot connect to {host}:{port}: {exc}") from exc
        return stream, writer

    async def send_h2(
        self,
        scheme: str,
        host: str,
        port: int,
        method: str,
        target: str,
        headers: Headers,
        body: bytes,
    ) -> tuple[H2Response, float] | None:
        """Send a request over HTTP/2.

        Returns ``None`` when the origin does not offer ``h2`` over ALPN, which
        lets the caller fall back to the HTTP/1.x path. An :class:`UpstreamError`
        is raised when an established HTTP/2 connection failed, because
        replaying the request over HTTP/1.x could repeat a side effect.
        """
        if not self.http2 or scheme != "https":
            return None
        key = (scheme, host, port)
        if key in self._h2_unsupported:
            return None

        connection = self._h2_connections.get(key)
        if connection is not None and not connection.usable():
            await connection.close()
            self._h2_connections.pop(key, None)
            connection = None

        if connection is None:
            connection = _H2Connection(
                scheme=scheme,
                host=host,
                port=port,
                ssl_context=self._ssl_context(ALPN_PROTOCOLS),
                timeout=self.timeout,
                upstream=self._chain(),
            )
            try:
                negotiated = await connection.connect()
            except UpstreamError:
                # The origin could not be reached at all; let the HTTP/1.x
                # path produce the error message.
                self._h2_unsupported.add(key)
                return None
            if not negotiated:
                self._h2_unsupported.add(key)
                await connection.close()
                return None
            self._h2_connections[key] = connection

        authority = host if port == 443 else f"{host}:{port}"
        if ":" in host:
            authority = f"[{host}]:{port}" if port != 443 else f"[{host}]"

        started = time.perf_counter()
        try:
            response = await connection.request(
                method=method,
                authority=authority,
                target=target,
                headers=headers,
                body=body,
            )
        except (TimeoutError, UpstreamError, OSError) as exc:
            await connection.close()
            self._h2_connections.pop(key, None)
            raise UpstreamError(str(exc)) from exc
        return response, (time.perf_counter() - started) * 1000

    async def close(self) -> None:
        for connection in list(self._connections.values()):
            await connection.close()
        self._connections.clear()
        for connection in list(self._h2_connections.values()):
            await connection.close()
        self._h2_connections.clear()
        self._h2_unsupported.clear()


class _Connection:
    """A single TCP (optionally TLS) connection to an origin."""

    def __init__(
        self,
        scheme: str,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None,
        timeout: float,
        max_header_size: int,
        max_body_size: int,
        upstream: UpstreamProxyConfig | None = None,
    ) -> None:
        self.scheme = scheme
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.timeout = timeout
        self.max_header_size = max_header_size
        self.max_body_size = max_body_size
        self.upstream = upstream
        self._reader: BufferedStream | None = None
        self._writer: asyncio.StreamWriter | None = None
        # A pooled connection carries one request at a time. Tools may send
        # requests in parallel, so the exchange is serialised here.
        self._lock = asyncio.Lock()

    def usable(self) -> bool:
        if self._writer is None:
            return False
        return not self._writer.is_closing()

    async def connect(self) -> None:
        try:
            stream, writer = await open_origin(
                self.host,
                self.port,
                self.scheme,
                self.ssl_context,
                self.upstream,
                self.timeout,
                self.max_header_size,
            )
            self._reader = stream
            self._writer = writer
        except (SocksError, UpstreamError) as exc:
            raise UpstreamError(str(exc)) from exc
        except (TimeoutError, OSError) as exc:
            raise UpstreamError(f"cannot connect to {self.host}:{self.port}: {exc}") from exc

    async def close(self) -> None:
        if self._writer is not None:
            try:
                self._writer.close()
                await asyncio.wait_for(self._writer.wait_closed(), timeout=2)
            except (TimeoutError, OSError, ssl.SSLError):
                pass
        self._reader = None
        self._writer = None

    async def request(
        self,
        method: str,
        target: str,
        headers: Headers,
        body: bytes,
        http_version: str = "HTTP/1.1",
    ) -> WireMessage:
        if self._reader is None or self._writer is None:
            raise UpstreamError("connection is not open")
        payload = serialize_request(method, target, headers, body, http_version)
        async with self._lock:
            try:
                self._writer.write(payload)
                await asyncio.wait_for(self._writer.drain(), timeout=self.timeout)
                message = await asyncio.wait_for(
                    read_message(
                        self._reader,
                        is_response=True,
                        max_header_size=self.max_header_size,
                        max_body_size=self.max_body_size,
                        read_to_eof=True,
                    ),
                    timeout=self.timeout,
                )
            except (TimeoutError, OSError, asyncio.IncompleteReadError) as exc:
                raise UpstreamError(str(exc)) from exc
        if message is None:
            raise UpstreamError("origin closed the connection without a response")
        return message


class _H2Connection:
    """A multiplexed HTTP/2 connection to a single origin."""

    def __init__(
        self,
        scheme: str,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None,
        timeout: float,
        upstream: UpstreamProxyConfig | None = None,
    ) -> None:
        self.scheme = scheme
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.timeout = timeout
        self.upstream = upstream
        self._conn = H2ClientConnection()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._task: asyncio.Task | None = None

    def usable(self) -> bool:
        if self._writer is None:
            return False
        return not self._writer.is_closing()

    async def connect(self) -> bool:
        """Open the connection. Returns ``False`` if the origin refused ``h2``."""
        try:
            stream, writer = await open_origin(
                self.host,
                self.port,
                self.scheme,
                self.ssl_context,
                self.upstream,
                self.timeout,
            )
        except (SocksError, UpstreamError) as exc:
            raise UpstreamError(str(exc)) from exc
        except (TimeoutError, OSError) as exc:
            raise UpstreamError(f"cannot connect to {self.host}:{self.port}: {exc}") from exc

        ssl_object = writer.get_extra_info("ssl_object")
        negotiated = ssl_object.selected_alpn_protocol() if ssl_object is not None else None
        if negotiated != "h2":
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            return False

        self._reader = stream.reader
        self._writer = writer
        self._writer.write(self._conn.data_to_send())
        await self._writer.drain()
        self._task = asyncio.create_task(self._read_loop())
        return True

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None
        self._fail_pending(UpstreamError("connection closed"))
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
                await asyncio.wait_for(self._writer.wait_closed(), timeout=2)
        self._reader = None
        self._writer = None

    def _fail_pending(self, error: Exception) -> None:
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(error)
        self._pending.clear()

    async def _read_loop(self) -> None:
        reader = self._reader
        writer = self._writer
        if reader is None or writer is None:
            return
        error: Exception = UpstreamError("origin closed the connection")
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                self._conn.receive(data)
                outbound = self._conn.data_to_send()
                if outbound:
                    writer.write(outbound)
                    await writer.drain()
                for response in self._conn.take_completed():
                    future = self._pending.pop(response.stream_id, None)
                    if future is not None and not future.done():
                        future.set_result(response)
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError, ssl.SSLError) as exc:
            error = UpstreamError(str(exc))
        except Exception as exc:  # noqa: BLE001 - a background task must not die silently
            log.debug("HTTP/2 upstream connection failed: %s", exc)
            error = UpstreamError(f"HTTP/2 upstream error: {exc}")
        finally:
            self._fail_pending(error)

    async def request(
        self,
        method: str,
        authority: str,
        target: str,
        headers: Headers,
        body: bytes,
    ) -> H2Response:
        if self._writer is None:
            raise UpstreamError("connection is not open")
        stream_id = self._conn.request(
            method=method,
            scheme=self.scheme,
            authority=authority,
            path=target,
            headers=headers,
            body=body,
        )
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[stream_id] = future
        outbound = self._conn.data_to_send()
        if outbound:
            self._writer.write(outbound)
            await self._writer.drain()
        try:
            return await asyncio.wait_for(future, timeout=self.timeout)
        except TimeoutError as exc:
            self._pending.pop(stream_id, None)
            raise UpstreamError("timed out waiting for the origin") from exc

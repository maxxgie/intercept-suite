"""The proxy server.

A single asyncio server handles two entry paths:

* absolute-form requests (``GET http://host/path HTTP/1.1``) sent to the proxy
  as a plain forward proxy;
* ``CONNECT host:port`` tunnels, which are terminated locally with a
  certificate issued by our own CA so the traffic inside the tunnel is
  readable.

Both paths end up in the same place: a request is framed, optionally held for
the user, forwarded upstream and recorded.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from intercept.core.config import Config
from intercept.core.events import EventBus
from intercept.core.models import Exchange, Headers, Request, Response
from intercept.crypto.ca import CertificateAuthority
from intercept.proxy.convert import (
    netloc as _netloc,
)
from intercept.proxy.convert import (
    prepare_upstream,
    wire_to_request,
    wire_to_response,
)
from intercept.proxy.convert import (
    request_to_wire as _wire_from_request,
)
from intercept.proxy.h2 import (
    H2Request,
    H2ServerConnection,
    h2_request_to_model,
    h2_response_to_model,
)
from intercept.proxy.http1 import (
    HTTPParseError,
    WireMessage,
    read_message,
    serialize_request,
    serialize_response,
)
from intercept.proxy.intercept import InterceptController
from intercept.proxy.stream import BufferedStream
from intercept.proxy.upstream import UpstreamError, UpstreamPool
from intercept.proxy.websocket import FrameParser

log = logging.getLogger("intercept.proxy")

__all__ = ["ProxyServer", "ProxySession"]

ExchangeHandler = Callable[[Exchange], Awaitable[None]]


def _host_port(value: str, default_port: int) -> tuple[str, int]:
    """Split ``host:port`` handling bracketed IPv6 literals."""
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if ":" in value:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host, int(port)
        return value, default_port
    return value, default_port


def _target_parts(
    request: Request, scheme: str, host: str, port: int
) -> tuple[str, str, int]:
    """Resolve the upstream target from the request, falling back to the tunnel."""
    req_scheme, req_host, req_port = request.parts[0], request.parts[1], request.parts[2]
    if req_host:
        return req_scheme, req_host, req_port
    return scheme, host, port


@dataclass
class ProxyServer:
    """Owns the listening socket and the upstream connection pool."""

    config: Config
    ca: CertificateAuthority
    bus: EventBus
    intercept: InterceptController
    on_exchange: ExchangeHandler | None = None
    websockets: Any = None
    pool: UpstreamPool = field(init=False)
    _server: asyncio.Server | None = field(default=None, init=False)
    _connections: set[asyncio.Task] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        self.pool = UpstreamPool(
            verify=self.config.proxy.upstream_verify,
            ca_file=self.config.proxy.upstream_ca,
            timeout=self.config.proxy.upstream_timeout,
            max_header_size=self.config.proxy.max_header_size,
            max_body_size=self.config.proxy.max_body_size,
            http2=self.config.proxy.http2,
        )

    async def start(self) -> None:
        proxy = self.config.proxy
        self._server = await asyncio.start_server(
            self._on_client,
            proxy.host,
            proxy.port,
            reuse_address=True,
        )
        log.info("proxy listening on %s:%s", proxy.host, proxy.port)
        self.bus.emit(
            "proxy.started",
            host=proxy.host,
            port=proxy.port,
            ca_fingerprint=self.ca.fingerprint(),
        )

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        for task in list(self._connections):
            task.cancel()
        await self.pool.close()
        self.bus.emit("proxy.stopped")

    async def _on_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connections.add(task)
        session = ProxySession(self, reader, writer)
        try:
            await session.run()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("unhandled error in proxy session")
        finally:
            if task is not None:
                self._connections.discard(task)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()


class ProxySession:
    """State for one client connection."""

    def __init__(
        self, server: ProxyServer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.server = server
        self.config = server.config
        self.writer = writer
        self.stream = BufferedStream(reader)
        peer = writer.get_extra_info("peername")
        self.client = f"{peer[0]}:{peer[1]}" if peer else ""
        self.tls = False
        self.scheme = "http"
        self.host = ""
        self.port = 80

    # ------------------------------------------------------------------ util

    async def _write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def _send_continue(self) -> None:
        await self._write(b"HTTP/1.1 100 Continue\r\n\r\n")

    def _negotiated_protocol(self) -> str:
        """The ALPN protocol chosen during the TLS handshake."""
        ssl_object = self.writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return ""
        try:
            return ssl_object.selected_alpn_protocol() or ""
        except (ValueError, AttributeError):  # pragma: no cover - defensive
            return ""

    async def _read_request(self) -> WireMessage | None:
        return await read_message(
            self.stream,
            is_response=False,
            max_header_size=self.config.proxy.max_header_size,
            max_body_size=self.config.proxy.max_body_size,
            on_continue=self._send_continue,
        )

    # ------------------------------------------------------------------ run

    async def run(self) -> None:
        try:
            first = await self._read_request()
        except HTTPParseError as exc:
            log.debug("malformed request: %s", exc)
            await self._error(400, f"Malformed request: {exc}")
            return
        except (ConnectionError, asyncio.IncompleteReadError):
            return
        if first is None:
            return

        method = first.start_line.split(" ")[0].upper() if first.start_line else ""
        if method == "CONNECT":
            await self._handle_connect(first)
        else:
            await self._handle_forward(first)

    async def _handle_connect(self, wire: WireMessage) -> None:
        target = wire.start_line.split(" ")[1] if " " in wire.start_line else ""
        host, port = _host_port(target, 443)
        if not host:
            await self._error(400, "Malformed CONNECT target")
            return

        self.host = host
        self.port = port
        self.scheme = "https"
        self.tls = True

        await self._write(b"HTTP/1.1 200 Connection established\r\n\r\n")

        try:
            context = self.server.ca.ssl_context(host)
            await self.writer.start_tls(context)
        except (ssl.SSLError, OSError) as exc:
            log.debug("tls handshake failed for %s: %s", host, exc)
            return

        if self._negotiated_protocol() == "h2":
            await self._handle_h2(host, port, "https")
            return

        while True:
            try:
                wire = await self._read_request()
            except HTTPParseError as exc:
                log.debug("malformed tunnelled request: %s", exc)
                await self._error(400, f"Malformed request: {exc}")
                return
            except (ConnectionError, asyncio.IncompleteReadError):
                return
            if wire is None:
                return
            keep_going = await self._process(wire, "https", host, port)
            if not keep_going:
                return

    async def _handle_forward(self, wire: WireMessage) -> None:
        """Handle a plain (non CONNECT) forward-proxy request."""
        target = wire.start_line.split(" ")[1] if " " in wire.start_line else ""
        if not target.lower().startswith(("http://", "https://")):
            await self._error(400, "Forward proxy requests must use an absolute URI")
            return
        split = urlsplit(target)
        scheme = split.scheme.lower()
        host = split.hostname or ""
        port = split.port or (443 if scheme == "https" else 80)
        if not host:
            await self._error(400, "Malformed absolute URI")
            return
        self.host = host
        self.port = port
        self.scheme = scheme
        self.tls = False

        while True:
            keep_going = await self._process(wire, scheme, host, port)
            if not keep_going:
                return
            try:
                wire = await self._read_request()
            except HTTPParseError as exc:
                log.debug("malformed request: %s", exc)
                await self._error(400, f"Malformed request: {exc}")
                return
            except (ConnectionError, asyncio.IncompleteReadError):
                return
            if wire is None:
                return

    # ------------------------------------------------------------------ h2

    async def _handle_h2(self, host: str, port: int, scheme: str) -> None:
        """Serve an HTTP/2 connection terminated by us.

        Every stream is forwarded independently, so a slow origin only blocks
        its own stream.
        """
        conn = H2ServerConnection()
        await self._write(conn.data_to_send())
        tasks: set[asyncio.Task] = set()
        try:
            while True:
                data = await self.stream.read(65536)
                if not data:
                    break
                conn.receive(data)
                outbound = conn.data_to_send()
                if outbound:
                    await self._write(outbound)
                for h2_request in conn.take_completed():
                    task = asyncio.create_task(
                        self._handle_h2_request(conn, h2_request, host, port, scheme)
                    )
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            return
        finally:
            for task in list(tasks):
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _handle_h2_request(
        self,
        conn: H2ServerConnection,
        h2_request: H2Request,
        host: str,
        port: int,
        scheme: str,
    ) -> None:
        stream_id = h2_request.stream_id
        request = h2_request_to_model(h2_request, client=self.client)
        self.server.bus.emit("request", request=request.summary())

        if self.server.intercept.enabled:
            decision = await self.server.intercept.hold(request)
            if decision.action == "drop":
                self.server.bus.emit("intercept.dropped", id=request.id)
                conn.reset_stream(stream_id)
                return
            if decision.request is not None:
                request = decision.request

        scheme, host, port = _target_parts(request, scheme, host, port)
        upstream_headers, upstream_body = prepare_upstream(request, host, port, scheme)
        if not any(name.lower() == "connection" for name, _ in upstream_headers):
            upstream_headers.set("Connection", "keep-alive")

        h2_result = None
        try:
            h2_result = await self.server.pool.send_h2(
                scheme=scheme,
                host=host,
                port=port,
                method=request.method,
                target=request.origin_form,
                headers=upstream_headers,
                body=upstream_body,
            )
        except UpstreamError as exc:
            # The HTTP/2 connection broke after the request went out, so the
            # request is not replayed over HTTP/1.x.
            log.debug("HTTP/2 upstream failed for %s: %s", request.url, exc)
            response = _error_response(502, f"Upstream error: {exc}")
            conn.send_response(stream_id, response.status, response.headers, response.body)
            await self._flush(conn)
            await self._record(Exchange(request=request, response=response, elapsed_ms=0.0))
            return

        if h2_result is not None:
            h2_response, elapsed = h2_result
            response = h2_response_to_model(h2_response, elapsed)
            conn.send_response(stream_id, response.status, response.headers, response.body)
            await self._flush(conn)
            await self._record(Exchange(request=request, response=response, elapsed_ms=elapsed))
            return

        try:
            upstream_message, elapsed = await self.server.pool.send(
                scheme=scheme,
                host=host,
                port=port,
                method=request.method,
                target=request.origin_form,
                headers=upstream_headers,
                body=upstream_body,
                http_version="HTTP/1.1",
            )
        except UpstreamError as exc:
            response = _error_response(502, f"Upstream error: {exc}")
            conn.send_response(stream_id, response.status, response.headers, response.body)
            await self._flush(conn)
            await self._record(Exchange(request=request, response=response, elapsed_ms=0.0))
            return

        response = self._to_response(upstream_message, elapsed)
        conn.send_response(stream_id, response.status, response.headers, response.body)
        await self._flush(conn)
        await self._record(Exchange(request=request, response=response, elapsed_ms=elapsed))

    async def _flush(self, conn: H2ServerConnection) -> None:
        outbound = conn.data_to_send()
        if outbound:
            await self._write(outbound)

    # -------------------------------------------------------------- process

    async def _process(self, wire: WireMessage, scheme: str, host: str, port: int) -> bool:
        """Forward one request. Returns ``True`` to keep the connection alive."""
        if wire.upgrade:
            await self._handle_upgrade(wire, scheme, host, port)
            return False

        request = self._to_request(wire, scheme, host, port)
        self.server.bus.emit("request", request=request.summary())

        if self.server.intercept.enabled:
            decision = await self.server.intercept.hold(request)
            if decision.action == "drop":
                self.server.bus.emit("intercept.dropped", id=request.id)
                return False
            if decision.request is not None:
                request = decision.request
                wire = _wire_from_request(request)

        upstream_headers, upstream_body = prepare_upstream(request, host, port, scheme)
        try:
            upstream_message, elapsed = await self.server.pool.send(
                scheme=scheme,
                host=host,
                port=port,
                method=request.method,
                target=request.origin_form,
                headers=upstream_headers,
                body=upstream_body,
                http_version=request.http_version,
            )
        except UpstreamError as exc:
            response = _error_response(502, f"Upstream error: {exc}")
            await self._write(response.raw)
            exchange = Exchange(request=request, response=response, elapsed_ms=0.0)
            await self._record(exchange)
            return True

        response = self._to_response(upstream_message, elapsed)
        await self._write(upstream_message.raw)
        await self._record(Exchange(request=request, response=response, elapsed_ms=elapsed))
        return upstream_message.keep_alive and not upstream_message.body_until_eof

    def _to_request(
        self, wire: WireMessage, scheme: str, host: str, port: int
    ) -> Request:
        return wire_to_request(wire, scheme, host, port, client=self.client, origin="proxy")

    def _to_response(self, wire: WireMessage, elapsed: float) -> Response:
        return wire_to_response(wire, elapsed, tls=self.tls)

    async def _record(self, exchange: Exchange) -> None:
        self.server.bus.emit("response", exchange=exchange.summary())
        if self.server.on_exchange is not None:
            try:
                await self.server.on_exchange(exchange)
            except Exception:
                log.exception("failed to record exchange")

    async def _error(self, status: int, message: str) -> None:
        body = message.encode()
        headers = Headers(
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(body))),
                ("Connection", "close"),
            ]
        )
        await self._write(serialize_response(status, "", headers, body))

    # -------------------------------------------------------------- upgrade

    async def _handle_upgrade(
        self, wire: WireMessage, scheme: str, host: str, port: int
    ) -> None:
        """Tunnel a protocol upgrade (WebSocket and friends) to the origin."""
        try:
            up_reader, up_writer = await self.server.pool.open_raw(scheme, host, port)
        except UpstreamError as exc:
            await self._error(502, f"Upstream error: {exc}")
            return

        target = wire.start_line.split(" ")[1] if " " in wire.start_line else "/"
        url = f"{scheme}://{_netloc(host, port, scheme)}{target}"
        request = Request(
            method=(wire.start_line.split(" ")[0] if wire.start_line else "GET").upper(),
            url=url,
            headers=wire.headers.copy(),
            body=wire.body,
            http_version=wire.version,
            raw=wire.raw,
            tls=scheme == "https",
            client=self.client,
            origin="proxy",
        )
        head = serialize_request(
            request.method, request.origin_form, *prepare_upstream(request, host, port, scheme)
        )
        up_writer.write(head)
        with contextlib.suppress(Exception):
            await up_writer.drain()

        connection = self._open_websocket(request, wire)
        try:
            await asyncio.gather(
                self._pump(self.stream.reader, up_writer, "client", connection),
                self._pump(up_reader, self.writer, "server", connection),
                return_exceptions=True,
            )
        finally:
            if connection is not None:
                self._close_websocket(connection)
            with contextlib.suppress(Exception):
                up_writer.close()
                await up_writer.wait_closed()

    def _open_websocket(self, request: Request, wire: WireMessage) -> Any:
        """Start recording the frames of a tunnelled WebSocket."""
        store = getattr(self.server, "websockets", None)
        if store is None:
            return None
        headers = {name: value for name, value in wire.headers.items()}
        connection = store.open_connection(
            request.url,
            host=request.parts[2],
            method=request.method,
            headers=headers,
        )
        self.server.bus.emit(
            "websocket.opened", connection=connection.to_dict()
        )
        return connection

    def _close_websocket(self, connection: Any) -> None:
        store = getattr(self.server, "websockets", None)
        if store is None or connection is None:
            return
        store.close_connection(connection.id)
        self.server.bus.emit("websocket.closed", connection=connection.to_dict())

    def _record_frames(self, connection: Any, direction: str, frames: list[Any]) -> None:
        store = getattr(self.server, "websockets", None)
        if store is None or connection is None:
            return
        for frame in frames:
            store.record_message(
                connection.id,
                direction,
                frame.name,
                frame.text,
                len(frame.payload),
            )
        self.server.bus.emit(
            "websocket.message",
            connection_id=connection.id,
            direction=direction,
            count=len(frames),
        )

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str = "",
        connection: Any = None,
    ) -> None:
        parser = FrameParser(direction) if connection is not None else None
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                if parser is not None:
                    self._record_frames(connection, direction, parser.feed(data))
        except (ConnectionError, OSError, ssl.SSLError):
            return
        finally:
            with contextlib.suppress(Exception):
                if writer.can_write_eof():
                    writer.write_eof()



def _error_response(status: int, message: str) -> Response:
    body = message.encode()
    headers = Headers(
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Connection", "close"),
        ]
    )
    from intercept.proxy.http1 import serialize_response

    return Response(
        status=status,
        reason="",
        headers=headers,
        body=body,
        raw=serialize_response(status, "", headers, body),
        error=message,
    )

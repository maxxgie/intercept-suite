"""The proxy server.

A single asyncio server handles several entry paths:

* absolute-form requests (``GET http://host/path HTTP/1.1``) sent to the proxy
  as a plain forward proxy;
* ``CONNECT host:port`` tunnels, which are terminated locally with a
  certificate issued by our own CA so the traffic inside the tunnel is
  readable;
* transparently redirected connections, where the destination is recovered
  from the socket rather than named by the client;
* SOCKS5 connections, where the destination is named in the handshake.

All paths end up in the same place: a request is framed, the rules are
applied, it is optionally held for the user, forwarded upstream, the rules
are applied to the response, it is optionally held as well, and the exchange
is recorded.
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
    prepare_upstream,
    wire_to_request,
    wire_to_response,
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
    parse_head_block,
    read_head_block,
    read_message,
    serialize_request,
    serialize_response,
)
from intercept.proxy.intercept import InterceptController
from intercept.proxy.listeners import is_tls_handshake, original_destination
from intercept.proxy.rules import RuleEngine
from intercept.proxy.socks import SocksError, accept, negotiate
from intercept.proxy.stream import BufferedStream
from intercept.proxy.upstream import UpstreamError, UpstreamPool
from intercept.proxy.websocket import FrameParser, WebSocketFrame

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


def listener_key(listener: Any) -> tuple[str, str, int]:
    """What tells two listeners apart."""
    return (listener.mode, listener.host, listener.port)


@dataclass
class ProxyServer:
    """Owns the listening socket and the upstream connection pool."""

    config: Config
    ca: CertificateAuthority
    bus: EventBus
    intercept: InterceptController
    on_exchange: ExchangeHandler | None = None
    websockets: Any = None
    rules: RuleEngine = field(default_factory=RuleEngine)
    pool: UpstreamPool = field(init=False)
    _server: asyncio.Server | None = field(default=None, init=False)
    _listeners: list[asyncio.Server] = field(default_factory=list, init=False)
    _extra_listeners: dict[tuple[str, str, int], asyncio.Server] = field(
        default_factory=dict, init=False
    )
    _connections: set[asyncio.Task] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        self.pool = UpstreamPool(
            verify=self.config.proxy.upstream_verify,
            ca_file=self.config.proxy.upstream_ca,
            timeout=self.config.proxy.upstream_timeout,
            max_header_size=self.config.proxy.max_header_size,
            max_body_size=self.config.proxy.max_body_size,
            http2=self.config.proxy.http2,
            upstream_proxy=self.config.proxy.upstream_proxy,
        )

    async def start(self) -> None:
        proxy = self.config.proxy
        self._server = await asyncio.start_server(
            self._on_client,
            proxy.host,
            proxy.port,
            reuse_address=True,
        )
        self._listeners.append(self._server)
        log.info("proxy listening on %s:%s", proxy.host, proxy.port)

        for listener in proxy.listeners:
            await self._open_listener(listener)

        self.bus.emit(
            "proxy.started",
            host=proxy.host,
            port=proxy.port,
            ca_fingerprint=self.ca.fingerprint(),
        )

    async def _open_listener(self, listener: Any) -> bool:
        """Open one extra listener. Returns ``True`` when it is open."""
        proxy = self.config.proxy
        if not listener.enabled or not listener.port:
            return False
        try:
            server = await asyncio.start_server(
                self._listener_callback(listener.mode),
                listener.host or proxy.host,
                listener.port,
                reuse_address=True,
            )
        except OSError as exc:
            log.warning(
                "could not open the %s listener on %s:%s: %s",
                listener.mode,
                listener.host,
                listener.port,
                exc,
            )
            return False
        self._listeners.append(server)
        self._extra_listeners[listener_key(listener)] = server
        log.info(
            "%s listener open on %s:%s", listener.mode, listener.host, listener.port
        )
        return True

    async def sync_listeners(self) -> None:
        """Open and close the extra listeners to match the configuration.

        The listeners are read from the configuration when the proxy starts, so
        a listener that is added or removed while the daemon runs would
        otherwise be ignored until the next start.
        """
        wanted = {
            listener_key(listener): listener
            for listener in self.config.proxy.listeners
            if listener.enabled and listener.port
        }
        for key, server in list(self._extra_listeners.items()):
            if key in wanted:
                continue
            self._extra_listeners.pop(key, None)
            with contextlib.suppress(Exception):
                server.close()
                await server.wait_closed()
            if server in self._listeners:
                self._listeners.remove(server)
            log.info("listener closed")
        for key, listener in wanted.items():
            if key in self._extra_listeners:
                continue
            await self._open_listener(listener)

    def _listener_callback(self, mode: str):
        async def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await self._on_client(reader, writer, mode)

        return callback

    async def stop(self) -> None:
        # The listeners are closed first so nothing new is accepted, then the
        # connections that are still open are cancelled. Waiting for a server
        # to close waits for its handlers too, so they have to be gone first.
        for server in self._listeners:
            server.close()
        tasks = list(self._connections)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._connections.clear()
        for server in self._listeners:
            with contextlib.suppress(Exception):
                await server.wait_closed()
        self._listeners.clear()
        self._extra_listeners.clear()
        self._server = None
        await self.pool.close()
        self.bus.emit("proxy.stopped")

    async def _on_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        mode: str = "explicit",
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connections.add(task)
        session = ProxySession(self, reader, writer, mode)
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
        self,
        server: ProxyServer,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        mode: str = "explicit",
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
        self.mode = mode
        #: The address the connection is actually made to, when it differs
        #: from the host the request names. A transparent listener uses it.
        self.connect_host = ""

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

    async def _peek(self) -> bytes:
        """Read the first byte and put it back."""
        first = await self.stream.read(1)
        if first:
            self.stream.feed(first)
        return first

    # ------------------------------------------------------------------ run

    async def run(self) -> None:
        if self.mode == "socks":
            await self._run_socks()
            return
        if self.mode == "transparent":
            await self._run_transparent()
            return

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

    # ---------------------------------------------------------------- socks

    async def _run_socks(self) -> None:
        """Serve a client that speaks SOCKS5."""
        socks = self.config.proxy.socks
        try:
            host, port = await negotiate(
                self.stream.reader, self.writer, socks.username, socks.password
            )
        except (SocksError, ConnectionError, asyncio.IncompleteReadError) as exc:
            log.debug("the socks handshake failed: %s", exc)
            return
        if not host:
            return

        self.host = host
        self.port = port
        self.scheme = "http"
        try:
            await accept(self.stream.reader, self.writer, host, port)
        except (ConnectionError, OSError):
            return

        first = await self._peek()
        if not first:
            return
        if is_tls_handshake(first):
            await self._terminate_tls(host)
            return
        await self._serve_tunnel("http", host, port)

    # ---------------------------------------------------------- transparent

    async def _run_transparent(self) -> None:
        """Serve a connection that the network redirected here."""
        destination = original_destination(self.writer.get_extra_info("socket"))
        if destination is None:
            await self._error(
                400,
                "This listener needs the traffic to be redirected to it by the "
                "network; the original destination could not be recovered.",
            )
            return
        address, port = destination
        self.host = address
        self.port = port
        self.scheme = "http"
        # The connection is made to the address the traffic was heading for,
        # whatever host name the request names.
        self.connect_host = address

        first = await self._peek()
        if not first:
            return
        if is_tls_handshake(first):
            await self._terminate_tls(address)
            return
        await self._serve_tunnel("http", address, port)

    async def _terminate_tls(self, host: str) -> None:
        """Terminate TLS for a tunnelled connection and serve HTTP inside it."""
        names: list[str] = []
        context = self.server.ca.sni_context(names.append)
        try:
            await self.writer.start_tls(context)
        except (ssl.SSLError, OSError) as exc:
            log.debug("the tls handshake failed for %s: %s", host, exc)
            return
        self.tls = True
        self.scheme = "https"
        name = names[0] if names else host
        if name:
            self.host = name
        if self._negotiated_protocol() == "h2":
            await self._handle_h2(name or host, self.port, "https")
            return
        await self._serve_tunnel("https", name or host, self.port)

    # -------------------------------------------------------------- connect

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

        await self._serve_tunnel("https", host, port)

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

    async def _serve_tunnel(self, scheme: str, host: str, port: int) -> None:
        """Serve HTTP requests inside a tunnel whose destination is known."""
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
            keep_going = await self._process(wire, scheme, host, port)
            if not keep_going:
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
        request = self.server.rules.apply_request(request)

        if self.server.intercept.enabled and self.server.rules.intercept_request(request):
            decision = await self.server.intercept.hold(request)
            if decision.action == "drop":
                self.server.bus.emit("intercept.dropped", id=request.id)
                conn.reset_stream(stream_id)
                return
            if decision.request is not None:
                request = decision.request
                request = self.server.rules.apply_request(request)

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
            before = (response.headers.raw_bytes(), response.body)
            response = self.server.rules.apply_response(request, response)
            if _changed(response, before):
                response = _reserialize(response, request.method)
            if self.server.intercept.enabled and self.server.rules.intercept_response(request):
                decision = await self.server.intercept.hold_response(request, response)
                if decision.action == "drop":
                    response = _error_response(502, "The response was dropped by the user")
                elif decision.response is not None:
                    response = _reserialize(decision.response, request.method)
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
        before = (response.headers.raw_bytes(), response.body)
        response = self.server.rules.apply_response(request, response)
        if _changed(response, before):
            response = _reserialize(response, request.method)
        if self.server.intercept.enabled and self.server.rules.intercept_response(request):
            decision = await self.server.intercept.hold_response(request, response)
            if decision.action == "drop":
                response = _error_response(502, "The response was dropped by the user")
            elif decision.response is not None:
                response = _reserialize(decision.response, request.method)
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
        request = self._to_request(wire, scheme, host, port)
        self.server.bus.emit("request", request=request.summary())
        request = self.server.rules.apply_request(request)

        if self.server.intercept.enabled and self.server.rules.intercept_request(request):
            decision = await self.server.intercept.hold(request)
            if decision.action == "drop":
                self.server.bus.emit("intercept.dropped", id=request.id)
                return False
            if decision.request is not None:
                request = decision.request
                request = self.server.rules.apply_request(request)

        if wire.upgrade:
            await self._handle_upgrade(wire, request, scheme, host, port)
            return False

        upstream_scheme, upstream_host, upstream_port = _target_parts(request, scheme, host, port)
        connect_host = self.connect_host or upstream_host
        upstream_headers, upstream_body = prepare_upstream(
            request, upstream_host, upstream_port, upstream_scheme
        )
        try:
            upstream_message, elapsed = await self.server.pool.send(
                scheme=upstream_scheme,
                host=connect_host,
                port=upstream_port,
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
        before = (response.headers.raw_bytes(), response.body)
        response = self.server.rules.apply_response(request, response)
        if _changed(response, before):
            response = _reserialize(response, request.method)

        if self.server.intercept.enabled and self.server.rules.intercept_response(request):
            decision = await self.server.intercept.hold_response(request, response)
            if decision.action == "drop":
                response = _error_response(502, "The response was dropped by the user")
            elif decision.response is not None:
                response = _reserialize(decision.response, request.method)

        await self._write(response.raw)
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
        self,
        wire: WireMessage,
        request: Request,
        scheme: str,
        host: str,
        port: int,
    ) -> None:
        """Tunnel a protocol upgrade (WebSocket and friends) to the origin."""
        try:
            up_stream, up_writer = await self.server.pool.open_raw(scheme, host, port)
        except UpstreamError as exc:
            await self._error(502, f"Upstream error: {exc}")
            return

        head = serialize_request(
            request.method, request.origin_form, *prepare_upstream(request, host, port, scheme)
        )
        up_writer.write(head)
        with contextlib.suppress(Exception):
            await up_writer.drain()

        # The handshake response is forwarded as it is. It is not a frame, so
        # it has to be read before the frame pumps start.
        try:
            block = await read_head_block(
                up_stream, self.config.proxy.max_header_size
            )
        except (HTTPParseError, ConnectionError, OSError):
            block = None
        if not block:
            return
        await self._write(block)

        start_line, _, _ = parse_head_block(block)
        parts = start_line.split(" ")
        try:
            status = int(parts[1])
        except (IndexError, ValueError):
            status = 0
        if status != 101:
            # The origin refused the upgrade, so the rest of its answer is
            # ordinary HTTP rather than frames.
            await self._copy(up_stream, self.writer)
            return

        connection = self._open_websocket(request, wire)
        try:
            await asyncio.gather(
                # The client is read through the buffered stream, because the
                # upgrade request may have been read ahead of time.
                self._pump(self.stream, up_writer, "client", connection),
                self._pump(up_stream, self.writer, "server", connection),
                return_exceptions=True,
            )
        finally:
            if connection is not None:
                self._close_websocket(connection)
            with contextlib.suppress(Exception):
                up_writer.close()
                await up_writer.wait_closed()

    async def _copy(
        self, reader: asyncio.StreamReader | BufferedStream, writer: asyncio.StreamWriter
    ) -> None:
        """Copy the rest of a stream to *writer*."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            return

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

    def _holds_frames(self, direction: str) -> bool:
        """Should the frames travelling in *direction* be held?"""
        return (
            self.server.intercept.enabled
            and self.config.proxy.intercept_websockets
            and direction in self.config.proxy.intercept_websocket_directions
        )

    async def _handle_frame(
        self, frame: WebSocketFrame, writer: asyncio.StreamWriter, connection: Any
    ) -> None:
        """Hold a WebSocket frame, then send it on - or a version of it."""
        decision = None
        if self._holds_frames(frame.direction):
            decision = await self.server.intercept.hold_frame(frame)
        if decision is not None and decision.action == "drop":
            return
        effective = frame
        if decision is not None and decision.frame is not None:
            effective = decision.frame
        self._record_frames(connection, frame.direction, [effective])
        # A frame from the client has to be masked, one from the server must not.
        writer.write(effective.serialize(mask=frame.direction == "client"))
        await writer.drain()

    async def _pump(
        self,
        reader: asyncio.StreamReader | BufferedStream,
        writer: asyncio.StreamWriter,
        direction: str = "",
        connection: Any = None,
    ) -> None:
        parser = FrameParser(direction) if connection is not None else None
        hold = self._holds_frames(direction)
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                if parser is not None and hold:
                    # The frames are handled one by one, so the bytes are not
                    # forwarded as they arrive.
                    for frame in parser.feed(data):
                        await self._handle_frame(frame, writer, connection)
                    continue
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


def _reserialize(response: Response, method: str = "GET") -> Response:
    """Rebuild the raw bytes of a response that was changed.

    The body may have a different length now, so the length header is
    re-derived. A ``HEAD`` response keeps the length the body would have had,
    and the chunked framing is dropped because the body is no longer framed.
    """
    headers = response.headers
    headers.remove("Transfer-Encoding")
    if method.upper() != "HEAD":
        headers.set("Content-Length", str(len(response.body)))
    response.headers = headers
    response.raw = serialize_response(
        response.status, response.reason, response.headers, response.body
    )
    return response


def _changed(response: Response, before: tuple[bytes, bytes]) -> bool:
    """Was the response changed since *before* was taken?"""
    return (response.headers.raw_bytes(), response.body) != before


def _error_response(status: int, message: str) -> Response:
    body = message.encode()
    headers = Headers(
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Connection", "close"),
        ]
    )
    return Response(
        status=status,
        reason="",
        headers=headers,
        body=body,
        raw=serialize_response(status, "", headers, body),
        error=message,
    )

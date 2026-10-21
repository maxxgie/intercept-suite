"""Shared HTTP client for the tools.

The repeater, the spider and any future scanner all send their traffic through
the same upstream pool the proxy uses, so their requests are framed, recorded
and displayed exactly like browser traffic.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from intercept.core.config import Config
from intercept.core.events import EventBus
from intercept.core.models import Exchange, Headers, Request, Response
from intercept.proxy.convert import prepare_upstream, wire_to_response
from intercept.proxy.h2 import h2_response_to_model
from intercept.proxy.upstream import UpstreamError, UpstreamPool

log = logging.getLogger("intercept.tools")

__all__ = ["ToolClient"]

ExchangeHandler = Callable[[Exchange], Awaitable[None]]


class ToolClient:
    """Sends requests on behalf of the tools and records the result."""

    def __init__(
        self,
        config: Config,
        pool: UpstreamPool,
        bus: EventBus,
        on_exchange: ExchangeHandler | None = None,
    ) -> None:
        self.config = config
        self.pool = pool
        self.bus = bus
        self.on_exchange = on_exchange

    async def send(self, request: Request, http2: bool = False) -> Response:
        """Send *request* to its origin and return the response.

        With *http2* the request is sent over HTTP/2, which the origin has to
        offer through ALPN. An origin that does not is answered over HTTP/1.1
        instead, so the switch never breaks a request.
        """
        scheme, host, port, _path, _query = request.parts
        if not host:
            response = Response(status=0, reason="", error="request has no host")
            return response

        headers, body = prepare_upstream(request, host, port, scheme)
        try:
            if http2:
                response = await self._send_h2(
                    scheme, host, port, request, headers, body
                )
            else:
                message, elapsed = await self.pool.send(
                    scheme=scheme,
                    host=host,
                    port=port,
                    method=request.method,
                    target=request.origin_form,
                    headers=headers,
                    body=body,
                    http_version=request.http_version,
                )
                response = wire_to_response(message, elapsed, tls=scheme == "https")
        except UpstreamError as exc:
            response = Response(status=0, reason="", error=str(exc))
            exchange = Exchange(request=request, response=response)
            await self._record(exchange)
            return response

        await self._record(
            Exchange(request=request, response=response, elapsed_ms=response.elapsed_ms)
        )
        return response

    async def _send_h2(
        self,
        scheme: str,
        host: str,
        port: int,
        request: Request,
        headers: Headers,
        body: bytes,
    ) -> Response:
        """Send a request over HTTP/2, falling back to HTTP/1.x when needed."""
        result = await self.pool.send_h2(
            scheme=scheme,
            host=host,
            port=port,
            method=request.method,
            target=request.origin_form,
            headers=headers,
            body=body,
        )
        if result is None:
            # The origin does not offer h2, so the request goes over HTTP/1.1.
            message, elapsed = await self.pool.send(
                scheme=scheme,
                host=host,
                port=port,
                method=request.method,
                target=request.origin_form,
                headers=headers,
                body=body,
                http_version=request.http_version,
            )
            return wire_to_response(message, elapsed, tls=scheme == "https")
        h2_response, elapsed = result
        return h2_response_to_model(h2_response, elapsed)

    async def _record(self, exchange: Exchange) -> None:
        self.bus.emit("response", exchange=exchange.summary())
        if self.on_exchange is not None:
            try:
                await self.on_exchange(exchange)
            except Exception:
                log.exception("failed to record tool exchange")

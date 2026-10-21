"""Protocol level constants shared by the proxy, the CA and the tools."""

from __future__ import annotations

__all__ = ["ALPN_PROTOCOLS", "HTTP_1_1", "HTTP_2"]

#: Protocols offered during the TLS handshake, most preferred first.
ALPN_PROTOCOLS = ["h2", "http/1.1"]

HTTP_1_1 = "HTTP/1.1"
HTTP_2 = "HTTP/2"

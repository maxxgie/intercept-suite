"""Listener modes.

The main listener is an ordinary forward proxy. Two other modes exist:

* ``transparent`` - the invisible proxy. The traffic is redirected to the
  listener by the network rather than by the client, so the request arrives in
  origin-form and the original destination has to be recovered from the socket.
* ``socks`` - a SOCKS5 listener. The client speaks SOCKS instead of HTTP, so
  the destination is named in the handshake.

Both modes end up serving HTTP in origin-form towards a destination that is
already known, which is what the tunnel path of the proxy does as well.
"""

from __future__ import annotations

import socket
import sys
from typing import Any

__all__ = ["original_destination", "is_tls_handshake", "TRANSPARENT_SUPPORTED"]

#: Linux ``SO_ORIGINAL_DST``. The name of the option is not exported by the
#: socket module, but the number is fixed by the kernel.
_SO_ORIGINAL_DST = 80

#: The same option for IPv6 sockets.
_IP6T_SO_ORIGINAL_DST = 80

#: The first byte of a TLS handshake record.
_TLS_HANDSHAKE = 0x16

#: Whether this machine can recover a transparently redirected destination.
TRANSPARENT_SUPPORTED = sys.platform.startswith("linux")


def is_tls_handshake(first: bytes) -> bool:
    """Does *first* start a TLS handshake?"""
    return bool(first) and first[0] == _TLS_HANDSHAKE


def _decode_original(raw: bytes, ipv6: bool) -> tuple[str, int] | None:
    if ipv6:
        if len(raw) < 24:
            return None
        port = int.from_bytes(raw[2:4], "little")
        host = socket.inet_ntop(socket.AF_INET6, raw[4:20])
        return host, port
    if len(raw) < 8:
        return None
    port = int.from_bytes(raw[2:4], "little")
    host = socket.inet_ntoa(raw[4:8])
    return host, port


def original_destination(sock: Any) -> tuple[str, int] | None:
    """Recover the destination a transparently redirected connection was for.

    Returns ``None`` when the platform cannot tell, or when the connection was
    not redirected at all.
    """
    if not TRANSPARENT_SUPPORTED or sock is None:
        return None
    try:
        family = sock.family
    except AttributeError:
        return None
    try:
        if family == socket.AF_INET6:
            raw = sock.getsockopt(socket.IPPROTO_IPV6, _IP6T_SO_ORIGINAL_DST, 28)
            return _decode_original(raw, ipv6=True)
        raw = sock.getsockopt(socket.SOL_IP, _SO_ORIGINAL_DST, 16)
        return _decode_original(raw, ipv6=False)
    except OSError:
        return None

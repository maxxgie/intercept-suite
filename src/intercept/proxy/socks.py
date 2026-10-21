"""SOCKS5.

Two sides live here. The server lets a client speak SOCKS5 to the proxy
instead of HTTP, so a tool that can only speak SOCKS can still be pointed at
Intercept. The client is used by the upstream pool to reach an origin through
a SOCKS5 proxy.

The wire format is RFC 1928. Only ``CONNECT`` is offered: it is the command
that carries HTTP traffic, which is all a proxy needs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
from typing import Any

__all__ = [
    "SocksError",
    "METHOD_NONE",
    "METHOD_USERPASS",
    "METHOD_UNACCEPTABLE",
    "CMD_CONNECT",
    "ATYP_IPV4",
    "ATYP_DOMAIN",
    "ATYP_IPV6",
    "negotiate",
    "open_socks5",
]

#: Authentication methods.
METHOD_NONE = 0x00
METHOD_USERPASS = 0x02
METHOD_UNACCEPTABLE = 0xFF

#: The only command Intercept offers.
CMD_CONNECT = 0x01

#: Address types.
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

#: Reply codes.
REPLY_SUCCEEDED = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONNECTION_REFUSED = 0x05
REPLY_COMMAND_NOT_SUPPORTED = 0x07
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class SocksError(Exception):
    """Raised when the SOCKS handshake cannot be completed."""


def _encode_address(host: str, port: int) -> bytes:
    """Encode a destination as the ATYP/ADDR/PORT triple."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # The name is sent as it is, the way it appears in the host name.
        try:
            encoded = host.encode("idna")
        except UnicodeError:
            encoded = host.encode("utf-8")
        if len(encoded) > 255:
            raise SocksError("the host name is too long") from None
        return bytes([ATYP_DOMAIN, len(encoded)]) + encoded + struct.pack("!H", port)
    if address.version == 4:
        return bytes([ATYP_IPV4]) + address.packed + struct.pack("!H", port)
    return bytes([ATYP_IPV6]) + address.packed + struct.pack("!H", port)


def _decode_address(data: bytes) -> tuple[str, int]:
    """Decode an ATYP/ADDR/PORT triple, returning the host and the port."""
    if not data:
        raise SocksError("the address is missing")
    atyp = data[0]
    if atyp == ATYP_IPV4:
        if len(data) < 7:
            raise SocksError("the IPv4 address is truncated")
        host = str(ipaddress.IPv4Address(data[1:5]))
        port = struct.unpack("!H", data[5:7])[0]
        return host, port
    if atyp == ATYP_IPV6:
        if len(data) < 19:
            raise SocksError("the IPv6 address is truncated")
        host = str(ipaddress.IPv6Address(data[1:17]))
        port = struct.unpack("!H", data[17:19])[0]
        return host, port
    if atyp == ATYP_DOMAIN:
        if len(data) < 2:
            raise SocksError("the host name is truncated")
        length = data[1]
        if len(data) < 2 + length + 2:
            raise SocksError("the host name is truncated")
        # The name is sent as plain bytes, not as an IDNA encoded label.
        host = data[2 : 2 + length].decode("utf-8", "replace")
        port = struct.unpack("!H", data[2 + length : 4 + length])[0]
        return host, port
    raise SocksError(f"unsupported address type {atyp:#x}")


def _reply(rep: int, host: str = "0.0.0.0", port: int = 0) -> bytes:
    """Build a SOCKS5 reply."""
    return bytes([0x05, rep, 0x00]) + _encode_address(host, port)


async def negotiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: str = "",
    password: str = "",
) -> tuple[str, int]:
    """Run the SOCKS5 handshake and return the destination the client asked for.

    Raises :class:`SocksError` when the handshake cannot be completed; the
    caller closes the connection in that case.
    """
    header = await reader.readexactly(2)
    if header[0] != 0x05:
        raise SocksError("only SOCKS5 is supported")
    methods = await reader.readexactly(header[1])
    if not methods:
        raise SocksError("no authentication method was offered")

    if username:
        if METHOD_USERPASS not in methods:
            writer.write(bytes([0x05, METHOD_UNACCEPTABLE]))
            await writer.drain()
            raise SocksError("the client does not offer username authentication")
        writer.write(bytes([0x05, METHOD_USERPASS]))
        await writer.drain()
        await _authenticate(reader, writer, username, password)
    else:
        if METHOD_NONE not in methods:
            writer.write(bytes([0x05, METHOD_UNACCEPTABLE]))
            await writer.drain()
            raise SocksError("the client does not offer anonymous access")
        writer.write(bytes([0x05, METHOD_NONE]))
        await writer.drain()

    request = await reader.readexactly(4)
    if request[0] != 0x05:
        raise SocksError("only SOCKS5 is supported")
    command, atyp = request[1], request[3]
    if command != CMD_CONNECT:
        writer.write(_reply(REPLY_COMMAND_NOT_SUPPORTED))
        await writer.drain()
        raise SocksError("only CONNECT is supported")

    if atyp == ATYP_IPV4:
        host, port = _decode_address(bytes([atyp]) + await reader.readexactly(6))
    elif atyp == ATYP_IPV6:
        host, port = _decode_address(bytes([atyp]) + await reader.readexactly(18))
    elif atyp == ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        host, port = _decode_address(
            bytes([atyp, length]) + await reader.readexactly(length + 2)
        )
    else:
        writer.write(_reply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED))
        await writer.drain()
        raise SocksError(f"unsupported address type {atyp:#x}")

    return host, port


async def _authenticate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    username: str,
    password: str,
) -> None:
    """Run the username and password sub-negotiation."""
    version = await reader.readexactly(1)
    if version[0] != 0x01:
        raise SocksError("unsupported authentication version")
    user_length = (await reader.readexactly(1))[0]
    user = await reader.readexactly(user_length)
    password_length = (await reader.readexactly(1))[0]
    secret = await reader.readexactly(password_length)
    if user.decode("utf-8", "replace") != username or secret.decode("utf-8", "replace") != password:
        writer.write(bytes([0x01, 0x01]))
        await writer.drain()
        raise SocksError("the credentials were rejected")
    writer.write(bytes([0x01, 0x00]))
    await writer.drain()


async def accept(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
) -> bool:
    """Tell the client the tunnel is open."""
    writer.write(_reply(REPLY_SUCCEEDED, host, port))
    await writer.drain()
    return True


async def refuse(
    writer: asyncio.StreamWriter,
    reason: str = "the destination could not be reached",
) -> None:
    """Tell the client the tunnel could not be opened."""
    writer.write(_reply(REPLY_CONNECTION_REFUSED))
    await writer.drain()


async def open_socks5(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    username: str = "",
    password: str = "",
    timeout: float = 30.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a tunnel to *dest_host* through a SOCKS5 proxy.

    This is the client half of the protocol, used when the origin traffic is
    chained through a SOCKS proxy.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy_host, proxy_port), timeout=timeout
        )
    except (TimeoutError, OSError) as exc:
        raise SocksError(f"cannot reach the SOCKS proxy {proxy_host}:{proxy_port}: {exc}") from exc

    try:
        if username:
            writer.write(bytes([0x05, 0x01, METHOD_USERPASS]))
        else:
            writer.write(bytes([0x05, 0x01, METHOD_NONE]))
        await writer.drain()

        version, method = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if version != 0x05:
            raise SocksError("the SOCKS proxy did not answer with SOCKS5")
        if method == METHOD_UNACCEPTABLE:
            raise SocksError("the SOCKS proxy rejected every authentication method")
        if method == METHOD_USERPASS:
            if not username:
                raise SocksError("the SOCKS proxy demands a username")
            user = username.encode("utf-8")[:255]
            secret = password.encode("utf-8")[:255]
            writer.write(bytes([0x01, len(user)]) + user + bytes([len(secret)]) + secret)
            await writer.drain()
            auth_version, status = await asyncio.wait_for(
                reader.readexactly(2), timeout=timeout
            )
            if auth_version != 0x01 or status != 0x00:
                raise SocksError("the SOCKS proxy rejected the credentials")
        elif method != METHOD_NONE:
            raise SocksError(f"the SOCKS proxy asked for an unsupported method {method:#x}")

        writer.write(bytes([0x05, CMD_CONNECT, 0x00]) + _encode_address(dest_host, dest_port))
        await writer.drain()

        head = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if head[0] != 0x05:
            raise SocksError("the SOCKS proxy did not answer with SOCKS5")
        reply = head[1]
        atyp = head[3]
        if atyp == ATYP_IPV4:
            await asyncio.wait_for(reader.readexactly(6), timeout=timeout)
        elif atyp == ATYP_IPV6:
            await asyncio.wait_for(reader.readexactly(18), timeout=timeout)
        elif atyp == ATYP_DOMAIN:
            length = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            await asyncio.wait_for(reader.readexactly(length + 2), timeout=timeout)
        else:
            raise SocksError(f"the SOCKS proxy sent an unsupported address type {atyp:#x}")
        if reply != REPLY_SUCCEEDED:
            raise SocksError(f"the SOCKS proxy refused the tunnel (code {reply})")
    except (TimeoutError, OSError, asyncio.IncompleteReadError) as exc:
        writer.close()
        raise SocksError(f"the SOCKS handshake failed: {exc}") from exc
    except Exception:
        writer.close()
        raise

    return reader, writer


def describe(data: Any) -> str:
    """A short description of a SOCKS destination, for the event log."""
    return str(data)

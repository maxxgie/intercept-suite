"""Runtime configuration.

Configuration is layered: built-in defaults, then a JSON file under the state
directory, then command line overrides. Every value is a plain dataclass so it
can be serialised straight to the API.
"""

from __future__ import annotations

import json
import os
from dataclasses import MISSING, asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, get_args, get_origin, get_type_hints

__all__ = ["Config", "ProxyConfig", "ApiConfig", "ScanConfig", "state_dir", "load_config"]


def state_dir() -> Path:
    """Root directory for the CA store, database and configuration."""
    override = os.environ.get("INTERCEPT_HOME")
    base = Path(override) if override else Path.home() / ".intercept"
    base.mkdir(parents=True, exist_ok=True)
    return base


@dataclass
class ListenerConfig:
    """An extra listener the proxy opens in addition to the main one.

    The mode decides how the listener reads the traffic it is given:

    * ``explicit`` - an ordinary forward proxy, as the main listener is.
    * ``transparent`` - an invisible proxy. The traffic is redirected here by
      the network, so the request arrives in origin-form and the original
      destination has to be recovered from the socket.
    * ``socks`` - a SOCKS5 proxy. The client speaks SOCKS instead of HTTP.
    """

    name: str = ""
    host: str = "127.0.0.1"
    port: int = 0
    mode: str = "explicit"
    enabled: bool = True


@dataclass
class UpstreamProxyConfig:
    """A proxy the origin traffic is chained through.

    The connection to the origin is opened through this proxy instead of
    directly. ``scheme`` selects the protocol: ``http`` for a normal forward
    proxy, ``socks5`` for a SOCKS5 proxy.
    """

    enabled: bool = False
    scheme: str = "http"
    host: str = "127.0.0.1"
    port: int = 8080
    username: str = ""
    password: str = ""


@dataclass
class SocksConfig:
    """Settings for the SOCKS5 listener."""

    #: Require these credentials. An empty username means no authentication.
    username: str = ""
    password: str = ""


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    #: Verify upstream certificates. Disabled for lab targets with self-signed certs.
    upstream_verify: bool = True
    #: Extra CA bundle used to verify upstream certificates.
    upstream_ca: str = ""
    #: Hold every request in the intercept queue instead of forwarding it.
    intercept_enabled: bool = False
    #: Seconds to wait for the user to answer an intercepted request.
    intercept_timeout: float = 60.0
    #: Maximum size of a request/response body buffered in memory (bytes).
    max_body_size: int = 32 * 1024 * 1024
    #: Maximum size of a single header block (bytes).
    max_header_size: int = 256 * 1024
    #: Seconds to wait for upstream response data.
    upstream_timeout: float = 30.0
    #: Follow 3xx redirects in generated tool traffic.
    follow_redirects: bool = True
    #: Extra headers added to every tool-generated request.
    user_agent: str = "Intercept/0.1"
    #: Hosts that bypass the proxy entirely (comma separated host:port).
    bypass: list[str] = field(default_factory=list)
    #: Offer HTTP/2 during the TLS handshake and use it with the origin.
    http2: bool = True
    #: Extra listeners opened next to the main one.
    listeners: list[ListenerConfig] = field(default_factory=list)
    #: The proxy the origin traffic is chained through.
    upstream_proxy: UpstreamProxyConfig = field(default_factory=UpstreamProxyConfig)
    #: Settings for the SOCKS5 listener.
    socks: SocksConfig = field(default_factory=SocksConfig)
    #: Hold WebSocket frames so they can be inspected and edited.
    intercept_websockets: bool = False
    #: Which directions of a WebSocket connection are held: "client" for the
    #: frames the client sends and "server" for the ones it receives.
    intercept_websocket_directions: list[str] = field(
        default_factory=lambda: ["client", "server"]
    )


@dataclass
class ApiConfig:
    host: str = "127.0.0.1"
    port: int = 9000
    cors_origins: list[str] = field(
        default_factory=lambda: ["http://localhost:*", "http://127.0.0.1:*"]
    )


@dataclass
class ScanConfig:
    #: How many concurrent requests a tool may issue.
    concurrency: int = 4
    #: Request timeout for tool generated traffic.
    timeout: float = 20.0
    #: Maximum pages a single spider run will fetch.
    max_pages: int = 500
    #: Maximum depth for the spider.
    max_depth: int = 5


@dataclass
class Config:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    api: ApiConfig = field(default_factory=ApiConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    #: Directory holding the CA, database and plugins.
    home: str = ""
    #: Log level name.
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if not self.home:
            self.home = str(state_dir())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def apply(self, data: dict[str, Any]) -> None:
        """Apply a configuration update in place.

        The nested sections are updated attribute by attribute, so they stay
        dataclasses and everything that holds a reference to one keeps seeing
        the new values. Replacing a section outright would turn it into a
        plain dictionary and break every reader of ``config.proxy.host``.
        """
        _apply_to(self, data)

    def save(self) -> Path:
        path = Path(self.home) / "config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        return _build(cls, data)


def _list_field_types(cls: type) -> dict[str, type]:
    """Map the names of the list fields to the type of their elements.

    The annotations are strings in this module, so they have to be resolved
    before the element type can be read.
    """
    out: dict[str, type] = {}
    try:
        hints = get_type_hints(cls)
    except Exception:  # noqa: BLE001 - an unresolvable hint is not fatal
        return out
    for name, hint in hints.items():
        if get_origin(hint) is not list:
            continue
        args = get_args(hint)
        if args and is_dataclass(args[0]):
            out[name] = args[0]
    return out


def _apply_to(target: Any, data: dict[str, Any]) -> None:
    """Apply *data* to the dataclass *target*, in place."""
    list_types = _list_field_types(type(target))
    known = {spec.name for spec in fields(target)}
    for key, value in (data or {}).items():
        if key not in known:
            continue
        current = getattr(target, key, None)
        if is_dataclass(current) and isinstance(value, dict):
            _apply_to(current, value)
            continue
        element = list_types.get(key)
        if element is not None and isinstance(value, list):
            setattr(
                target,
                key,
                [_build(element, item) for item in value if isinstance(item, dict)],
            )
            continue
        setattr(target, key, value)


def _build(cls: type, data: Any) -> Any:
    """Recursively build a dataclass from a dict, ignoring unknown keys."""
    if not is_dataclass(cls):
        return data
    kwargs: dict[str, Any] = {}
    known = {f.name: f for f in fields(cls)}
    list_types = _list_field_types(cls)
    for key, value in (data or {}).items():
        spec = known.get(key)
        if spec is None:
            continue
        default = (
            spec.default_factory()
            if spec.default_factory is not MISSING
            else spec.default
        )  # type: ignore[misc]
        if is_dataclass(default) and isinstance(value, dict):
            kwargs[key] = _build(type(default), value)
            continue
        element = list_types.get(key)
        if element is not None and isinstance(value, list):
            kwargs[key] = [
                _build(element, item) for item in value if isinstance(item, dict)
            ]
            continue
        kwargs[key] = value
    return cls(**kwargs)


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    """Load configuration from ``path`` (default ``<home>/config.json``)."""
    home = state_dir()
    target = Path(path) if path else home / "config.json"
    if not target.exists():
        return Config(home=str(home))
    try:
        data = json.loads(target.read_text())
    except (OSError, json.JSONDecodeError):
        return Config(home=str(home))
    config = Config.from_dict(data)
    config.home = str(home)
    return config

"""Runtime configuration.

Configuration is layered: built-in defaults, then a JSON file under the state
directory, then command line overrides. Every value is a plain dataclass so it
can be serialised straight to the API.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

__all__ = ["Config", "ProxyConfig", "ApiConfig", "ScanConfig", "state_dir", "load_config"]


def state_dir() -> Path:
    """Root directory for the CA store, database and configuration."""
    override = os.environ.get("INTERCEPT_HOME")
    base = Path(override) if override else Path.home() / ".intercept"
    base.mkdir(parents=True, exist_ok=True)
    return base


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

    def save(self) -> Path:
        path = Path(self.home) / "config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        return _build(cls, data)


def _build(cls: type, data: dict[str, Any]) -> Any:
    """Recursively build a dataclass from a dict, ignoring unknown keys."""
    if not is_dataclass(cls):
        return data
    kwargs: dict[str, Any] = {}
    known = {f.name: f for f in fields(cls)}
    for key, value in (data or {}).items():
        spec = known.get(key)
        if spec is None:
            continue
        default = spec.default_factory() if spec.default_factory is not None else spec.default  # type: ignore[misc]
        if is_dataclass(default) and isinstance(value, dict):
            kwargs[key] = _build(type(default), value)
        else:
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

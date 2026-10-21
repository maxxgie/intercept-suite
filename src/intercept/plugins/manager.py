"""Plugin discovery and execution.

Plugins are loaded from ``<home>/plugins/<name>/`` and from the built in
example directory. Loading is defensive: a plugin that raises is reported and
skipped instead of taking the daemon down with it.
"""

from __future__ import annotations

import asyncio
import importlib.util
import logging
import sys
import tomllib
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from intercept.plugins.api import ActiveCheck, PluginAPI, PluginContext, Tool

log = logging.getLogger("intercept.plugins")

__all__ = ["PluginManager", "PluginInfo"]


def _builtin_plugin_dir() -> Path:
    """Where the example plugins live.

    A frozen build keeps them next to the bundle, a source checkout keeps them
    in the repository.
    """
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass) / "plugins"
    return Path(__file__).resolve().parent.parent.parent.parent / "plugins"


@dataclass
class PluginInfo:
    """Metadata about a loaded plugin."""

    name: str
    label: str
    version: str = "0.0.0"
    description: str = ""
    path: str = ""
    builtin: bool = False
    enabled: bool = True
    error: str = ""
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "version": self.version,
            "description": self.description,
            "path": self.path,
            "builtin": self.builtin,
            "enabled": self.enabled,
            "error": self.error,
            "tools": list(self.tools),
        }


class PluginManager:
    """Loads plugins and routes tool execution."""

    def __init__(self, home: Path | str, context: PluginContext) -> None:
        self.home = Path(home)
        self.context = context
        self.plugins: dict[str, PluginInfo] = {}
        self.tools: dict[str, Tool] = {}
        self.checks: dict[str, ActiveCheck] = {}
        self.hooks: dict[str, list[tuple[str, Any]]] = {}
        self.builtin_dir = _builtin_plugin_dir()

    # ------------------------------------------------------------- discovery

    def plugin_dirs(self) -> list[tuple[Path, bool]]:
        """Candidate plugin directories, each of which holds a ``plugin.toml``."""
        dirs: list[tuple[Path, bool]] = []
        for root, builtin in (
            (self.builtin_dir / "examples", True),
            (self.home / "plugins", False),
        ):
            if not root.is_dir():
                continue
            if (root / "plugin.toml").exists():
                dirs.append((root, builtin))
                continue
            for entry in sorted(root.iterdir()):
                if entry.is_dir() and (entry / "plugin.toml").exists():
                    dirs.append((entry, builtin))
        return dirs

    def load_all(self) -> list[PluginInfo]:
        for directory, builtin in self.plugin_dirs():
            self.load_directory(directory, builtin)
        return list(self.plugins.values())

    def load_directory(self, directory: Path, builtin: bool = False) -> PluginInfo | None:
        manifest_path = directory / "plugin.toml"
        if not manifest_path.exists():
            return None
        try:
            manifest = tomllib.loads(manifest_path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as exc:
            log.error("invalid manifest in %s: %s", directory, exc)
            return None

        name = str(manifest.get("name") or directory.name)
        info = PluginInfo(
            name=name,
            label=str(manifest.get("label") or name),
            version=str(manifest.get("version") or "0.0.0"),
            description=str(manifest.get("description") or ""),
            path=str(directory),
            builtin=builtin,
        )
        self.plugins[name] = info

        entry = str(manifest.get("entry") or "plugin.py")
        module_path = directory / entry
        if not module_path.exists():
            info.error = f"entry module {entry!r} not found"
            log.error("plugin %s: %s", name, info.error)
            return info

        module_name = f"intercept_plugin_{name.replace('-', '_')}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"cannot load {module_path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            register = getattr(module, "register", None)
            if register is None:
                raise AttributeError("plugin does not expose register(api)")
            api = PluginAPI(self, name)
            register(api)
        except Exception as exc:  # noqa: BLE001 - a plugin must never kill the daemon
            info.error = f"{type(exc).__name__}: {exc}"
            log.error("plugin %s failed to load: %s\n%s", name, exc, traceback.format_exc())
            return info

        info.tools = [tool.id for tool in self.tools.values() if tool.id]
        return info

    def unload(self, name: str) -> bool:
        info = self.plugins.pop(name, None)
        if info is None:
            return False
        for tool_id in list(self.tools):
            if tool_id.startswith(f"{name}."):
                self.tools.pop(tool_id, None)
        return True

    # -------------------------------------------------------------- registry

    def add_tool(self, plugin_name: str, tool: Tool) -> None:
        tool_id = tool.id if tool.id.startswith(f"{plugin_name}.") else f"{plugin_name}.{tool.id}"
        tool.id = tool_id
        self.tools[tool_id] = tool
        info = self.plugins.get(plugin_name)
        if info is not None and tool_id not in info.tools:
            info.tools.append(tool_id)

    def add_check(self, plugin_name: str, check: ActiveCheck) -> None:
        check_id = (
            check.id if check.id.startswith(f"{plugin_name}.") else f"{plugin_name}.{check.id}"
        )
        check.id = check_id
        self.checks[check_id] = check

    def add_hook(self, plugin_name: str, event: str, callback: Any) -> None:
        self.hooks.setdefault(event, []).append((plugin_name, callback))

    def log(self, plugin_name: str, message: str) -> None:
        log.info("[%s] %s", plugin_name, message)
        if self.context.bus is not None:
            self.context.bus.emit("plugin.log", plugin=plugin_name, message=message)

    # ------------------------------------------------------------- execution

    def describe_tools(self) -> list[dict[str, Any]]:
        return [tool.describe() for tool in self.tools.values()]

    async def run_tool(self, tool_id: str, values: dict[str, Any]) -> dict[str, Any]:
        tool = self.tools.get(tool_id)
        if tool is None:
            return {"error": f"unknown tool {tool_id!r}"}
        try:
            result = await tool.run(self.context, values)
        except Exception as exc:  # noqa: BLE001
            log.exception("tool %s failed", tool_id)
            return {"error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()}
        if not isinstance(result, dict):
            result = {"result": result}
        result.setdefault("tool", tool_id)
        return result

    async def dispatch(self, event: str, payload: Any) -> list[Any]:
        """Invoke every hook registered for *event*."""
        results = []
        for plugin_name, callback in self.hooks.get(event, []):
            try:
                outcome = callback(payload)
                if asyncio.iscoroutine(outcome):
                    outcome = await outcome
                results.append(outcome)
            except Exception as exc:  # noqa: BLE001
                log.error("hook %s from %s failed: %s", event, plugin_name, exc)
        return results

"""Site map and scope rules.

The site map is derived from observed traffic: every host the proxy has seen
becomes a root, and every path becomes a node in a tree. Scope rules decide
which hosts and URLs are in scope, which the spider and any future active
scanner will respect.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from intercept.store.history import HistoryStore

__all__ = ["SiteMap", "Scope", "ScopeRule"]


@dataclass(slots=True)
class ScopeRule:
    pattern: str
    kind: str = "include"  # "include" | "exclude"
    target: str = "host"  # "host" | "url"
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern": self.pattern,
            "kind": self.kind,
            "target": self.target,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScopeRule:
        return cls(
            pattern=str(data.get("pattern", "")),
            kind=str(data.get("kind", "include")),
            target=str(data.get("target", "host")),
            enabled=bool(data.get("enabled", True)),
        )


def _match(pattern: str, value: str, target: str) -> bool:
    """Match *pattern* against *value*.

    Patterns are globs. A pattern with no wildcards matches loosely: for a
    host it matches the host itself and any subdomain of it, for a URL it
    matches any path that contains it. ``re:`` switches to a regular
    expression.
    """
    if pattern.startswith("re:"):
        try:
            return re.search(pattern[3:], value, re.IGNORECASE) is not None
        except re.error:
            return False
    if fnmatch.fnmatch(value.lower(), pattern.lower()):
        return True
    if any(char in pattern for char in "*?["):
        return False
    if target == "host":
        return value.lower() == pattern.lower() or value.lower().endswith(
            f".{pattern.lower()}"
        )
    return pattern.lower() in value.lower()


class Scope:
    """A list of include/exclude rules evaluated against hosts and URLs."""

    def __init__(self, rules: list[ScopeRule] | None = None) -> None:
        self.rules: list[ScopeRule] = list(rules or [])

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [rule.to_dict() for rule in self.rules]}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scope:
        return cls([ScopeRule.from_dict(item) for item in data.get("rules", [])])

    def add(self, rule: ScopeRule) -> None:
        self.rules = [r for r in self.rules if r.to_dict() != rule.to_dict()]
        self.rules.append(rule)

    def remove(self, pattern: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.pattern != pattern]
        return len(self.rules) != before

    def is_in_scope(self, url: str) -> bool:
        """Evaluate the rules for *url*.

        An explicit exclude always wins. When no include rule matches, the URL
        is out of scope, so a scope has to be opened deliberately.
        """
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0].lower()
        included = False
        for rule in self.rules:
            if not rule.enabled:
                continue
            value = host if rule.target == "host" else url.lower()
            if not _match(rule.pattern, value, rule.target):
                continue
            if rule.kind == "exclude":
                return False
            included = True
        return included

    def save(self, path: Path | str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path | str) -> Scope:
        target = Path(path)
        if not target.exists():
            return cls()
        try:
            return cls.from_dict(json.loads(target.read_text()))
        except (OSError, json.JSONDecodeError):
            return cls()


class SiteMap:
    """Builds a browsable tree of the hosts and paths seen by the proxy."""

    def __init__(self, store: HistoryStore) -> None:
        self.store = store

    async def hosts(self) -> list[dict[str, Any]]:
        return await self.store.distinct_hosts()

    async def tree(self) -> list[dict[str, Any]]:
        """Return one tree per host, ordered by traffic volume."""
        hosts = await self.hosts()
        trees = []
        for host in hosts:
            paths = await self.store.distinct_paths(host["host"])
            trees.append(
                {
                    "host": host["host"],
                    "scheme": host["scheme"],
                    "hits": host["hits"],
                    "last_seen": host["last_seen"],
                    "nodes": _build_tree(paths),
                }
            )
        return trees


def _build_tree(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn a flat list of paths into a nested tree."""
    root: dict[str, Any] = {"children": {}, "paths": {}}

    for entry in paths:
        path = entry.get("path") or "/"
        segments = [segment for segment in path.split("/") if segment]
        node = root
        prefix = ""
        for segment in segments:
            prefix = f"{prefix}/{segment}"
            children = node["children"]
            if segment not in children:
                children[segment] = {"children": {}, "paths": {}}
            node = children[segment]
            node["paths"].setdefault(prefix, []).append(entry)

    def render(node: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for name, child in node["children"].items():
            leaves = child["paths"]
            entries = next(iter(leaves.values())) if leaves else []
            sample = entries[0] if entries else {}
            out.append(
                {
                    "name": name,
                    "path": sample.get("path", ""),
                    "methods": sorted({e.get("method", "") for e in entries if e.get("method")}),
                    "hits": sum(e.get("hits", 0) for e in entries),
                    "status": sample.get("status", 0),
                    "last_seen": sample.get("last_seen", 0),
                    "children": render(child),
                }
            )
        return out

    return render(root)

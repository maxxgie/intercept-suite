"""The command registry.

Every action the interface can take is a command: the ones in the command
palette, the ones in a context menu, the keyboard shortcuts and the scheduled
tasks all go through the same registry. That way there is exactly one place
that knows what an action is called and how it runs.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Command", "CommandRegistry", "CommandError"]


class CommandError(RuntimeError):
    """Raised when a command cannot be run."""


@dataclass(slots=True)
class Command:
    id: str
    title: str
    category: str = "General"
    description: str = ""
    keywords: list[str] = field(default_factory=list)
    shortcut: str = ""
    icon: str = ""
    hidden: bool = False
    handler: Callable[[dict[str, Any]], Awaitable[Any] | Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "keywords": list(self.keywords),
            "shortcut": self.shortcut,
            "icon": self.icon,
            "hidden": self.hidden,
        }

    def search_text(self) -> str:
        return " ".join([self.title, self.category, self.description, *self.keywords]).lower()


class CommandRegistry:
    """A registry of commands that can be searched and run."""

    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}

    def register(
        self,
        id: str,
        title: str,
        *,
        category: str = "General",
        description: str = "",
        keywords: list[str] | None = None,
        shortcut: str = "",
        icon: str = "",
        hidden: bool = False,
        handler: Callable[[dict[str, Any]], Awaitable[Any] | Any] | None = None,
    ) -> Command:
        command = Command(
            id=id,
            title=title,
            category=category,
            description=description,
            keywords=list(keywords or []),
            shortcut=shortcut,
            icon=icon,
            hidden=hidden,
            handler=handler,
        )
        self._commands[id] = command
        return command

    def add(self, command: Command) -> Command:
        self._commands[command.id] = command
        return command

    def remove(self, id: str) -> bool:
        return self._commands.pop(id, None) is not None

    def get(self, id: str) -> Command | None:
        return self._commands.get(id)

    def list(self, *, include_hidden: bool = False) -> list[dict[str, Any]]:
        commands = [
            command.to_dict()
            for command in self._commands.values()
            if include_hidden or not command.hidden
        ]
        commands.sort(key=lambda item: (item["category"].lower(), item["title"].lower()))
        return commands

    def categories(self) -> list[str]:
        return sorted({command.category for command in self._commands.values()})

    def search(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Find commands by title, category, description or keyword."""
        text = (query or "").strip().lower()
        if not text:
            return self.list()[:limit]
        scored: list[tuple[int, str, dict[str, Any]]] = []
        for command in self._commands.values():
            if command.hidden:
                continue
            haystack = command.search_text()
            title = command.title.lower()
            if title.startswith(text):
                score = 0
            elif text in title:
                score = 1
            elif text in command.keywords:
                score = 2
            elif text in haystack:
                score = 3
            else:
                # A loose subsequence match, so "cltr" finds "Clear traffic".
                if _subsequence(text, haystack):
                    score = 4
                else:
                    continue
            scored.append((score, command.title, command.to_dict()))
        scored.sort(key=lambda item: (item[0], item[1].lower()))
        return [item[2] for item in scored[:limit]]

    async def run(self, id: str, args: dict[str, Any] | None = None) -> Any:
        command = self._commands.get(id)
        if command is None:
            raise CommandError(f"unknown command: {id}")
        if command.handler is None:
            raise CommandError(f"the command {id} has nothing to do")
        result = command.handler(args or {})
        if inspect.isawaitable(result):
            return await result
        return result

    def __len__(self) -> int:
        return len(self._commands)

    def __contains__(self, id: object) -> bool:
        return id in self._commands


def _subsequence(needle: str, haystack: str) -> bool:
    position = 0
    for char in needle:
        if char.isspace():
            continue
        position = haystack.find(char, position)
        if position < 0:
            return False
        position += 1
    return True


async def gather(*coroutines: Awaitable[Any]) -> list[Any]:
    """Run several commands at the same time."""
    return list(await asyncio.gather(*coroutines, return_exceptions=True))

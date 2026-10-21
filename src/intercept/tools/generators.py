"""Payload generators and processing rules for the Intruder.

A generator turns a short description into the list of payloads to try, and a
processing rule rewrites every payload before it is sent. Both are small and
predictable, so a run can be repeated exactly by keeping the description
instead of the list it produced.
"""

from __future__ import annotations

import base64
import calendar
import datetime as dt
import hashlib
import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

__all__ = [
    "Generator",
    "ProcessingRule",
    "generate_payloads",
    "apply_rules",
    "GENERATOR_KINDS",
    "RULE_KINDS",
]

#: The generators the Intruder knows.
GENERATOR_KINDS = (
    "list",
    "numbers",
    "dates",
    "bruteforce",
    "substitution",
    "grep",
    "file",
    "custom",
)

#: The rules that rewrite a payload.
RULE_KINDS = (
    "url-encode",
    "base64",
    "hash",
    "prefix",
    "suffix",
    "replace",
    "extract",
)


def _expand(template: str, charset: str, counter: int) -> str:
    """Fill the placeholders of a custom template.

    ``§0§`` is the counter, ``§a§`` a letter of the charset and ``§A§`` an
    upper case one. ``§!§`` cycles through the charset.
    """
    letters = [c for c in charset if c.isalpha()]
    digits = [c for c in charset if c.isdigit()]

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        if not key:
            return ""
        if key == "0":
            return str(counter)
        if key.isdigit():
            return digits[(counter // (10 ** (int(key) - 1))) % len(digits)] if digits else "0"
        if key == "!":
            return charset[counter % len(charset)] if charset else ""
        if key.islower() and letters:
            return letters[counter % len(letters)]
        if key.isupper() and letters:
            return letters[counter % len(letters)].upper()
        return key

    return re.sub(r"§([^§]*)§", replace, template)


@dataclass
class Generator:
    """A description of the payloads to try."""

    kind: str = "list"
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "options": dict(self.options)}

    def generate(self) -> list[str]:
        """The payloads this generator describes."""
        kind = self.kind
        options = self.options

        if kind == "list":
            return [str(item) for item in options.get("payloads", [])]

        if kind == "numbers":
            start = int(options.get("start", 1))
            end = int(options.get("end", 100))
            step = int(options.get("step", 1)) or 1
            count = options.get("count")
            if count:
                return [str(start + index * step) for index in range(int(count))]
            if step > 0:
                return [str(value) for value in range(start, end + 1, step)]
            return [str(value) for value in range(start, end - 1, step)]

        if kind == "dates":
            start = str(options.get("start", "2024-01-01"))
            count = int(options.get("count", 10))
            step = int(options.get("step", 1)) or 1
            unit = str(options.get("unit", "days"))
            try:
                moment = dt.datetime.fromisoformat(start)
            except ValueError:
                moment = dt.datetime(2024, 1, 1)
            out: list[str] = []
            for index in range(count):
                if unit == "months":
                    total = moment.month - 1 + index * step
                    year = moment.year + total // 12
                    month = total % 12 + 1
                    last = calendar.monthrange(year, month)[1]
                    day = min(moment.day, last)
                    out.append(dt.date(year, month, day).isoformat())
                elif unit == "seconds":
                    out.append((moment + dt.timedelta(seconds=index * step)).isoformat())
                else:
                    out.append((moment + dt.timedelta(days=index * step)).date().isoformat())
            return out

        if kind == "bruteforce":
            charset = str(options.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789"))
            length = int(options.get("length", 3))
            if length < 1:
                return []
            return ["".join(combo) for combo in itertools.product(charset, repeat=length)]

        if kind == "substitution":
            base = str(options.get("base", ""))
            substitutions: list[tuple[str, str]] = []
            for pair in options.get("substitutions", []):
                if isinstance(pair, dict):
                    substitutions.append((str(pair.get("from", "")), str(pair.get("to", ""))))
                else:
                    text = str(pair)
                    old, _, new = text.partition("=")
                    substitutions.append((old, new))
            out = [base]
            for old, new in substitutions:
                out.append(base.replace(old, new))
            return out

        if kind == "grep":
            pattern = str(options.get("pattern", ""))
            root = Path(str(options.get("path", ".")))
            if not pattern:
                return []
            try:
                matcher = re.compile(pattern)
            except re.error:
                return []
            found: list[str] = []
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for number, line in enumerate(text.splitlines(), start=1):
                    if matcher.search(line):
                        found.append(f"{path}:{number}:{line.strip()}")
                        if len(found) >= int(options.get("limit", 1000)):
                            return found
            return found

        if kind == "file":
            path = Path(str(options.get("path", "")))
            if not path.is_file():
                return []
            out = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    out.append(line.strip())
            return out

        if kind == "custom":
            template = str(options.get("template", "§a§§a§"))
            charset = str(options.get("charset", "abcdefghijklmnopqrstuvwxyz0123456789"))
            count = int(options.get("count", 100))
            return [_expand(template, charset, index) for index in range(count)]

        return []


@dataclass
class ProcessingRule:
    """A rewrite that is applied to every payload."""

    kind: str = ""
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "options": dict(self.options)}

    def apply(self, payload: str) -> str:
        """The payload after this rule was applied."""
        kind = self.kind
        options = self.options

        if kind == "url-encode":
            if options.get("form"):
                return quote_plus(payload)
            return quote(payload, safe=str(options.get("safe", "")))

        if kind == "base64":
            return base64.b64encode(payload.encode("utf-8")).decode("ascii")

        if kind == "hash":
            algorithm = str(options.get("algorithm", "md5")).lower()
            digest = hashlib.new(algorithm, payload.encode("utf-8"))
            return digest.hexdigest()

        if kind == "prefix":
            return f"{options.get('text', '')}{payload}"

        if kind == "suffix":
            return f"{payload}{options.get('text', '')}"

        if kind == "replace":
            pattern = str(options.get("pattern", ""))
            replacement = str(options.get("replacement", ""))
            if not pattern:
                return payload
            try:
                return re.sub(pattern, replacement, payload)
            except re.error:
                return payload

        if kind == "extract":
            pattern = str(options.get("pattern", ""))
            group = int(options.get("group", 0))
            if not pattern:
                return payload
            try:
                match = re.search(pattern, payload)
            except re.error:
                return payload
            if match is None:
                return ""
            try:
                return match.group(group) or ""
            except (IndexError, re.error):
                return ""

        return payload


def generate_payloads(generator: Generator | None) -> list[str]:
    """The payloads of a generator, without the rules applied."""
    if generator is None:
        return []
    return generator.generate()


def apply_rules(payloads: list[str], rules: list[ProcessingRule]) -> list[str]:
    """Apply every rule to every payload, in order."""
    out = list(payloads)
    for rule in rules:
        out = [rule.apply(payload) for payload in out]
    return out

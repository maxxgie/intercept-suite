"""Proxy rules.

A rule is a small instruction that the proxy applies to the traffic it sees.
Three kinds exist, and they share the same match fields so the same matching
code serves all of them:

* ``intercept`` - hold the matching request, or the matching response, so the
  analyst can decide what happens to it.
* ``forward`` - let the matching request through without asking, even while
  interception is switched on. This is the auto-forwarding rule.
* ``replace`` - rewrite a part of the matching request or response. This is
  the match and replace rule.

The three match fields are globs. An empty field matches everything, so a
rule only has to name what it cares about. ``host`` and ``method`` are matched
case insensitively, ``path`` is not, because a path is case sensitive on the
wire.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from intercept.core.models import Headers, Request, Response

__all__ = ["Rule", "RuleEngine", "RULE_KINDS", "RULE_PHASES", "RULE_PLACES"]

#: The kinds of rule the engine understands.
RULE_KINDS = ("intercept", "forward", "replace")

#: The phases a request can be held in.
RULE_PHASES = ("request", "response", "both")

#: The parts of a message a replace rule can rewrite.
RULE_PLACES = ("header", "header-add", "body", "url")


def _glob(pattern: str, value: str, *, case_sensitive: bool = False) -> bool:
    """Match *value* against a glob. An empty pattern matches everything."""
    if not pattern:
        return True
    if case_sensitive:
        return fnmatch.fnmatch(value, pattern)
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def _expand(match: re.Match[str], replacement: str) -> str:
    """Expand ``\\1`` style backreferences in *replacement*."""
    try:
        return match.expand(replacement)
    except (re.error, IndexError):
        return replacement


def _expand_bytes(match: re.Match[bytes], replacement: str) -> bytes:
    try:
        return match.expand(replacement.encode("utf-8"))
    except (re.error, IndexError, UnicodeError):
        return replacement.encode("utf-8", "replace")


def substitute(pattern: str, replacement: str, data: str, *, regex: bool = True) -> str:
    """Replace every occurrence of *pattern* in *data*."""
    if not pattern:
        return data
    if not regex:
        return data.replace(pattern, replacement)
    try:
        compiled = re.compile(pattern)
    except re.error:
        return data
    return compiled.sub(lambda m: _expand(m, replacement), data)


def substitute_bytes(
    pattern: str, replacement: str, data: bytes, *, regex: bool = True
) -> bytes:
    """Replace every occurrence of *pattern* in a byte string."""
    if not pattern:
        return data
    if not regex:
        return data.replace(pattern.encode("utf-8"), replacement.encode("utf-8"))
    try:
        compiled = re.compile(pattern.encode("utf-8"))
    except (re.error, UnicodeError):
        return data
    return compiled.sub(lambda m: _expand_bytes(m, replacement), data)


@dataclass(slots=True)
class Rule:
    """One instruction the proxy applies to the traffic it sees."""

    id: str
    name: str = ""
    kind: str = "intercept"
    enabled: bool = True
    #: Glob matched against the host of the request.
    host: str = ""
    #: Glob matched against the path of the request.
    path: str = ""
    #: Glob matched against the method of the request.
    method: str = ""
    #: Which phase an intercept rule holds: the request, the response or both.
    phase: str = "request"
    #: Which message a replace rule rewrites.
    target: str = "request"
    #: Which part of the message a replace rule rewrites.
    place: str = "header"
    #: The header a replace rule rewrites, for the header places.
    field: str = ""
    #: The pattern to look for.
    match: str = ""
    #: What to put in its place.
    replace: str = ""
    #: Whether *match* is a regular expression rather than a literal.
    regex: bool = True
    created_at: float = 0.0
    updated_at: float = 0.0

    def matches(self, request: Request) -> bool:
        """Does this rule apply to *request*?"""
        _, host, _, path, _ = request.parts
        return (
            _glob(self.host, host)
            and _glob(self.method, request.method)
            and _glob(self.path, path, case_sensitive=True)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "enabled": self.enabled,
            "host": self.host,
            "path": self.path,
            "method": self.method,
            "phase": self.phase,
            "target": self.target,
            "place": self.place,
            "field": self.field,
            "match": self.match,
            "replace": self.replace,
            "regex": self.regex,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        return cls(
            id=str(data.get("id", "")),
            name=str(data.get("name", "")),
            kind=str(data.get("kind", "intercept")),
            enabled=bool(data.get("enabled", True)),
            host=str(data.get("host", "")),
            path=str(data.get("path", "")),
            method=str(data.get("method", "")),
            phase=str(data.get("phase", "request")),
            target=str(data.get("target", "request")),
            place=str(data.get("place", data.get("where", "header"))),
            field=str(data.get("field", "")),
            match=str(data.get("match", "")),
            replace=str(data.get("replace", "")),
            regex=bool(data.get("regex", True)),
            created_at=float(data.get("created_at", 0.0)),
            updated_at=float(data.get("updated_at", 0.0)),
        )


@dataclass
class RuleEngine:
    """Holds the rules and applies them to the traffic."""

    _rules: list[Rule] = field(default_factory=list)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def set_rules(self, rules: list[Rule]) -> None:
        self._rules = list(rules)

    def _of_kind(self, kind: str) -> list[Rule]:
        return [rule for rule in self._rules if rule.enabled and rule.kind == kind]

    def _any_of_kind(self, kind: str) -> list[Rule]:
        return [rule for rule in self._rules if rule.kind == kind]

    # ------------------------------------------------------------- decisions

    def auto_forward(self, request: Request) -> bool:
        """Should this request be let through without asking?"""
        return any(rule.matches(request) for rule in self._of_kind("forward"))

    def intercept_request(self, request: Request) -> bool:
        """Should this request be held for the analyst?"""
        if self.auto_forward(request):
            return False
        if not self._any_of_kind("intercept"):
            # Without any rule to narrow it down, the switch holds everything.
            return True
        return any(
            rule.matches(request) and rule.phase in ("request", "both")
            for rule in self._of_kind("intercept")
        )

    def intercept_response(self, request: Request) -> bool:
        """Should the response to this request be held for the analyst?"""
        if not self._any_of_kind("intercept"):
            return False
        return any(
            rule.matches(request) and rule.phase in ("response", "both")
            for rule in self._of_kind("intercept")
        )

    # ---------------------------------------------------------- replacements

    def apply_request(self, request: Request) -> Request:
        """Apply every matching replace rule to *request*."""
        for rule in self._of_kind("replace"):
            if rule.target != "request" or not rule.matches(request):
                continue
            request = _apply_to_request(rule, request)
        return request

    def apply_response(self, request: Request, response: Response) -> Response:
        """Apply every matching replace rule to *response*."""
        for rule in self._of_kind("replace"):
            if rule.target != "response" or not rule.matches(request):
                continue
            response = _apply_to_response(rule, response)
        return response


def _apply_to_request(rule: Rule, request: Request) -> Request:
    if rule.place == "url":
        request.url = substitute(
            rule.match, rule.replace, request.url, regex=rule.regex
        )
    elif rule.place == "header":
        request.headers = _replace_header(rule, request.headers)
    elif rule.place == "header-add":
        request.headers.set(rule.field, rule.replace)
    elif rule.place == "body":
        request.body = substitute_bytes(
            rule.match, rule.replace, request.body, regex=rule.regex
        )
    return request


def _apply_to_response(rule: Rule, response: Response) -> Response:
    if rule.place == "header":
        response.headers = _replace_header(rule, response.headers)
    elif rule.place == "header-add":
        response.headers.set(rule.field, rule.replace)
    elif rule.place == "body":
        response.body = substitute_bytes(
            rule.match, rule.replace, response.body, regex=rule.regex
        )
    elif rule.place == "url":
        # A response has no URL of its own; the rule does not apply to it.
        return response
    return response


def _replace_header(rule: Rule, headers: Headers) -> Headers:
    """Rewrite the value of every header named by the rule."""
    if not rule.field:
        return headers
    out = Headers()
    for name, value in headers.items():
        if name.lower() == rule.field.lower():
            value = substitute(rule.match, rule.replace, value, regex=rule.regex)
        out.add(name, value)
    return out

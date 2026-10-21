"""The filter expression language.

Filters are the thing that makes a large history usable, so the language is
small but complete:

    host == "example.com" and status >= 400
    path contains "/admin" or method == "POST"
    request =~ "(?i)password" and not mime == "text/html"

Grammar::

    expression := term (("and" | "or") term)*
    term       := "not" term | "(" expression ")" | comparison
    comparison := key operator value
    operator   := "==" | "!=" | ">=" | "<=" | ">" | "<" | "=~" | "!~"
                | "contains" | "not contains" | "startswith" | "endswith"
                | "in" | "not in"

Values may be quoted with single or double quotes. A bare word is matched
case insensitively, a quoted word exactly.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "FilterError",
    "Filter",
    "FilterState",
    "parse",
    "compile_filter",
    "FIELDS",
]


class FilterError(ValueError):
    """Raised when a filter expression cannot be understood."""


#: The fields a filter may talk about, with their aliases.
FIELDS: dict[str, str] = {
    "host": "host",
    "hostname": "host",
    "domain": "host",
    "ip": "host",
    "path": "path",
    "url": "url",
    "uri": "url",
    "method": "method",
    "status": "status",
    "code": "status",
    "reason": "reason",
    "scheme": "scheme",
    "port": "port",
    "query": "query",
    "mime": "mime_type",
    "mimetype": "mime_type",
    "type": "mime_type",
    "ext": "extension",
    "extension": "extension",
    "size": "response_length",
    "length": "response_length",
    "requestsize": "request_length",
    "time": "elapsed_ms",
    "elapsed": "elapsed_ms",
    "duration": "elapsed_ms",
    "origin": "origin",
    "source": "origin",
    "tag": "tags",
    "tags": "tags",
    "note": "notes",
    "notes": "notes",
    "comment": "comment",
    "request": "request_raw",
    "response": "response_raw",
    "body": "body",
    "highlighted": "highlighted",
    "highlight": "highlighted",
    "level": "level",
    "component": "source",
    "message": "message",
}

#: Fields that hold text and are searched case insensitively by default.
_TEXT_FIELDS = {
    "level",
    "component",
    "message",
    "host",
    "path",
    "url",
    "method",
    "reason",
    "scheme",
    "query",
    "mime_type",
    "origin",
    "request_raw",
    "response_raw",
    "body",
    "comment",
}

#: Fields that hold numbers.
_NUMBER_FIELDS = {"status", "port", "response_length", "request_length", "elapsed_ms"}

#: Fields that hold a list of words.
_LIST_FIELDS = {"tags", "notes"}

#: Fields that can be used on their own as a boolean.
_BOOLEAN_FIELDS = {"highlighted"}


# ------------------------------------------------------------------ tokenizer


@dataclass(slots=True)
class _Token:
    kind: str  # "word", "string", "op", "lparen", "rparen", "and", "or", "not"
    value: str
    position: int


_OPERATORS = ("==", "!=", ">=", "<=", "=~", "!~", ">", "<")
_WORD_OPERATORS = {"contains", "startswith", "endswith", "in"}


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "(":
            tokens.append(_Token("lparen", "(", index))
            index += 1
            continue
        if char == ")":
            tokens.append(_Token("rparen", ")", index))
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            start = index
            while index < length and text[index] != quote:
                index += 1
            if index >= length:
                raise FilterError(f"unterminated string at position {start}")
            tokens.append(_Token("string", text[start:index], start))
            index += 1
            continue
        for operator in _OPERATORS:
            if text.startswith(operator, index):
                tokens.append(_Token("op", operator, index))
                index += len(operator)
                break
        else:
            start = index
            while index < length and not text[index].isspace() and text[index] not in "()":
                index += 1
            word = text[start:index]
            lowered = word.lower()
            if lowered in ("and", "or", "not"):
                tokens.append(_Token(lowered, lowered, start))
            elif lowered in _WORD_OPERATORS:
                tokens.append(_Token("op", lowered, start))
            elif word:
                tokens.append(_Token("word", word, start))
    return tokens


# --------------------------------------------------------------------- nodes


class _Node:
    def matches(self, row: dict[str, Any]) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def describe(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError


@dataclass(slots=True)
class _All(_Node):
    def matches(self, row: dict[str, Any]) -> bool:
        return True

    def describe(self) -> str:
        return ""


@dataclass(slots=True)
class _None_(_Node):
    def matches(self, row: dict[str, Any]) -> bool:
        return False

    def describe(self) -> str:
        return "false"


@dataclass(slots=True)
class _And(_Node):
    left: _Node
    right: _Node

    def matches(self, row: dict[str[str, Any]]) -> bool:
        return self.left.matches(row) and self.right.matches(row)

    def describe(self) -> str:
        return f"({self.left.describe()} and {self.right.describe()})"


@dataclass(slots=True)
class _Or(_Node):
    left: _Node
    right: _Node

    def matches(self, row: dict[str, Any]) -> bool:
        return self.left.matches(row) or self.right.matches(row)

    def describe(self) -> str:
        return f"({self.left.describe()} or {self.right.describe()})"


@dataclass(slots=True)
class _Not(_Node):
    inner: _Node

    def matches(self, row: dict[str, Any]) -> bool:
        return not self.inner.matches(row)

    def describe(self) -> str:
        return f"not {self.inner.describe()}"


@dataclass(slots=True)
class _Comparison(_Node):
    field: str
    operator: str
    value: str
    literal: bool

    def matches(self, row: dict[str, Any]) -> bool:
        return _compare(self.field, self.operator, self.value, self.literal, row)

    def describe(self) -> str:
        shown = f'"{self.value}"' if self.literal else self.value
        return f"{self.field} {self.operator} {shown}"


# ----------------------------------------------------------------- operators


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return " ".join(str(item) for item in value)
    return str(value)


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _compare(
    field: str, operator: str, value: str, literal: bool, row: dict[str, Any]
) -> bool:
    actual = row.get(field)
    if actual is None and field in _LIST_FIELDS:
        actual = []

    if operator in ("=~", "!~"):
        haystack = _as_text(actual)
        if field in ("request_raw", "response_raw", "body"):
            haystack = row.get(field) or ""
            if isinstance(haystack, bytes):
                haystack = haystack.decode("utf-8", "replace")
        try:
            pattern = re.compile(value, re.IGNORECASE if not literal else 0)
        except re.error as exc:
            raise FilterError(f"invalid regular expression {value!r}: {exc}") from exc
        found = pattern.search(haystack) is not None
        return found if operator == "=~" else not found

    if field in _NUMBER_FIELDS:
        left = _as_number(actual)
        right = _as_number(value)
        if left is None or right is None:
            if operator == "==":
                return False
            return operator == "!="
        if operator == "==":
            return left == right
        if operator == "!=":
            return left != right
        if operator == ">":
            return left > right
        if operator == "<":
            return left < right
        if operator == ">=":
            return left >= right
        if operator == "<=":
            return left <= right
        return False

    if field in _LIST_FIELDS:
        items = [str(item) for item in (actual or [])]
        if operator == "==":
            return value in items
        if operator == "!=":
            return value not in items
        if operator == "in":
            return any(item in value for item in items)
        if operator == "not in":
            return not any(item in value for item in items)
        if operator == "contains":
            return any(value.lower() in item.lower() for item in items)
        haystack = " ".join(items)
    else:
        haystack = _as_text(actual)

    left_text = haystack
    right_text = value
    if not literal and field in _TEXT_FIELDS:
        left_text = left_text.lower()
        right_text = right_text.lower()

    if operator == "==":
        return left_text == right_text
    if operator == "!=":
        return left_text != right_text
    if operator == "contains":
        return right_text in left_text
    if operator == "not contains":
        return right_text not in left_text
    if operator == "startswith":
        return left_text.startswith(right_text)
    if operator == "endswith":
        return left_text.endswith(right_text)
    if operator == "in":
        return left_text in right_text
    if operator == "not in":
        return left_text not in right_text
    if operator == ">":
        return left_text > right_text
    if operator == "<":
        return left_text < right_text
    if operator == ">=":
        return left_text >= right_text
    if operator == "<=":
        return left_text <= right_text
    return False


# -------------------------------------------------------------------- parser


class _Parser:
    def __init__(self, tokens: Sequence[_Token]) -> None:
        self.tokens = list(tokens)
        self.index = 0

    def peek(self) -> _Token | None:
        if self.index < len(self.tokens):
            return self.tokens[self.index]
        return None

    def take(self) -> _Token:
        token = self.peek()
        if token is None:
            raise FilterError("the filter ended unexpectedly")
        self.index += 1
        return token

    def parse(self) -> _Node:
        node = self.parse_or()
        if self.peek() is not None:
            token = self.tokens[self.index]
            raise FilterError(f"unexpected {token.value!r} at position {token.position}")
        return node

    def parse_or(self) -> _Node:
        node = self.parse_and()
        while (token := self.peek()) is not None and token.kind == "or":
            self.take()
            node = _Or(node, self.parse_and())
        return node

    def parse_and(self) -> _Node:
        node = self.parse_unary()
        while (token := self.peek()) is not None and token.kind == "and":
            self.take()
            node = _And(node, self.parse_unary())
        return node

    def parse_unary(self) -> _Node:
        token = self.peek()
        if token is None:
            raise FilterError("the filter ended unexpectedly")
        if token.kind == "not":
            self.take()
            return _Not(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> _Node:
        token = self.take()
        if token.kind == "lparen":
            node = self.parse_or()
            closing = self.peek()
            if closing is None or closing.kind != "rparen":
                raise FilterError("a bracket was not closed")
            self.take()
            return node
        if token.kind in ("and", "or"):
            raise FilterError(f"unexpected {token.value!r} at position {token.position}")
        if token.kind != "word":
            raise FilterError(f"expected a field name at position {token.position}")
        field = FIELDS.get(token.value.lower())
        if field is None:
            raise FilterError(f"unknown field {token.value!r}")
        operator_token = self.peek()
        if operator_token is None or operator_token.kind != "op":
            if field in _BOOLEAN_FIELDS:
                # "highlighted" on its own means "highlighted == true".
                return _Comparison(field, "==", "true", True)
            raise FilterError(f"expected an operator after {token.value!r}")
        self.take()
        operator = operator_token.value
        if operator == "not":
            following = self.peek()
            if following is None or following.value.lower() not in ("contains", "in"):
                raise FilterError("not must be followed by contains or in")
            self.take()
            operator = f"not {following.value.lower()}"
        value_token = self.take()
        if value_token.kind == "string":
            return _Comparison(field, operator, value_token.value, True)
        if value_token.kind == "word":
            if value_token.value.lower() in ("and", "or", "not"):
                raise FilterError(f"missing a value at position {value_token.position}")
            return _Comparison(field, operator, value_token.value, False)
        raise FilterError(f"expected a value at position {value_token.position}")


# --------------------------------------------------------------------- api


class Filter:
    """A compiled filter expression."""

    def __init__(self, expression: str, node: _Node) -> None:
        self.expression = expression
        self._node = node

    def matches(self, row: dict[str, Any]) -> bool:
        return self._node.matches(row)

    def filter(self, rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        return [row for row in rows if self.matches(row)]

    def describe(self) -> str:
        return self._node.describe()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Filter({self.expression!r})"


def parse(expression: str) -> Filter:
    """Compile *expression* into a filter."""
    text = (expression or "").strip()
    if not text:
        return Filter("", _All())
    tokens = _tokenize(text)
    if not tokens:
        return Filter("", _All())
    return Filter(text, _Parser(tokens).parse())


def compile_filter(expression: str) -> Callable[[dict[str, Any]], bool]:
    """Compile *expression* into a predicate."""
    compiled = parse(expression)
    return compiled.matches


class FilterState:
    """The filter that is currently applied to the history.

    A broken expression is remembered so the interface can show the error,
    but it never stops the history from being shown.
    """

    def __init__(self, expression: str = "") -> None:
        self._expression = ""
        self._compiled = Filter("", _All())
        self.error = ""
        if expression:
            self.set(expression)

    def set(self, expression: str) -> bool:
        try:
            compiled = parse(expression)
        except FilterError as exc:
            self.error = str(exc)
            return False
        self._expression = expression
        self._compiled = compiled
        self.error = ""
        return True

    def clear(self) -> None:
        self._expression = ""
        self._compiled = Filter("", _All())
        self.error = ""

    @property
    def expression(self) -> str:
        return self._expression

    def matches(self, row: dict[str, Any]) -> bool:
        return self._compiled.matches(row)

    def to_dict(self) -> dict[str, Any]:
        return {"expression": self._expression, "error": self.error}

"""The comparer.

The comparer puts two things next to each other and says what is different
and what is the same. It knows the shapes that turn up in web traffic: a
request, a response, a body that is JSON, XML or HTML, a set of tokens and a
file that is not text at all.

The comparison always has three parts:

* the **differences**, one entry for every thing that is not the same;
* the **similarities**, one entry for every thing that is the same, so a
  difference is only worth what it tells you about the rest;
* the **rows**, the side by side view of the two things, with the lines that
  differ marked.

Everything is done on the bytes, so a file that is not text can be compared as
well: the bytes that differ are reported with their place in the file.
"""

from __future__ import annotations

import base64
import difflib
import json
import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

__all__ = [
    "Comparer",
    "Comparison",
    "DiffRow",
    "Difference",
    "Similarity",
    "COMPARISON_KINDS",
    "compare_bytes",
    "compare_documents",
    "diff_lines",
    "extract_tokens",
    "guess_kind",
]

#: The kinds of comparison the comparer knows.
COMPARISON_KINDS: tuple[str, ...] = (
    "auto",
    "request",
    "response",
    "json",
    "xml",
    "html",
    "tokens",
    "binary",
    "text",
)

#: The names that hold a token, and the name of the header they sit in.
_TOKEN_NAMES = (
    "jsessionid",
    "phpsessid",
    "sessionid",
    "session",
    "sid",
    "csrf",
    "csrf_token",
    "csrftoken",
    "_token",
    "xsrf",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "nonce",
    "auth",
    "authorization",
    "password",
    "secret",
)

_TOKEN_NAME_RE = re.compile(
    r"(?:^|[\s;&,?])(" + "|".join(_TOKEN_NAMES) + r")\s*=\s*([^;&,\s\"']+)",
    re.IGNORECASE,
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
_LONG_VALUE_RE = re.compile(r"\b([A-Za-z0-9+/_-]{24,})={0,2}\b")
_XML_DECL = re.compile(r"^\s*<\?xml", re.IGNORECASE)


@dataclass
class Difference:
    """One thing that is not the same on both sides."""

    kind: str
    path: str
    left: str
    right: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "left": self.left,
            "right": self.right,
            "note": self.note,
        }


@dataclass
class Similarity:
    """One thing that is the same on both sides."""

    kind: str
    path: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "path": self.path, "value": self.value}


@dataclass
class DiffRow:
    """A line of the side by side view."""

    left: str | None
    right: str | None
    kind: str
    left_span: tuple[int, int] | None = None
    right_span: tuple[int, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "kind": self.kind,
            "left_span": list(self.left_span) if self.left_span else None,
            "right_span": list(self.right_span) if self.right_span else None,
        }


@dataclass
class Comparison:
    """Everything the comparer found out about two things."""

    kind: str
    identical: bool = True
    left_size: int = 0
    right_size: int = 0
    differences: list[Difference] = field(default_factory=list)
    similarities: list[Similarity] = field(default_factory=list)
    rows: list[DiffRow] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identical": self.identical,
            "left_size": self.left_size,
            "right_size": self.right_size,
            "differences": [difference.to_dict() for difference in self.differences],
            "similarities": [similarity.to_dict() for similarity in self.similarities],
            "rows": [row.to_dict() for row in self.rows],
            "summary": self.summary,
        }


# ------------------------------------------------------------------- tokens


@dataclass
class Token:
    """A token that was found in a piece of text."""

    name: str
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "value": self.value}


def extract_tokens(text: str) -> list[Token]:
    """The tokens in a piece of text.

    A token is a value that sits under a name that says what it is, a JSON web
    token, or a long value that looks like it was made up rather than written.
    """
    found: list[Token] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, value: str) -> None:
        value = value.strip()
        if len(value) < 6:
            return
        key = (name.lower(), value)
        if key in seen:
            return
        seen.add(key)
        found.append(Token(name, value))

    for match in _TOKEN_NAME_RE.finditer(text):
        add(match.group(1), match.group(2))
    for match in _JWT_RE.finditer(text):
        add("jwt", match.group(0))
    for match in _LONG_VALUE_RE.finditer(text):
        value = match.group(1)
        if not re.search(r"[0-9]", value) and not re.search(r"[a-zA-Z]", value):
            continue
        if len(set(value)) < 6:
            continue
        add("value", value)
    return found


# --------------------------------------------------------------------- diff


def _span(left: str, right: str) -> tuple[tuple[int, int] | None, tuple[int, int] | None]:
    """The parts of two lines that are not the same."""
    if not left or not right or left == right:
        return None, None
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
    left_span: tuple[int, int] | None = None
    right_span: tuple[int, int] | None = None
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        left_span = (i1, i2) if left_span is None else (left_span[0], i2)
        right_span = (j1, j2) if right_span is None else (right_span[0], j2)
    return left_span, right_span


def diff_lines(left: str, right: str) -> list[DiffRow]:
    """The two texts next to each other, with the lines that differ marked."""
    a = left.splitlines()
    b = right.splitlines()
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    rows: list[DiffRow] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            rows.extend(DiffRow(line, line, "same") for line in a[i1:i2])
            continue
        if tag == "delete":
            rows.extend(DiffRow(line, None, "removed") for line in a[i1:i2])
            continue
        if tag == "insert":
            rows.extend(DiffRow(None, line, "added") for line in b[j1:j2])
            continue
        removed = a[i1:i2]
        added = b[j1:j2]
        for index in range(max(len(removed), len(added))):
            line_a = removed[index] if index < len(removed) else None
            line_b = added[index] if index < len(added) else None
            if line_a is None:
                rows.append(DiffRow(None, line_b, "added"))
                continue
            if line_b is None:
                rows.append(DiffRow(line_a, None, "removed"))
                continue
            left_span, right_span = _span(line_a, line_b)
            rows.append(DiffRow(line_a, line_b, "different", left_span, right_span))
    return rows


# ---------------------------------------------------------------------- json


def _json_walk(left: Any, right: Any, path: str) -> tuple[list[Difference], list[Similarity]]:
    """Compare two pieces of JSON, key by key."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []

    if isinstance(left, dict) and isinstance(right, dict):
        for key in left:
            child = f"{path}.{key}" if path else key
            if key not in right:
                differences.append(
                    Difference("json", child, _json_text(left[key]), "", "only in A")
                )
                continue
            sub_diff, sub_same = _json_walk(left[key], right[key], child)
            differences.extend(sub_diff)
            similarities.extend(sub_same)
        for key in right:
            if key not in left:
                child = f"{path}.{key}" if path else key
                differences.append(
                    Difference("json", child, "", _json_text(right[key]), "only in B")
                )
        return differences, similarities

    if isinstance(left, list) and isinstance(right, list):
        for index in range(min(len(left), len(right))):
            sub_diff, sub_same = _json_walk(left[index], right[index], f"{path}[{index}]")
            differences.extend(sub_diff)
            similarities.extend(sub_same)
        for index in range(len(right), len(left)):
            differences.append(
                Difference("json", f"{path}[{index}]", _json_text(left[index]), "", "only in A")
            )
        for index in range(len(left), len(right)):
            differences.append(
                Difference("json", f"{path}[{index}]", "", _json_text(right[index]), "only in B")
            )
        return differences, similarities

    if left == right:
        similarities.append(Similarity("json", path, _json_text(left)))
        return differences, similarities

    note = "the type changed" if type(left) is not type(right) else ""
    differences.append(Difference("json", path, _json_text(left), _json_text(right), note))
    return differences, similarities


def _json_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


# ----------------------------------------------------------------------- xml


def _xml_walk(
    left: ElementTree.Element,
    right: ElementTree.Element,
    path: str,
) -> tuple[list[Difference], list[Similarity]]:
    """Compare two XML trees, element by element."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []

    def tag_of(element: ElementTree.Element) -> str:
        return element.tag.split("}")[-1]

    name = tag_of(left)
    child_path = f"{path}/{name}" if path else name
    if tag_of(right) != name:
        differences.append(
            Difference("xml", child_path, name, tag_of(right), "the element is a different one")
        )
        return differences, similarities

    left_attributes = {key.lower(): value for key, value in left.attrib.items()}
    right_attributes = {key.lower(): value for key, value in right.attrib.items()}
    for key, value in left_attributes.items():
        if key not in right_attributes:
            differences.append(Difference("xml", f"{child_path}@{key}", value, "", "only in A"))
        elif right_attributes[key] != value:
            differences.append(
                Difference("xml", f"{child_path}@{key}", value, right_attributes[key], "")
            )
        else:
            similarities.append(Similarity("xml", f"{child_path}@{key}", value))
    for key, value in right_attributes.items():
        if key not in left_attributes:
            differences.append(Difference("xml", f"{child_path}@{key}", "", value, "only in B"))

    left_text = (left.text or "").strip()
    right_text = (right.text or "").strip()
    if left_text != right_text:
        differences.append(Difference("xml", child_path, left_text, right_text, "the text changed"))
    elif left_text:
        similarities.append(Similarity("xml", child_path, left_text))

    left_children = list(left)
    right_children = list(right)
    right_by_tag: dict[str, list[ElementTree.Element]] = {}
    for child in right_children:
        right_by_tag.setdefault(tag_of(child), []).append(child)
    used: set[int] = set()
    for child in left_children:
        bucket = right_by_tag.get(tag_of(child), [])
        partner = None
        for candidate in bucket:
            if id(candidate) not in used:
                partner = candidate
                used.add(id(candidate))
                break
        if partner is None:
            differences.append(
                Difference(
                    "xml", f"{child_path}/{tag_of(child)}", _xml_text(child), "", "only in A"
                )
            )
            continue
        sub_diff, sub_same = _xml_walk(child, partner, child_path)
        differences.extend(sub_diff)
        similarities.extend(sub_same)
    for child in right_children:
        if id(child) not in used:
            differences.append(
                Difference(
                    "xml", f"{child_path}/{tag_of(child)}", "", _xml_text(child), "only in B"
                )
            )
    return differences, similarities


def _xml_text(element: ElementTree.Element) -> str:
    try:
        return ElementTree.tostring(element, encoding="unicode").strip()
    except TypeError:
        return element.tag


# ---------------------------------------------------------------------- html


class _HtmlReader(HTMLParser):
    """Turn a page into a list of tags, attributes and pieces of text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.items: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        rendered = " ".join(f"{name}={value or ''}" for name, value in attrs)
        self.items.append(("tag", tag, rendered))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        self.items.append(("end", tag, ""))

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self.items.append(("text", "", text))


def _html_items(text: str) -> list[tuple[str, str, str]]:
    reader = _HtmlReader()
    try:
        reader.feed(text)
        reader.close()
    except Exception:  # noqa: BLE001 - a broken page still gives what was read
        pass
    return reader.items


def _html_walk(
    left: list[tuple[str, str, str]],
    right: list[tuple[str, str, str]],
) -> tuple[list[Difference], list[Similarity]]:
    """Compare two pages, tag by tag."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []
    matcher = difflib.SequenceMatcher(
        None,
        [f"{kind}:{name}:{value}" for kind, name, value in left],
        [f"{kind}:{name}:{value}" for kind, name, value in right],
        autojunk=False,
    )
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for index in range(i1, i2):
                kind, name, value = left[index]
                similarities.append(Similarity("html", name or "text", value))
            continue
        removed = left[i1:i2]
        added = right[j1:j2]
        for index in range(max(len(removed), len(added))):
            item_a = removed[index] if index < len(removed) else None
            item_b = added[index] if index < len(added) else None
            if item_a is None:
                kind, name, value = item_b
                differences.append(
                    Difference("html", name or "text", "", value, f"only in B ({kind})")
                )
                continue
            if item_b is None:
                kind, name, value = item_a
                differences.append(
                    Difference("html", name or "text", value, "", f"only in A ({kind})")
                )
                continue
            if item_a[0] == item_b[0] and item_a[1] == item_b[1]:
                differences.append(
                    Difference("html", item_a[1] or "text", item_a[2], item_b[2], "it changed")
                )
                continue
            differences.append(
                Difference("html", item_a[1] or "text", item_a[2], "", f"only in A ({item_a[0]})")
            )
            differences.append(
                Difference("html", item_b[1] or "text", "", item_b[2], f"only in B ({item_b[0]})")
            )
    return differences, similarities


# -------------------------------------------------------------------- binary


def _binary_differences(left: bytes, right: bytes) -> tuple[list[Difference], list[Similarity]]:
    """The bytes that are not the same, with the place they sit at."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []
    length = min(len(left), len(right))
    reported = 0
    for index in range(length):
        if left[index] == right[index]:
            continue
        if reported < 64:
            differences.append(
                Difference(
                    "byte",
                    f"offset {index}",
                    f"{left[index]:02x}",
                    f"{right[index]:02x}",
                    "",
                )
            )
        reported += 1
    if reported > 64:
        differences.append(
            Difference("byte", "the rest", f"{reported - 64} more", f"{reported - 64} more", "")
        )
    if len(left) > length:
        differences.append(
            Difference("byte", "the end", f"{len(left) - length} bytes", "", "only in A")
        )
    if len(right) > length:
        differences.append(
            Difference("byte", "the end", "", f"{len(right) - length} bytes", "only in B")
        )
    if reported == 0 and len(left) == len(right):
        similarities.append(Similarity("byte", "the whole file", f"{length} bytes"))
    return differences, similarities


# -------------------------------------------------------------------- tokens


def _token_differences(
    left: list[Token],
    right: list[Token],
) -> tuple[list[Difference], list[Similarity]]:
    """Which tokens are the same and which are not."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []
    right_values = {token.value for token in right}
    left_values = {token.value for token in left}
    for token in left:
        if token.value in right_values:
            similarities.append(Similarity("token", token.name, token.value))
        else:
            differences.append(Difference("token", token.name, token.value, "", "only in A"))
    for token in right:
        if token.value not in left_values:
            differences.append(Difference("token", token.name, "", token.value, "only in B"))
    return differences, similarities


# ------------------------------------------------------------------- guessing


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    control = sum(1 for byte in sample if byte < 32 and byte not in (9, 10, 13))
    return control / len(sample) > 0.05


def guess_kind(left: bytes, right: bytes, content_type: str = "") -> str:
    """What the two things most likely are."""
    lowered = content_type.lower()
    if "json" in lowered:
        return "json"
    if "xml" in lowered:
        return "xml"
    if "html" in lowered:
        return "html"
    if _looks_binary(left) or _looks_binary(right):
        return "binary"
    for data in (left, right):
        try:
            text = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            continue
        if not text:
            continue
        if text.startswith("{") or text.startswith("["):
            try:
                json.loads(text)
            except ValueError:
                pass
            else:
                return "json"
        if text.startswith("<"):
            if _XML_DECL.match(text) or "<?xml" in text[:200].lower():
                return "xml"
            return "html"
    return "text"


# ------------------------------------------------------------------- headers


def _header_differences(
    left: list[tuple[str, str]],
    right: list[tuple[str, str]],
) -> tuple[list[Difference], list[Similarity]]:
    """The headers that are not the same, and the ones that are."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []
    left_map: dict[str, list[str]] = {}
    right_map: dict[str, list[str]] = {}
    for name, value in left:
        left_map.setdefault(name.lower(), []).append(value)
    for name, value in right:
        right_map.setdefault(name.lower(), []).append(value)
    for name, values in left_map.items():
        other = right_map.get(name)
        if other is None:
            differences.append(Difference("header", name, ", ".join(values), "", "only in A"))
        elif other != values:
            differences.append(Difference("header", name, ", ".join(values), ", ".join(other), ""))
        else:
            similarities.append(Similarity("header", name, ", ".join(values)))
    for name, values in right_map.items():
        if name not in left_map:
            differences.append(Difference("header", name, "", ", ".join(values), "only in B"))
    return differences, similarities


# ------------------------------------------------------------------ messages


@dataclass
class Message:
    """A message that was taken apart: the head and the body."""

    start_line: str
    headers: list[tuple[str, str]]
    body: bytes


def _split_message(raw: bytes) -> Message:
    """Take a raw message apart at the first empty line."""
    head, _, body = raw.partition(b"\r\n\r\n")
    if not body:
        head, _, body = raw.partition(b"\n\n")
    text = head.decode("latin-1", "replace")
    lines = text.replace("\r\n", "\n").split("\n")
    start_line = lines[0].strip() if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        headers.append((name.strip(), value.strip()))
    return Message(start_line=start_line, headers=headers, body=body)


def _message_differences(
    left: Message,
    right: Message,
    kind: str,
) -> tuple[list[Difference], list[Similarity], str]:
    """Compare two messages: the start line, the headers and the body."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []

    if left.start_line != right.start_line:
        differences.append(
            Difference("line", "the first line", left.start_line, right.start_line, "")
        )
    else:
        similarities.append(Similarity("line", "the first line", left.start_line))

    header_diff, header_same = _header_differences(left.headers, right.headers)
    differences.extend(header_diff)
    similarities.extend(header_same)

    body_kind = kind if kind in {"json", "xml", "html", "text", "binary"} else "auto"
    body = compare_bytes(left.body, right.body, body_kind)
    for difference in body.differences:
        difference.kind = f"body.{difference.kind}"
    for similarity in body.similarities:
        similarity.kind = f"body.{similarity.kind}"
    differences.extend(body.differences)
    similarities.extend(body.similarities)
    return differences, similarities, body.kind


# ------------------------------------------------------------------ the api


def compare_bytes(left: bytes, right: bytes, kind: str = "auto") -> Comparison:
    """Compare two pieces of data and say what is different."""
    if kind == "auto":
        kind = guess_kind(left, right)
    comparison = Comparison(kind=kind, left_size=len(left), right_size=len(right))

    if kind in {"request", "response"}:
        message_left = _split_message(left)
        message_right = _split_message(right)
        differences, similarities, body_kind = _message_differences(
            message_left, message_right, kind
        )
        comparison.differences = differences
        comparison.similarities = similarities
        comparison.rows = diff_lines(
            left.decode("utf-8", "replace"), right.decode("utf-8", "replace")
        )
        comparison.identical = not differences
        comparison.summary = _summary(comparison)
        comparison.kind = f"{kind} ({body_kind})"
        return comparison

    if kind == "binary":
        differences, similarities = _binary_differences(left, right)
        comparison.differences = differences
        comparison.similarities = similarities
        comparison.rows = diff_lines(
            left[:4096].decode("latin-1", "replace"), right[:4096].decode("latin-1", "replace")
        )
        comparison.identical = not differences
        comparison.summary = _summary(comparison)
        return comparison

    left_text = left.decode("utf-8", "replace")
    right_text = right.decode("utf-8", "replace")
    comparison.rows = diff_lines(left_text, right_text)

    if kind == "json":
        differences, similarities = _compare_json_text(left_text, right_text)
    elif kind == "xml":
        differences, similarities = _compare_xml_text(left_text, right_text)
    elif kind == "html":
        differences, similarities = _html_walk(_html_items(left_text), _html_items(right_text))
    elif kind == "tokens":
        differences, similarities = _token_differences(
            extract_tokens(left_text), extract_tokens(right_text)
        )
    else:
        differences, similarities = _line_differences(comparison.rows)

    comparison.differences = differences
    comparison.similarities = similarities
    comparison.identical = not differences
    comparison.summary = _summary(comparison)
    return comparison


def _compare_json_text(left: str, right: str) -> tuple[list[Difference], list[Similarity]]:
    try:
        left_value = json.loads(left)
    except ValueError:
        left_value = None
    try:
        right_value = json.loads(right)
    except ValueError:
        right_value = None
    if left_value is None and right_value is None:
        differences = []
        if left.strip() != right.strip():
            differences.append(Difference("json", "the whole body", left, right, "not JSON"))
        return differences, []
    if left_value is None or right_value is None:
        return [Difference("json", "the whole body", left, right, "one side is not JSON")], []
    return _json_walk(left_value, right_value, "")


def _compare_xml_text(left: str, right: str) -> tuple[list[Difference], list[Similarity]]:
    try:
        left_root = ElementTree.fromstring(left)
    except ElementTree.ParseError:
        left_root = None
    try:
        right_root = ElementTree.fromstring(right)
    except ElementTree.ParseError:
        right_root = None
    if left_root is None and right_root is None:
        if left.strip() != right.strip():
            return [Difference("xml", "the whole body", left, right, "not XML")], []
        return [], []
    if left_root is None or right_root is None:
        return [Difference("xml", "the whole body", left, right, "one side is not XML")], []
    return _xml_walk(left_root, right_root, "")


def compare_documents(
    left: str,
    right: str,
    kind: str = "auto",
    content_type: str = "",
) -> Comparison:
    """Compare two documents that were given as text."""
    left_bytes = left.encode("utf-8", "surrogatepass")
    right_bytes = right.encode("utf-8", "surrogatepass")
    if kind == "auto":
        kind = guess_kind(left_bytes, right_bytes, content_type)
    return compare_bytes(left_bytes, right_bytes, kind)


def _summary(comparison: Comparison) -> str:
    """A sentence about what the comparison found."""
    if comparison.identical:
        return "The two are the same."
    count = len(comparison.differences)
    noun = "difference" if count == 1 else "differences"
    if comparison.left_size != comparison.right_size:
        return (
            f"{count} {noun}, and the sizes are {comparison.left_size} and "
            f"{comparison.right_size} bytes."
        )
    return f"{count} {noun}."


def _content_type(message: dict[str, Any]) -> str:
    """The content type of a message, as it was set."""
    headers = message.get("headers") or {}
    if isinstance(headers, dict):
        for name, values in headers.items():
            if name.lower() == "content-type" and values:
                first = values[0]
                return first if isinstance(first, str) else str(first)
    return ""


def document_from_exchange(exchange: dict[str, Any], part: str) -> tuple[bytes, str]:
    """The bytes of the part of an exchange that should be compared.

    The raw request and the raw response are text, and a body that is not
    text keeps its bytes, so a file can be compared as it was sent.
    """
    request = exchange.get("request") or {}
    response = exchange.get("response") or {}

    if part == "request":
        raw = request.get("raw") or ""
        return raw.encode("utf-8", "surrogatepass"), _content_type(request)
    if part == "response" and response:
        raw = response.get("raw") or ""
        return raw.encode("utf-8", "surrogatepass"), _content_type(response)

    source = response or request
    body = source.get("body") or ""
    encoding = source.get("body_encoding") or ""
    if encoding == "base64":
        try:
            return base64.b64decode(body), _content_type(source)
        except (ValueError, TypeError):
            pass
    return body.encode("utf-8", "surrogatepass"), _content_type(source)


def _line_differences(rows: list[DiffRow]) -> tuple[list[Difference], list[Similarity]]:
    """The lines that are not the same, taken from the side by side view."""
    differences: list[Difference] = []
    similarities: list[Similarity] = []
    number = 0
    for row in rows:
        number += 1
        if row.kind == "same":
            if row.left:
                similarities.append(Similarity("line", f"line {number}", row.left))
            continue
        if row.kind == "different":
            differences.append(
                Difference("line", f"line {number}", row.left or "", row.right or "", "")
            )
        elif row.kind == "added":
            differences.append(
                Difference("line", f"line {number}", "", row.right or "", "only in B")
            )
        else:
            differences.append(
                Difference("line", f"line {number}", row.left or "", "", "only in A")
            )
    return differences, similarities


class Comparer:
    """The comparer as the API and the interface use it."""

    def compare(
        self,
        left: str,
        right: str,
        kind: str = "auto",
        content_type: str = "",
    ) -> dict[str, Any]:
        """Compare two documents."""
        return compare_documents(left, right, kind, content_type).to_dict()

    def compare_bytes(
        self,
        left: bytes,
        right: bytes,
        kind: str = "auto",
    ) -> dict[str, Any]:
        """Compare two pieces of data."""
        return compare_bytes(left, right, kind).to_dict()

    def catalog(self) -> dict[str, Any]:
        """The kinds of comparison the comparer knows."""
        return {"kinds": list(COMPARISON_KINDS)}

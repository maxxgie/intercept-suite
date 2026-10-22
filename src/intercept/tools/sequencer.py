"""The sequencer.

The sequencer answers one question: is this token random? A token that is
not random can be guessed, so the answer matters for session identifiers,
anti-CSRF tokens, API keys, password reset tokens and the signature of a JSON
web token.

The tool works on a list of samples of the same token. Every sample is
measured on its own and the samples are looked at together, because a token
can look random while the way it is built is not: a counter, a timestamp or a
fixed prefix with a small random part.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "Sequencer",
    "SequencerReport",
    "TokenSample",
    "TOKEN_KINDS",
    "chi_square",
    "detect_kind",
    "monte_carlo_pi",
    "serial_correlation",
    "shannon_entropy",
]

#: The kinds of token the sequencer knows.
TOKEN_KINDS: tuple[str, ...] = (
    "session",
    "jwt",
    "csrf",
    "api-key",
    "password-reset",
    "nonce",
    "unknown",
)

#: The secrets that are used over and over again.
WEAK_SECRETS: tuple[str, ...] = (
    "secret",
    "password",
    "changeme",
    "1234567890",
    "supersecret",
    "your-256-bit-secret",
    "jwtsecret",
    "key",
    "test",
    "development",
)

_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_NUMERIC = re.compile(r"^\d+$")
_DIGITS = re.compile(r"\d{10}")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

#: The names that hold a token, used to guess what a token is.
NAME_HINTS: dict[str, tuple[str, ...]] = {
    "session": ("jsessionid", "phpsessid", "sessionid", "session", "sid", "sess"),
    "csrf": ("csrf", "xsrf", "_token", "authenticity_token", "requesttoken"),
    "api-key": ("api_key", "apikey", "api_token", "access_token", "accesstoken", "bearer"),
    "password-reset": ("reset", "password_reset", "reset_token", "resetkey", "recovery"),
    "nonce": ("nonce", "one_time", "otp", "state"),
}


# --------------------------------------------------------------- statistics


def shannon_entropy(data: bytes) -> float:
    """The entropy of the data in bits per byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _gamma_series(a: float, x: float) -> float:
    """The series form of the regularized lower incomplete gamma function."""
    total = 1.0 / a
    delta = total
    for index in range(1, 1000):
        ap = a + index
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-15:
            break
    return total * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _gamma_continued(a: float, x: float) -> float:
    """The continued fraction form of the regularized upper incomplete gamma."""
    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for index in range(1, 1000):
        an = -index * (index - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def _gamma_upper(a: float, x: float) -> float:
    """The regularized upper incomplete gamma function."""
    if x <= 0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gamma_series(a, x)
    return _gamma_continued(a, x)


def chi_square(data: bytes) -> tuple[float, float]:
    """The chi square statistic of the byte distribution and its p value.

    A small p value means the bytes are spread out more evenly than chance
    would explain, which is what a broken generator looks like. The buckets
    are the values that actually show up, so a token that only uses sixteen
    characters is measured against sixteen buckets and not against 256.
    """
    if not data:
        return 0.0, 1.0
    counts = Counter(data)
    buckets = len(counts)
    if buckets <= 1:
        # Every byte is the same, which no random data does.
        return float(len(data)), 0.0
    expected = len(data) / buckets
    statistic = sum((count - expected) ** 2 / expected for count in counts.values())
    p_value = _gamma_upper((buckets - 1) / 2, statistic / 2)
    return statistic, p_value


def serial_correlation(data: bytes) -> float:
    """How much a byte depends on the byte before it.

    The measure is the lag one autocorrelation of the byte values. It is
    near zero when the bytes do not know each other, which is what random
    data looks like, and near one when each byte follows from the last.
    """
    length = len(data)
    if length < 2:
        return 0.0
    values = list(data)
    mean = sum(values) / length
    deviation = [value - mean for value in values]
    total = sum(value * value for value in deviation)
    if total == 0:
        # Every byte is the same, so the next one is known without guessing.
        return 1.0
    numerator = sum(deviation[index] * deviation[index - 1] for index in range(1, length))
    return numerator / total


def monte_carlo_pi(data: bytes) -> float:
    """The value of pi that the data estimates.

    The bytes are read as pairs of coordinates and counted as points in a
    square. Random data gives a value near 3.14159. The bytes are ranked
    first, so the test also works for a token that is written in letters
    instead of raw bytes.
    """
    length = len(data)
    pairs = length // 2
    if pairs == 0:
        return 0.0
    ranks = {value: rank for rank, value in enumerate(sorted(set(data)))}
    scale = len(ranks)
    if scale < 2:
        return 0.0
    inside = 0
    for index in range(pairs):
        x = ranks[data[index * 2]]
        y = ranks[data[index * 2 + 1]]
        if x * x + y * y < scale * scale:
            inside += 1
    return 4.0 * inside / pairs


def bit_bias(data: bytes) -> float:
    """How far the bits of the data are from being even."""
    ones = 0
    total = 0
    for byte in data:
        ones += bin(byte).count("1")
        total += 8
    if total == 0:
        return 0.0
    return abs(ones / total - 0.5)


def longest_run(data: bytes) -> int:
    """The longest run of the same byte in the data."""
    best = 0
    current = 0
    previous = None
    for byte in data:
        if byte == previous:
            current += 1
        else:
            current = 1
            previous = byte
        best = max(best, current)
    return best


# -------------------------------------------------------------------- kinds


def detect_kind(value: str, name: str = "") -> str:
    """What kind of token a value looks like."""
    text = value.strip()
    lowered = name.lower()
    for kind, hints in NAME_HINTS.items():
        if any(hint in lowered for hint in hints):
            return kind
    if _JWT.match(text) and text.count(".") == 2:
        return "jwt"
    return "unknown"


def _decode_segment(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return b""


def _entropy_of_text(text: str) -> float:
    return shannon_entropy(text.encode("utf-8", "replace"))


def _common_affix(values: list[str], from_end: bool = False) -> str:
    """The part that every sample starts with (or ends with)."""
    if not values:
        return ""
    shortest = min(len(value) for value in values)
    length = 0
    for index in range(shortest):
        piece = values[0][-index - 1] if from_end else values[0][index]
        if all((value[-index - 1] if from_end else value[index]) == piece for value in values):
            length += 1
        else:
            break
    if from_end:
        return values[0][-length:] if length else ""
    return values[0][:length]


def _random_parts(values: list[str], prefix: str, suffix: str) -> list[str]:
    """The part of every sample that is not the part they all share.

    A token that starts with the same text every time is only random after
    that text, so the measures are taken over what is left. When the samples
    are the same all the way through there is nothing left, and the samples
    themselves are measured.
    """
    parts = []
    for value in values:
        start = len(prefix)
        end = len(value) - len(suffix)
        if end < start:
            end = start
        parts.append(value[start:end])
    if not any(part for part in parts):
        return list(values)
    return parts


def _looks_sequential(values: list[str]) -> bool:
    """Whether the samples are a counter rather than random values."""
    numbers: list[int] = []
    for value in values:
        if not _NUMERIC.match(value):
            return False
        numbers.append(int(value))
    if len(numbers) < 3:
        return False
    steps = {numbers[index + 1] - numbers[index] for index in range(len(numbers) - 1)}
    return len(steps) == 1 and 0 not in steps


def _decode_hex(value: str) -> bytes:
    """The bytes of a token that is written in hexadecimal."""
    text = value.strip()
    if len(text) % 2 or not _HEX.match(text):
        return b""
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def _embedded_timestamp(values: list[str]) -> int:
    """A Unix time that is hidden in the samples.

    A time that is really part of the token sits at the same place in every
    sample, so the bytes are looked at as they were written down. The time
    is only reported when the numbers agree, when they are close to each
    other, and when they either come near the present or climb the way a
    clock climbs.
    """
    now = int(time.time())
    low = 946684800  # the year 2000
    high = now + 10 * 365 * 24 * 3600
    close = 2 * 365 * 24 * 3600
    if len(values) < 3:
        return 0

    groups: list[list[bytes]] = []
    decoded = [_decode_segment(value) for value in values]
    if all(decoded):
        groups.append(decoded)
    hexed = [_decode_hex(value) for value in values]
    if all(hexed):
        groups.append(hexed)

    # A time that is written out in plain digits comes before the search in
    # the bytes, because that is what the reader meant by it.
    rows = []
    for value in values:
        found = [
            int(match.group())
            for match in _DIGITS.finditer(value)
            if low < int(match.group()) < high
        ]
        rows.append(found)
    if rows and all(rows):
        first = rows[0][0]
        if all(any(abs(number - first) <= 60 * 60 * 24 for number in row) for row in rows):
            return first

    for group in groups:
        length = min(len(raw) for raw in group)
        for offset in range(length):
            for width in (4, 8):
                if offset + width > length:
                    continue
                numbers = [int.from_bytes(raw[offset : offset + width], "big") for raw in group]
                if not all(low < number < high for number in numbers):
                    continue
                if any(abs(number - numbers[0]) > 60 * 60 * 24 for number in numbers):
                    continue
                near = all(abs(number - now) < close for number in numbers)
                climbs = all(
                    numbers[index] <= numbers[index + 1] for index in range(len(numbers) - 1)
                )
                spread = numbers[-1] - numbers[0]
                if not near and not (climbs and spread >= 60):
                    # The numbers only look like a time by accident.
                    continue
                return numbers[0]
    return 0


# ------------------------------------------------------------------- report


@dataclass
class TokenSample:
    """One token that was collected."""

    value: str
    kind: str = "unknown"
    source: str = ""
    length: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "kind": self.kind,
            "source": self.source,
            "length": self.length,
        }


@dataclass
class SequencerReport:
    """What the sequencer found out about a set of samples."""

    kind: str = "unknown"
    samples: int = 0
    length: int = 0
    #: The length of the part that changes between the samples.
    random_length: int = 0
    unique: int = 0
    verdict: str = "unknown"
    score: float = 0.0
    entropy: float = 0.0
    entropy_per_character: float = 0.0
    expected_entropy: float = 0.0
    #: The number of bits one token carries.
    total_bits: float = 0.0
    chi_square: float = 0.0
    chi_square_p: float = 1.0
    serial_correlation: float = 0.0
    monte_carlo_pi: float = 0.0
    bit_bias: float = 0.0
    unique_bytes: int = 0
    longest_run: int = 0
    common_prefix: str = ""
    common_suffix: str = ""
    sequential: bool = False
    duplicates: list[str] = field(default_factory=list)
    embedded_timestamp: int = 0
    characters: dict[str, int] = field(default_factory=dict)
    jwt: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "samples": self.samples,
            "length": self.length,
            "random_length": self.random_length,
            "unique": self.unique,
            "verdict": self.verdict,
            "score": round(self.score, 3),
            "entropy": round(self.entropy, 3),
            "entropy_per_character": round(self.entropy_per_character, 3),
            "expected_entropy": round(self.expected_entropy, 3),
            "total_bits": round(self.total_bits, 2),
            "chi_square": round(self.chi_square, 3),
            "chi_square_p": round(self.chi_square_p, 6),
            "serial_correlation": round(self.serial_correlation, 4),
            "monte_carlo_pi": round(self.monte_carlo_pi, 4),
            "bit_bias": round(self.bit_bias, 4),
            "unique_bytes": self.unique_bytes,
            "longest_run": self.longest_run,
            "common_prefix": self.common_prefix,
            "common_suffix": self.common_suffix,
            "sequential": self.sequential,
            "duplicates": list(self.duplicates),
            "embedded_timestamp": self.embedded_timestamp,
            "characters": dict(self.characters),
            "jwt": self.jwt,
            "notes": list(self.notes),
        }


class Sequencer:
    """Measures the randomness of a set of tokens."""

    def analyse(
        self,
        samples: list[str],
        kind: str = "auto",
        name: str = "",
    ) -> SequencerReport:
        """The report for the samples."""
        values = [value.strip() for value in samples if value and value.strip()]
        report = SequencerReport()
        report.samples = len(values)
        if not values:
            report.notes.append("There are no samples to look at.")
            return report

        report.kind = kind if kind and kind != "auto" else detect_kind(values[0], name)
        report.unique = len(set(values))
        report.length = min(len(value) for value in values)
        report.common_prefix = _common_affix(values)
        report.common_suffix = _common_affix(values, from_end=True)

        counts = Counter(values)
        report.duplicates = [value for value, count in counts.items() if count > 1]

        # The part that every sample shares is not random, so the measures
        # are taken over the part that changes.
        parts = _random_parts(values, report.common_prefix, report.common_suffix)
        report.random_length = min(len(part) for part in parts) if parts else 0
        text = "".join(parts)
        joined = text.encode("utf-8", "replace")
        report.entropy = shannon_entropy(joined)
        report.entropy_per_character = _entropy_of_text(text)
        report.unique_bytes = len(set(joined))
        # The most the characters that show up could carry at all.
        report.expected_entropy = math.log2(report.unique_bytes) if report.unique_bytes > 1 else 0.0
        # The number of bits an attacker has to guess.
        report.total_bits = report.entropy_per_character * report.random_length
        # The characters that only shape the token say nothing about how
        # random it is, so they are left out of the distribution.
        shaped = bytes(byte for byte in joined if chr(byte) not in "-_.")
        report.chi_square, report.chi_square_p = chi_square(shaped or joined)
        report.serial_correlation = serial_correlation(joined)
        # The monte carlo test needs a wide alphabet and enough pairs, or the
        # answer is an artefact of the grid and not of the data.
        if report.unique_bytes >= 32 and len(joined) // 2 >= 200:
            report.monte_carlo_pi = monte_carlo_pi(joined)
        report.bit_bias = bit_bias(joined)
        report.longest_run = longest_run(joined)
        report.characters = {chr(byte): count for byte, count in sorted(Counter(joined).items())}
        report.sequential = _looks_sequential(values)
        if len(set(values)) >= 3:
            report.embedded_timestamp = _embedded_timestamp(values)

        if report.kind == "jwt":
            report.jwt = self._analyse_jwt(values)

        self._judge(report, values)
        return report

    # ------------------------------------------------------------------ jwt

    def _analyse_jwt(self, values: list[str]) -> dict[str, Any]:
        """What the JSON web tokens of the samples tell us."""
        parts = values[0].split(".")
        result: dict[str, Any] = {"segments": len(parts)}
        if len(parts) != 3:
            result["error"] = "the token does not have three parts"
            return result

        header_raw = _decode_segment(parts[0])
        payload_raw = _decode_segment(parts[1])
        signature = parts[2]
        result["signature_length"] = len(signature)
        result["signature_entropy"] = round(shannon_entropy(signature.encode()), 3)
        result["payload_entropy"] = round(shannon_entropy(payload_raw), 3)

        try:
            result["header"] = json.loads(header_raw.decode("utf-8", "replace"))
        except ValueError:
            result["header"] = {}
        try:
            result["payload"] = json.loads(payload_raw.decode("utf-8", "replace"))
        except ValueError:
            result["payload"] = {}

        algorithm = str(result["header"].get("alg", ""))
        result["algorithm"] = algorithm
        result["forgable"] = False
        if algorithm.lower() == "none":
            result["forgable"] = True
            result["reason"] = "the token says that it is not signed"
        else:
            for secret in WEAK_SECRETS:
                if self._signs(parts, secret):
                    result["forgable"] = True
                    result["secret"] = secret
                    result["reason"] = f"the signature can be made with the secret {secret!r}"
                    break

        claims = result["payload"] if isinstance(result["payload"], dict) else {}
        result["claims"] = sorted(claims)
        predictable = [
            name for name in ("iat", "nbf", "exp", "sub", "role", "user_id") if name in claims
        ]
        result["predictable_claims"] = predictable
        return result

    def _signs(self, parts: list[str], secret: str) -> bool:
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        signature = parts[2]
        for algorithm in ("sha256", "sha384", "sha512"):
            digest = hmac.new(secret.encode(), signing_input, getattr(hashlib, algorithm)).digest()
            expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            if hmac.compare_digest(expected, signature):
                return True
        return False

    # --------------------------------------------------------------- verdict

    def _judge(self, report: SequencerReport, values: list[str]) -> None:
        """Turn the measures into a verdict and the reasons for it."""
        notes: list[str] = []
        score = 1.0

        if report.samples < 3:
            notes.append("There are fewer than three samples, so the measures are only a hint.")
            score -= 0.1

        if report.duplicates:
            notes.append(
                f"{len(report.duplicates)} of the samples are the same, so the token is "
                "repeated instead of being made again."
            )
            score -= 0.5

        if report.sequential:
            notes.append("The samples follow each other in steps, so this is a counter.")
            score -= 0.7

        if report.embedded_timestamp:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(report.embedded_timestamp))
            notes.append(
                f"The samples hold the time {stamp}, so the token is built from the clock."
            )
            score -= 0.7

        if report.common_prefix and len(report.common_prefix) >= 4:
            notes.append(
                f"Every sample starts with {report.common_prefix!r}, so only the rest is random."
            )
            score -= 0.2

        ratio = (
            report.entropy_per_character / report.expected_entropy
            if report.expected_entropy
            else 0.0
        )
        if ratio < 0.5:
            notes.append(
                f"The entropy is {report.entropy_per_character:.2f} bits per character, "
                f"where the characters of the token could carry "
                f"{report.expected_entropy:.2f}. That is far too little for a random value."
            )
            score -= 0.5
        elif ratio < 0.85:
            notes.append(
                f"The entropy is {report.entropy_per_character:.2f} bits per character, "
                f"where the characters of the token could carry "
                f"{report.expected_entropy:.2f}. That is less than random data."
            )
            score -= 0.2

        if report.total_bits < 32:
            notes.append(
                f"A token carries {report.total_bits:.0f} bits, which is too few to be safe "
                "against guessing."
            )
            score -= 0.35
        elif report.total_bits < 64:
            notes.append(
                f"A token carries {report.total_bits:.0f} bits, which is on the short side."
            )
            score -= 0.1

        if report.bit_bias > 0.1:
            notes.append(f"The bits are not even: {report.bit_bias:.2f} away from a fair split.")
            score -= 0.2

        if report.serial_correlation > 0.25:
            notes.append(
                f"The bytes depend on each other (correlation {report.serial_correlation:.2f}), "
                "which points at a generator that repeats itself."
            )
            score -= 0.3

        structured = all(_UUID.match(value) for value in values)
        if report.chi_square_p < 0.01 and not structured:
            notes.append(
                "The characters are not spread out the way chance would spread them, so a "
                "generator that always picks from the same values looks like this."
            )
            score -= 0.2

        if report.monte_carlo_pi and abs(report.monte_carlo_pi - math.pi) > 0.3:
            notes.append(
                f"The data estimates pi as {report.monte_carlo_pi:.3f}, which is not the "
                "3.14159 that random data gives."
            )
            score -= 0.2

        jwt = report.jwt
        if jwt.get("forgable"):
            notes.append(f"The token can be forged: {jwt.get('reason')}.")
            score -= 0.9
        if jwt.get("predictable_claims"):
            notes.append(
                "The claims "
                + ", ".join(jwt["predictable_claims"])
                + " hold values that can be guessed."
            )
            score -= 0.15

        report.score = max(0.0, min(1.0, score))
        if report.score >= 0.75:
            report.verdict = "random"
        elif report.score >= 0.4:
            report.verdict = "weak"
        else:
            report.verdict = "predictable"
        report.notes = notes

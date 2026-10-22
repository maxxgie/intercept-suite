"""The decoder.

The decoder turns a value into something a person can read, and back again. It
knows the encodings that turn up in web traffic: percent encoding, HTML
entities, base64, base32, hexadecimal, ASCII and binary codes, gzip and deflate,
unicode escapes and JSON web tokens. It also recognises the hashes that show up
in password databases and in the headers of a server.

Three things are on top of the plain conversions:

* **hash generation**, which digests a value with the algorithm that is asked
  for, with or without a key for the keyed ones;
* **smart decode**, which tries every decoder and ranks the answers by how
  much they look like something a person would have written;
* **chained transforms**, which run several conversions one after the other, so
  a value that was base64 encoded and then url encoded can be taken apart in
  one go.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import html
import json
import re
import zlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote

__all__ = [
    "Decoder",
    "DecoderError",
    "DecodeResult",
    "HashCandidate",
    "Transform",
    "HASH_ALGORITHMS",
    "TRANSFORM_KINDS",
    "decode",
    "encode",
    "identify_hash",
    "make_hash",
    "run_chain",
    "smart_decode",
]


class DecoderError(ValueError):
    """The value could not be turned into what was asked for."""


#: The conversions the decoder knows.
TRANSFORM_KINDS: tuple[str, ...] = (
    "url",
    "html",
    "base64",
    "base32",
    "hex",
    "ascii",
    "binary",
    "gzip",
    "deflate",
    "unicode",
    "jwt",
    "hashes",
)

#: The labels the interface shows.
KIND_LABELS: dict[str, str] = {
    "url": "URL",
    "html": "HTML",
    "base64": "Base64",
    "base32": "Base32",
    "hex": "Hex",
    "ascii": "ASCII",
    "binary": "Binary",
    "gzip": "Gzip",
    "deflate": "Deflate",
    "unicode": "Unicode",
    "jwt": "JWT",
    "hashes": "Hashes",
}

#: The digests that can be made.
HASH_ALGORITHMS: tuple[str, ...] = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "blake2b",
    "blake2s",
    "crc32",
    "adler32",
    "hmac-md5",
    "hmac-sha1",
    "hmac-sha256",
    "hmac-sha512",
)

#: The algorithms that need a key.
KEYED_ALGORITHMS: tuple[str, ...] = (
    "hmac-md5",
    "hmac-sha1",
    "hmac-sha256",
    "hmac-sha512",
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")
_NUMERIC_RE = re.compile(r"^\d+$")
_UNICODE_ESCAPE_RE = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})")
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}


# ------------------------------------------------------------------ helpers


def _clean(value: str) -> str:
    """The value without the spaces and line breaks that were only layout."""
    return re.sub(r"[\s]+", "", value)


def _to_bytes(value: str) -> bytes:
    return value.encode("utf-8", "surrogatepass")


def _from_bytes(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _printable_ratio(value: str) -> float:
    """How much of the text could be read."""
    if not value:
        return 0.0
    readable = sum(1 for char in value if ord(char) in _PRINTABLE)
    return readable / len(value)


def _is_binary_noise(value: str) -> bool:
    """Whether the text is mostly control characters, which means it is wrong."""
    if not value:
        return False
    control = sum(1 for char in value if ord(char) < 32 and char not in "\t\r\n")
    return control / len(value) > 0.1


# ------------------------------------------------------------------- base64


def _decode_base64(value: str) -> str:
    text = _clean(value)
    if not text:
        raise DecoderError("there is nothing to decode")
    padded = text + "=" * (-len(text) % 4)
    try:
        return _from_bytes(base64.b64decode(padded, validate=True))
    except (binascii.Error, ValueError):
        pass
    try:
        return _from_bytes(base64.urlsafe_b64decode(padded))
    except (binascii.Error, ValueError) as exc:
        raise DecoderError(f"this is not base64: {exc}") from exc


def _encode_base64(value: str) -> str:
    return base64.b64encode(_to_bytes(value)).decode("ascii")


def _decode_base32(value: str) -> str:
    text = _clean(value).upper()
    if not text:
        raise DecoderError("there is nothing to decode")
    padded = text + "=" * (-len(text) % 8)
    try:
        return _from_bytes(base64.b32decode(padded, casefold=True))
    except (binascii.Error, ValueError) as exc:
        raise DecoderError(f"this is not base32: {exc}") from exc


def _encode_base32(value: str) -> str:
    return base64.b32encode(_to_bytes(value)).decode("ascii")


def _decode_hex(value: str) -> str:
    text = _clean(value).replace("0x", "").replace("0X", "")
    if not text:
        raise DecoderError("there is nothing to decode")
    if len(text) % 2:
        raise DecoderError("a hex value has an even number of characters")
    try:
        return _from_bytes(bytes.fromhex(text))
    except ValueError as exc:
        raise DecoderError(f"this is not hex: {exc}") from exc


def _encode_hex(value: str) -> str:
    return _to_bytes(value).hex()


# ------------------------------------------------------------------- ascii


def _code(part: str) -> int:
    """The number a part stands for.

    A part that carries a prefix that says how it is written is read in that
    base, and a part that holds letters is read as hexadecimal. Everything
    else is a plain decimal number.
    """
    cleaned = part.strip()
    lowered = cleaned.lower()
    if lowered.startswith(("0x", "\\x", "\\u")):
        return int(cleaned[2:], 16)
    if lowered.startswith(("u+", "u-")):
        return int(cleaned[2:], 16)
    if _HEX_RE.match(cleaned) and re.search(r"[a-fA-F]", cleaned):
        return int(cleaned, 16)
    return int(cleaned, 10)


def _decode_ascii(value: str) -> str:
    """Turn numbers into the characters they stand for.

    The numbers may be written in decimal (``104``), in hexadecimal
    (``0x68``) or as an escape (``\\x68``), and they may be separated by
    spaces, commas or nothing at all.
    """
    text = value.strip()
    if not text:
        raise DecoderError("there is nothing to decode")
    parts = [part for part in re.split(r"[\s,;]+", text) if part]
    if not parts:
        raise DecoderError("there is nothing to decode")
    codes: list[int] = []
    for part in parts:
        try:
            codes.append(_code(part))
        except ValueError as exc:
            raise DecoderError(f"{part!r} is not a number") from exc
    try:
        return bytes(code % 256 for code in codes).decode("utf-8", "replace")
    except (ValueError, OverflowError) as exc:
        raise DecoderError(str(exc)) from exc


def _encode_ascii(value: str) -> str:
    return " ".join(str(byte) for byte in _to_bytes(value))


# ------------------------------------------------------------------ binary


def _decode_binary(value: str) -> str:
    """Turn a string of ones and zeroes into the bytes it stands for."""
    text = _clean(value)
    if not text:
        raise DecoderError("there is nothing to decode")
    if not set(text) <= {"0", "1"}:
        raise DecoderError("this is not a binary value")
    if len(text) % 8:
        raise DecoderError("a binary value has a multiple of eight digits")
    data = bytearray()
    for index in range(0, len(text), 8):
        data.append(int(text[index : index + 8], 2))
    return _from_bytes(bytes(data))


def _encode_binary(value: str) -> str:
    return " ".join(format(byte, "08b") for byte in _to_bytes(value))


# ----------------------------------------------------------------- unicode


def _decode_unicode(value: str) -> str:
    """Take the escapes apart, or read the code points as they are written."""
    text = value.strip()
    if not text:
        raise DecoderError("there is nothing to decode")
    if "\\u" in text.lower():
        def replace(match: re.Match[str]) -> str:
            code = match.group(1) or match.group(2)
            return chr(int(code, 16))

        return _UNICODE_ESCAPE_RE.sub(replace, text)
    parts = [part for part in re.split(r"[\s,;]+", text) if part]
    codes = []
    for part in parts:
        cleaned = part.strip()
        if cleaned.lower().startswith(("u+", "0x", "u-")):
            cleaned = cleaned[2:]
        try:
            codes.append(int(cleaned, 16) if _HEX_RE.match(cleaned) else int(cleaned, 10))
        except ValueError as exc:
            raise DecoderError(f"{part!r} is not a code point") from exc
    try:
        return "".join(chr(code) for code in codes)
    except (ValueError, OverflowError) as exc:
        raise DecoderError(str(exc)) from exc


def _encode_unicode(value: str) -> str:
    return "".join(f"\\u{ord(char):04x}" for char in value)


# ------------------------------------------------------------------- gzip


def _decode_gzip(value: str) -> str:
    """Take a gzip archive apart.

    The archive is base64, because that is how a compressed body travels in a
    message. Raw bytes are accepted as well when they can be read.
    """
    data = _binary_payload(value)
    try:
        return _from_bytes(gzip.decompress(data))
    except (OSError, EOFError, zlib.error) as exc:
        raise DecoderError(f"this is not a gzip archive: {exc}") from exc


def _encode_gzip(value: str) -> str:
    return base64.b64encode(gzip.compress(_to_bytes(value))).decode("ascii")


def _decode_deflate(value: str) -> str:
    """Take a deflate stream apart, in either of its shapes."""
    data = _binary_payload(value)
    for function in (zlib.decompress, lambda raw: zlib.decompress(raw, -zlib.MAX_WBITS)):
        try:
            return _from_bytes(function(data))
        except zlib.error:
            continue
    raise DecoderError("this is not a deflate stream")


def _encode_deflate(value: str) -> str:
    return base64.b64encode(zlib.compress(_to_bytes(value))).decode("ascii")


def _binary_payload(value: str) -> bytes:
    """The bytes of a value that carries binary data."""
    text = value.strip()
    if not text:
        raise DecoderError("there is nothing to decode")
    if _HEX_RE.match(_clean(text)) and len(_clean(text)) % 2 == 0:
        try:
            return bytes.fromhex(_clean(text))
        except ValueError:
            pass
    cleaned = _clean(text)
    if cleaned and set(cleaned) <= {"0", "1"} and len(cleaned) % 8 == 0:
        return bytes(
            int(cleaned[index : index + 8], 2) for index in range(0, len(cleaned), 8)
        )
    try:
        return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecoderError(f"the archive is not base64 or hex: {exc}") from exc


# --------------------------------------------------------------------- jwt


def _decode_jwt(value: str) -> str:
    """Open a JSON web token and show what is inside it."""
    token = value.strip()
    if token.count(".") != 2:
        raise DecoderError("a JSON web token has three parts")
    header, payload, signature = token.split(".")
    result: dict[str, Any] = {}
    for name, part in (("header", header), ("payload", payload)):
        raw = _b64url_decode(part)
        try:
            result[name] = json.loads(raw)
        except ValueError:
            result[name] = _from_bytes(raw)
    result["signature"] = signature
    result["algorithm"] = str(result["header"].get("alg", "")) if isinstance(
        result["header"], dict
    ) else ""
    return json.dumps(result, indent=2, sort_keys=True)


def _encode_jwt(value: str, secret: str = "") -> str:
    """Make a JSON web token out of a payload."""
    text = value.strip()
    if not text:
        raise DecoderError("there is nothing to sign")
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise DecoderError(f"the payload is not JSON: {exc}") from exc
    header = {"alg": "HS256", "typ": "JWT"}
    if isinstance(payload, dict) and "header" in payload:
        header = payload.pop("header") or header
    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(part: str) -> bytes:
    padded = part + "=" * (-len(part) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise DecoderError(f"this part is not base64: {exc}") from exc


# ------------------------------------------------------------------ hashes


@dataclass
class HashCandidate:
    """A hash that a value could be."""

    name: str
    label: str
    length: int
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "length": self.length,
            "note": self.note,
        }


#: The hashes that are recognised, by the length of their hex form.
_HEX_HASHES: tuple[tuple[str, str, int, str], ...] = (
    ("md5", "MD5", 32, "A plain MD5 digest."),
    ("ntlm", "NTLM", 32, "The same length as MD5, so it cannot be told apart by the length."),
    ("sha1", "SHA-1", 40, "A plain SHA-1 digest."),
    ("sha224", "SHA-224", 56, "A plain SHA-224 digest."),
    ("sha256", "SHA-256", 64, "A plain SHA-256 digest."),
    ("sha384", "SHA-384", 96, "A plain SHA-384 digest."),
    ("sha512", "SHA-512", 128, "A plain SHA-512 digest."),
)


def identify_hash(value: str) -> list[HashCandidate]:
    """The hashes a value could be."""
    text = value.strip()
    found: list[HashCandidate] = []
    if not text:
        return found

    lowered = text.lower()
    if lowered.startswith("$2a$") or lowered.startswith("$2b$") or lowered.startswith("$2y$"):
        found.append(
            HashCandidate("bcrypt", "bcrypt", len(text), "A bcrypt hash, with its salt and cost.")
        )
        return found
    if lowered.startswith("$argon2"):
        found.append(
            HashCandidate("argon2", "Argon2", len(text), "An Argon2 hash.")
        )
        return found
    if lowered.startswith(("pbkdf2_sha", "django_pbkdf2", "scrypt$")):
        found.append(
            HashCandidate("django", "Django", len(text), "A password hash made by Django.")
        )
        return found
    if lowered.startswith("$6$"):
        found.append(HashCandidate("sha512crypt", "sha512crypt", len(text), "A sha512 crypt hash."))
        return found
    if lowered.startswith("$5$"):
        found.append(HashCandidate("sha256crypt", "sha256crypt", len(text), "A sha256 crypt hash."))
        return found
    if lowered.startswith("$1$"):
        found.append(HashCandidate("md5crypt", "md5crypt", len(text), "An md5 crypt hash."))
        return found
    if text.startswith("*") and len(text) == 41 and _HEX_RE.match(text[1:]):
        found.append(
            HashCandidate("mysql", "MySQL", len(text), "A MySQL password hash, with the star.")
        )
        return found

    body = text
    if body.startswith(("0x", "0X")):
        body = body[2:]
    if _HEX_RE.match(body) and len(body) % 2 == 0:
        for name, label, length, note in _HEX_HASHES:
            if len(body) == length:
                found.append(HashCandidate(name, label, length, note))
    return found


def make_hash(value: str, algorithm: str, key: str = "") -> str:
    """Digest a value with the algorithm that is asked for."""
    name = algorithm.strip().lower()
    if name not in HASH_ALGORITHMS:
        raise DecoderError(f"unknown hash {algorithm!r}")
    data = _to_bytes(value)
    if name in KEYED_ALGORITHMS:
        if not key:
            raise DecoderError(f"{name} needs a key")
        digest = {
            "hmac-md5": hashlib.md5,
            "hmac-sha1": hashlib.sha1,
            "hmac-sha256": hashlib.sha256,
            "hmac-sha512": hashlib.sha512,
        }[name]
        return hmac.new(key.encode(), data, digest).hexdigest()
    if name == "crc32":
        return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
    if name == "adler32":
        return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")
    if name == "blake2b":
        return hashlib.blake2b(data).hexdigest()
    if name == "blake2s":
        return hashlib.blake2s(data).hexdigest()
    return hashlib.new(name, data).hexdigest()


# ------------------------------------------------------------------ hashes


def _decode_hashes(value: str) -> str:
    """Show which hashes a value could be."""
    found = identify_hash(value)
    if not found:
        raise DecoderError("this does not look like a hash")
    return json.dumps([candidate.to_dict() for candidate in found], indent=2)


# ----------------------------------------------------------------- the map

#: What each kind does when it is asked to decode and to encode.
_DECODERS: dict[str, Any] = {
    "url": lambda value: unquote(value),
    "html": lambda value: html.unescape(value),
    "base64": _decode_base64,
    "base32": _decode_base32,
    "hex": _decode_hex,
    "ascii": _decode_ascii,
    "binary": _decode_binary,
    "gzip": _decode_gzip,
    "deflate": _decode_deflate,
    "unicode": _decode_unicode,
    "jwt": _decode_jwt,
    "hashes": _decode_hashes,
}

_ENCODERS: dict[str, Any] = {
    "url": lambda value: quote(value, safe=""),
    "html": lambda value: html.escape(value),
    "base64": _encode_base64,
    "base32": _encode_base32,
    "hex": _encode_hex,
    "ascii": _encode_ascii,
    "binary": _encode_binary,
    "gzip": _encode_gzip,
    "deflate": _encode_deflate,
    "unicode": _encode_unicode,
    "jwt": _encode_jwt,
    "hashes": lambda value: make_hash(value, "sha256"),
}


def decode(value: str, kind: str) -> str:
    """Turn a value into something readable."""
    handler = _DECODERS.get(kind)
    if handler is None:
        raise DecoderError(f"unknown decoding {kind!r}")
    if not value:
        raise DecoderError("there is nothing to decode")
    return handler(value)


def encode(value: str, kind: str, options: dict[str, Any] | None = None) -> str:
    """Turn a value into an encoded one."""
    handler = _ENCODERS.get(kind)
    if handler is None:
        raise DecoderError(f"unknown encoding {kind!r}")
    if not value:
        raise DecoderError("there is nothing to encode")
    secret = str((options or {}).get("secret", ""))
    if kind == "jwt":
        return _encode_jwt(value, secret)
    return handler(value)


# ------------------------------------------------------------------ chains


@dataclass
class Transform:
    """One step of a chain."""

    kind: str
    mode: str = "decode"
    options: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "mode": self.mode, "options": dict(self.options)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Transform:
        options = data.get("options") or {}
        return cls(
            kind=str(data.get("kind", "")),
            mode=str(data.get("mode", "decode")),
            options=dict(options) if isinstance(options, dict) else {},
        )


@dataclass
class DecodeResult:
    """What a chain of transforms produced."""

    output: str
    steps: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"output": self.output, "steps": list(self.steps)}


def run_chain(value: str, steps: list[Transform]) -> DecodeResult:
    """Run several transforms one after the other."""
    current = value
    done: list[dict[str, Any]] = []
    for index, step in enumerate(steps):
        if step.mode == "encode":
            current = encode(current, step.kind, step.options)
        else:
            current = decode(current, step.kind)
        done.append(
            {
                "index": index,
                "kind": step.kind,
                "mode": step.mode,
                "output": current,
            }
        )
    return DecodeResult(output=current, steps=done)


# ------------------------------------------------------------------- smart


@dataclass
class DecodeCandidate:
    """One of the answers the smart decode found."""

    kind: str
    label: str
    score: float
    output: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "score": round(self.score, 3),
            "output": self.output,
            "reason": self.reason,
        }


def _score(value: str) -> tuple[float, str]:
    """How much a result looks like something a person would have written."""
    if not value:
        return 0.0, "the result is empty"
    ratio = _printable_ratio(value)
    if ratio < 0.85:
        return ratio * 0.5, "most of it is not text"
    score = 0.5
    reason = "the result is readable"
    try:
        json.loads(value)
    except ValueError:
        pass
    else:
        score += 0.3
        reason = "the result is JSON"
    if re.search(r"<[a-zA-Z!/][^>]*>", value):
        score += 0.15
        reason = "the result looks like markup"
    if _is_binary_noise(value):
        score -= 0.4
        reason = "most of it is control characters"
    letters = sum(1 for char in value if char.isalpha() or char.isspace())
    if letters / len(value) > 0.6:
        score += 0.1
    return max(0.0, min(1.0, score)), reason


def smart_decode(value: str) -> list[DecodeCandidate]:
    """Try every decoder and rank the answers."""
    if not value:
        return []
    candidates: list[DecodeCandidate] = []
    for kind in TRANSFORM_KINDS:
        if kind in {"jwt", "hashes"}:
            continue
        try:
            output = decode(value, kind)
        except DecoderError:
            continue
        except Exception:  # noqa: BLE001 - a broken decoder must not stop the rest
            continue
        score, reason = _score(output)
        if score <= 0.0:
            continue
        candidates.append(
            DecodeCandidate(
                kind=kind,
                label=KIND_LABELS.get(kind, kind),
                score=score,
                output=output,
                reason=reason,
            )
        )
    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    return candidates


# ------------------------------------------------------------------ hashes


class Decoder:
    """The decoder as the API and the interface use it."""

    def convert(
        self,
        value: str,
        kind: str,
        mode: str = "decode",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """One conversion."""
        output = encode(value, kind, options) if mode == "encode" else decode(value, kind)
        return {
            "kind": kind,
            "label": KIND_LABELS.get(kind, kind),
            "mode": mode,
            "output": output,
        }

    def chain(self, value: str, steps: list[dict[str, Any]]) -> dict[str, Any]:
        """Several conversions, one after the other."""
        transforms = [Transform.from_dict(step) for step in steps]
        result = run_chain(value, transforms)
        return result.to_dict()

    def smart(self, value: str) -> dict[str, Any]:
        """Every decoding that made sense, the best one first."""
        candidates = [candidate.to_dict() for candidate in smart_decode(value)]
        return {
            "candidates": candidates,
            "best": candidates[0] if candidates else None,
        }

    def hashes(self, value: str) -> dict[str, Any]:
        """The hashes a value could be."""
        return {"hashes": [candidate.to_dict() for candidate in identify_hash(value)]}

    def digest(self, value: str, algorithm: str, key: str = "") -> dict[str, Any]:
        """A digest of a value."""
        return {
            "algorithm": algorithm,
            "output": make_hash(value, algorithm, key),
        }

    def catalog(self) -> dict[str, Any]:
        """The conversions and the digests the decoder knows."""
        return {
            "kinds": [
                {"id": kind, "label": KIND_LABELS.get(kind, kind)} for kind in TRANSFORM_KINDS
            ],
            "algorithms": list(HASH_ALGORITHMS),
            "keyed": list(KEYED_ALGORITHMS),
        }

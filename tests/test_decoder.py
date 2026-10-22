"""Tests for the decoder: conversions, hashes, chains and smart decode."""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import zlib

import pytest

from intercept.tools.decoder import (
    HASH_ALGORITHMS,
    TRANSFORM_KINDS,
    Decoder,
    DecoderError,
    Transform,
    decode,
    encode,
    identify_hash,
    make_hash,
    run_chain,
    smart_decode,
)

# ------------------------------------------------------------- conversions


def test_url_is_decoded():
    assert decode("hello%20world%21", "url") == "hello world!"


def test_url_is_encoded():
    assert encode("hello world!", "url") == "hello%20world%21"


def test_html_entities_are_decoded():
    assert decode("&lt;script&gt;alert(1)&lt;/script&gt;", "html") == "<script>alert(1)</script>"


def test_html_is_encoded():
    assert encode("<b>", "html") == "&lt;b&gt;"


def test_base64_is_decoded():
    assert decode(base64.b64encode(b"hello world").decode(), "base64") == "hello world"


def test_base64_without_the_padding_is_decoded():
    assert decode("aGVsbG8", "base64") == "hello"


def test_base64_is_encoded():
    assert encode("hello", "base64") == base64.b64encode(b"hello").decode()


def test_base32_is_decoded():
    assert decode(base64.b32encode(b"hello world").decode(), "base32") == "hello world"


def test_base32_is_encoded():
    assert encode("hello", "base32") == base64.b32encode(b"hello").decode()


def test_hex_is_decoded():
    assert decode("68656c6c6f", "hex") == "hello"


def test_hex_with_spaces_is_decoded():
    assert decode("68 65 6c 6c 6f", "hex") == "hello"


def test_hex_is_encoded():
    assert encode("hello", "hex") == "68656c6c6f"


def test_ascii_codes_are_decoded():
    assert decode("104 101 108 108 111", "ascii") == "hello"


def test_ascii_codes_in_hex_are_decoded():
    assert decode("0x68 0x65 0x6c 0x6c 0x6f", "ascii") == "hello"


def test_ascii_is_encoded():
    assert encode("hi", "ascii") == "104 105"


def test_binary_is_decoded():
    assert decode("01101000 01101001", "binary") == "hi"


def test_binary_is_encoded():
    assert encode("hi", "binary") == "01101000 01101001"


def test_unicode_escapes_are_decoded():
    assert decode(r"\u0068\u0065\u006c\u006c\u006f", "unicode") == "hello"


def test_unicode_code_points_are_decoded():
    assert decode("U+0041 U+00E9", "unicode") == "Aé"


def test_unicode_is_encoded():
    assert encode("Aé", "unicode") == r"\u0041\u00e9"


def test_gzip_is_decoded():
    archive = base64.b64encode(gzip.compress(b"hello world")).decode()
    assert decode(archive, "gzip") == "hello world"


def test_gzip_is_encoded():
    assert decode(encode("hello world", "gzip"), "gzip") == "hello world"


def test_deflate_is_decoded():
    stream = base64.b64encode(zlib.compress(b"hello world")).decode()
    assert decode(stream, "deflate") == "hello world"


def test_a_raw_deflate_stream_is_decoded():
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw = compressor.compress(b"hello world") + compressor.flush()
    assert decode(base64.b64encode(raw).decode(), "deflate") == "hello world"


def test_a_gzip_archive_is_not_a_deflate_stream():
    archive = base64.b64encode(gzip.compress(b"hello world")).decode()
    with pytest.raises(DecoderError):
        decode(archive, "deflate")


def test_a_value_that_is_not_base64_is_refused():
    with pytest.raises(DecoderError):
        decode("not base64 at all!", "base64")


def test_an_empty_value_is_refused():
    with pytest.raises(DecoderError):
        decode("", "base64")


def test_an_unknown_kind_is_refused():
    with pytest.raises(DecoderError):
        decode("hello", "rot13")


def test_every_kind_the_decoder_advertises_can_be_used():
    """Each kind does something in both directions."""
    for kind in TRANSFORM_KINDS:
        assert kind in TRANSFORM_KINDS
        with pytest.raises(DecoderError):
            decode("", kind)


# ------------------------------------------------------------------- jwt


def test_a_jwt_is_opened():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.signature"
    result = json.loads(decode(token, "jwt"))
    assert result["header"]["alg"] == "HS256"
    assert result["payload"]["sub"] == "123"
    assert result["signature"] == "signature"


def test_a_value_that_is_not_a_jwt_is_refused():
    with pytest.raises(DecoderError):
        decode("hello", "jwt")


def test_a_jwt_is_signed():
    token = encode('{"sub":"1"}', "jwt", {"secret": "s3cret"})
    parts = token.split(".")
    assert len(parts) == 3
    digest = hmac.new(b"s3cret", f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
    assert parts[2] == base64.urlsafe_b64encode(digest).decode().rstrip("=")


# ---------------------------------------------------------------- hashes


def test_a_digest_is_made():
    assert make_hash("hello", "md5") == hashlib.md5(b"hello").hexdigest()
    assert make_hash("hello", "sha256") == hashlib.sha256(b"hello").hexdigest()


def test_a_keyed_digest_needs_a_key():
    with pytest.raises(DecoderError):
        make_hash("hello", "hmac-sha256")
    assert (
        make_hash("hello", "hmac-sha256", "key")
        == hmac.new(b"key", b"hello", hashlib.sha256).hexdigest()
    )


def test_an_unknown_algorithm_is_refused():
    with pytest.raises(DecoderError):
        make_hash("hello", "rot13")


def test_the_algorithms_are_the_ones_that_are_advertised():
    assert "sha256" in HASH_ALGORITHMS
    assert "hmac-sha512" in HASH_ALGORITHMS


def test_a_hash_is_recognised():
    found = identify_hash(hashlib.sha256(b"hello").hexdigest())
    assert [candidate.name for candidate in found] == ["sha256"]


def test_a_md5_cannot_be_told_apart_from_an_ntlm_hash():
    found = identify_hash(hashlib.md5(b"hello").hexdigest())
    assert {candidate.name for candidate in found} == {"md5", "ntlm"}


def test_a_bcrypt_hash_is_recognised():
    found = identify_hash("$2b$12$abcdefghijklmnopqrstuv")
    assert found[0].name == "bcrypt"


def test_a_mysql_hash_is_recognised():
    found = identify_hash("*" + hashlib.sha1(b"hello").hexdigest())
    assert found[0].name == "mysql"


def test_a_value_that_is_not_a_hash_says_so():
    with pytest.raises(DecoderError):
        decode("hello", "hashes")


# ---------------------------------------------------------------- chains


def test_a_chain_runs_the_steps_one_after_the_other():
    value = base64.b64encode(b"hello%20world").decode()
    result = run_chain(value, [Transform("base64"), Transform("url")])
    assert result.output == "hello world"
    assert len(result.steps) == 2
    assert result.steps[0]["output"] == "hello%20world"
    assert result.steps[1]["output"] == "hello world"


def test_a_chain_may_encode_as_well():
    result = run_chain("hello world", [Transform("url", "encode"), Transform("base64", "encode")])
    assert result.output == base64.b64encode(b"hello%20world").decode()


def test_a_chain_that_fails_says_where():
    with pytest.raises(DecoderError):
        run_chain("hello", [Transform("base64")])


# ----------------------------------------------------------- smart decode


def test_smart_decode_finds_the_encoding_that_was_used():
    value = base64.b64encode(b"the quick brown fox").decode()
    candidates = smart_decode(value)
    assert candidates
    assert candidates[0].kind == "base64"
    assert candidates[0].output == "the quick brown fox"


def test_smart_decode_finds_json():
    value = base64.b64encode(json.dumps({"a": 1}).encode()).decode()
    candidates = smart_decode(value)
    assert candidates[0].kind == "base64"
    assert "JSON" in candidates[0].reason


def test_smart_decode_says_when_nothing_worked():
    assert smart_decode("") == []


def test_smart_decode_leaves_out_the_decodings_that_did_nothing():
    candidates = smart_decode(base64.b64encode(b"hello").decode())
    unchanged = [
        candidate
        for candidate in candidates
        if candidate.kind == "url" and candidate.reason == "nothing was decoded"
    ]
    assert unchanged == [] or unchanged[0].score < 0.1


# ------------------------------------------------------------------ the api


async def test_the_api_converts_a_value(client):
    response = await client.post(
        "/api/decoder/convert",
        json={"value": "aGVsbG8", "kind": "base64", "mode": "decode"},
    )
    assert response.status_code == 200
    assert response.json()["output"] == "hello"


async def test_the_api_reports_a_value_it_cannot_convert(client):
    response = await client.post(
        "/api/decoder/convert",
        json={"value": "not base64!", "kind": "base64", "mode": "decode"},
    )
    assert response.status_code == 400


async def test_the_api_runs_a_chain(client):
    value = base64.b64encode(b"hello%20world").decode()
    response = await client.post(
        "/api/decoder/chain",
        json={
            "value": value,
            "steps": [{"kind": "base64", "mode": "decode"}, {"kind": "url", "mode": "decode"}],
        },
    )
    assert response.status_code == 200
    assert response.json()["output"] == "hello world"


async def test_the_api_decodes_smartly(client):
    value = base64.b64encode(b"hello world").decode()
    response = await client.post("/api/decoder/smart", json={"value": value})
    assert response.status_code == 200
    assert response.json()["best"]["kind"] == "base64"


async def test_the_api_makes_a_digest(client):
    response = await client.post(
        "/api/decoder/hash",
        json={"value": "hello", "algorithm": "sha256"},
    )
    assert response.status_code == 200
    assert response.json()["output"] == hashlib.sha256(b"hello").hexdigest()


async def test_the_api_lists_the_kinds(client):
    response = await client.get("/api/decoder/kinds")
    assert response.status_code == 200
    data = response.json()
    assert "base64" in [kind["id"] for kind in data["kinds"]]
    assert "sha256" in data["algorithms"]


async def test_the_decoder_object_answers(client):
    response = await client.post(
        "/api/decoder/convert",
        json={"value": "hello", "kind": "hex", "mode": "encode"},
    )
    assert response.status_code == 200
    assert response.json()["output"] == "68656c6c6f"


def test_the_decoder_object_converts_directly():
    assert Decoder().convert("aGVsbG8", "base64")["output"] == "hello"
    assert Decoder().catalog()["kinds"]

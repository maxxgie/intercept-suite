"""Tests for the sequencer: measures, verdicts and token forgery."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

import pytest

from intercept.tools.sequencer import (
    TOKEN_KINDS,
    Sequencer,
    bit_bias,
    chi_square,
    detect_kind,
    longest_run,
    monte_carlo_pi,
    serial_correlation,
    shannon_entropy,
)


def _jwt(payload: dict, secret: str = "secret", algorithm: str = "HS256") -> str:
    """A JSON web token that is signed the given way."""
    digest = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[algorithm]
    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": algorithm, "typ": "JWT"}).encode())
        .decode()
        .rstrip("=")
    )
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header}.{body}".encode()
    signature = (
        base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input, digest).digest())
        .decode()
        .rstrip("=")
    )
    return f"{header}.{body}.{signature}"


# ---------------------------------------------------------------- measures


def test_entropy_of_a_single_repeated_character_is_zero():
    assert shannon_entropy(b"aaaaaaaa") == 0.0


def test_entropy_of_evenly_spread_data_is_the_size_of_the_alphabet():
    assert shannon_entropy(bytes(range(16))) == pytest.approx(4.0)


def test_chi_square_says_nothing_about_data_that_is_even():
    statistic, p_value = chi_square(bytes(range(16)) * 8)
    assert p_value > 0.99
    assert statistic == pytest.approx(0.0, abs=1e-9)


def test_chi_square_finds_data_that_always_uses_the_same_value():
    _, p_value = chi_square(b"aaaaaaaaaaaaaaaa")
    assert p_value == 0.0


def test_serial_correlation_is_near_zero_for_random_data():
    data = os.urandom(4096)
    assert abs(serial_correlation(data)) < 0.1


def test_serial_correlation_is_high_for_data_that_follows_itself():
    ramp = bytes(index % 256 for index in range(1024))
    assert serial_correlation(ramp) > 0.5


def test_monte_carlo_pi_lands_near_pi_for_random_data():
    assert abs(monte_carlo_pi(os.urandom(20000)) - 3.14159) < 0.2


def test_bit_bias_is_small_for_random_data():
    assert bit_bias(os.urandom(4096)) < 0.05


def test_longest_run_finds_the_repeated_stretch():
    assert longest_run(b"abc" + b"z" * 5 + b"abc") == 5


def test_the_measures_survive_an_empty_input():
    assert shannon_entropy(b"") == 0.0
    assert serial_correlation(b"") == 0.0
    assert monte_carlo_pi(b"") == 0.0
    assert bit_bias(b"") == 0.0
    assert longest_run(b"") == 0


# ------------------------------------------------------------------ kinds


def test_detect_kind_finds_a_jwt_by_its_shape():
    assert detect_kind(_jwt({"sub": "1"})) == "jwt"


def test_detect_kind_uses_the_name_of_the_token():
    assert detect_kind("abc", name="csrf_token") == "csrf"
    assert detect_kind("abc", name="JSESSIONID") == "session"
    assert detect_kind("abc", name="api_key") == "api-key"
    assert detect_kind("abc", name="password_reset") == "password-reset"
    assert detect_kind("abc", name="nonce") == "nonce"


def test_detect_kind_says_unknown_when_it_cannot_tell():
    assert detect_kind("abc") == "unknown"


def test_the_kinds_are_the_ones_the_tool_advertises():
    assert "jwt" in TOKEN_KINDS
    assert "csrf" in TOKEN_KINDS
    assert "session" in TOKEN_KINDS


# --------------------------------------------------------------- verdicts


def test_random_samples_are_called_random():
    report = Sequencer().analyse([os.urandom(16).hex() for _ in range(40)])
    assert report.verdict == "random"
    assert report.score > 0.8
    assert report.samples == 40
    assert report.unique == 40


def test_a_counter_is_called_predictable():
    report = Sequencer().analyse([str(1000 + index) for index in range(20)])
    assert report.verdict == "predictable"
    assert report.sequential is True
    assert any("counter" in note for note in report.notes)


def test_the_same_token_over_and_over_is_called_predictable():
    report = Sequencer().analyse(["abcdef0123456789"] * 10)
    assert report.verdict == "predictable"
    assert report.duplicates == ["abcdef0123456789"]


def test_a_token_with_too_little_entropy_is_called_weak():
    samples = ["".join("ab"[index % 2] for index in range(20)) for _ in range(30)]
    report = Sequencer().analyse(samples)
    assert report.verdict in {"weak", "predictable"}
    assert report.total_bits < 64


def test_a_fixed_prefix_leaves_little_that_is_random():
    samples = [f"sess_{os.urandom(8).hex()}" for _ in range(20)]
    report = Sequencer().analyse(samples)
    assert report.common_prefix == "sess_"
    assert report.verdict != "random"


def test_the_measures_only_look_at_the_part_that_changes():
    """A prefix that every sample shares is not part of the randomness."""
    samples = [f"sess_{os.urandom(8).hex()}" for _ in range(20)]
    report = Sequencer().analyse(samples)
    assert report.length == 21
    assert report.random_length == 16
    assert report.total_bits == pytest.approx(report.entropy_per_character * 16)
    assert report.serial_correlation < 0.25


def test_a_token_without_a_prefix_is_measured_whole():
    """The whole token is random when nothing is shared."""
    samples = [os.urandom(16).hex() for _ in range(20)]
    report = Sequencer().analyse(samples)
    assert report.random_length == report.length == 32
    assert report.common_prefix == ""


def test_a_uuid_is_not_mistaken_for_a_bad_generator():
    import uuid

    samples = [str(uuid.uuid4()) for _ in range(40)]
    report = Sequencer().analyse(samples)
    assert report.verdict == "random"
    assert report.embedded_timestamp == 0


def test_a_clock_inside_the_token_is_found():
    stamp = int(time.time())
    samples = [
        base64.b64encode(stamp.to_bytes(4, "big") + os.urandom(8)).decode() for _ in range(10)
    ]
    report = Sequencer().analyse(samples)
    assert report.embedded_timestamp == stamp
    assert report.verdict == "predictable"
    assert any("clock" in note for note in report.notes)


def test_a_clock_written_out_in_digits_is_found():
    stamp = int(time.time())
    samples = [f"sess_{stamp + index}_x" for index in range(10)]
    report = Sequencer().analyse(samples)
    assert report.embedded_timestamp == stamp + 0


def test_no_samples_leave_the_report_empty():
    report = Sequencer().analyse([])
    assert report.samples == 0
    assert report.notes


def test_the_samples_are_taken_from_the_report():
    report = Sequencer().analyse(["  value  ", "other", ""])
    assert report.samples == 2
    assert report.length == 5


def test_the_report_can_be_handed_over_as_data():
    report = Sequencer().analyse([os.urandom(8).hex() for _ in range(10)])
    data = report.to_dict()
    assert data["verdict"] == report.verdict
    assert data["samples"] == 10
    assert isinstance(data["notes"], list)


# -------------------------------------------------------------------- jwt


def test_a_jwt_that_is_not_signed_can_be_forged():
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(b'{"sub":"1"}').decode().rstrip("=")
    report = Sequencer().analyse([f"{header}.{body}.", f"{header}.{body}."], kind="jwt")
    assert report.jwt["forgable"] is True
    assert report.verdict == "predictable"


def test_a_jwt_signed_with_a_weak_secret_can_be_forged():
    token = _jwt({"sub": "1"}, secret="secret")
    report = Sequencer().analyse([token], kind="jwt")
    assert report.jwt["forgable"] is True
    assert report.jwt["secret"] == "secret"


def test_a_jwt_signed_with_a_good_secret_cannot_be_forged():
    token = _jwt({"sub": "1"}, secret="a" * 40 + "!")
    report = Sequencer().analyse([token], kind="jwt")
    assert report.jwt["forgable"] is False
    assert report.jwt["algorithm"] == "HS256"


def test_the_claims_of_a_jwt_are_listed():
    token = _jwt({"sub": "42", "role": "admin", "iat": 1})
    report = Sequencer().analyse([token], kind="jwt")
    assert report.jwt["claims"] == ["iat", "role", "sub"]
    assert "sub" in report.jwt["predictable_claims"]


def test_the_kind_of_a_jwt_is_found_when_it_is_not_given():
    token = _jwt({"sub": "1"})
    report = Sequencer().analyse([token])
    assert report.kind == "jwt"
    assert report.jwt


# ------------------------------------------------------------------- api


async def test_the_api_measures_a_set_of_samples(client):
    response = await client.post(
        "/api/sequencer/analyze",
        json={"samples": [os.urandom(8).hex() for _ in range(10)], "kind": "auto"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["samples"] == 10
    assert data["verdict"] in {"random", "weak", "predictable"}


async def test_the_api_needs_samples(client):
    response = await client.post("/api/sequencer/analyze", json={"samples": []})
    assert response.status_code == 400


async def test_the_api_lists_the_kinds_of_token(client):
    response = await client.get("/api/sequencer/kinds")
    assert response.status_code == 200
    assert "jwt" in response.json()["kinds"]

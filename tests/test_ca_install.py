"""Tests for the certificate export and the browser trust store integration."""

from __future__ import annotations

import json
import platform
from pathlib import Path

import pytest
from cryptography import x509

from intercept.cli import build_parser, cmd_ca
from intercept.core.config import Config
from intercept.crypto import install as trust
from intercept.crypto.ca import CertificateAuthority


@pytest.fixture
def ca(tmp_path) -> CertificateAuthority:
    authority = CertificateAuthority(home=tmp_path)
    authority.ensure_root()
    return authority


def test_the_root_certificate_is_a_ca(ca):
    certificate = ca.root_certificate()
    constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is True
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_cert_sign is True


def test_the_exported_certificate_is_the_root(ca, tmp_path):
    target = ca.export(tmp_path / "out.crt")
    certificate = x509.load_pem_x509_certificate(target.read_bytes())
    assert certificate == ca.root_certificate()


def test_the_export_command_writes_a_pem_file(tmp_path, capsys):
    parser = build_parser()
    args = parser.parse_args(["ca", "export", "--out", str(tmp_path / "ca.crt")])
    args.home_ca = str(tmp_path)
    assert cmd_ca(args) == 0

    written = Path(capsys.readouterr().out.splitlines()[0])
    assert written.read_text().startswith("-----BEGIN CERTIFICATE-----")


def test_the_fingerprint_is_stable(ca):
    assert ca.fingerprint() == ca.fingerprint()
    assert len(ca.fingerprint()) == 64


# ------------------------------------------------------------------- targets


def test_the_targets_match_the_platform():
    found = trust.targets()
    assert found
    names = {target.name for target in found}
    if platform.system() == "Linux":
        assert {"system", "nss", "firefox"} <= names
    elif platform.system() == "Darwin":
        assert {"keychain", "firefox"} <= names
    else:
        assert "firefox" in names


def test_every_target_explains_itself():
    for target in trust.targets():
        payload = target.to_dict()
        assert payload["label"]
        if not payload["available"]:
            assert payload["reason"]
        if not payload["steps"]:
            assert payload["available"]


def test_the_steps_reference_the_certificate_placeholder():
    for target in trust.targets():
        for step in target.steps:
            if " -i " in step or "add-trusted-cert" in step or "addstore" in step:
                assert "{certificate}" in step


def test_the_unknown_platform_target_is_reported():
    target = trust.Target("manual", "nothing", False, "unsupported")
    assert target.to_dict()["available"] is False


def test_a_target_without_certutil_is_never_available(monkeypatch):
    monkeypatch.setattr(trust, "_certutil", lambda: None)
    for target in trust.targets():
        if target.name in ("nss", "firefox"):
            assert target.available is False
            assert "certutil" in target.reason


def test_the_package_manager_is_known_on_linux():
    if platform.system() != "Linux":
        pytest.skip("linux only")
    manager = trust.package_manager()
    assert manager is None or manager[0] in ("dnf", "apt-get", "pacman", "zypper")


def test_the_system_store_is_known_on_a_supported_distribution():
    if platform.system() != "Linux":
        pytest.skip("linux only")
    if trust.distribution() == "unknown":
        pytest.skip("unsupported distribution")
    store = trust.system_store()
    assert store is not None
    assert store[0].is_absolute()


# --------------------------------------------------------------- cli plumbing


def test_the_install_command_lists_the_targets(tmp_path, capsys):
    parser = build_parser()
    args = parser.parse_args(["ca", "install", "--list"])
    args.home_ca = str(tmp_path)
    assert cmd_ca(args) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["targets"]
    assert {"name", "label", "available", "reason", "location", "steps"} <= set(
        payload["targets"][0]
    )


def test_the_install_command_rejects_an_unknown_target(tmp_path, capsys):
    parser = build_parser()
    args = parser.parse_args(["ca", "install", "--target", "nope"])
    args.home_ca = str(tmp_path)
    assert cmd_ca(args) == 1
    assert "unknown target" in capsys.readouterr().err


def test_the_install_command_exports_the_certificate(tmp_path, capsys):
    parser = build_parser()
    args = parser.parse_args(["ca", "install", "--target", "system"])
    args.home_ca = str(tmp_path)
    cmd_ca(args)

    out = capsys.readouterr().out
    assert "certificate:" in out
    assert "sha256 fingerprint:" in out
    assert (tmp_path / "ca.crt").exists()


def test_a_configured_home_is_used(tmp_path):
    config = Config(home=str(tmp_path))
    assert config.home == str(tmp_path)


# -------------------------------------------------------------------- the api


async def test_the_api_lists_the_trust_stores(client):
    response = await client.get("/api/ca/targets")
    assert response.status_code == 200
    assert response.json()["targets"]


async def test_the_api_installs_into_a_named_target(client):
    response = await client.post("/api/ca/install", json={"target": "system"})
    assert response.status_code == 200
    data = response.json()
    assert data["fingerprint"]
    assert data["results"]
    assert data["results"][0]["target"] == "system"


async def test_the_api_rejects_an_unknown_target(client):
    response = await client.post("/api/ca/install", json={"target": "nope"})
    assert response.status_code == 400
    assert "unknown target" in response.json()["detail"]


async def test_the_api_can_remove_the_certificate_again(client):
    response = await client.post("/api/ca/uninstall", json={"target": "system"})
    assert response.status_code == 200
    assert response.json()["results"]

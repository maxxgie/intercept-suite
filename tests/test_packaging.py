"""Tests for the packaging setup."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from intercept.cli import _with_default_subcommand, build_parser

ROOT = Path(__file__).resolve().parent.parent


def test_the_cli_defaults_to_serve():
    assert _with_default_subcommand([]) == ["serve"]
    assert _with_default_subcommand(["--home", "/tmp/x"]) == ["serve", "--home", "/tmp/x"]
    assert _with_default_subcommand(["doctor"]) == ["doctor"]
    assert _with_default_subcommand(["ca", "export"]) == ["ca", "export"]


def test_the_parser_accepts_a_bare_serve():
    parser = build_parser()
    args = parser.parse_args(["serve", "--port", "1234"])
    assert args.command == "serve"
    assert args.port == 1234


def test_the_pyinstaller_spec_exists_and_is_valid():
    spec = ROOT / "packaging" / "intercept.spec"
    assert spec.exists()
    text = spec.read_text()
    assert "intercept" in text
    assert "__main__.py" in text
    assert "plugins" in text


def test_the_build_script_is_executable():
    script = ROOT / "scripts" / "build_daemon.sh"
    assert script.exists()
    assert script.read_text().startswith("#!/usr/bin/env bash")


def test_the_desktop_package_ships_the_daemon():
    package = json.loads((ROOT / "apps" / "desktop" / "package.json").read_text())
    scripts = package["scripts"]
    assert "build:daemon" in scripts
    assert "build:daemon" in scripts["package"]
    assert "build:daemon" in scripts["dist"]

    resources = package["build"]["extraResources"]
    assert any(entry["from"].endswith("dist/intercept") for entry in resources)


def test_the_manifest_declares_the_new_dependencies():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependencies = data["project"]["dependencies"]
    assert any(dep.startswith("h2") for dep in dependencies)


def test_the_example_plugin_manifest_is_valid():
    manifest = ROOT / "plugins" / "examples" / "encodings" / "plugin.toml"
    data = tomllib.loads(manifest.read_text())
    assert data["name"]
    assert data["entry"]


@pytest.mark.parametrize("command", ["serve", "ca", "doctor"])
def test_every_subcommand_is_known(command):
    assert command in ("serve", "ca", "doctor")

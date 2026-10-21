"""Tests for the command line behaviour of the daemon."""

from __future__ import annotations

import socket
import sys

import pytest
from conftest import free_port

from intercept.cli import _busy_ports, _port_is_free, build_parser, cmd_serve
from intercept.core.config import Config


def _args(**overrides) -> object:
    parser = build_parser()
    args = parser.parse_args(["serve"])
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Point the daemon at a throwaway home directory."""
    monkeypatch.setenv("INTERCEPT_HOME", str(tmp_path))
    return tmp_path


def test_a_free_port_is_reported_as_free():
    assert _port_is_free("127.0.0.1", free_port()) is True


def test_a_busy_port_is_reported_as_busy():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = int(sock.getsockname()[1])
        assert _port_is_free("127.0.0.1", port) is False


def test_busy_ports_names_the_listening_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = int(sock.getsockname()[1])

        config = Config()
        config.proxy.host = "127.0.0.1"
        config.proxy.port = free_port()
        config.api.host = "127.0.0.1"
        config.api.port = port

        assert _busy_ports(config, with_proxy=True) == [f"api port {port}"]


def test_busy_ports_ignores_the_proxy_when_it_is_disabled():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = int(sock.getsockname()[1])

        config = Config()
        config.proxy.host = "127.0.0.1"
        config.proxy.port = port
        config.api.host = "127.0.0.1"
        config.api.port = free_port()

        assert _busy_ports(config, with_proxy=False) == []


def test_serve_reports_a_busy_port_instead_of_crashing(isolated_home, capsys):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = int(sock.getsockname()[1])

        args = _args(port=port, api_port=free_port(), home_sub=str(isolated_home))
        assert cmd_serve(args) == 1

    error = capsys.readouterr().err
    assert "cannot start" in error
    assert f"proxy port {port}" in error
    assert "already in use" in error
    assert "intercept serve --port" in error


def test_serve_reports_a_busy_api_port(isolated_home, capsys):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = int(sock.getsockname()[1])

        args = _args(port=free_port(), api_port=port, home_sub=str(isolated_home))
        assert cmd_serve(args) == 1

    error = capsys.readouterr().err
    assert f"api port {port}" in error


def test_the_busy_message_carries_the_marker_the_desktop_shell_parses(
    isolated_home, capsys
):
    """The desktop shell looks for "already in use" and "api port <n>"."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = int(sock.getsockname()[1])

        args = _args(port=free_port(), api_port=port, home_sub=str(isolated_home))
        cmd_serve(args)

    error = capsys.readouterr().err
    assert "already in use" in error
    assert f"api port {port}" in error


def test_the_doctor_command_lists_the_port_state(isolated_home, capsys):
    from intercept.cli import cmd_doctor

    parser = build_parser()
    args = parser.parse_args(["doctor"])
    args.home_sub = str(isolated_home)
    assert cmd_doctor(args) == 0

    out = capsys.readouterr().out
    assert "proxy port" in out
    assert "api port" in out


def test_the_default_subcommand_is_serve():
    from intercept.cli import _with_default_subcommand

    assert _with_default_subcommand([]) == ["serve"]
    assert _with_default_subcommand(["--home", "/tmp/x"]) == ["serve", "--home", "/tmp/x"]


def test_the_help_keeps_the_top_level_help():
    """``intercept --help`` has to list the subcommands, not only ``serve``."""
    from intercept.cli import _with_default_subcommand

    assert _with_default_subcommand(["--help"]) == ["--help"]
    assert _with_default_subcommand(["-h"]) == ["-h"]
    assert _with_default_subcommand(["serve", "--help"]) == ["serve", "--help"]


def test_the_serve_command_takes_a_log_level():
    parser = build_parser()
    args = parser.parse_args(["serve", "--log-level", "DEBUG"])
    assert args.log_level == "DEBUG"


def test_the_module_entry_point_is_callable():
    from intercept.__main__ import main

    assert callable(main)
    assert sys.modules["intercept.__main__"] is not None

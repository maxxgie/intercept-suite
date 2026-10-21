"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import errno
import json
import logging
import os
import sys
from pathlib import Path

from intercept.core.config import Config, load_config

__all__ = ["main"]


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-18s %(message)s",
        datefmt="%H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="intercept",
        description="An extensible web application security proxy and testing workbench.",
    )
    parser.add_argument("--home", help="directory for the CA, database and plugins")
    parser.add_argument("--log-level", default="INFO", help="log level (default: INFO)")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="run the proxy and the API")
    serve.add_argument("--home", dest="home_sub", help="directory for the CA, database and plugins")
    serve.add_argument(
        "--log-level",
        dest="log_level",
        default=argparse.SUPPRESS,
        help="log level (default: INFO)",
    )
    serve.add_argument("--host", help="proxy listen address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, help="proxy listen port (default: 8080)")
    serve.add_argument("--api-host", help="API listen address (default: 127.0.0.1)")
    serve.add_argument("--api-port", type=int, help="API listen port (default: 9000)")
    serve.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify upstream certificates (use for lab targets)",
    )
    serve.add_argument(
        "--no-proxy",
        action="store_true",
        help="start the API without the proxy listener",
    )
    serve.add_argument("--print-config", action="store_true", help="print the config and exit")

    ca = sub.add_parser("ca", help="certificate authority commands")
    ca.add_argument("--home", dest="home_sub", help="directory holding the certificate authority")
    ca_sub = ca.add_subparsers(dest="ca_command", required=True)
    ca_export = ca_sub.add_parser("export", help="write the root CA certificate")
    ca_export.add_argument("--out", help="output path (default: <home>/ca.crt)")
    ca_export.add_argument(
        "--home", dest="home_ca", help="directory holding the certificate authority"
    )
    ca_fingerprint = ca_sub.add_parser("fingerprint", help="print the root CA fingerprint")
    ca_fingerprint.add_argument(
        "--home", dest="home_ca", help="directory holding the certificate authority"
    )
    ca_info = ca_sub.add_parser("info", help="print details about the root CA")
    ca_info.add_argument(
        "--home", dest="home_ca", help="directory holding the certificate authority"
    )
    ca_install = ca_sub.add_parser(
        "install", help="trust the root CA in the browsers on this machine"
    )
    ca_install.add_argument(
        "--target", help="only use this trust store (system, nss, firefox)"
    )
    ca_install.add_argument("--out", help="where to write the certificate first")
    ca_install.add_argument(
        "--deps",
        action="store_true",
        help="install the missing system packages first (uses sudo)",
    )
    ca_install.add_argument(
        "--list", dest="list_targets", action="store_true", help="list the trust stores"
    )
    ca_install.add_argument(
        "--home", dest="home_ca", help="directory holding the certificate authority"
    )
    ca_uninstall = ca_sub.add_parser("uninstall", help="remove the root CA again")
    ca_uninstall.add_argument("--target", help="only use this trust store")
    ca_uninstall.add_argument(
        "--home", dest="home_ca", help="directory holding the certificate authority"
    )

    doctor = sub.add_parser("doctor", help="check the installation")
    doctor.add_argument(
        "--home", dest="home_sub", help="directory holding the certificate authority"
    )
    return parser


def _load(args: argparse.Namespace) -> Config:
    home = (
        getattr(args, "home", None)
        or getattr(args, "home_sub", None)
        or getattr(args, "home_ca", None)
        or os.environ.get("INTERCEPT_HOME")
    )
    if home:
        os.environ["INTERCEPT_HOME"] = home
    config = load_config()
    if getattr(args, "host", None):
        config.proxy.host = args.host
    if getattr(args, "port", None):
        config.proxy.port = args.port
    if getattr(args, "api_host", None):
        config.api.host = args.api_host
    if getattr(args, "api_port", None):
        config.api.port = args.api_port
    if getattr(args, "insecure", False):
        config.proxy.upstream_verify = False
    if getattr(args, "log_level", None):
        config.log_level = args.log_level
    return config


def _port_is_free(host: str, port: int) -> bool:
    """Best effort check that *port* can still be bound."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _busy_ports(config: Config, *, with_proxy: bool) -> list[str]:
    busy = []
    if with_proxy and not _port_is_free(config.proxy.host, config.proxy.port):
        busy.append(f"proxy port {config.proxy.port}")
    if not _port_is_free(config.api.host, config.api.port):
        busy.append(f"api port {config.api.port}")
    return busy


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from intercept.api.app import create_api
    from intercept.app import InterceptApp

    config = _load(args)
    if args.print_config:
        print(json.dumps(config.to_dict(), indent=2))
        return 0

    busy = _busy_ports(config, with_proxy=not args.no_proxy)
    if busy:
        return _report_busy(busy, config)

    app = InterceptApp(config)

    async def run() -> None:
        if not args.no_proxy:
            await app.startup()
        else:
            app.ca.ensure_root()
            await app.store.start()
            app.plugins.load_all()

        api = create_api(app)
        url = f"http://{config.api.host}:{config.api.port}"
        print(
            f"proxy listening on {config.proxy.host}:{config.proxy.port}\n"
            f"ca fingerprint {app.ca.fingerprint()}",
            file=sys.stderr,
            flush=True,
        )

        config_ = uvicorn.Config(
            api,
            host=config.api.host,
            port=config.api.port,
            log_level=config.log_level.lower(),
            access_log=False,
        )

        class _Server(uvicorn.Server):
            """Announce the API only once it is really listening."""

            async def startup(self, sockets=None) -> None:
                await super().startup(sockets=sockets)
                print(f"api listening on {url}", file=sys.stderr, flush=True)
                print(json.dumps({"event": "api-ready", "url": url}), flush=True)

        server = _Server(config_)
        try:
            await server.serve()
        finally:
            await app.shutdown()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, errno.EACCES):
            return _report_busy(
                [f"port for {config.api.host}"], config
            )
        print(f"cannot start: {exc}", file=sys.stderr)
        return 1
    return 0


def _report_busy(busy: list[str], config: Config) -> int:
    """Explain a failed start in one line instead of a traceback."""
    print(
        f"cannot start: {' and '.join(busy)} is already in use.\n"
        "Another daemon is probably running. Stop it, or start this one on\n"
        "different ports, for example:\n"
        f"  intercept serve --port {config.proxy.port + 1} "
        f"--api-port {config.api.port + 1}",
        file=sys.stderr,
    )
    return 1


def cmd_ca(args: argparse.Namespace) -> int:
    from intercept.crypto.ca import CertificateAuthority

    config = _load(args)
    ca = CertificateAuthority(home=Path(config.home))
    ca.ensure_root()

    if args.ca_command == "export":
        target = ca.export(args.out)
        print(target)
        print(
            f"sha256 fingerprint {ca.fingerprint()}\n"
            "Import this file into the browser that should be intercepted.",
            file=sys.stderr,
        )
        return 0
    if args.ca_command == "fingerprint":
        print(ca.fingerprint())
        return 0
    if args.ca_command == "install":
        return _cmd_ca_install(args, ca, config)
    if args.ca_command == "uninstall":
        return _cmd_ca_uninstall(args, config)
    print(json.dumps({"subject": ca.subject(), "fingerprint": ca.fingerprint()}, indent=2))
    return 0


def _cmd_ca_install(args: argparse.Namespace, ca, config: Config) -> int:
    """Put the root CA into the trust stores the browsers on this machine read."""
    from intercept.crypto import install as trust

    found = trust.targets()
    if args.list_targets:
        print(json.dumps({"targets": [target.to_dict() for target in found]}, indent=2))
        return 0

    if getattr(args, "deps", False):
        try:
            for line in trust.install_dependencies():
                print(line)
        except Exception as exc:  # noqa: BLE001
            print(f"could not install the dependencies: {exc}", file=sys.stderr)
        found = trust.targets()

    wanted = getattr(args, "target", None)
    if wanted:
        chosen = [target for target in found if target.name == wanted]
        if not chosen:
            print(
                f"unknown target: {wanted}\n"
                f"known targets: {', '.join(target.name for target in found)}",
                file=sys.stderr,
            )
            return 1
    else:
        chosen = [target for target in found if target.available]

    certificate = ca.export(args.out or (Path(config.home) / "ca.crt"))
    print(f"certificate: {certificate}")
    print(f"sha256 fingerprint: {ca.fingerprint()}")
    sys.stdout.flush()

    def manual_steps() -> str:
        return "\n".join(
            f"  {step.replace('{certificate}', str(certificate))}"
            for target in found
            for step in target.steps
        )

    if not chosen:
        print(
            "\nnothing could be installed automatically. Do it by hand:\n" + manual_steps(),
            file=sys.stderr,
        )
        return 1

    failures = 0
    for target in chosen:
        try:
            detail = trust.install(target.name, certificate)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"{target.label}: failed - {exc}", file=sys.stderr)
            continue
        print(f"{target.label}: {detail}")
    sys.stdout.flush()

    if failures:
        print(
            "\nsome trust stores could not be updated. Do it by hand:\n" + manual_steps(),
            file=sys.stderr,
        )
        return 1

    print(
        "\nNow restart the browser and point it at the proxy:\n"
        f"  http://{config.proxy.host}:{config.proxy.port}\n"
        "Firefox and Chrome both read the certificate from the trust store, so\n"
        "every site the proxy intercepts is trusted."
    )
    return 0


def _cmd_ca_uninstall(args: argparse.Namespace, config: Config) -> int:
    from intercept.crypto import install as trust

    found = trust.targets()
    wanted = getattr(args, "target", None)
    chosen = (
        [target for target in found if target.name == wanted]
        if wanted
        else [target for target in found if target.available]
    )
    if not chosen:
        print("nothing to remove", file=sys.stderr)
        return 1

    failures = 0
    for target in chosen:
        try:
            detail = trust.uninstall(target.name)
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"{target.label}: failed - {exc}", file=sys.stderr)
            continue
        print(f"{target.label}: {detail}")
    return 1 if failures else 0


def cmd_doctor(args: argparse.Namespace) -> int:
    import importlib

    config = _load(args)
    checks: list[dict[str, object]] = []

    for module in ("cryptography", "httpx", "fastapi", "uvicorn"):
        try:
            importlib.import_module(module)
            checks.append({"check": module, "status": "ok"})
        except ImportError:
            checks.append({"check": module, "status": "missing"})

    home = Path(config.home)
    checks.append({"check": "home", "status": "ok", "detail": str(home)})
    try:
        from intercept.crypto.ca import CertificateAuthority

        ca = CertificateAuthority(home=home)
        ca.ensure_root()
        checks.append(
            {"check": "certificate authority", "status": "ok", "detail": ca.fingerprint()}
        )
    except Exception as exc:  # noqa: BLE001
        checks.append({"check": "certificate authority", "status": "error", "detail": str(exc)})

    for port, label in ((config.proxy.port, "proxy"), (config.api.port, "api")):
        import socket

        with socket.socket() as sock:
            busy = sock.connect_ex(("127.0.0.1", port)) == 0
        checks.append(
            {"check": f"{label} port {port}", "status": "in use" if busy else "free"}
        )

    print(json.dumps({"checks": checks}, indent=2))
    return 0


SUBCOMMANDS = ("serve", "ca", "doctor")


def _with_default_subcommand(argv: list[str]) -> list[str]:
    """Insert ``serve`` when no subcommand was given.

    The packaged daemon is started without arguments by the desktop shell, so
    running the binary on its own has to start the proxy and the API. Asking
    for help keeps the top level help, so the subcommands stay discoverable.
    """
    if any(value in SUBCOMMANDS for value in argv):
        return argv
    if any(value in ("-h", "--help") for value in argv):
        return argv
    return ["serve", *argv]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_with_default_subcommand(raw))
    _setup_logging(getattr(args, "log_level", "INFO"))
    if args.command == "serve":
        return cmd_serve(args)
    if args.command == "ca":
        return cmd_ca(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

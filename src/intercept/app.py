"""Application container.

Owns every long lived object and the wiring between them. The proxy, the
tools, the store and the API all talk to the same instances, which is what
makes the tool traffic show up in the same history as browser traffic.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from intercept.core.commands import CommandRegistry
from intercept.core.config import Config
from intercept.core.events import EventBus
from intercept.core.filters import FilterState
from intercept.core.models import Exchange
from intercept.core.protocols import ALPN_PROTOCOLS
from intercept.crypto.ca import CertificateAuthority
from intercept.plugins.api import PluginContext
from intercept.plugins.manager import PluginManager
from intercept.proxy.intercept import InterceptController
from intercept.proxy.rules import RuleEngine
from intercept.proxy.server import ProxyServer
from intercept.scanner.engine import Scanner
from intercept.store.findings import FindingStore
from intercept.store.history import HistoryStore
from intercept.store.issues import IssueStore
from intercept.store.logger import EventLog
from intercept.store.notes import NoteStore
from intercept.store.project import ProjectStore
from intercept.store.rules import RuleStore
from intercept.store.sessions import SessionStore
from intercept.store.sitemap import Scope, SiteMap
from intercept.store.targets import TargetStore
from intercept.store.tasks import Scheduler, TaskStore
from intercept.store.websockets import WebSocketStore
from intercept.tools.client import ToolClient
from intercept.tools.collaborator import Collaborator
from intercept.tools.fuzzer import Fuzzer
from intercept.tools.repeater import Repeater
from intercept.tools.spider import Spider

log = logging.getLogger("intercept")

__all__ = ["InterceptApp"]


class InterceptApp:
    """The running daemon."""

    def __init__(self, config: Config) -> None:
        self.config = config
        home = Path(config.home)
        self.bus = EventBus()
        self.ca = CertificateAuthority(
            home=home,
            alpn=ALPN_PROTOCOLS if config.proxy.http2 else ["http/1.1"],
        )
        self.store = HistoryStore(home / "history.db")
        self.finding_store = FindingStore(home / "findings.db")
        self.log = EventLog(str(home / "events.db"))
        self.notes = NoteStore(str(home / "notes.db"))
        self.issues = IssueStore(str(home / "issues.db"))
        self.sessions = SessionStore(str(home / "sessions.db"))
        self.targets = TargetStore(str(home / "targets.db"))
        self.task_store = TaskStore(str(home / "tasks.db"))
        self.websockets = WebSocketStore(str(home / "websockets.db"))
        self.rule_store = RuleStore(str(home / "rules.db"))
        self.projects = ProjectStore(home)
        self.filters = FilterState()
        self.commands = CommandRegistry()
        self.sitemap = SiteMap(self.store)
        self.scope = Scope.load(home / "scope.json")
        self.intercept = InterceptController(self.bus, config.proxy.intercept_timeout)
        self.rules = RuleEngine()

        self.proxy = ProxyServer(
            config=config,
            ca=self.ca,
            bus=self.bus,
            intercept=self.intercept,
            on_exchange=self._record,
            websockets=self.websockets,
            rules=self.rules,
        )
        self.pool = self.proxy.pool
        self.client = ToolClient(config, self.pool, self.bus, on_exchange=self._record)
        self.repeater = Repeater(self.client, self.bus)
        self.spider = Spider(self.client, self.scope, config, self.bus)
        self.fuzzer = Fuzzer(self.client, self.bus, config)
        self.collaborator = Collaborator(config.collaborator, self.bus)
        self.scanner = Scanner(
            self.client,
            self.bus,
            self.finding_store,
            config,
            collaborator=self.collaborator,
        )

        self.plugins = PluginManager(
            home,
            PluginContext(
                config=config,
                bus=self.bus,
                client=self.client,
                store=self.store,
                scope=self.scope,
            ),
        )
        self.scheduler = Scheduler(self.task_store, self._run_task)
        self._started = False

    # ------------------------------------------------------------- lifecycle

    async def startup(self) -> None:
        from intercept.commands import register_builtin

        self.ca.ensure_root()
        await self.store.start()
        self.rules.set_rules(await self.rule_store.list())
        await self.proxy.start()
        await self._start_collaborator()
        self.plugins.load_all()
        for check in self.plugins.checks.values():
            self.scanner.register_check(check)
        register_builtin(self)
        await self.scheduler.start()
        self._started = True
        self.log.record("info", "app", "the daemon started", {"ca": self.ca.fingerprint()})
        self.bus.emit("app.started", ca=self.ca.fingerprint())

    async def shutdown(self) -> None:
        self._started = False
        await self.scheduler.stop()
        with_suppress = self.spider.stop_all()
        try:
            await with_suppress
        except Exception:
            log.debug("failed to stop spider cleanly", exc_info=True)
        await self.collaborator.stop()
        await self.proxy.stop()
        await self.store.stop()
        self.finding_store.close()
        self.log.record("info", "app", "the daemon stopped")
        self.bus.emit("app.stopped")

    async def _start_collaborator(self) -> None:
        """Open the collaborator, unless it was turned off.

        A collaborator that cannot listen is not a reason to refuse to start,
        so the failure is recorded and the daemon carries on without it.
        """
        if not self.config.collaborator.enabled:
            return
        try:
            await self.collaborator.start()
        except Exception as exc:  # noqa: BLE001 - the daemon must still start
            log.warning("the collaborator did not start: %s", exc)
            self.log.record(
                "warning",
                "collaborator",
                "the collaborator did not start",
                {"detail": str(exc)},
            )

    async def _restart_collaborator(self) -> None:
        """Open the collaborator again, so a new setting takes effect.

        The ports and the address are read when the listeners are opened, so
        a change to them needs a new set of listeners. The calls that were
        already heard are kept.
        """
        await self.collaborator.stop()
        await self._start_collaborator()

    def _collaborator_settings(self) -> tuple[Any, ...]:
        """The settings that the listeners of the collaborator depend on."""
        collaborator = self.config.collaborator
        return (
            collaborator.host,
            collaborator.port,
            collaborator.dns_port,
            collaborator.smtp_port,
            collaborator.dns_address,
        )

    async def _run_task(self, command: str, args: dict[str, Any]) -> Any:
        """Run a scheduled task through the command registry."""
        self.log.record("info", "tasks", "task started", {"command": command, "args": args})
        result = await self.commands.run(command, args)
        self.log.record("info", "tasks", "task finished", {"command": command})
        return result

    async def _record(self, exchange: Exchange) -> None:
        await self.store.add(exchange)
        await self._analyse(exchange)

    async def _analyse(self, exchange: Exchange) -> None:
        """Run the passive checks over observed traffic."""
        if exchange.response is None:
            return
        for finding in self.scanner.analyse(exchange.request, exchange.response):
            await self.finding_store.add_async(finding, source="passive")
            self.bus.emit("scan.finding", finding=finding.to_dict())

    # --------------------------------------------------------------- reports

    async def build_report(self, title: str = "Intercept report") -> dict[str, Any]:
        """Collect everything the engagement produced into one report."""
        from intercept.core.reports import build_report

        findings = await self.finding_store.list(limit=1000)
        issues = await self.issues.list(limit=1000)
        notes = await self.notes.list(limit=1000)
        targets = await self.targets.list()
        return build_report(
            title=title,
            findings=findings,
            issues=issues,
            notes=notes,
            targets=targets,
            stats=await self.store.stats(),
            scope=self.scope.to_dict(),
        )

    async def save_project(self, project_id: str = "") -> dict[str, Any] | None:
        """Write the live state into a project directory."""
        project = None
        if project_id:
            project = self.projects.get(project_id)
        if project is None:
            project = self.projects.current()
        if project is None:
            return None
        home = Path(self.config.home)
        return self.projects.save(
            project["id"],
            history=self.store.path,
            scope=home / "scope.json",
            notes=await self.notes.list(limit=10000),
            issues=await self.issues.list(limit=10000),
            findings=await self.finding_store.list(limit=10000),
        )

    # ----------------------------------------------------------------- state

    async def reload_rules(self) -> list[Any]:
        """Reload the rules from the store into the engine the proxy reads."""
        rules = await self.rule_store.list()
        self.rules.set_rules(rules)
        return rules

    def state(self) -> dict[str, Any]:
        return {
            "proxy": {
                "host": self.config.proxy.host,
                "port": self.config.proxy.port,
                "upstream_verify": self.config.proxy.upstream_verify,
                "http2": self.config.proxy.http2,
                "listeners": [
                    {
                        "name": listener.name,
                        "host": listener.host,
                        "port": listener.port,
                        "mode": listener.mode,
                        "enabled": listener.enabled,
                    }
                    for listener in self.config.proxy.listeners
                ],
                "upstream_proxy": asdict(self.config.proxy.upstream_proxy),
            },
            "ca": {
                "subject": self.ca.subject(),
                "fingerprint": self.ca.fingerprint(),
                "path": str(self.ca.root_cert_path),
            },
            "intercept": self.intercept.state(),
            "collaborator": self.collaborator.status(),
            "plugins": [info.to_dict() for info in self.plugins.plugins.values()],
            "tools": self.plugins.describe_tools(),
            "checks": self.scanner.catalog(),
        }

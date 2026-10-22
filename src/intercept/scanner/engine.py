"""The scanner engine.

A scan job takes a list of target URLs and a list of checks, finds the places
under those targets that take input, runs the checks and collects the
findings. Jobs run in the background and report their progress on the event
bus, so the UI can follow a scan live.

The work is split in two:

* a **host check** asks the server about itself and runs once per target;
* an **endpoint check** probes a place that takes input and runs for every
  endpoint the crawl found.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import itertools
import time
from dataclasses import dataclass, field
from typing import Any

from intercept.core.events import EventBus
from intercept.plugins.api import Finding
from intercept.scanner.base import ActiveCheck, PassiveCheck
from intercept.scanner.checks import BUILTIN_CHECKS, check_catalog
from intercept.scanner.target import Endpoint, EndpointCrawler
from intercept.store.findings import FindingStore
from intercept.tools.client import ToolClient

__all__ = ["Scanner", "ScanJob", "ScanResult", "ScanOptions"]


@dataclass
class ScanOptions:
    """How a scan should behave."""

    #: Look for the endpoints under the target before the checks are run.
    crawl: bool = True
    #: How many pages the crawl may read.
    max_pages: int = 20
    #: How deep the crawl may go.
    max_depth: int = 2
    #: How many endpoints are probed.
    max_endpoints: int = 20

    def to_dict(self) -> dict[str, Any]:
        return {
            "crawl": self.crawl,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "max_endpoints": self.max_endpoints,
        }


@dataclass
class ScanResult:
    """One check run against one target."""

    id: str
    job_id: str
    check_id: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    elapsed_ms: float = 0.0
    scope: str = "host"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "check_id": self.check_id,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
            "scope": self.scope,
        }


@dataclass
class ScanJob:
    """A running or finished scan."""

    id: str
    targets: list[str] = field(default_factory=list)
    check_ids: list[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | finished | stopped | failed
    results: list[ScanResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    options: ScanOptions = field(default_factory=ScanOptions)
    #: How many runs the plan holds, once it is known.
    planned: int = 0
    created_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    error: str = ""
    _task: asyncio.Task | None = field(default=None, repr=False, compare=False)

    @property
    def total(self) -> int:
        if self.planned:
            return self.planned
        return len(self.targets) * len(self.check_ids)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "total": self.total,
            "completed": len(self.results),
            "targets": list(self.targets),
            "check_ids": list(self.check_ids),
            "options": self.options.to_dict(),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "results": [r.to_dict() for r in self.results],
            "findings": [f.to_dict() for f in self.findings],
        }


class Scanner:
    """Runs checks against targets and stores the findings."""

    def __init__(
        self,
        client: ToolClient,
        bus: EventBus,
        findings: FindingStore,
        config: Any = None,
        collaborator: Any = None,
    ) -> None:
        self.client = client
        self.bus = bus
        self.findings = findings
        self.config = config
        #: The server that waits for a blind flaw to call back.
        self.collaborator = collaborator
        self._jobs: dict[str, ScanJob] = {}
        self._counter = itertools.count(1)
        self._checks: dict[str, Any] = {c.id: c for c in BUILTIN_CHECKS}

    # ------------------------------------------------------------- registry

    def register_check(self, check: Any) -> None:
        """Register a check, replacing a built in one with the same id."""
        self._checks[check.id] = check

    def unregister_check(self, check_id: str) -> bool:
        return self._checks.pop(check_id, None) is not None

    def checks(self) -> list[dict[str, Any]]:
        catalog = [check.info().to_dict() for check in self._checks.values()]
        catalog.sort(key=lambda item: (item["category"], item["id"]))
        return catalog

    def catalog(self) -> list[dict[str, Any]]:
        """Every known check, including the ones that are not registered."""
        known = {item["id"] for item in self.checks()}
        entries = [item for item in check_catalog() if item["id"] not in known]
        return [*self.checks(), *entries]

    def check(self, check_id: str) -> Any | None:
        return self._checks.get(check_id)

    # ------------------------------------------------------------------ jobs

    def create_job(
        self,
        targets: list[str],
        check_ids: list[str] | None = None,
        options: ScanOptions | None = None,
    ) -> ScanJob:
        selected = check_ids or [c.id for c in self._checks.values()]
        job = ScanJob(
            id=f"scan-{next(self._counter)}",
            targets=list(targets),
            check_ids=list(selected),
            options=options or ScanOptions(),
        )
        self._jobs[job.id] = job
        self.bus.emit("scan.job.created", job=job.to_dict())
        return job

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def jobs(self) -> list[ScanJob]:
        return list(self._jobs.values())

    def delete_job(self, job_id: str) -> bool:
        job = self._jobs.pop(job_id, None)
        if job is not None:
            self.stop(job_id)
            self.bus.emit("scan.job.deleted", id=job_id)
        return job is not None

    def stop(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job is None or job._task is None:
            return False
        if not job._task.done():
            job._task.cancel()
        job.status = "stopped"
        job.finished_at = time.time()
        self.bus.emit("scan.job.stopped", id=job_id)
        return True

    async def start(self, job_id: str) -> ScanJob | None:
        job = self._jobs.get(job_id)
        if job is None:
            return None
        if job._task is not None and not job._task.done():
            return job
        job.status = "running"
        job.error = ""
        job._task = asyncio.create_task(self._run(job), name=f"scan-{job_id}")
        return job

    async def run(self, job_id: str) -> ScanJob | None:
        job = await self.start(job_id)
        if job is None:
            return None
        if job._task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await job._task
        return job

    async def _run(self, job: ScanJob) -> None:
        concurrency = self._concurrency()
        timeout = self._timeout()
        semaphore = asyncio.Semaphore(concurrency)

        try:
            endpoints = await self._crawl(job)
            job.endpoints = endpoints
            self.bus.emit(
                "scan.endpoints", job_id=job.id, endpoints=[e.to_dict() for e in endpoints]
            )

            plan = self._plan(job, endpoints)
            job.planned = len(plan)

            async def worker(
                index: int, target: Any, check_id: str, scope: str
            ) -> ScanResult | None:
                check = self._checks[check_id]
                async with semaphore:
                    return await self._run_check(job, check, target, timeout, index, scope)

            if plan:
                gathered = await asyncio.gather(
                    *(
                        worker(index, target, check_id, scope)
                        for index, (target, check_id, scope) in enumerate(plan)
                    ),
                    return_exceptions=True,
                )
                for outcome in gathered:
                    if isinstance(outcome, BaseException) or outcome is None:
                        continue
                    job.results.append(outcome)
                    job.findings.extend(outcome.findings)
                    self.bus.emit("scan.result", job_id=job.id, result=outcome.to_dict())
            job.status = "finished"
        except asyncio.CancelledError:
            job.status = "stopped"
            raise
        except Exception as exc:  # noqa: BLE001 - a job must report its failure
            job.status = "failed"
            job.error = str(exc)
            self.bus.emit("scan.job.failed", id=job.id, error=str(exc))
        finally:
            job.finished_at = time.time()
            self.bus.emit("scan.job.finished", id=job.id, status=job.status)

    async def _crawl(self, job: ScanJob) -> list[Endpoint]:
        """The endpoints that the targets hold."""
        options = job.options
        found: list[Endpoint] = []
        if not options.crawl:
            return [Endpoint(url=target) for target in job.targets]
        crawler = EndpointCrawler(
            self.client, max_pages=options.max_pages, max_depth=options.max_depth
        )
        for target in job.targets:
            try:
                found.extend(await crawler.crawl(target))
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - a broken crawl must not stop the scan
                continue
            if len(found) >= options.max_endpoints * 2:
                break
        return found[: options.max_endpoints * 2]

    def _plan(self, job: ScanJob, endpoints: list[Endpoint]) -> list[tuple[Any, str, str]]:
        """The work of the scan: which check runs against what."""
        plan: list[tuple[Any, str, str]] = []
        for check_id in job.check_ids:
            check = self._checks.get(check_id)
            if check is None:
                continue
            if not isinstance(check, ActiveCheck):
                # A passive check reads the traffic that was observed and has
                # nothing to ask the server itself.
                continue
            scope = getattr(check, "scope", "host")
            if scope == "host":
                for target in job.targets:
                    plan.append((Endpoint(url=target), check_id, "host"))
            else:
                for endpoint in endpoints[: job.options.max_endpoints]:
                    plan.append((endpoint, check_id, "endpoint"))
        return plan

    def _concurrency(self) -> int:
        scan = getattr(self.config, "scan", None)
        return max(1, int(getattr(scan, "concurrency", 4)))

    def _timeout(self) -> float:
        scan = getattr(self.config, "scan", None)
        return float(getattr(scan, "timeout", 20.0))

    async def _run_check(
        self,
        job: ScanJob,
        check: ActiveCheck,
        target: Endpoint,
        timeout: float,
        index: int = 0,
        scope: str = "host",
    ) -> ScanResult | None:
        started = time.perf_counter()
        error = ""
        findings: list[Finding] = []
        try:
            findings = await asyncio.wait_for(self._call(check, target), timeout=max(timeout, 30.0))
        except TimeoutError:
            error = "timeout"
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - one broken check must not stop the scan
            error = f"{type(exc).__name__}: {exc}"
        elapsed = (time.perf_counter() - started) * 1000
        result = ScanResult(
            id=f"{job.id}-{index}",
            job_id=job.id,
            check_id=check.id,
            target=target.url,
            findings=findings,
            error=error,
            elapsed_ms=elapsed,
            scope=scope,
        )
        for finding in findings:
            await self.findings.add_async(finding, source="scanner")
            self.bus.emit("scan.finding", job_id=job.id, finding=finding.to_dict())
        return result

    async def _call(self, check: Any, target: Endpoint) -> list[Finding]:
        """Run a check, whichever way it was written.

        A check that was written against an older version of the scanner takes
        a plain URL, a newer one takes the endpoint. The name of the argument
        says which one it is.
        """
        run = getattr(check, "run", None)
        if run is None:
            return []
        self._hand_over(check)
        if self._takes_url(check):
            return await run(self.client, target.url)
        return await run(self.client, target)

    def _hand_over(self, check: Any) -> None:
        """Give a check the collaborator, when it needs one.

        The check needs the server that waits for a callback, and the scanner
        is the one that holds it. The server of this scanner is always the one
        that is handed over, because the built in checks are shared between
        scanners and a stale one would make a check wait on the wrong server.
        """
        if not getattr(check, "needs_collaborator", False):
            return
        with contextlib.suppress(AttributeError):
            check.collaborator = self.collaborator

    def _takes_url(self, check: Any) -> bool:
        cached = getattr(check, "_intercept_takes_url", None)
        if cached is not None:
            return bool(cached)
        takes_url = False
        try:
            parameters = list(inspect.signature(run_of(check)).parameters.values())
            takes_url = len(parameters) >= 2 and parameters[1].name == "url"
        except (TypeError, ValueError):  # pragma: no cover - a check without a signature
            takes_url = False
        with contextlib.suppress(AttributeError):  # a check with slots
            check._intercept_takes_url = takes_url
        return takes_url

    # --------------------------------------------------------------- passive

    def analyse(self, request: Any, response: Any) -> list[Finding]:
        """Run the passive checks against one observed exchange."""
        findings: list[Finding] = []
        for check in self._checks.values():
            if not isinstance(check, PassiveCheck):
                continue
            try:
                findings.extend(check.run(request, response))
            except Exception:  # noqa: BLE001 - a broken check must not break the proxy
                continue
        return findings


def run_of(check: Any) -> Any:
    """The method a check is run with."""
    return check.run

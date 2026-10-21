"""The scanner engine.

A scan job takes a list of target URLs and a list of checks, runs them and
collects the findings. Jobs run in the background and report their progress on
the event bus, so the UI can follow a scan live.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import time
from dataclasses import dataclass, field
from typing import Any

from intercept.core.events import EventBus
from intercept.plugins.api import Finding
from intercept.scanner.checks import (
    BUILTIN_CHECKS,
    ActiveCheck,
    CheckInfo,
    PassiveCheck,
    check_catalog,
)
from intercept.store.findings import FindingStore
from intercept.tools.client import ToolClient

__all__ = ["Scanner", "ScanJob", "ScanResult"]


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "check_id": self.check_id,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "elapsed_ms": self.elapsed_ms,
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
    created_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    error: str = ""
    _task: asyncio.Task | None = field(default=None, repr=False, compare=False)

    @property
    def total(self) -> int:
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
    ) -> None:
        self.client = client
        self.bus = bus
        self.findings = findings
        self.config = config
        self._jobs: dict[str, ScanJob] = {}
        self._counter = itertools.count(1)
        self._checks: dict[str, Any] = {c.id: c for c in BUILTIN_CHECKS}

    # ------------------------------------------------------------- registry

    def register_check(self, check: Any) -> None:
        """Register a check, replacing a built in one with the same id."""
        self._checks[check.id] = check

    def unregister_check(self, check_id: str) -> bool:
        return self._checks.pop(check_id, None) is not None

    def checks(self) -> list[CheckInfo]:
        catalog = [check.info().to_dict() for check in self._checks.values()]
        catalog.sort(key=lambda item: (item["category"], item["id"]))
        return catalog  # type: ignore[return-value]

    def catalog(self) -> list[dict[str, Any]]:
        """Every known check, including the ones that are not registered."""
        known = {item["id"] for item in self.checks()}
        entries = [item for item in check_catalog() if item["id"] not in known]
        return [*self.checks(), *entries]

    # ------------------------------------------------------------------ jobs

    def create_job(
        self,
        targets: list[str],
        check_ids: list[str] | None = None,
    ) -> ScanJob:
        selected = check_ids or [c.id for c in self._checks.values()]
        job = ScanJob(
            id=f"scan-{next(self._counter)}",
            targets=list(targets),
            check_ids=list(selected),
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
        plan = [
            (target, check_id)
            for target in job.targets
            for check_id in job.check_ids
            if isinstance(self._checks.get(check_id), ActiveCheck)
        ]

        try:
            async def worker(index: int, target: str, check_id: str) -> ScanResult | None:
                check = self._checks[check_id]
                async with semaphore:
                    return await self._run_check(job, check, target, timeout, index)

            gathered = await asyncio.gather(
                *(worker(index, target, check_id) for index, (target, check_id) in enumerate(plan)),
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
        target: str,
        timeout: float,
        index: int = 0,
    ) -> ScanResult | None:
        started = time.perf_counter()
        error = ""
        findings: list[Finding] = []
        try:
            findings = await asyncio.wait_for(check.run(self.client, target), timeout=timeout)
        except TimeoutError:
            error = "timeout"
        except Exception as exc:  # noqa: BLE001 - one broken check must not stop the scan
            error = f"{type(exc).__name__}: {exc}"
        elapsed = (time.perf_counter() - started) * 1000
        result = ScanResult(
            id=f"{job.id}-{index}",
            job_id=job.id,
            check_id=check.id,
            target=target,
            findings=findings,
            error=error,
            elapsed_ms=elapsed,
        )
        for finding in findings:
            await self.findings.add_async(finding, source="scanner")
            self.bus.emit("scan.finding", job_id=job.id, finding=finding.to_dict())
        return result

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

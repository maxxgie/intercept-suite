"""The fuzzer (Intruder).

The fuzzer takes a request template, finds the markers the user left in it
(``§value§``) and fires one request per payload for every position. Results
are compared against a baseline response so that interesting differences stand
out, which is what makes a fuzzing run useful.

The model is deliberately small:

``FuzzPosition``
    one marked position in the request;
``FuzzTemplate``
    a request plus its positions and the payload list;
``FuzzJob``
    a running or finished run, holding one result per request that was sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import re
import time
from dataclasses import dataclass, field
from typing import Any

from intercept.core.events import EventBus
from intercept.core.models import Headers, Request, Response
from intercept.tools.client import ToolClient

__all__ = [
    "Fuzzer",
    "FuzzJob",
    "FuzzPosition",
    "FuzzResult",
    "FuzzTemplate",
    "MARKER",
    "parse_template",
    "default_payloads",
]

#: A position is written as ``§name§`` in the request text.
MARKER = "§"

_MARKER_RE = re.compile(r"§([^§]*)§")


def default_payloads() -> list[str]:
    """A small, useful payload list to start from."""
    return [
        "1",
        "0",
        "-1",
        "999999999",
        "null",
        "true",
        "false",
        "'",
        "\"",
        "<script>alert(1)</script>",
        "../../../../etc/passwd",
        "%00",
        "{{7*7}}",
        "${7*7}",
        "admin",
    ]


@dataclass
class FuzzPosition:
    """One marked position inside a request."""

    name: str
    start: int
    end: int

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "start": self.start, "end": self.end}


@dataclass
class FuzzTemplate:
    """A request template with marked positions."""

    request: Request
    positions: list[FuzzPosition] = field(default_factory=list)
    markers: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def url(self) -> str:
        return self.request.url

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(include_raw=True),
            "positions": [p.to_dict() for p in self.positions],
            "url": self.url,
            "method": self.request.method,
        }


@dataclass
class FuzzResult:
    """The outcome of a single request made by the fuzzer."""

    id: str
    job_id: str
    url: str
    method: str
    payload: str
    position: str
    status: int = 0
    length: int = 0
    elapsed_ms: float = 0.0
    content_type: str = ""
    markers: list[str] = field(default_factory=list)
    diff: str = ""
    status_delta: int = 0
    length_delta: int = 0
    error: str = ""
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    interesting: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "job_id": self.job_id,
            "url": self.url,
            "method": self.method,
            "payload": self.payload,
            "position": self.position,
            "status": self.status,
            "length": self.length,
            "elapsed_ms": self.elapsed_ms,
            "content_type": self.content_type,
            "markers": list(self.markers),
            "diff": self.diff,
            "status_delta": self.status_delta,
            "length_delta": self.length_delta,
            "error": self.error,
            "request": self.request,
            "response": self.response,
            "interesting": self.interesting,
            "created_at": self.created_at,
        }


@dataclass
class FuzzJob:
    """A fuzzing run."""

    id: str
    template: FuzzTemplate
    payloads: list[str] = field(default_factory=list)
    position_filter: str = ""
    status: str = "pending"  # pending | running | finished | stopped | failed
    results: list[FuzzResult] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    error: str = ""
    _task: asyncio.Task | None = field(default=None, repr=False, compare=False)

    @property
    def total(self) -> int:
        positions = self._selected_positions()
        return len(positions) * len(self.payloads)

    def _selected_positions(self) -> list[FuzzPosition]:
        if not self.position_filter:
            return list(self.template.positions)
        wanted = {p.strip() for p in self.position_filter.split(",") if p.strip()}
        return [p for p in self.template.positions if p.name in wanted]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "total": self.total,
            "completed": len(self.results),
            "payloads": list(self.payloads),
            "position_filter": self.position_filter,
            "template": self.template.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }


def parse_template(request: Request) -> FuzzTemplate:
    """Find the marked positions in a request.

    Markers may appear in the URL, in a header value or in the body. The
    returned positions carry byte offsets into the matching part of the
    request, so the same request can be rebuilt with a different payload.
    """
    positions: list[FuzzPosition] = []
    markers: dict[str, tuple[int, int]] = {}

    def scan(text: str, offset: int) -> list[tuple[str, int, int]]:
        found = []
        for match in _MARKER_RE.finditer(text):
            name = match.group(1).strip() or f"pos{len(found) + 1}"
            found.append((name, offset + match.start(), offset + match.end()))
        return found

    for name, start, end in scan(request.url, 0):
        positions.append(FuzzPosition(name=name, start=start, end=end))
        markers.setdefault(name, (start, end))

    for header_name, header_value in request.headers:
        for name, start, end in scan(header_value, 0):
            positions.append(
                FuzzPosition(name=f"{header_name}:{name}", start=start, end=end)
            )
            markers.setdefault(f"{header_name}:{name}", (start, end))

    body_text = request.body.decode("utf-8", "replace")
    for name, start, end in scan(body_text, 0):
        positions.append(FuzzPosition(name=f"body:{name}", start=start, end=end))
        markers.setdefault(f"body:{name}", (start, end))

    return FuzzTemplate(request=request, positions=positions, markers=markers)


def _substitute(text: str, marker: str, payload: str) -> str:
    """Replace the first ``§marker§`` occurrence in *text*."""

    def replace(match: re.Match[str]) -> str:
        name = (match.group(1) or "").strip()
        return payload if name == marker else match.group(0)

    return _MARKER_RE.sub(replace, text, count=1)


def _apply(request: Request, position: FuzzPosition, payload: str) -> Request:
    """Build a copy of *request* with *payload* substituted at *position*."""
    clone = request.clone()

    if position.name.startswith("body:"):
        marker = position.name[len("body:") :]
        text = clone.body.decode("utf-8", "replace")
        clone.body = _substitute(text, marker, payload).encode("utf-8")
        return clone

    if ":" in position.name:
        header_name, _, marker = position.name.partition(":")
        headers = Headers()
        for name, value in clone.headers:
            if name.lower() == header_name.lower():
                value = _substitute(value, marker, payload)
            headers.add(name, value)
        clone.headers = headers
        return clone

    clone.url = _substitute(clone.url, position.name, payload)
    return clone


def _diff_markers(baseline: str, current: str) -> list[str]:
    """Return the words that only appear in the fuzzed response."""
    import re as _re

    base_words = set(_re.findall(r"[A-Za-z0-9_.\-]{4,}", baseline))
    current_words = set(_re.findall(r"[A-Za-z0-9_.\-]{4,}", current))
    return sorted(current_words - base_words)[:20]


class Fuzzer:
    """Runs fuzzing jobs against a request template."""

    def __init__(self, client: ToolClient, bus: EventBus, config: Any = None) -> None:
        self.client = client
        self.bus = bus
        self.config = config
        self._jobs: dict[str, FuzzJob] = {}
        self._counter = itertools.count(1)

    # ------------------------------------------------------------------ jobs

    def create_job(
        self,
        request: Request,
        payloads: list[str] | None = None,
        position_filter: str = "",
        name: str = "",
    ) -> FuzzJob:
        template = parse_template(request)
        job = FuzzJob(
            id=f"fuzz-{next(self._counter)}",
            template=template,
            payloads=list(payloads) if payloads else default_payloads(),
            position_filter=position_filter,
        )
        self._jobs[job.id] = job
        self.bus.emit("fuzz.job.created", job=job.to_dict())
        return job

    def get(self, job_id: str) -> FuzzJob | None:
        return self._jobs.get(job_id)

    def jobs(self) -> list[FuzzJob]:
        return list(self._jobs.values())

    def delete_job(self, job_id: str) -> bool:
        job = self._jobs.pop(job_id, None)
        if job is not None:
            self.stop(job_id)
            self.bus.emit("fuzz.job.deleted", id=job_id)
        return job is not None

    def stop(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job is None or job._task is None:
            return False
        if not job._task.done():
            job._task.cancel()
        job.status = "stopped"
        job.finished_at = time.time()
        self.bus.emit("fuzz.job.stopped", id=job_id)
        return True

    # ------------------------------------------------------------------ run

    async def start(self, job_id: str) -> FuzzJob | None:
        """Start a job in the background and return it."""
        job = self._jobs.get(job_id)
        if job is None:
            return None
        if job._task is not None and not job._task.done():
            return job
        job.status = "running"
        job.error = ""
        job._task = asyncio.create_task(self._run(job), name=f"fuzz-{job_id}")
        return job

    async def run(self, job_id: str) -> FuzzJob | None:
        """Run a job to completion, awaiting the result."""
        job = await self.start(job_id)
        if job is None:
            return None
        task = job._task
        if task is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        return job

    async def _run(self, job: FuzzJob) -> None:
        positions = job._selected_positions()
        concurrency = self._concurrency()
        timeout = self._timeout()
        semaphore = asyncio.Semaphore(concurrency)
        combinations = [
            (position, payload) for position in positions for payload in job.payloads
        ]

        try:
            baseline: Response | None = None
            baseline_text = ""
            results: list[FuzzResult] = []
            if combinations:
                # The first request establishes the baseline every other answer
                # is compared against, so it has to finish before the rest.
                position, payload = combinations[0]
                first = await self._fire(job, position, payload, None, "", timeout, 0)
                baseline = first[1]
                baseline_text = first[2]
                results.append(first[0])
                self.bus.emit("fuzz.result", job_id=job.id, result=first[0].to_dict())
                combinations = combinations[1:]

            async def worker(
                index: int, position: FuzzPosition, payload: str
            ) -> FuzzResult | None:
                async with semaphore:
                    result, _baseline, _text = await self._fire(
                        job, position, payload, baseline, baseline_text, timeout, index
                    )
                    return result

            if combinations:
                gathered = await asyncio.gather(
                    *(
                        worker(index + 1, position, payload)
                        for index, (position, payload) in enumerate(combinations)
                    ),
                    return_exceptions=True,
                )
                for outcome in gathered:
                    if isinstance(outcome, BaseException):
                        continue
                    if outcome is None:
                        continue
                    results.append(outcome)
                    self.bus.emit("fuzz.result", job_id=job.id, result=outcome.to_dict())

            job.results = results
            job.status = "finished"
        except asyncio.CancelledError:
            job.status = "stopped"
            raise
        except Exception as exc:  # noqa: BLE001 - a job must report its failure
            job.status = "failed"
            job.error = str(exc)
            self.bus.emit("fuzz.job.failed", id=job.id, error=str(exc))
        finally:
            job.finished_at = time.time()
            self.bus.emit("fuzz.job.finished", id=job.id, status=job.status)

    def _concurrency(self) -> int:
        scan = getattr(self.config, "scan", None)
        return max(1, int(getattr(scan, "concurrency", 4)))

    def _timeout(self) -> float:
        scan = getattr(self.config, "scan", None)
        return float(getattr(scan, "timeout", 20.0))

    async def _fire(
        self,
        job: FuzzJob,
        position: FuzzPosition,
        payload: str,
        baseline: Response | None,
        baseline_text: str,
        timeout: float,
        index: int = 0,
    ) -> tuple[FuzzResult, Response | None, str]:
        request = _apply(job.template.request, position, payload)
        request.origin = "fuzzer"
        try:
            response = await asyncio.wait_for(self.client.send(request), timeout=timeout)
        except TimeoutError:
            response = Response(status=0, reason="", error="timeout")

        text = response.body.decode("utf-8", "replace")
        if baseline is None:
            baseline = response
            baseline_text = text
            status_delta = 0
            length_delta = 0
            markers: list[str] = []
        else:
            status_delta = response.status - baseline.status
            length_delta = len(response.body) - len(baseline.body)
            markers = _diff_markers(baseline_text, text)

        interesting = bool(markers) or status_delta != 0 or bool(response.error)
        result = FuzzResult(
            id=f"{job.id}-{index}",
            job_id=job.id,
            url=request.url,
            method=request.method,
            payload=payload,
            position=position.name,
            status=response.status,
            length=len(response.body),
            elapsed_ms=response.elapsed_ms,
            content_type=response.mime_type,
            markers=markers,
            status_delta=status_delta,
            length_delta=length_delta,
            error=response.error,
            request=request.to_dict(include_raw=False),
            response=response.to_dict(include_raw=False),
            interesting=interesting,
        )
        return result, baseline, baseline_text

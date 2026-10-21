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

The way the payloads are spread over the positions is the attack type: a sniper
tries one payload in one position at a time, a battering ram puts the same
payload in every position, a pitchfork walks the positions together and a
cluster bomb tries every combination.
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
from intercept.tools.generators import ProcessingRule, apply_rules

__all__ = [
    "Fuzzer",
    "FuzzJob",
    "FuzzPosition",
    "FuzzResult",
    "FuzzTemplate",
    "ATTACK_TYPES",
    "MARKER",
    "parse_template",
    "default_payloads",
]

#: A position is written as ``§name§`` in the request text.
MARKER = "§"

#: The ways the payloads can be spread over the positions.
ATTACK_TYPES = ("sniper", "battering-ram", "pitchfork", "cluster-bomb")

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
        '"',
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
    hit: bool = False
    extracted: str = ""
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
            "hit": self.hit,
            "extracted": self.extracted,
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
    attack_type: str = "cluster-bomb"
    payload_sets: list[list[str]] = field(default_factory=list)
    rules: list[ProcessingRule] = field(default_factory=list)
    grep_match: str = ""
    grep_extract: str = ""
    _task: asyncio.Task | None = field(default=None, repr=False, compare=False)

    @property
    def total(self) -> int:
        return len(self.combinations())

    def _selected_positions(self) -> list[FuzzPosition]:
        if not self.position_filter:
            return list(self.template.positions)
        wanted = {p.strip() for p in self.position_filter.split(",") if p.strip()}
        return [p for p in self.template.positions if p.name in wanted]

    def _sets(self) -> list[list[str]]:
        """The payload lists, one per position where that makes sense.

        The processing rules are applied here, so the payload that is sent is
        the payload after every rule.
        """
        if self.payload_sets:
            return [apply_rules(list(group), self.rules) for group in self.payload_sets]
        return [apply_rules(list(self.payloads), self.rules)]

    def combinations(self) -> list[tuple[list[FuzzPosition], list[str]]]:
        """The requests the run will make.

        Every entry is the positions that are filled and the payload that goes
        into each of them, in the same order.
        """
        positions = self._selected_positions()
        if not positions:
            return []
        sets = self._sets()
        if not sets or not any(sets):
            return []

        if self.attack_type == "sniper":
            # One payload in one position at a time, the others left empty.
            if not sets[0]:
                return []
            out: list[tuple[list[FuzzPosition], list[str]]] = []
            for position in positions:
                for payload in sets[0]:
                    out.append(([position], [payload]))
            return out

        if self.attack_type == "battering-ram":
            # The same payload in every position at once.
            return [(list(positions), [payload] * len(positions)) for payload in sets[0]]

        if self.attack_type == "pitchfork":
            # The positions walk together, one payload each.
            groups = self._groups_for(positions, sets)
            length = max((len(group) for group in groups), default=0)
            out = []
            for index in range(length):
                out.append(
                    (list(positions), [group[min(index, len(group) - 1)] for group in groups])
                )
            return out

        # A cluster bomb tries every combination.
        groups = self._groups_for(positions, sets)
        if not groups:
            return []
        out = []
        for combo in itertools.product(*groups):
            out.append((list(positions), list(combo)))
        return out

    def _groups_for(self, positions: list[FuzzPosition], sets: list[list[str]]) -> list[list[str]]:
        """One payload list per position.

        A position without payloads of its own stays blank in every request,
        so the lists keep lining up with the positions.
        """
        groups: list[list[str]] = []
        for index in range(len(positions)):
            if index < len(sets):
                group = list(sets[index])
            elif sets:
                group = list(sets[0])
            else:
                group = []
            groups.append(group if group else [""])
        return groups

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
            "attack_type": self.attack_type,
            "payload_sets": [list(group) for group in self.payload_sets],
            "rules": [rule.to_dict() for rule in self.rules],
            "grep_match": self.grep_match,
            "grep_extract": self.grep_extract,
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
            positions.append(FuzzPosition(name=f"{header_name}:{name}", start=start, end=end))
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


def _apply_many(template: FuzzTemplate, assignments: list[tuple[FuzzPosition, str]]) -> Request:
    """Build a copy of the request with every payload substituted.

    A position that was not given a payload is emptied, so a sniper leaves the
    positions it is not working on blank.
    """
    clone = template.request.clone()
    values = {position.name: "" for position in template.positions}
    for position, payload in assignments:
        values[position.name] = payload

    url_values: dict[str, str] = {}
    header_values: dict[str, dict[str, str]] = {}
    body_values: dict[str, str] = {}
    for position in template.positions:
        value = values.get(position.name, "")
        if position.name.startswith("body:"):
            body_values[position.name[len("body:") :]] = value
        elif ":" in position.name:
            header_name, _, marker = position.name.partition(":")
            header_values.setdefault(header_name.lower(), {})[marker] = value
        else:
            url_values[position.name] = value

    def substitute(text: str, table: dict[str, str]) -> str:
        def replace(match: re.Match[str]) -> str:
            name = (match.group(1) or "").strip()
            if name in table:
                return table[name]
            return match.group(0)

        return _MARKER_RE.sub(replace, text)

    clone.url = substitute(clone.url, url_values)
    headers = Headers()
    for name, value in clone.headers:
        table = header_values.get(name.lower())
        headers.add(name, substitute(value, table) if table else value)
    clone.headers = headers
    clone.body = substitute(clone.body.decode("utf-8", "replace"), body_values).encode("utf-8")
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
        attack_type: str = "sniper",
        payload_sets: list[list[str]] | None = None,
        rules: list[ProcessingRule] | None = None,
        grep_match: str = "",
        grep_extract: str = "",
    ) -> FuzzJob:
        template = parse_template(request)
        if attack_type not in ATTACK_TYPES:
            attack_type = "sniper"
        sets = [list(group) for group in (payload_sets or [])]
        if payloads:
            chosen = list(payloads)
        elif sets:
            chosen = []
        else:
            chosen = default_payloads()
        job = FuzzJob(
            id=f"fuzz-{next(self._counter)}",
            template=template,
            payloads=chosen,
            position_filter=position_filter,
            attack_type=attack_type,
            payload_sets=sets,
            rules=list(rules or []),
            grep_match=grep_match,
            grep_extract=grep_extract,
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
        concurrency = self._concurrency()
        timeout = self._timeout()
        semaphore = asyncio.Semaphore(concurrency)
        combinations = job.combinations()

        try:
            baseline: Response | None = None
            baseline_text = ""
            job.results = []
            if combinations:
                # The first request establishes the baseline every other answer
                # is compared against, so it has to finish before the rest.
                positions, payloads = combinations[0]
                first = await self._fire(job, positions, payloads, None, "", timeout, 0)
                baseline = first[1]
                baseline_text = first[2]
                job.results.append(first[0])
                self.bus.emit("fuzz.result", job_id=job.id, result=first[0].to_dict())
                combinations = combinations[1:]

            async def worker(
                index: int, positions: list[FuzzPosition], payloads: list[str]
            ) -> FuzzResult | None:
                async with semaphore:
                    result, _baseline, _text = await self._fire(
                        job, positions, payloads, baseline, baseline_text, timeout, index
                    )
                    # The result is stored as soon as it comes in, so that a
                    # running job can be watched instead of only its end.
                    job.results.append(result)
                    self.bus.emit("fuzz.result", job_id=job.id, result=result.to_dict())
                    return result

            if combinations:
                await asyncio.gather(
                    *(
                        worker(index + 1, positions, payloads)
                        for index, (positions, payloads) in enumerate(combinations)
                    ),
                    return_exceptions=True,
                )

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
        positions: list[FuzzPosition],
        payloads: list[str],
        baseline: Response | None,
        baseline_text: str,
        timeout: float,
        index: int = 0,
    ) -> tuple[FuzzResult, Response | None, str]:
        assignments = list(zip(positions, payloads, strict=False))
        request = _apply_many(job.template, assignments)
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

        hit, extracted = self._grep(job, text)
        interesting = bool(markers) or status_delta != 0 or bool(response.error) or hit
        payload_text = " | ".join(payloads) if payloads else ""
        position_text = ", ".join(position.name for position in positions)
        result = FuzzResult(
            id=f"{job.id}-{index}",
            job_id=job.id,
            url=request.url,
            method=request.method,
            payload=payload_text,
            position=position_text,
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
            hit=hit,
            extracted=extracted,
        )
        return result, baseline, baseline_text

    def _grep(self, job: FuzzJob, text: str) -> tuple[bool, str]:
        """Look for the string and the pattern the job asked for."""
        hit = False
        extracted = ""
        if job.grep_match:
            hit = job.grep_match in text
        if job.grep_extract:
            try:
                match = re.search(job.grep_extract, text)
            except re.error:
                match = None
            if match is not None:
                extracted = match.group(0)
                hit = True
        return hit, extracted

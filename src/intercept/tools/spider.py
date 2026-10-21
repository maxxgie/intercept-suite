"""The spider.

Crawls a starting set of URLs, following links found in HTML responses. Only
in-scope URLs are followed, and the crawler records every request it makes so
the site map fills up as it goes.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from intercept.core.config import Config
from intercept.core.events import EventBus
from intercept.core.models import Headers, Request
from intercept.store.sitemap import Scope
from intercept.tools.client import ToolClient

log = logging.getLogger("intercept.spider")

__all__ = ["Spider", "LinkParser"]

_INTERESTING = {"a", "link", "script", "iframe", "form", "area", "base"}


class LinkParser(HTMLParser):
    """Collects candidate links from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.base: str | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag == "base" and values.get("href"):
            self.base = values["href"]
        elif tag in _INTERESTING:
            for attribute in ("href", "src", "action"):
                target = values.get(attribute)
                if target and not target.startswith(("javascript:", "data:", "mailto:", "#")):
                    self.links.append(target)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


@dataclass
class SpiderJob:
    """State of one crawl."""

    id: str
    seeds: list[str]
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    crawled: int = 0
    queued: int = 0
    errors: int = 0
    state: str = "running"
    visited: set[str] = field(default_factory=set)
    queue: deque[tuple[str, int]] = field(default_factory=deque)
    found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "seeds": list(self.seeds),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "crawled": self.crawled,
            "queued": len(self.queue),
            "errors": self.errors,
            "state": self.state,
            "found": list(self.found[-200:]),
        }


class Spider:
    """Crawls in-scope URLs breadth first."""

    def __init__(self, client: ToolClient, scope: Scope, config: Config, bus: EventBus) -> None:
        self.client = client
        self.scope = scope
        self.config = config
        self.bus = bus
        self._jobs: dict[str, SpiderJob] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._counter = 0

    def jobs(self) -> list[SpiderJob]:
        return list(self._jobs.values())

    def job(self, job_id: str) -> SpiderJob | None:
        return self._jobs.get(job_id)

    async def start(self, seeds: list[str]) -> SpiderJob:
        self._counter += 1
        job = SpiderJob(id=f"spider-{self._counter}", seeds=list(seeds))
        for seed in seeds:
            job.queue.append((seed, 0))
        self._jobs[job.id] = job
        self._tasks[job.id] = asyncio.create_task(self._run(job), name=job.id)
        self.bus.emit("spider.started", job=job.to_dict())
        return job

    async def stop(self, job_id: str) -> bool:
        task = self._tasks.pop(job_id, None)
        if task is None:
            return False
        task.cancel()
        job = self._jobs.get(job_id)
        if job is not None:
            job.state = "stopped"
            job.finished_at = time.time()
        self.bus.emit("spider.stopped", id=job_id)
        return True

    async def stop_all(self) -> None:
        for job_id in list(self._tasks):
            await self.stop(job_id)

    async def _run(self, job: SpiderJob) -> None:
        semaphore = asyncio.Semaphore(max(1, self.config.scan.concurrency))
        max_pages = self.config.scan.max_pages
        max_depth = self.config.scan.max_depth

        async def worker() -> None:
            while job.queue:
                if job.crawled >= max_pages:
                    return
                url, depth = job.queue.popleft()
                if url in job.visited:
                    continue
                job.visited.add(url)
                if depth > max_depth:
                    continue
                async with semaphore:
                    await self._crawl(job, url, depth)

        worker_count = max(1, self.config.scan.concurrency)
        workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            raise
        finally:
            job.state = "finished" if job.state == "running" else job.state
            job.finished_at = time.time()
            self.bus.emit("spider.finished", job=job.to_dict())

    async def _crawl(self, job: SpiderJob, url: str, depth: int) -> None:
        request = Request(
            method="GET",
            url=url,
            headers=Headers([("User-Agent", self.config.proxy.user_agent), ("Accept", "*/*")]),
            origin="spider",
        )
        response = await self.client.send(request)
        job.crawled += 1
        if response.status == 0:
            job.errors += 1
            return
        content_type = response.mime_type
        if content_type not in ("text/html", "application/xhtml+xml", ""):
            return
        try:
            text = response.body.decode("utf-8", "replace")
        except Exception:
            return
        parser = LinkParser()
        try:
            parser.feed(text)
        except Exception:
            log.debug("failed to parse links from %s", url)
            return
        base = urljoin(url, parser.base) if parser.base else url
        for link in parser.links:
            absolute = urljoin(base, link)
            if not absolute.startswith(("http://", "https://")):
                continue
            absolute = absolute.split("#")[0]
            if not absolute or absolute in job.visited:
                continue
            if not self.scope.is_in_scope(absolute):
                continue
            job.queue.append((absolute, depth + 1))
            job.found.append(absolute)
        self.bus.emit(
            "spider.progress",
            job=job.to_dict(),
            url=url,
            depth=depth,
            links=len(job.found),
        )

    def seed_from_hosts(self, hosts: list[str]) -> list[str]:
        """Turn host names into seed URLs."""
        seeds = []
        for host in hosts:
            if host.startswith(("http://", "https://")):
                seeds.append(host)
            else:
                seeds.append(f"https://{host}/")
        return seeds


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()

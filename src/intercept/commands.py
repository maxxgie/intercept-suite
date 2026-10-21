"""The built-in commands.

Every command the interface offers is registered here, so the command palette,
the context menus, the keyboard shortcuts and the task scheduler all run the
same code.
"""

from __future__ import annotations

from typing import Any

from intercept.app import InterceptApp
from intercept.core.commands import CommandRegistry

__all__ = ["register_builtin"]


def register_builtin(app: InterceptApp) -> CommandRegistry:
    """Register the commands the daemon itself provides."""
    registry = app.commands

    # ------------------------------------------------------------- workspace

    def show_view(view: str) -> dict[str, str]:
        return {"view": view}

    for view, title in (
        ("dashboard", "Dashboard"),
        ("traffic", "HTTP history"),
        ("websockets", "WebSocket history"),
        ("repeater", "Repeater"),
        ("fuzzer", "Fuzzer"),
        ("scanner", "Scanner"),
        ("findings", "Findings"),
        ("issues", "Issue tracker"),
        ("notes", "Notes and highlights"),
        ("organizer", "Organizer"),
        ("sites", "Site map and scope"),
        ("targets", "Targets"),
        ("logger", "Event log"),
        ("tasks", "Task scheduler"),
        ("reports", "Report generator"),
        ("browser", "Browser"),
        ("projects", "Project files"),
        ("extensions", "Extensions"),
        ("settings", "Settings"),
    ):
        registry.register(
            f"view.{view}",
            f"Show {title}",
            category="Workspace",
            description=f"Open the {title} view",
            keywords=[view, title.lower()],
            handler=(lambda target=view: show_view(target)),
        )

    # --------------------------------------------------------------- traffic

    async def clear_traffic(args: dict[str, Any] | None = None) -> dict[str, Any]:
        removed = await app.store.clear()
        app.log.record("info", "traffic", "traffic history cleared", {"removed": removed})
        return {"removed": removed}

    registry.register(
        "traffic.clear",
        "Clear HTTP history",
        category="Traffic",
        description="Remove every exchange from the history",
        shortcut="Ctrl+Shift+K",
        keywords=["delete", "wipe", "history"],
        handler=clear_traffic,
    )

    async def set_filter(args: dict[str, Any]) -> dict[str, Any]:
        expression = str(args.get("filter", ""))
        app.filters.set(expression)
        app.log.record("info", "traffic", "filter changed", {"filter": expression})
        return {"filter": expression}

    registry.register(
        "traffic.filter",
        "Set the traffic filter",
        category="Traffic",
        description="Apply a filter expression to the history",
        shortcut="Ctrl+F",
        keywords=["search", "filter", "expression"],
        handler=set_filter,
    )

    async def export_traffic(args: dict[str, Any]) -> dict[str, Any]:
        from intercept.core.reports import build_report, render_report

        items = await app.store.list(limit=1000)
        report = build_report(title="Traffic export", stats=await app.store.stats())
        report["findings"] = items
        target = str(args.get("path", "traffic-export.md"))
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(render_report(report, str(args.get("format", "markdown"))))
        return {"path": target, "items": len(items)}

    registry.register(
        "traffic.export",
        "Export the traffic history",
        category="Traffic",
        description="Write the history to a file",
        keywords=["save", "download"],
        handler=export_traffic,
    )

    # ------------------------------------------------------------- intercept

    async def toggle_intercept(args: dict[str, Any]) -> dict[str, Any]:
        enabled = bool(args.get("enabled"))
        if "enabled" not in args:
            enabled = not app.intercept.enabled
        app.intercept.enabled = enabled
        app.bus.emit("intercept.toggled", enabled=enabled)
        app.log.record("info", "intercept", f"interception turned {'on' if enabled else 'off'}")
        return {"enabled": enabled}

    registry.register(
        "intercept.toggle",
        "Turn interception on or off",
        category="Intercept",
        description="Hold every request so it can be inspected before it is sent",
        shortcut="Ctrl+I",
        keywords=["hold", "pause"],
        handler=toggle_intercept,
    )

    # ---------------------------------------------------------------- rules

    async def new_rule(args: dict[str, Any]) -> dict[str, Any]:
        from intercept.proxy.rules import Rule

        rule = Rule(
            id="",
            name=str(args.get("name", "")),
            kind=str(args.get("kind", "intercept")),
            host=str(args.get("host", "")),
            path=str(args.get("path", "")),
            method=str(args.get("method", "")),
            phase=str(args.get("phase", "request")),
            target=str(args.get("target", "request")),
            place=str(args.get("place", "header")),
            field=str(args.get("field", "")),
            match=str(args.get("match", "")),
            replace=str(args.get("replace", "")),
        )
        await app.rule_store.create(rule)
        await app.reload_rules()
        return rule.to_dict()

    registry.register(
        "rule.create",
        "New proxy rule",
        category="Rules",
        description="Add a rule that holds, forwards or rewrites traffic",
        keywords=["rule", "intercept", "replace", "forward"],
        handler=new_rule,
    )

    async def list_rules(args: dict[str, Any]) -> dict[str, Any]:
        rules = await app.rule_store.list()
        return {"rules": [rule.to_dict() for rule in rules]}

    registry.register(
        "rule.list",
        "List the proxy rules",
        category="Rules",
        description="Show every rule the proxy applies",
        keywords=["rules", "list"],
        handler=list_rules,
    )

    # -------------------------------------------------------------- repeater

    async def new_repeater_tab(args: dict[str, Any]) -> dict[str, Any]:
        from intercept.core.models import Headers, Request
        from intercept.proxy.http1 import serialize_request

        url = str(args.get("url", ""))
        if not url:
            return {"error": "a url is required"}
        request = Request(
            method=str(args.get("method", "GET")).upper(), url=url, headers=Headers([])
        )
        request.raw = serialize_request(
            request.method, request.origin_form, request.headers, request.body
        )
        tab = app.repeater.create_tab(request, str(args.get("name", "")))
        return tab.to_dict()

    registry.register(
        "repeater.new",
        "New repeater tab",
        category="Repeater",
        description="Open a new request tab",
        keywords=["tab", "request"],
        handler=new_repeater_tab,
    )

    # ---------------------------------------------------------------- spider

    async def crawl(args: dict[str, Any]) -> dict[str, Any]:
        seeds = list(args.get("seeds", []))
        if not seeds:
            hosts = await app.store.distinct_hosts()
            seeds = app.spider.seed_from_hosts([host["host"] for host in hosts])
        if not seeds:
            return {"error": "no seeds available"}
        job = await app.spider.start(seeds)
        app.log.record("info", "spider", "crawl started", {"seeds": seeds})
        return job.to_dict()

    registry.register(
        "spider.crawl",
        "Crawl the known hosts",
        category="Spider",
        description="Start a crawl of everything that has been seen",
        keywords=["crawl", "spider", "discover"],
        handler=crawl,
    )

    # --------------------------------------------------------------- scanner

    async def scan(args: dict[str, Any]) -> dict[str, Any]:
        targets = list(args.get("targets", []))
        if not targets:
            hosts = await app.store.distinct_hosts()
            targets = [f"http://{host['host']}/" for host in hosts]
        if not targets:
            return {"error": "no targets available"}
        checks = list(args.get("checks", []))
        job = app.scanner.create_job(targets, checks)
        await app.scanner.start(job.id)
        app.log.record("info", "scanner", "scan started", {"targets": targets})
        return job.to_dict()

    registry.register(
        "scanner.scan",
        "Scan the known hosts",
        category="Scanner",
        description="Run the scanner over the hosts that have been seen",
        keywords=["scan", "vulnerability", "check"],
        handler=scan,
    )

    # ----------------------------------------------------------------- notes

    async def add_note(args: dict[str, Any]) -> dict[str, Any]:
        note = await app.notes.create(
            str(args.get("subject", "exchange")),
            str(args.get("subject_id", "")),
            str(args.get("text", "")),
            str(args.get("color", "")),
            list(args.get("tags", [])),
        )
        return note.to_dict()

    registry.register(
        "note.create",
        "Add a note",
        category="Notes",
        description="Attach a note to an exchange, a finding or a site",
        keywords=["remark", "comment", "highlight"],
        handler=add_note,
    )

    # ---------------------------------------------------------------- issues

    async def add_issue(args: dict[str, Any]) -> dict[str, Any]:
        issue = await app.issues.create(
            str(args.get("title", "Untitled issue")),
            description=str(args.get("description", "")),
            severity=str(args.get("severity", "medium")),
            status=str(args.get("status", "open")),
            category=str(args.get("category", "")),
            exchange_ids=list(args.get("exchange_ids", [])),
        )
        app.log.record("info", "issues", "issue raised", {"title": issue.title})
        return issue.to_dict()

    registry.register(
        "issue.create",
        "Raise an issue",
        category="Issues",
        description="Open a new issue in the tracker",
        keywords=["bug", "ticket", "tracker"],
        handler=add_issue,
    )

    async def set_issue_status(args: dict[str, Any]) -> dict[str, Any]:
        issue = await app.issues.update(
            str(args.get("id", "")), status=str(args.get("status", "open"))
        )
        return issue.to_dict() if issue else {"error": "no such issue"}

    registry.register(
        "issue.status",
        "Change the status of an issue",
        category="Issues",
        description="Move an issue to another status",
        keywords=["close", "resolve", "reopen"],
        handler=set_issue_status,
    )

    # -------------------------------------------------------------- sessions

    async def new_session(args: dict[str, Any]) -> dict[str, Any]:
        session = await app.sessions.create(str(args.get("name", "Session")))
        return session.to_dict()

    registry.register(
        "session.create",
        "New session",
        category="Sessions",
        description="Start a new named session",
        keywords=["group", "bookmark"],
        handler=new_session,
    )

    # -------------------------------------------------------------- targets

    async def add_target(args: dict[str, Any]) -> dict[str, Any]:
        target = await app.targets.create(
            str(args.get("name", "")),
            host=str(args.get("host", "")),
            port=int(args.get("port", 443)),
            scheme=str(args.get("scheme", "https")),
            in_scope=bool(args.get("in_scope", True)),
            notes=str(args.get("notes", "")),
        )
        return target.to_dict()

    registry.register(
        "target.add",
        "Add a target",
        category="Targets",
        description="Record a host the engagement is about",
        keywords=["host", "scope", "add"],
        handler=add_target,
    )

    # ---------------------------------------------------------------- logger

    async def clear_log(args: dict[str, Any] | None = None) -> dict[str, Any]:
        removed = await app.log.clear()
        return {"removed": removed}

    registry.register(
        "log.clear",
        "Clear the event log",
        category="Logger",
        description="Remove every entry from the event log",
        keywords=["wipe", "clean"],
        handler=clear_log,
    )

    # --------------------------------------------------------------- reports

    async def make_report(args: dict[str, Any]) -> dict[str, Any]:
        report = await app.build_report(str(args.get("title", "Intercept report")))
        return {"report": report}

    registry.register(
        "report.build",
        "Build a report",
        category="Reports",
        description="Collect the findings, issues and notes into a report",
        keywords=["export", "summary", "writeup"],
        handler=make_report,
    )

    # -------------------------------------------------------------- projects

    async def new_project(args: dict[str, Any]) -> dict[str, Any]:
        project = app.projects.create(
            str(args.get("name", "Project")),
            description=str(args.get("description", "")),
        )
        app.log.record("info", "projects", "project created", {"name": project["name"]})
        return project

    registry.register(
        "project.create",
        "New project",
        category="Projects",
        description="Create a project directory for this engagement",
        keywords=["new", "engagement", "workspace"],
        handler=new_project,
    )

    async def save_project(args: dict[str, Any]) -> dict[str, Any]:
        project = await app.save_project(str(args.get("id", "")))
        if not project:
            return {"error": "no such project"}
        return project

    registry.register(
        "project.save",
        "Save the project",
        category="Projects",
        description="Write the current state into the project directory",
        keywords=["save", "checkpoint"],
        handler=save_project,
    )

    return registry

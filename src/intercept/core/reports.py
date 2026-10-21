"""The report generator.

Turns what the engagement produced into something a person can hand over: a
summary, the findings by severity, the issues that were raised, the notes and
the traffic statistics. Three formats are offered, because a report is either
read in a browser, pasted into a ticket or fed to another tool.
"""

from __future__ import annotations

import html
import json
import time
from typing import Any

__all__ = ["build_report", "render_report"]

_FORMATS = ("markdown", "html", "json")

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def build_report(
    *,
    title: str,
    findings: list[dict[str, Any]] | None = None,
    issues: list[dict[str, Any]] | None = None,
    notes: list[dict[str, Any]] | None = None,
    targets: list[dict[str, Any]] | None = None,
    stats: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect everything a report needs into one structure."""
    findings = list(findings or [])
    issues = list(issues or [])
    notes = list(notes or [])
    targets = list(targets or [])

    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        by_severity[severity] = by_severity.get(severity, 0) + 1

    return {
        "title": title,
        "generated_at": time.time(),
        "summary": {
            "findings": len(findings),
            "issues": len(issues),
            "notes": len(notes),
            "targets": len(targets),
            "by_severity": by_severity,
            "open_issues": sum(1 for issue in issues if issue.get("status") == "open"),
        },
        "findings": sorted(
            findings,
            key=lambda item: (
                _SEVERITY_ORDER.index(str(item.get("severity", "info")).lower())
                if str(item.get("severity", "info")).lower() in _SEVERITY_ORDER
                else len(_SEVERITY_ORDER),
                str(item.get("title", "")),
            ),
        ),
        "issues": issues,
        "notes": notes,
        "targets": targets,
        "stats": dict(stats or {}),
        "scope": dict(scope or {}),
    }


def render_report(report: dict[str, Any], fmt: str = "markdown") -> str:
    """Render *report* in the requested format."""
    if fmt == "json":
        return json.dumps(report, indent=2, default=str)
    if fmt == "html":
        return _render_html(report)
    if fmt == "markdown":
        return _render_markdown(report)
    raise ValueError(f"unknown report format: {fmt}")


# ------------------------------------------------------------------ markdown


def _render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = [f"# {report.get('title', 'Intercept report')}", ""]
    summary = report.get("summary", {})
    lines.append(f"Generated on {_stamp(report.get('generated_at'))}.")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| | Count |")
    lines.append("| --- | --- |")
    lines.append(f"| Findings | {summary.get('findings', 0)} |")
    lines.append(f"| Issues | {summary.get('issues', 0)} |")
    lines.append(f"| Open issues | {summary.get('open_issues', 0)} |")
    lines.append(f"| Notes | {summary.get('notes', 0)} |")
    lines.append(f"| Targets | {summary.get('targets', 0)} |")
    for severity in _SEVERITY_ORDER:
        count = summary.get("by_severity", {}).get(severity, 0)
        if count:
            lines.append(f"| {severity.capitalize()} findings | {count} |")
    lines.append("")

    stats = report.get("stats", {})
    if stats:
        lines.append("## Traffic")
        lines.append("")
        for key, value in stats.items():
            lines.append(f"- **{key}**: {value}")
        lines.append("")

    targets = report.get("targets", [])
    if targets:
        lines.append("## Targets")
        lines.append("")
        for target in targets:
            scope = "in scope" if target.get("in_scope", True) else "out of scope"
            where = target.get("url") or target.get("host") or ""
            lines.append(f"- **{target.get('name')}** — {where} ({scope})")
            if target.get("notes"):
                lines.append(f"  - {target['notes']}")
        lines.append("")

    findings = report.get("findings", [])
    if findings:
        lines.append("## Findings")
        lines.append("")
        for finding in findings:
            severity = str(finding.get("severity", "info")).upper()
            heading = finding.get("title", finding.get("check_id", "finding"))
            lines.append(f"### [{severity}] {heading}")
            lines.append("")
            if finding.get("url"):
                lines.append(f"URL: `{finding['url']}`")
                lines.append("")
            if finding.get("detail"):
                lines.append(f"{finding['detail']}")
                lines.append("")
            if finding.get("evidence"):
                lines.append("```")
                lines.append(str(finding["evidence"])[:2000])
                lines.append("```")
                lines.append("")

    issues = report.get("issues", [])
    if issues:
        lines.append("## Issues")
        lines.append("")
        for issue in issues:
            severity = issue.get("severity", "medium")
            status = issue.get("status", "open")
            lines.append(f"- **{issue.get('title')}** ({severity}, {status})")
            if issue.get("description"):
                lines.append(f"  - {issue['description']}")
        lines.append("")

    notes = report.get("notes", [])
    if notes:
        lines.append("## Notes")
        lines.append("")
        for note in notes:
            subject = note.get("subject_id") or note.get("subject") or ""
            lines.append(f"- **{note.get('text', '')}** ({subject})")
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- html


_HTML_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto;
       max-width: 60rem; color: #1b1f24; line-height: 1.5; }
h1, h2, h3 { color: #0b0e12; }
h2 { border-bottom: 1px solid #d8dee4; padding-bottom: .3rem; margin-top: 2.5rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #d8dee4; padding: .45rem .7rem; text-align: left; }
th { background: #f4f6f8; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em; }
pre { background: #f4f6f8; padding: .8rem; overflow-x: auto; border-radius: 4px; }
.severity { font-weight: 600; padding: .1rem .4rem; border-radius: 3px; color: #fff; }
.critical { background: #6b1d1d; } .high { background: #a33; } .medium { background: #b8860b; }
.low { background: #4a7d3a; } .info { background: #5a6672; }
.muted { color: #5a6672; }
"""


def _render_html(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    parts: list[str] = [
        "<!doctype html>",
        "<html lang='en'><head><meta charset='utf-8'>",
        f"<title>{html.escape(str(report.get('title', 'Intercept report')))}</title>",
        f"<style>{_HTML_STYLE}</style></head><body>",
        f"<h1>{html.escape(str(report.get('title', 'Intercept report')))}</h1>",
        f"<p class='muted'>Generated on {_stamp(report.get('generated_at'))}.</p>",
        "<h2>Summary</h2><table><tr><th>Metric</th><th>Count</th></tr>",
    ]
    parts.append(f"<tr><td>Findings</td><td>{summary.get('findings', 0)}</td></tr>")
    parts.append(f"<tr><td>Issues</td><td>{summary.get('issues', 0)}</td></tr>")
    parts.append(f"<tr><td>Open issues</td><td>{summary.get('open_issues', 0)}</td></tr>")
    parts.append(f"<tr><td>Notes</td><td>{summary.get('notes', 0)}</td></tr>")
    parts.append(f"<tr><td>Targets</td><td>{summary.get('targets', 0)}</td></tr>")
    for severity in _SEVERITY_ORDER:
        count = summary.get("by_severity", {}).get(severity, 0)
        if count:
            parts.append(
                f"<tr><td>{severity.capitalize()} findings</td><td>{count}</td></tr>"
            )
    parts.append("</table>")

    stats = report.get("stats", {})
    if stats:
        parts.append("<h2>Traffic</h2><table>")
        for key, value in stats.items():
            parts.append(f"<tr><td>{html.escape(str(key))}</td><td>{html.escape(str(value))}</td></tr>")
        parts.append("</table>")

    targets = report.get("targets", [])
    if targets:
        parts.append("<h2>Targets</h2><table><tr><th>Name</th><th>URL</th><th>Scope</th><th>Notes</th></tr>")
        for target in targets:
            scope = "in scope" if target.get("in_scope", True) else "out of scope"
            where = html.escape(str(target.get("url") or target.get("host") or ""))
            name = html.escape(str(target.get("name", "")))
            notes = html.escape(str(target.get("notes", "")))
            parts.append(
                f"<tr><td>{name}</td><td><code>{where}</code></td>"
                f"<td>{scope}</td><td>{notes}</td></tr>"
            )
        parts.append("</table>")

    findings = report.get("findings", [])
    if findings:
        parts.append("<h2>Findings</h2>")
        for finding in findings:
            severity = str(finding.get("severity", "info")).lower()
            parts.append(
                f"<h3><span class='severity {severity}'>{severity.upper()}</span> "
                f"{html.escape(str(finding.get('title', finding.get('check_id', 'finding'))))}</h3>"
            )
            if finding.get("url"):
                parts.append(f"<p><code>{html.escape(str(finding['url']))}</code></p>")
            if finding.get("detail"):
                parts.append(f"<p>{html.escape(str(finding['detail']))}</p>")
            if finding.get("evidence"):
                parts.append(f"<pre>{html.escape(str(finding['evidence'])[:2000])}</pre>")

    issues = report.get("issues", [])
    if issues:
        parts.append(
            "<h2>Issues</h2><table><tr><th>Title</th><th>Severity</th><th>Status</th><th>Description</th></tr>"
        )
        for issue in issues:
            parts.append(
                f"<tr><td>{html.escape(str(issue.get('title', '')))}</td>"
                f"<td>{html.escape(str(issue.get('severity', '')))}</td>"
                f"<td>{html.escape(str(issue.get('status', '')))}</td>"
                f"<td>{html.escape(str(issue.get('description', '')))}</td></tr>"
            )
        parts.append("</table>")

    notes = report.get("notes", [])
    if notes:
        parts.append("<h2>Notes</h2><ul>")
        for note in notes:
            subject = note.get("subject_id") or note.get("subject") or ""
            parts.append(
                f"<li>{html.escape(str(note.get('text', '')))} "
                f"<span class='muted'>({html.escape(str(subject))})</span></li>"
            )
        parts.append("</ul>")

    parts.append("</body></html>")
    return "\n".join(parts)


def _stamp(value: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
    except (TypeError, ValueError):
        return "an unknown time"

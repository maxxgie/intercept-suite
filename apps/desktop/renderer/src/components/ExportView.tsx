import { useState } from "react";
import { api } from "../lib/api";
import { useStore } from "../state/store";

function download(name: string, body: string, type: string): void {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

/**
 * Take the results out of the tool: the report, the findings, the traffic and
 * the log, in the formats the daemon already serves.
 */
export default function ExportView() {
  const runCommand = useStore((s) => s.runCommand);
  const setError = useStore((s) => s.setError);
  const findings = useStore((s) => s.findings);
  const total = useStore((s) => s.total);
  const issues = useStore((s) => s.issues);

  const [title, setTitle] = useState("Intercept report");
  const [format, setFormat] = useState("markdown");
  const [path, setPath] = useState("traffic-export.md");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<string | null>(null);

  async function fetchReport(as: string): Promise<void> {
    setBusy(true);
    try {
      const body = await api.text(
        `/api/reports/render?title=${encodeURIComponent(title)}&format=${as}`,
      );
      const extension = as === "html" ? "html" : as === "json" ? "json" : "md";
      download(`intercept-report.${extension}`, body, "text/plain");
      setOutcome(`The report was downloaded as ${extension}.`);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function exportFindings(): Promise<void> {
    setBusy(true);
    try {
      const body = await api.text("/api/findings?limit=1000");
      download("intercept-findings.json", body, "application/json");
      setOutcome("The findings were downloaded.");
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function exportLog(): Promise<void> {
    setBusy(true);
    try {
      const body = await api.text("/api/log/export");
      download("intercept-events.log", body, "text/plain");
      setOutcome("The event log was downloaded.");
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function exportOnDaemon(): Promise<void> {
    setBusy(true);
    try {
      const result = (await runCommand("traffic.export", {
        path: path.trim() || "traffic-export.md",
        format: format,
      })) as { path?: string; items?: number } | null;
      setOutcome(
        result?.path
          ? `The daemon wrote ${result.items ?? 0} exchanges to ${result.path}.`
          : "The daemon could not write the export.",
      );
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="export-view">
      <div className="pane-header">
        <span className="grow">Export results</span>
        <span className="muted">
          {total} exchanges · {findings.length} findings · {issues.length} issues
        </span>
      </div>

      <div className="dashboard-grid">
        <section className="card">
          <h2>Vulnerability report</h2>
          <p className="muted">The findings, the issues, the notes and the scope as one document.</p>
          <label className="field">
            <span>Title</span>
            <input
              className="filter"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
            />
          </label>
          <div className="row">
            <button className="button primary" disabled={busy} onClick={() => void fetchReport(format)}>
              Download {format}
            </button>
            <button className="button" disabled={busy} onClick={() => void fetchReport("markdown")}>
              Markdown
            </button>
            <button className="button" disabled={busy} onClick={() => void fetchReport("html")}>
              HTML
            </button>
            <button className="button" disabled={busy} onClick={() => void fetchReport("json")}>
              JSON
            </button>
          </div>
        </section>

        <section className="card">
          <h2>Raw results</h2>
          <p className="muted">The parts on their own, for a script that wants to read them.</p>
          <div className="row wrap">
            <button className="button" disabled={busy} onClick={() => void exportFindings()}>
              Findings (JSON)
            </button>
            <button className="button" disabled={busy} onClick={() => void exportLog()}>
              Event log (text)
            </button>
          </div>
        </section>

        <section className="card">
          <h2>Write on the daemon</h2>
          <p className="muted">
            The daemon writes the file itself, so the export can be large.
          </p>
          <label className="field">
            <span>Path</span>
            <input
              className="filter mono"
              value={path}
              onChange={(event) => setPath(event.target.value)}
            />
          </label>
          <label className="field">
            <span>Format</span>
            <select
              className="filter"
              value={format}
              onChange={(event) => setFormat(event.target.value)}
            >
              <option value="markdown">Markdown</option>
              <option value="html">HTML</option>
              <option value="json">JSON</option>
            </select>
          </label>
          <div className="row">
            <button className="button primary" disabled={busy} onClick={() => void exportOnDaemon()}>
              Write the file
            </button>
          </div>
        </section>
      </div>

      {outcome && <div className="banner muted">{outcome}</div>}
    </div>
  );
}

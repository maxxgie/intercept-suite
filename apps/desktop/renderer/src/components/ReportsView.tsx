import { useEffect, useState } from "react";
import { useStore } from "../state/store";
import { api } from "../lib/api";

export default function ReportsView() {
  const setView = useStore((s) => s.setView);
  const [title, setTitle] = useState("Intercept report");
  const [format, setFormat] = useState("markdown");
  const [body, setBody] = useState("");
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void build();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function build() {
    setBusy(true);
    try {
      const report = await api.get<{ summary: Record<string, unknown> }>(
        `/api/reports?title=${encodeURIComponent(title)}`,
      );
      setSummary(report.summary);
      const rendered = await api.text(
        `/api/reports/render?title=${encodeURIComponent(title)}&format=${format}`,
      );
      setBody(rendered);
    } catch {
      setBody("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <span className="muted">Report generator</span>
        </div>
        <div className="form">
          <label className="field">
            <span>Title</span>
            <input
              className="filter"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
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
            <button className="button primary" onClick={() => void build()}>
              {busy ? "Building…" : "Build"}
            </button>
            <button className="button" onClick={() => setView("issues")}>
              Review the issues
            </button>
          </div>
        </div>

        {summary && (
          <div className="card">
            <h2>Summary</h2>
            {Object.entries(summary).map(([key, value]) => (
              <div className="bar-row" key={key}>
                <span>{key.replace(/_/g, " ")}</span>
                <span className="grow" />
                <span className="mono">
                  {typeof value === "object" ? JSON.stringify(value) : String(value)}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span className="grow">Preview</span>
          <button
            className="button"
            onClick={() => {
              void navigator.clipboard.writeText(body);
            }}
          >
            Copy
          </button>
        </div>
        <pre className="report-preview mono">{body || "Build a report to see it here."}</pre>
      </section>
    </div>
  );
}

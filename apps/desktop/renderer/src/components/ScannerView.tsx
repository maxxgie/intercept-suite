import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";

export default function ScannerView() {
  const checks = useStore((s) => s.checks);
  const scanJobs = useStore((s) => s.scanJobs);
  const activeScanJobId = useStore((s) => s.activeScanJobId);
  const busy = useStore((s) => s.busy);
  const refreshScanJobs = useStore((s) => s.refreshScanJobs);
  const refreshChecks = useStore((s) => s.refreshChecks);
  const startScanJob = useStore((s) => s.startScanJob);
  const stopScanJob = useStore((s) => s.stopScanJob);
  const setView = useStore((s) => s.setView);

  const [targets, setTargets] = useState("https://example.com");
  const [selected, setSelected] = useState<string[]>([]);

  useEffect(() => {
    void refreshScanJobs();
    void refreshChecks();
  }, [refreshScanJobs, refreshChecks]);

  const active = scanJobs.find((job) => job.id === activeScanJobId) ?? null;
  const grouped = useMemo(() => {
    const map = new Map<string, typeof checks>();
    for (const check of checks) {
      const bucket = map.get(check.category) ?? [];
      bucket.push(check);
      map.set(check.category, bucket);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [checks]);

  const toggle = (id: string) => {
    setSelected((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  };

  const start = () => {
    const list = targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    void startScanJob(list, selected);
  };

  return (
    <div className="scanner">
      <div className="scanner-side">
        <div className="pane-header">
          <span className="muted mono grow">Targets</span>
        </div>
        <textarea
          className="editor mono"
          spellCheck={false}
          value={targets}
          onChange={(event) => setTargets(event.target.value)}
        />
        <div className="pane-header">
          <span className="muted mono grow">Checks</span>
          <button className="link" onClick={() => setSelected(checks.map((c) => c.id))}>
            select all
          </button>
          <button className="link" onClick={() => setSelected([])}>
            clear
          </button>
        </div>
        <div className="check-list">
          {grouped.map(([category, items]) => (
            <div key={category} className="check-group">
              <div className="check-category">{category}</div>
              {items.map((check) => (
                <label key={check.id} className="checkline" title={check.description}>
                  <input
                    type="checkbox"
                    checked={selected.includes(check.id)}
                    onChange={() => toggle(check.id)}
                  />
                  <span className="check-label">{check.label}</span>
                  <span className={`sev sev-${check.severity}`}>{check.severity}</span>
                </label>
              ))}
            </div>
          ))}
        </div>
        <div className="scanner-actions">
          <button className="button primary" disabled={busy} onClick={start}>
            {busy ? "Starting…" : `Run ${selected.length} checks`}
          </button>
        </div>
      </div>

      <div className="scanner-main">
        <div className="pane-header">
          <span className="mono grow">Scan results</span>
          {active && (
            <span className="muted">
              {active.completed}/{active.total} · {active.status}
            </span>
          )}
          {active?.status === "running" && (
            <button className="button" onClick={() => void stopScanJob(active.id)}>
              Stop
            </button>
          )}
          <button className="button" onClick={() => setView("findings")}>
            All findings
          </button>
        </div>
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-method">Check</th>
                <th className="col-host">Target</th>
                <th className="col-status">Findings</th>
                <th className="col-size">Time</th>
              </tr>
            </thead>
            <tbody>
              {active?.results.map((result) => (
                <tr key={result.id}>
                  <td className="col-method mono">{result.check_id}</td>
                  <td className="col-host mono" title={result.target}>
                    {result.target}
                  </td>
                  <td className="col-status">
                    {result.error ? (
                      <span className="status error">error</span>
                    ) : result.findings.length > 0 ? (
                      <span className="status warn">{result.findings.length}</span>
                    ) : (
                      <span className="status ok">0</span>
                    )}
                  </td>
                  <td className="col-size">{Math.round(result.elapsed_ms)} ms</td>
                </tr>
              ))}
              {!active && (
                <tr>
                  <td colSpan={4} className="empty">
                    No scan yet. Pick a target and press Run.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {active && active.findings.length > 0 && (
          <div className="scanner-findings">
            {active.findings.map((finding) => (
              <div key={finding.check_id + finding.title + finding.url} className="finding">
                <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
                <div className="finding-body">
                  <div className="finding-title">{finding.title}</div>
                  <div className="muted small">{finding.description}</div>
                  {finding.remediation && (
                    <div className="muted small">Fix: {finding.remediation}</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

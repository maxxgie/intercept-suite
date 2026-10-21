import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";

const CATEGORY_LABELS: Record<string, string> = {
  injection: "Injection",
  auth: "Authentication and access",
  web: "Web and application",
  graphql: "GraphQL",
  headers: "Headers",
  http: "HTTP",
  files: "Files",
  tls: "TLS",
  info: "Information",
  general: "General",
};

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

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
  const [crawl, setCrawl] = useState(true);
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxEndpoints, setMaxEndpoints] = useState(20);
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [onlyFindings, setOnlyFindings] = useState(false);

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

  const categories = useMemo(() => grouped.map(([name]) => name), [grouped]);

  const toggle = (id: string) => {
    setSelected((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    );
  };

  const toggleCategory = (name: string) => {
    const ids = checks.filter((check) => check.category === name).map((check) => check.id);
    const allSelected = ids.every((id) => selected.includes(id));
    setSelected((current) =>
      allSelected
        ? current.filter((id) => !ids.includes(id))
        : [...new Set([...current, ...ids])],
    );
  };

  const start = () => {
    const list = targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    void startScanJob(list, selected, {
      crawl,
      max_depth: maxDepth,
      max_endpoints: maxEndpoints,
    });
  };

  const results = useMemo(() => {
    if (!active) return [];
    const rows = onlyFindings
      ? active.results.filter((result) => result.findings.length > 0 || result.error)
      : active.results;
    return rows.filter((result) => {
      if (category === "all") return true;
      const check = checks.find((item) => item.id === result.check_id);
      return check?.category === category;
    });
  }, [active, onlyFindings, category, checks]);

  const findings = useMemo(() => {
    if (!active) return [];
    const list = active.findings.filter((finding) => {
      if (severity !== "all" && finding.severity !== severity) return false;
      if (category === "all") return true;
      const check = checks.find((item) => item.id === finding.check_id);
      return check?.category === category;
    });
    return [...list].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    );
  }, [active, severity, category, checks]);

  const counts = useMemo(() => {
    const map = new Map<string, number>();
    for (const finding of active?.findings ?? []) {
      map.set(finding.severity, (map.get(finding.severity) ?? 0) + 1);
    }
    return map;
  }, [active]);

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
          <span className="muted mono grow">Scan</span>
          <label className="checkline" title="Look for the pages and the parameters under the target first">
            <input
              type="checkbox"
              checked={crawl}
              onChange={(event) => setCrawl(event.target.checked)}
            />
            crawl
          </label>
          <label className="checkline" title="How deep the crawl goes">
            depth
            <input
              className="filter"
              style={{ width: 52 }}
              type="number"
              min={0}
              max={5}
              value={maxDepth}
              onChange={(event) => setMaxDepth(Number(event.target.value))}
            />
          </label>
          <label className="checkline" title="How many places are probed">
            places
            <input
              className="filter"
              style={{ width: 56 }}
              type="number"
              min={1}
              max={100}
              value={maxEndpoints}
              onChange={(event) => setMaxEndpoints(Number(event.target.value))}
            />
          </label>
        </div>

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
          {grouped.map(([name, items]) => (
            <div key={name} className="check-group">
              <div className="check-category">
                <button className="link" onClick={() => toggleCategory(name)}>
                  {CATEGORY_LABELS[name] ?? name}
                </button>
                <span className="muted small">{items.length}</span>
              </div>
              {items.map((check) => (
                <label key={check.id} className="checkline" title={check.description}>
                  <input
                    type="checkbox"
                    checked={selected.includes(check.id)}
                    onChange={() => toggle(check.id)}
                  />
                  <span className="check-label">{check.label}</span>
                  <span className={`sev sev-${check.severity}`}>{check.severity}</span>
                  {check.scope === "endpoint" && (
                    <span className="muted small" title="Runs for every place that takes input">
                      input
                    </span>
                  )}
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
              {active.completed}/{active.total} · {active.status} · {active.endpoints.length} places
            </span>
          )}
          {active?.status === "running" && (
            <button className="button" onClick={() => void stopScanJob(active.id)}>
              Stop
            </button>
          )}
          <select
            className="filter"
            value={category}
            onChange={(event) => setCategory(event.target.value)}
          >
            <option value="all">every category</option>
            {categories.map((name) => (
              <option key={name} value={name}>
                {CATEGORY_LABELS[name] ?? name}
              </option>
            ))}
          </select>
          <select
            className="filter"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            <option value="all">every severity</option>
            {SEVERITY_ORDER.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
          <label className="checkline">
            <input
              type="checkbox"
              checked={onlyFindings}
              onChange={(event) => setOnlyFindings(event.target.checked)}
            />
            only what was found
          </label>
          <button className="button" onClick={() => setView("findings")}>
            All findings
          </button>
        </div>

        {active && active.findings.length > 0 && (
          <div className="scanner-summary">
            {SEVERITY_ORDER.map((level) =>
              counts.get(level) ? (
                <button
                  key={level}
                  className={`sev sev-${level}`}
                  onClick={() => setSeverity(severity === level ? "all" : level)}
                >
                  {level} {counts.get(level)}
                </button>
              ) : null,
            )}
          </div>
        )}

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
              {results.map((result) => (
                <tr key={result.id}>
                  <td className="col-method mono" title={result.scope}>
                    {result.check_id}
                  </td>
                  <td className="col-host mono" title={result.target}>
                    {result.target}
                  </td>
                  <td className="col-status">
                    {result.error ? (
                      <span className="status error" title={result.error}>
                        error
                      </span>
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
              {active && results.length === 0 && (
                <tr>
                  <td colSpan={4} className="empty">
                    Nothing matches the current filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {findings.length > 0 && (
          <div className="scanner-findings">
            {findings.map((finding, index) => (
              <div key={`${finding.check_id}-${index}`} className="finding">
                <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
                <div className="finding-body">
                  <div className="finding-title">{finding.title}</div>
                  <div className="muted small">{finding.description}</div>
                  {finding.evidence && (
                    <div className="muted small mono">{finding.evidence}</div>
                  )}
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

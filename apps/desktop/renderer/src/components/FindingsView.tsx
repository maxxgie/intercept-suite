import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";
import type { Finding } from "../types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export default function FindingsView() {
  const findings = useStore((s) => s.findings);
  const refreshFindings = useStore((s) => s.refreshFindings);
  const acknowledgeFinding = useStore((s) => s.acknowledgeFinding);
  const clearFindings = useStore((s) => s.clearFindings);

  const [severity, setSeverity] = useState<string>("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    void refreshFindings();
  }, [refreshFindings]);

  const counts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const finding of findings) {
      map[finding.severity] = (map[finding.severity] ?? 0) + 1;
    }
    return map;
  }, [findings]);

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return findings.filter((finding) => {
      if (severity && finding.severity !== severity) return false;
      if (!needle) return true;
      return (
        finding.title.toLowerCase().includes(needle) ||
        finding.url.toLowerCase().includes(needle) ||
        finding.check_id.toLowerCase().includes(needle)
      );
    });
  }, [findings, severity, search]);

  return (
    <div className="findings">
      <div className="pane-header">
        <input
          className="filter"
          placeholder="Filter by title, url or check"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <div className="sev-filters">
          <button className={severity === "" ? "sev-chip active" : "sev-chip"} onClick={() => setSeverity("")}>
            all {findings.length}
          </button>
          {SEVERITIES.map((level) => (
            <button
              key={level}
              className={severity === level ? "sev-chip active" : "sev-chip"}
              onClick={() => setSeverity(level)}
            >
              {level} {counts[level] ?? 0}
            </button>
          ))}
        </div>
        <button className="button" onClick={() => void clearFindings()}>
          Clear
        </button>
      </div>
      <div className="findings-list">
        {rows.map((finding) => (
          <FindingRow
            key={finding.id}
            finding={finding}
            onAcknowledge={() => void acknowledgeFinding(finding.id)}
          />
        ))}
        {rows.length === 0 && (
          <div className="placeholder">
            <p>No findings yet.</p>
            <p className="muted">Run a scan, or browse a target to trigger the passive checks.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function FindingRow({ finding, onAcknowledge }: { finding: Finding; onAcknowledge: () => void }) {
  return (
    <div className={finding.acknowledged ? "finding acknowledged" : "finding"}>
      <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
      <div className="finding-body">
        <div className="finding-title">{finding.title}</div>
        <div className="muted small">
          {finding.check_id} · {finding.url || "no url"} · {finding.source}
        </div>
        {finding.description && <div className="small">{finding.description}</div>}
        {finding.evidence && (
          <pre className="finding-evidence mono small">{finding.evidence}</pre>
        )}
        {finding.remediation && <div className="muted small">Fix: {finding.remediation}</div>}
      </div>
      <button className="link" onClick={onAcknowledge}>
        {finding.acknowledged ? "reopen" : "acknowledge"}
      </button>
    </div>
  );
}

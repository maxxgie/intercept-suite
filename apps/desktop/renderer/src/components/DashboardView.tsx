import { useEffect } from "react";
import { useStore } from "../state/store";

function severityClass(severity: string): string {
  if (severity === "critical" || severity === "high") return "status error";
  if (severity === "medium") return "status warn";
  if (severity === "low" || severity === "info") return "status info";
  return "status";
}

export default function DashboardView() {
  const dashboard = useStore((s) => s.dashboard);
  const refresh = useStore((s) => s.refreshDashboard);
  const setView = useStore((s) => s.setView);
  const runCommand = useStore((s) => s.runCommand);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (!dashboard) {
    return <div className="placeholder">Loading the overview…</div>;
  }

  const severities = Object.entries(dashboard.findings?.by_severity ?? {}).sort(
    (a, b) => b[1] - a[1],
  );
  const statuses = Object.entries(dashboard.issues?.by_status ?? {});
  const levels = Object.entries(dashboard.log?.levels ?? {});

  return (
    <div className="dashboard">
      <div className="stat-row">
        <button className="stat" onClick={() => setView("traffic")}>
          <span className="stat-value">{dashboard.traffic?.exchanges ?? 0}</span>
          <span className="stat-label">exchanges</span>
        </button>
        <button className="stat" onClick={() => setView("sites")}>
          <span className="stat-value">{dashboard.traffic?.hosts ?? 0}</span>
          <span className="stat-label">hosts</span>
        </button>
        <button className="stat" onClick={() => setView("findings")}>
          <span className="stat-value">{dashboard.findings?.total ?? 0}</span>
          <span className="stat-label">findings</span>
        </button>
        <button className="stat" onClick={() => setView("issues")}>
          <span className="stat-value">{dashboard.issues?.total ?? 0}</span>
          <span className="stat-label">issues</span>
        </button>
        <button className="stat" onClick={() => setView("notes")}>
          <span className="stat-value">{dashboard.notes}</span>
          <span className="stat-label">notes</span>
        </button>
        <button className="stat" onClick={() => setView("websockets")}>
          <span className="stat-value">{dashboard.websockets}</span>
          <span className="stat-label">websocket frames</span>
        </button>
      </div>

      <div className="dashboard-grid">
        <section className="card">
          <h2>Findings by severity</h2>
          {severities.length === 0 && <div className="muted small">Nothing found yet.</div>}
          {severities.map(([severity, count]) => (
            <div className="bar-row" key={severity}>
              <span className={severityClass(severity)}>{severity}</span>
              <span className="bar">
                <span
                  className={`bar-fill ${severity}`}
                  style={{ width: `${Math.min(100, count * 8)}%` }}
                />
              </span>
              <span className="mono">{count}</span>
            </div>
          ))}
        </section>

        <section className="card">
          <h2>Issues by status</h2>
          {statuses.length === 0 && <div className="muted small">No issues raised.</div>}
          {statuses.map(([status, count]) => (
            <div className="bar-row" key={status}>
              <span>{status}</span>
              <span className="bar">
                <span className="bar-fill" style={{ width: `${Math.min(100, count * 8)}%` }} />
              </span>
              <span className="mono">{count}</span>
            </div>
          ))}
        </section>

        <section className="card">
          <h2>Targets</h2>
          {(dashboard.targets ?? []).length === 0 && (
            <div className="muted small">No targets recorded.</div>
          )}
          {(dashboard.targets ?? []).map((target) => (
            <div className="plugin-row" key={target.id}>
              <div>
                <strong>{target.name}</strong>
                <div className="muted small mono">{target.url}</div>
              </div>
              <span className={`status ${target.in_scope ? "ok" : "muted"}`}>
                {target.in_scope ? "in scope" : "out of scope"}
              </span>
            </div>
          ))}
        </section>

        <section className="card">
          <h2>Event log</h2>
          <div className="muted small">{dashboard.log?.total ?? 0} entries</div>
          {levels.map(([level, count]) => (
            <div className="bar-row" key={level}>
              <span className={`log-level ${level}`}>{level}</span>
              <span className="bar">
                <span className="bar-fill" style={{ width: `${Math.min(100, count * 4)}%` }} />
              </span>
              <span className="mono">{count}</span>
            </div>
          ))}
          <div className="row">
            <button className="button" onClick={() => setView("logger")}>
              Open the log
            </button>
          </div>
        </section>
      </div>

      <section className="card">
        <h2>Quick actions</h2>
        <div className="row wrap">
          <button className="button" onClick={() => void runCommand("spider.crawl")}>
            Crawl the known hosts
          </button>
          <button className="button" onClick={() => void runCommand("scanner.scan")}>
            Scan the known hosts
          </button>
          <button className="button" onClick={() => void runCommand("report.build")}>
            Build a report
          </button>
          <button className="button" onClick={() => setView("projects")}>
            Project files
          </button>
        </div>
      </section>
    </div>
  );
}

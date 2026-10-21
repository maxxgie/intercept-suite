import { useEffect, useMemo } from "react";
import { useStore, type BottomTab } from "../state/store";
import { IconChevron, IconClose } from "./icons";

const TABS: { id: BottomTab; label: string }[] = [
  { id: "logs", label: "Logs" },
  { id: "events", label: "Events" },
  { id: "alerts", label: "Alerts" },
  { id: "status", label: "Status" },
];

function timeOf(seconds: number): string {
  return new Date(seconds * 1000).toLocaleTimeString(undefined, { hour12: false });
}

/**
 * The bottom panel: the log, the live event stream, the alerts and the state
 * of the daemon. It folds away when the workspace needs the room.
 */
export default function BottomPanel() {
  const tab = useStore((s) => s.bottomTab);
  const setTab = useStore((s) => s.setBottomTab);
  const collapsed = useStore((s) => s.bottomCollapsed);
  const toggleBottom = useStore((s) => s.toggleBottom);
  const entries = useStore((s) => s.logEntries);
  const events = useStore((s) => s.daemonEvents);
  const clearEvents = useStore((s) => s.clearDaemonEvents);
  const findings = useStore((s) => s.findings);
  const issues = useStore((s) => s.issues);
  const daemon = useStore((s) => s.daemon);
  const connected = useStore((s) => s.connected);
  const adopted = useStore((s) => s.adopted);
  const total = useStore((s) => s.total);
  const refreshLog = useStore((s) => s.refreshLog);

  useEffect(() => {
    void refreshLog();
  }, [refreshLog]);

  const alerts = useMemo(() => {
    const fromLog = entries
      .filter((entry) => entry.level === "error" || entry.level === "critical")
      .map((entry) => ({
        id: `log-${entry.id}`,
        at: entry.created_at,
        level: entry.level,
        source: entry.source,
        message: entry.message,
      }));
    const fromFindings = findings
      .filter((finding) => finding.severity === "critical" || finding.severity === "high")
      .map((finding) => ({
        id: `finding-${finding.id}`,
        at: finding.created_at,
        level: finding.severity,
        source: "scanner",
        message: finding.title,
      }));
    const fromIssues = issues
      .filter((issue) => issue.severity === "critical" || issue.severity === "high")
      .map((issue) => ({
        id: `issue-${issue.id}`,
        at: issue.created_at,
        level: issue.severity,
        source: "issues",
        message: issue.title,
      }));
    return [...fromLog, ...fromFindings, ...fromIssues].sort((a, b) => b.at - a.at);
  }, [entries, findings, issues]);

  const recent = useMemo(() => [...events].reverse().slice(0, 300), [events]);

  return (
    <section className={collapsed ? "bottom-panel collapsed" : "bottom-panel"}>
      <div className="bottom-header">
        {TABS.map((item) => (
          <button
            key={item.id}
            className={tab === item.id && !collapsed ? "bottom-tab active" : "bottom-tab"}
            onClick={() => setTab(item.id)}
          >
            {item.label}
            {item.id === "alerts" && alerts.length > 0 && (
              <span className="nav-count warn">{alerts.length}</span>
            )}
          </button>
        ))}

        <span className="spacer" />

        {tab === "events" && !collapsed && (
          <button className="link" onClick={clearEvents}>
            clear
          </button>
        )}

        <button
          className="icon-button"
          onClick={toggleBottom}
          title={collapsed ? "Show the panel" : "Hide the panel"}
          aria-label={collapsed ? "Show the panel" : "Hide the panel"}
        >
          {collapsed ? <IconChevron size={14} /> : <IconClose size={14} />}
        </button>
      </div>

      {!collapsed && (
        <div className="bottom-body">
          {tab === "logs" && (
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="col-time">Time</th>
                  <th className="col-method">Level</th>
                  <th className="col-host">Source</th>
                  <th className="col-path">Message</th>
                </tr>
              </thead>
              <tbody>
                {[...entries].reverse().slice(0, 300).map((entry) => (
                  <tr key={entry.id}>
                    <td className="col-time">{timeOf(entry.created_at)}</td>
                    <td className="col-method">
                      <span className={`log-level ${entry.level}`}>{entry.level}</span>
                    </td>
                    <td className="col-host">{entry.source}</td>
                    <td className="col-path" title={entry.message}>
                      {entry.message}
                    </td>
                  </tr>
                ))}
                {entries.length === 0 && (
                  <tr>
                    <td colSpan={4} className="empty">
                      Nothing logged yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}

          {tab === "events" && (
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="col-time">Time</th>
                  <th className="col-method">Event</th>
                  <th className="col-host">Detail</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((event) => (
                  <tr key={event.id}>
                    <td className="col-time">{timeOf(event.ts)}</td>
                    <td className="col-method mono">{event.type}</td>
                    <td className="col-host mono" title={JSON.stringify(event.data)}>
                      {summarise(event.data)}
                    </td>
                  </tr>
                ))}
                {recent.length === 0 && (
                  <tr>
                    <td colSpan={3} className="empty">
                      No events have come in yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}

          {tab === "alerts" && (
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="col-time">Time</th>
                  <th className="col-method">Severity</th>
                  <th className="col-host">Source</th>
                  <th className="col-path">Message</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td className="col-time">{timeOf(alert.at)}</td>
                    <td className="col-method">
                      <span className={`sev sev-${alert.level}`}>{alert.level}</span>
                    </td>
                    <td className="col-host">{alert.source}</td>
                    <td className="col-path">{alert.message}</td>
                  </tr>
                ))}
                {alerts.length === 0 && (
                  <tr>
                    <td colSpan={4} className="empty">
                      Nothing needs attention.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}

          {tab === "status" && (
            <div className="status-grid">
              <div className="status-cell">
                <span className="muted small">Daemon</span>
                <strong>{connected ? "online" : "offline"}</strong>
                {adopted && <span className="muted small">attached to a running instance</span>}
              </div>
              <div className="status-cell">
                <span className="muted small">Proxy</span>
                <strong className="mono">
                  {daemon ? `${daemon.proxy.host}:${daemon.proxy.port}` : "—"}
                </strong>
                <span className="muted small">
                  upstream verification {daemon?.proxy.upstream_verify ? "on" : "off"}
                </span>
              </div>
              <div className="status-cell">
                <span className="muted small">HTTP/2</span>
                <strong>{daemon?.proxy.http2 ? "on" : "off"}</strong>
              </div>
              <div className="status-cell">
                <span className="muted small">Exchanges</span>
                <strong>{total}</strong>
              </div>
              <div className="status-cell">
                <span className="muted small">Findings</span>
                <strong>{findings.length}</strong>
              </div>
              <div className="status-cell">
                <span className="muted small">Open issues</span>
                <strong>{issues.filter((issue) => issue.status === "open").length}</strong>
              </div>
              <div className="status-cell">
                <span className="muted small">Certificate authority</span>
                <strong className="mono small">{daemon?.ca.fingerprint ?? "—"}</strong>
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function summarise(data: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(data)) {
    if (value === null || value === undefined) continue;
    if (typeof value === "object") continue;
    parts.push(`${key}=${String(value).slice(0, 60)}`);
  }
  return parts.slice(0, 4).join("  ");
}

import { useEffect, useMemo } from "react";
import { useStore } from "../state/store";
import type { ExchangeSummary, LogEntry } from "../types";

interface Entry {
  id: string;
  at: number;
  kind: "traffic" | "event";
  title: string;
  detail: string;
  severity: string;
  exchange?: ExchangeSummary;
}

/**
 * What happened, in the order it happened: the traffic that came through and
 * the events the daemon published.
 */
export default function ActivityView() {
  const traffic = useStore((s) => s.traffic);
  const entries = useStore((s) => s.logEntries);
  const events = useStore((s) => s.daemonEvents);
  const refreshLog = useStore((s) => s.refreshLog);
  const select = useStore((s) => s.select);
  const setView = useStore((s) => s.setView);
  const setFilter = useStore((s) => s.setFilter);

  useEffect(() => {
    void refreshLog();
  }, [refreshLog]);

  const timeline = useMemo<Entry[]>(() => {
    const fromTraffic: Entry[] = traffic.slice(0, 120).map((exchange) => ({
      id: `t-${exchange.id}`,
      at: exchange.created_at,
      kind: "traffic",
      title: `${exchange.method} ${exchange.path || "/"}`,
      detail: `${exchange.host} · ${exchange.status || "ERR"}`,
      severity:
        exchange.status >= 500
          ? "error"
          : exchange.status >= 400
            ? "warning"
            : exchange.status >= 300
              ? "info"
              : "ok",
      exchange,
    }));

    const fromLog: Entry[] = entries.map((entry: LogEntry) => ({
      id: `l-${entry.id}`,
      at: entry.created_at,
      kind: "event",
      title: entry.message,
      detail: entry.source,
      severity: entry.level === "critical" ? "error" : entry.level,
    }));

    const fromBus: Entry[] = events.slice(-120).map((event) => ({
      id: `e-${event.id}`,
      at: event.ts,
      kind: "event",
      title: event.type,
      detail: Object.entries(event.data)
        .filter(([, value]) => typeof value !== "object")
        .slice(0, 3)
        .map(([key, value]) => `${key}=${String(value).slice(0, 40)}`)
        .join(" · "),
      severity: "info",
    }));

    return [...fromTraffic, ...fromLog, ...fromBus].sort((a, b) => b.at - a.at).slice(0, 400);
  }, [traffic, entries, events]);

  return (
    <div className="activity-view">
      <div className="pane-header">
        <span className="muted grow">{timeline.length} entries</span>
        <button className="button" onClick={() => void refreshLog()}>
          Refresh
        </button>
      </div>

      <div className="activity-list">
        {timeline.map((entry) => (
          <div className="activity-row" key={entry.id}>
            <span className={`activity-dot ${entry.severity}`} />
            <span className="activity-time mono">
              {new Date(entry.at * 1000).toLocaleTimeString(undefined, { hour12: false })}
            </span>
            <span className="activity-title grow" title={entry.title}>
              {entry.title}
            </span>
            <span className="activity-detail muted small" title={entry.detail}>
              {entry.detail}
            </span>
            {entry.exchange && (
              <div className="row tight">
                <button
                  className="link"
                  onClick={() => {
                    void setFilter(`host == "${entry.exchange!.host}"`);
                    setView("traffic");
                  }}
                >
                  filter
                </button>
                <button
                  className="link"
                  onClick={() => {
                    void select(entry.exchange!.id);
                    setView("traffic");
                  }}
                >
                  open
                </button>
              </div>
            )}
          </div>
        ))}
        {timeline.length === 0 && (
          <div className="placeholder">
            Nothing has happened yet. Browse a site through the proxy to see the activity.
          </div>
        )}
      </div>
    </div>
  );
}

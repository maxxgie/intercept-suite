import { useMemo, useState } from "react";
import { useStore } from "../state/store";
import type { ExchangeSummary } from "../types";
import MessageViewer from "./MessageViewer";

function statusClass(status: number): string {
  if (status === 0) return "status error";
  if (status >= 500) return "status error";
  if (status >= 400) return "status warn";
  if (status >= 300) return "status info";
  if (status >= 200) return "status ok";
  return "status";
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatTime(seconds: number): string {
  const date = new Date(seconds * 1000);
  return date.toLocaleTimeString(undefined, { hour12: false });
}

export default function TrafficView() {
  const traffic = useStore((s) => s.traffic);
  const total = useStore((s) => s.total);
  const selectedId = useStore((s) => s.selectedId);
  const detail = useStore((s) => s.detail);
  const select = useStore((s) => s.select);
  const openInRepeater = useStore((s) => s.openInRepeater);
  const [filter, setFilter] = useState("");

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    if (!needle) return traffic;
    return traffic.filter(
      (item) =>
        item.url.toLowerCase().includes(needle) ||
        item.method.toLowerCase().includes(needle) ||
        item.host.toLowerCase().includes(needle),
    );
  }, [traffic, filter]);

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <input
            className="filter"
            placeholder="Filter by host, path or method"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
          <span className="muted">{rows.length}/{total}</span>
        </div>
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-time">Time</th>
                <th className="col-method">Method</th>
                <th className="col-host">Host</th>
                <th className="col-path">Path</th>
                <th className="col-status">Status</th>
                <th className="col-size">Size</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  className={row.id === selectedId ? "selected" : undefined}
                  onClick={() => void select(row.id)}
                >
                  <td className="col-time">{formatTime(row.created_at)}</td>
                  <td className="col-method">
                    <span className={`method method-${row.method.toLowerCase()}`}>{row.method}</span>
                  </td>
                  <td className="col-host" title={row.host}>
                    {row.host}
                  </td>
                  <td className="col-path" title={row.url}>
                    {row.path}
                    {row.query ? `?${row.query}` : ""}
                  </td>
                  <td className="col-status">
                    <span className={statusClass(row.status)}>{row.status || "ERR"}</span>
                  </td>
                  <td className="col-size">{formatSize(row.response_length)}</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={6} className="empty">
                    No traffic captured yet. Point a browser at the proxy to start.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="pane detail-pane">
        {detail ? (
          <>
            <div className="pane-header">
              <span className="mono grow" title={detail.request.url}>
                {detail.request.method} {detail.request.url}
              </span>
              <button className="button" onClick={() => void openInRepeater(detail)}>
                Send to repeater
              </button>
            </div>
            <MessageViewer exchange={detail} />
          </>
        ) : (
          <div className="placeholder">Select a request to inspect it.</div>
        )}
      </section>
    </div>
  );
}

export function exchangeLabel(row: ExchangeSummary): string {
  return `${row.method} ${row.path}`;
}

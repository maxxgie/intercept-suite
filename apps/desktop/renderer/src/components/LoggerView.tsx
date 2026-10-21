import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";

const LEVELS = ["debug", "info", "warning", "error", "critical"];

export default function LoggerView() {
  const entries = useStore((s) => s.logEntries);
  const refresh = useStore((s) => s.refreshLog);
  const clear = useStore((s) => s.clearLog);
  const [level, setLevel] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return entries.filter((entry) => {
      if (level && entry.level !== level) return false;
      if (!needle) return true;
      return (
        entry.message.toLowerCase().includes(needle) ||
        entry.source.toLowerCase().includes(needle)
      );
    });
  }, [entries, level, search]);

  return (
    <div className="pane list-pane">
      <div className="pane-header">
        <input
          className="filter"
          placeholder="Search the log"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <select
          className="filter"
          value={level}
          onChange={(event) => setLevel(event.target.value)}
        >
          <option value="">every level</option>
          {LEVELS.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        <span className="muted">
          {rows.length}/{entries.length}
        </span>
        <button className="button" onClick={() => void clear()}>
          Clear
        </button>
      </div>
      <div className="table-wrap">
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
            {rows.map((entry) => (
              <tr key={entry.id}>
                <td className="col-time">
                  {new Date(entry.created_at * 1000).toLocaleTimeString(undefined, {
                    hour12: false,
                  })}
                </td>
                <td className="col-method">
                  <span className={`log-level ${entry.level}`}>{entry.level}</span>
                </td>
                <td className="col-host">{entry.source}</td>
                <td className="col-path" title={entry.message}>
                  {entry.message}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={4} className="empty">
                  Nothing logged yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

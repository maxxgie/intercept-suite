import { useEffect, useState } from "react";
import { useStore } from "../state/store";

export default function WebSocketView() {
  const connections = useStore((s) => s.websocketConnections);
  const messages = useStore((s) => s.websocketMessages);
  const refresh = useStore((s) => s.refreshWebsockets);
  const [selected, setSelected] = useState<string | null>(null);
  const [direction, setDirection] = useState("");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const rows = messages.filter((message) => {
    if (selected && message.connection_id !== selected) return false;
    if (direction && message.direction !== direction) return false;
    return true;
  });

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <select
            className="filter"
            value={selected ?? ""}
            onChange={(event) => setSelected(event.target.value || null)}
          >
            <option value="">every connection</option>
            {connections.map((connection) => (
              <option key={connection.id} value={connection.id}>
                {connection.url}
              </option>
            ))}
          </select>
          <select
            className="filter"
            value={direction}
            onChange={(event) => setDirection(event.target.value)}
          >
            <option value="">both ways</option>
            <option value="client">to server</option>
            <option value="server">to client</option>
          </select>
          <span className="muted">{rows.length} frames</span>
        </div>
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-time">Time</th>
                <th className="col-method">Direction</th>
                <th className="col-host">Type</th>
                <th className="col-path">Payload</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((message) => (
                <tr key={message.id}>
                  <td className="col-time">
                    {new Date(message.created_at * 1000).toLocaleTimeString(undefined, {
                      hour12: false,
                    })}
                  </td>
                  <td className="col-method">
                    <span className={`method method-${message.direction}`}>
                      {message.direction}
                    </span>
                  </td>
                  <td className="col-host">{message.opcode}</td>
                  <td className="col-path mono" title={message.payload}>
                    {message.payload.slice(0, 200)}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={4} className="empty">
                    No WebSocket traffic yet. Browse a site that uses one.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span>Connections</span>
        </div>
        <div className="notes-list">
          {connections.map((connection) => (
            <div className="note-card" key={connection.id}>
              <div className="note-text mono">{connection.url}</div>
              <div className="note-meta muted small">
                <span>{connection.method}</span>
                <span>{connection.host}</span>
                <span>{connection.closed ? "closed" : "open"}</span>
                <span>{new Date(connection.created_at * 1000).toLocaleTimeString()}</span>
              </div>
            </div>
          ))}
          {connections.length === 0 && (
            <div className="placeholder">No WebSocket connections were seen.</div>
          )}
        </div>
      </section>
    </div>
  );
}

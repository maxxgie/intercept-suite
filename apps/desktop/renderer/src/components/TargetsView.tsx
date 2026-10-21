import { useEffect, useState } from "react";
import { useStore } from "../state/store";

export default function TargetsView() {
  const targets = useStore((s) => s.targets);
  const refresh = useStore((s) => s.refreshTargets);
  const create = useStore((s) => s.createTarget);
  const update = useStore((s) => s.updateTarget);
  const remove = useStore((s) => s.deleteTarget);
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [scheme, setScheme] = useState("https");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function add() {
    if (!name.trim() || !host.trim()) return;
    await create(name.trim(), host.trim(), Number(port) || 443, scheme);
    setName("");
    setHost("");
  }

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <span className="muted">{targets.length} targets</span>
        </div>
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-host">Name</th>
                <th className="col-path">URL</th>
                <th className="col-status">Scope</th>
                <th className="col-time">Notes</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((target) => (
                <tr key={target.id}>
                  <td className="col-host">{target.name}</td>
                  <td className="col-path mono">{target.url}</td>
                  <td className="col-status">
                    <button
                      className={`status ${target.in_scope ? "ok" : "muted"}`}
                      onClick={() => void update(target.id, { in_scope: !target.in_scope })}
                    >
                      {target.in_scope ? "in scope" : "out of scope"}
                    </button>
                  </td>
                  <td className="col-time" title={target.notes}>
                    {target.notes}
                  </td>
                </tr>
              ))}
              {targets.length === 0 && (
                <tr>
                  <td colSpan={4} className="empty">
                    No targets yet. Add the hosts you are testing.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span>Add a target</span>
        </div>
        <div className="form">
          <input
            className="filter"
            placeholder="Name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <input
            className="filter"
            placeholder="Host"
            value={host}
            onChange={(event) => setHost(event.target.value)}
          />
          <div className="row">
            <select
              className="filter"
              value={scheme}
              onChange={(event) => setScheme(event.target.value)}
            >
              <option value="https">https</option>
              <option value="http">http</option>
            </select>
            <input
              className="filter"
              placeholder="Port"
              value={port}
              onChange={(event) => setPort(event.target.value)}
            />
          </div>
          <div className="row">
            <span className="grow" />
            <button className="button primary" onClick={() => void add()}>
              Add target
            </button>
          </div>
        </div>

        {targets.length > 0 && (
          <div className="card">
            <h2>Remove</h2>
            {targets.map((target) => (
              <div className="plugin-row" key={target.id}>
                <span>{target.name}</span>
                <button className="link" onClick={() => void remove(target.id)}>
                  remove
                </button>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

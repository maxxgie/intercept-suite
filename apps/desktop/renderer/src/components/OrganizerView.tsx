import { Fragment, useEffect, useState } from "react";
import { useStore } from "../state/store";

export default function OrganizerView() {
  const hosts = useStore((s) => s.organizer);
  const refresh = useStore((s) => s.refreshOrganizer);
  const setFilter = useStore((s) => s.setFilter);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <div className="pane list-pane">
      <div className="pane-header">
        <span className="muted">{hosts.length} hosts</span>
      </div>
      <div className="table-wrap">
        <table className="traffic-table">
          <thead>
            <tr>
              <th className="col-host">Host</th>
              <th className="col-method">Requests</th>
              <th className="col-status">Statuses</th>
              <th className="col-size">Size</th>
              <th className="col-time">Filter</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((host) => (
              <Fragment key={host.host}>
                <tr
                  className="organizer-host"
                  onClick={() => setOpen(open === host.host ? null : host.host)}
                >
                  <td className="col-host">
                    {open === host.host ? "▾" : "▸"} {host.host}
                  </td>
                  <td className="col-method">{host.count}</td>
                  <td className="col-status">
                    {Object.entries(host.statuses ?? {})
                      .sort((a, b) => b[1] - a[1])
                      .slice(0, 4)
                      .map(([status, count]) => (
                        <span className="status-chip" key={status}>
                          {status} × {count}
                        </span>
                      ))}
                  </td>
                  <td className="col-size">{(host.size / 1024).toFixed(1)} kB</td>
                  <td className="col-time">
                    <button
                      className="link"
                      onClick={(event) => {
                        event.stopPropagation();
                        void setFilter(`host == "${host.host}"`);
                      }}
                    >
                      show
                    </button>
                  </td>
                </tr>
                {open === host.host &&
                  Object.values(host.paths ?? {})
                    .sort((a, b) => b.count - a.count)
                    .map((path) => (
                      <tr className="organizer-path" key={path.path}>
                        <td className="col-host" />
                        <td className="col-method mono" colSpan={2}>
                          {path.path}
                        </td>
                        <td className="col-size">{path.count}</td>
                        <td className="col-time">
                          <button
                            className="link"
                            onClick={(event) => {
                              event.stopPropagation();
                              void setFilter(
                                `host == "${host.host}" and path == "${path.path}"`,
                              );
                            }}
                          >
                            show
                          </button>
                        </td>
                      </tr>
                    ))}
              </Fragment>
            ))}
            {hosts.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  Nothing to organise yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

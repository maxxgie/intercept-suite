import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";

interface Endpoint {
  host: string;
  scheme: string;
  path: string;
  methods: string[];
  hits: number;
  status: number;
}

/**
 * Every path that was seen, as one table. The site map shows the same thing
 * as a tree; this is the flat list.
 */
export default function EndpointsView() {
  const sites = useStore((s) => s.sites);
  const refresh = useStore((s) => s.refreshSites);
  const openInRepeater = useStore((s) => s.openInRepeater);
  const setFilter = useStore((s) => s.setFilter);
  const [search, setSearch] = useState("");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const endpoints = useMemo<Endpoint[]>(() => {
    const rows: Endpoint[] = [];
    for (const site of sites) {
      for (const node of site.nodes) {
        rows.push({
          host: site.host,
          scheme: site.scheme,
          path: node.path,
          methods: node.methods,
          hits: node.hits,
          status: node.status,
        });
      }
    }
    return rows.sort((a, b) => b.hits - a.hits || a.host.localeCompare(b.host));
  }, [sites]);

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return endpoints;
    return endpoints.filter(
      (row) => row.path.toLowerCase().includes(needle) || row.host.toLowerCase().includes(needle),
    );
  }, [endpoints, search]);

  return (
    <div className="endpoints-view">
      <div className="pane-header">
        <input
          className="filter"
          placeholder="Filter by host or path"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <span className="muted">
          {visible.length}/{endpoints.length}
        </span>
        <button className="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>

      <div className="table-wrap">
        <table className="traffic-table">
          <thead>
            <tr>
              <th className="col-host">Host</th>
              <th className="col-path">Path</th>
              <th className="col-method">Methods</th>
              <th className="col-status">Status</th>
              <th className="col-size">Hits</th>
              <th className="col-time" />
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <tr key={`${row.host}${row.path}`}>
                <td className="col-host" title={`${row.scheme}://${row.host}`}>
                  {row.host}
                </td>
                <td className="col-path mono" title={row.path}>
                  {row.path}
                </td>
                <td className="col-method">
                  <span className="pill">{row.methods.join(" ") || "—"}</span>
                </td>
                <td className="col-status">
                  <span className={row.status >= 400 ? "status warn" : "status ok"}>
                    {row.status || "—"}
                  </span>
                </td>
                <td className="col-size">{row.hits}</td>
                <td className="col-time">
                  <div className="row tight">
                    <button
                      className="link"
                      onClick={() => void setFilter(`host == "${row.host}" and path == "${row.path}"`)}
                    >
                      filter
                    </button>
                    <button
                      className="link"
                      onClick={() =>
                        void openInRepeater({
                          url: `${row.scheme}://${row.host}${row.path}`,
                          method: row.methods[0] ?? "GET",
                        } as never)
                      }
                    >
                      repeater
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  No endpoint has been discovered yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

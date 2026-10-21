import { useState } from "react";
import { useStore } from "../state/store";
import type { SiteNode } from "../types";

function NodeRow({
  node,
  depth,
}: {
  node: SiteNode;
  depth: number;
}) {
  const [open, setOpen] = useState(depth < 1);
  const hasChildren = node.children.length > 0;
  const openInRepeater = useStore((s) => s.openInRepeater);

  return (
    <>
      <div className="tree-row" style={{ paddingLeft: depth * 14 + 6 }}>
        {hasChildren ? (
          <button className="twisty" onClick={() => setOpen(!open)}>
            {open ? "▾" : "▸"}
          </button>
        ) : (
          <span className="twisty spacer" />
        )}
        <span className="tree-name">{node.name}</span>
        {node.methods.length > 0 && <span className="pill">{node.methods.join(" ")}</span>}
        {node.status > 0 && <span className="muted mono">{node.status}</span>}
        <span className="grow" />
        <button
          className="link"
          onClick={() => void openInRepeater({ url: node.path, method: node.methods[0] ?? "GET" } as never)}
        >
          repeater
        </button>
      </div>
      {open &&
        node.children.map((child) => <NodeRow key={child.path} node={child} depth={depth + 1} />)}
    </>
  );
}

export default function SiteMapView() {
  const sites = useStore((s) => s.sites);
  const refresh = useStore((s) => s.refreshSites);
  const [filter, setFilter] = useState("");

  const visible = sites.filter((site) =>
    filter ? site.host.toLowerCase().includes(filter.toLowerCase()) : true,
  );

  return (
    <div className="sites">
      <div className="pane-header">
        <input
          className="filter"
          placeholder="Filter hosts"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        />
        <button className="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>
      <div className="tree">
        {visible.map((site) => (
          <div className="tree-host" key={site.host}>
            <div className="tree-row host">
              <span className="tree-name">
                {site.scheme}://{site.host}
              </span>
              <span className="pill">{site.hits}</span>
            </div>
            {site.nodes.map((node) => (
              <NodeRow key={node.path} node={node} depth={1} />
            ))}
          </div>
        ))}
        {visible.length === 0 && (
          <div className="placeholder">
            Nothing discovered yet. Browse a site through the proxy or run the crawler.
          </div>
        )}
      </div>
    </div>
  );
}

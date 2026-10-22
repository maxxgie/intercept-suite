import { useMemo, useState } from "react";
import { useStore } from "../state/store";
import type { CollaboratorInteraction } from "../types";

const KIND_HINTS: Record<string, string> = {
  http: "A URL the target is told to fetch. Use it for a blind SSRF or a blind XXE.",
  xxe: "An XML document with an entity that points at the collaborator.",
  ssrf: "A URL that is put into a place where the target fetches it.",
  sqli: "A SQL fragment that makes the database read the URL.",
  rce: "A command that reaches out to the collaborator.",
  dns: "A name under the collaborator domain. Use it when HTTP is not possible.",
  smtp: "An address the target sends mail to.",
};

const KIND_LABELS: Record<string, string> = {
  http: "HTTP callback",
  xxe: "Blind XXE",
  ssrf: "Blind SSRF",
  sqli: "Blind SQL injection",
  rce: "Blind RCE",
  dns: "DNS interaction",
  smtp: "SMTP interaction",
};

const KIND_CLASS: Record<string, string> = {
  http: "badge",
  xxe: "badge warn",
  ssrf: "badge warn",
  sqli: "badge error",
  rce: "badge error",
  dns: "badge",
  smtp: "badge",
};

/** Copy a text to the clipboard, so a payload can be pasted somewhere. */
async function copy(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    /* the clipboard may not be reachable, which is not worth an error */
  }
}

/** The time the interaction arrived, in the local form. */
function stamp(value: number): string {
  if (!value) return "";
  return new Date(value * 1000).toLocaleTimeString();
}

export default function CollaboratorView() {
  const status = useStore((s) => s.collaboratorStatus);
  const interactions = useStore((s) => s.collaboratorInteractions);
  const payload = useStore((s) => s.collaboratorPayload);
  const busy = useStore((s) => s.busy);
  const refresh = useStore((s) => s.refreshCollaborator);
  const build = useStore((s) => s.buildCollaboratorPayload);
  const clear = useStore((s) => s.clearCollaboratorInteractions);
  const setRunning = useStore((s) => s.setCollaboratorRunning);

  const [kind, setKind] = useState("http");
  const [target, setTarget] = useState("");
  const [extra, setExtra] = useState("");
  const [filter, setFilter] = useState("");
  const [only, setOnly] = useState("");

  const kinds = status?.kinds ?? [];
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return interactions.filter((item) => {
      if (only && item.kind !== only) return false;
      if (!needle) return true;
      return `${item.kind} ${item.token} ${item.peer} ${item.detail} ${item.body}`
        .toLowerCase()
        .includes(needle);
    });
  }, [interactions, filter, only]);

  const buildPayload = () => {
    void build(kind, target, extra);
  };

  const selected = interactions.length > 0 ? interactions[0] : null;

  return (
    <div className="collaborator">
      <div className="collaborator-side">
        <div className="pane-header">
          <span className="muted mono grow">The collaborator</span>
          {status?.running ? (
            <span className="badge ok">listening</span>
          ) : (
            <span className="badge error">not running</span>
          )}
        </div>

        <div className="card">
          <dl>
            <dt>HTTP</dt>
            <dd className="mono">{status?.url || "—"}</dd>
            <dt>DNS</dt>
            <dd className="mono">
              {status?.dns_server ? `${status.dns_server} (${status.domain})` : "—"}
            </dd>
            <dt>SMTP</dt>
            <dd className="mono">{status?.smtp_server || "—"}</dd>
            <dt>Heard</dt>
            <dd>{status?.interactions ?? 0} interactions</dd>
          </dl>
        </div>

        <div className="pane-header">
          <button className="button" onClick={() => void refresh()}>
            Refresh
          </button>
          <button
            className="button"
            onClick={() => void setRunning(!status?.running)}
          >
            {status?.running ? "Stop" : "Start"}
          </button>
        </div>

        <div className="pane-header">
          <span className="muted mono grow">A payload</span>
        </div>

        <div className="pane-header">
          <select
            className="filter"
            value={kind}
            onChange={(event) => setKind(event.target.value)}
          >
            {kinds.length > 0
              ? kinds.map((item) => (
                  <option key={item.kind} value={item.kind}>
                    {item.label}
                  </option>
                ))
              : Object.entries(KIND_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
          </select>
        </div>
        <p className="muted small collaborator-hint">
          {KIND_HINTS[kind] ?? ""}
        </p>

        <div className="pane-header">
          <input
            className="filter"
            placeholder="where the payload goes (a URL, a parameter, a command)"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
          />
        </div>
        <div className="pane-header">
          <input
            className="filter"
            placeholder="data to carry along (optional)"
            value={extra}
            onChange={(event) => setExtra(event.target.value)}
          />
          <button
            className="button primary"
            disabled={busy || !status?.running}
            onClick={buildPayload}
          >
            {busy ? "Building…" : "Build"}
          </button>
        </div>

        {payload && (
          <>
            <div className="pane-header">
              <span className="muted mono grow">{payload.label}</span>
              <span className="muted small mono">{payload.token}</span>
            </div>
            <div className="collaborator-payload">
              <pre className="mono">{payload.payload}</pre>
              <button
                className="button"
                onClick={() => void copy(payload.payload)}
              >
                Copy the payload
              </button>
            </div>
            <div className="card">
              <dl>
                <dt>URL</dt>
                <dd className="mono">{payload.url}</dd>
                <dt>Name</dt>
                <dd className="mono">{payload.hostname}</dd>
                <dt>Mail</dt>
                <dd className="mono">{payload.mail}</dd>
                {payload.dns_server && (
                  <>
                    <dt>DNS server</dt>
                    <dd className="mono">{payload.dns_server}</dd>
                  </>
                )}
                {payload.smtp_server && (
                  <>
                    <dt>Mail server</dt>
                    <dd className="mono">{payload.smtp_server}</dd>
                  </>
                )}
              </dl>
            </div>
          </>
        )}
      </div>

      <div className="collaborator-main">
        <div className="pane-header">
          <span className="mono grow">The calls that arrived</span>
          <select
            className="filter"
            value={only}
            onChange={(event) => setOnly(event.target.value)}
          >
            <option value="">every kind</option>
            {Object.entries(KIND_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <input
            className="filter"
            placeholder="filter"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          />
          <button className="button" onClick={() => void clear()}>
            Clear
          </button>
        </div>

        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-method">Kind</th>
                <th className="col-path">Token</th>
                <th className="col-path">Detail</th>
                <th className="col-size">From</th>
                <th className="col-size">When</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((item: CollaboratorInteraction) => (
                <tr key={item.id}>
                  <td className="col-method">
                    <span className={KIND_CLASS[item.kind] ?? "badge"}>
                      {KIND_LABELS[item.kind] ?? item.kind}
                    </span>
                  </td>
                  <td className="col-path mono">{item.token}</td>
                  <td className="col-path mono" title={item.detail}>
                    {item.detail.slice(0, 70)}
                  </td>
                  <td className="col-size mono">{item.peer}</td>
                  <td className="col-size">{stamp(item.at)}</td>
                </tr>
              ))}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={5} className="empty">
                    Nothing has called the collaborator yet. Put a payload into the target
                    and wait for it to reach out.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {selected && (
          <>
            <div className="pane-header">
              <span className="mono grow">The last call</span>
              <span className={KIND_CLASS[selected.kind] ?? "badge"}>
                {KIND_LABELS[selected.kind] ?? selected.kind}
              </span>
            </div>
            <div className="card">
              <dl>
                <dt>Token</dt>
                <dd className="mono">{selected.token}</dd>
                <dt>From</dt>
                <dd className="mono">{selected.peer}</dd>
                <dt>Detail</dt>
                <dd className="mono">{selected.detail}</dd>
              </dl>
            </div>
            {Object.keys(selected.headers).length > 0 && (
              <div className="table-wrap">
                <table className="traffic-table">
                  <thead>
                    <tr>
                      <th className="col-path">Header</th>
                      <th className="col-path">Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(selected.headers).map(([name, value]) => (
                      <tr key={name}>
                        <td className="col-path mono">{name}</td>
                        <td className="col-path mono" title={value}>
                          {value}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {selected.body && (
              <>
                <div className="pane-header">
                  <span className="muted mono grow">The body it sent</span>
                </div>
                <pre className="mono collaborator-body">{selected.body}</pre>
              </>
            )}
            {selected.raw && (
              <>
                <div className="pane-header">
                  <span className="muted mono grow">The call as it arrived</span>
                </div>
                <pre className="mono collaborator-body">{selected.raw}</pre>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}

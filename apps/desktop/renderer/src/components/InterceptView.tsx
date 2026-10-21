import { useEffect, useState } from "react";
import { useStore } from "../state/store";
import type { HeldMessage } from "../types";
import { api } from "../lib/api";
import { IconClose, IconPlay } from "./icons";

interface HeldMessageProps {
  id: string;
  onDecided: () => void;
}

/**
 * The text of a held message, with the fields that may be changed.
 *
 * The response may be rewritten before it is let through: a different status,
 * different headers or a different body.
 */
function HeldMessageEditor({ id, onDecided }: HeldMessageProps) {
  const decide = useStore((s) => s.decideHeldRequestWith);
  const [message, setMessage] = useState<HeldMessage | null>(null);
  const [status, setStatus] = useState("");
  const [body, setBody] = useState("");
  const [headers, setHeaders] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void api
      .get<HeldMessage>(`/api/intercept/${id}`)
      .then((response) => {
        if (cancelled) return;
        setMessage(response);
        const editing = response.phase === "response" ? response.response : response.request;
        setStatus(response.response ? String(response.response.status) : "");
        setBody(editing?.body ?? "");
        setHeaders(
          editing
            ? Object.entries(editing.headers)
                .map(([name, values]) => `${name}: ${values.join(", ")}`)
                .join("\n")
            : "",
        );
      })
      .catch((cause: Error) => {
        if (!cancelled) setError(cause.message);
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  async function forwardEdited() {
    if (!message) return;
    const headerMap: Record<string, string[]> = {};
    for (const line of headers.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const index = trimmed.indexOf(":");
      if (index <= 0) continue;
      const name = trimmed.slice(0, index).trim();
      const value = trimmed.slice(index + 1).trim();
      headerMap[name] = [...(headerMap[name] ?? []), value];
    }
    const payload: Record<string, unknown> = { action: "forward" };
    if (message.phase === "response" && message.response) {
      payload.status = Number(status) || message.response.status;
      payload.response_headers = headerMap;
      payload.response_body = body;
    } else {
      // The head of the original request is sent along, so the request line
      // and the version stay the way the client wrote them.
      const raw = message.request.raw ?? "";
      const index = raw.indexOf("\r\n\r\n");
      payload.raw = index === -1 ? raw : raw.slice(0, index);
      payload.url = message.request.url;
      payload.method = message.request.method;
      payload.headers = headerMap;
      payload.body = body;
    }
    await decide(id, payload);
    onDecided();
  }

  if (error) return <div className="placeholder small">{error}</div>;
  if (!message) return <div className="placeholder small">Loading the message…</div>;

  return (
    <div className="form">
      <dl className="small">
        <dt>Method</dt>
        <dd className="mono">{message.request.method}</dd>
        <dt>URL</dt>
        <dd className="mono">{message.request.url}</dd>
        {message.response && (
          <>
            <dt>Status</dt>
            <dd className="mono">{message.response.status} {message.response.reason}</dd>
          </>
        )}
      </dl>

      {message.phase === "response" && (
        <div className="field">
          <label htmlFor={`held-status-${id}`}>Status</label>
          <input
            id={`held-status-${id}`}
            className="filter"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          />
        </div>
      )}

      <div className="field">
        <label htmlFor={`held-headers-${id}`}>Headers</label>
        <textarea
          id={`held-headers-${id}`}
          className="filter mono"
          rows={4}
          value={headers}
          onChange={(event) => setHeaders(event.target.value)}
        />
      </div>

      <div className="field">
        <label htmlFor={`held-body-${id}`}>Body</label>
        <textarea
          id={`held-body-${id}`}
          className="filter mono"
          rows={8}
          value={body}
          onChange={(event) => setBody(event.target.value)}
        />
      </div>

      <div className="row">
        <button className="button primary" onClick={() => void forwardEdited()}>
          <IconPlay size={12} />
          Forward the edited {message.phase}
        </button>
      </div>
    </div>
  );
}

/**
 * The requests the proxy is holding.
 *
 * Turning interception on makes the proxy hold every request until it is
 * answered here, which is what makes request smuggling and cache poisoning
 * analysis possible. A response can be held as well, and it can be rewritten
 * before it is let through.
 */
export default function InterceptView() {
  const enabled = useStore((s) => s.interceptEnabled);
  const setIntercept = useStore((s) => s.setIntercept);
  const held = useStore((s) => s.heldRequests);
  const items = useStore((s) => s.heldItems);
  const frames = useStore((s) => s.heldFrames);
  const decide = useStore((s) => s.decideHeldRequest);
  const decideFrame = useStore((s) => s.decideHeldFrame);
  const refresh = useStore((s) => s.refreshHeldRequests);
  const [open, setOpen] = useState<string | null>(null);
  const [frameText, setFrameText] = useState<Record<string, string>>({});

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const rows = items.length > 0 ? items : held;

  return (
    <div className="intercept-view">
      <div className="pane-header">
        <button
          className={enabled ? "intercept-toggle active" : "intercept-toggle"}
          onClick={() => void setIntercept(!enabled)}
        >
          {enabled ? "Interception is on" : "Interception is off"}
        </button>
        <span className="muted">
          {rows.length === 0 && frames.length === 0
            ? "No request is being held."
            : `${rows.length} message${rows.length === 1 ? "" : "s"} and ${frames.length} frame${
                frames.length === 1 ? "" : "s"
              } waiting for an answer.`}
        </span>
      </div>

      <div className="table-wrap">
        <table className="traffic-table">
          <thead>
            <tr>
              <th className="col-time">Held at</th>
              <th className="col-method">Method</th>
              <th className="col-host">Host</th>
              <th className="col-path">Path</th>
              <th className="col-size">Size</th>
              <th className="col-status">Decision</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((request) => (
              <tr key={request.id}>
                <td className="col-time">
                  {new Date(request.created_at * 1000).toLocaleTimeString(undefined, {
                    hour12: false,
                  })}
                </td>
                <td className="col-method">
                  <span className={`method method-${request.method.toLowerCase()}`}>
                    {request.method}
                  </span>
                  {"phase" in request && request.phase === "response" && (
                    <span className="muted small"> response</span>
                  )}
                </td>
                <td className="col-host" title={request.url}>
                  {request.host}
                </td>
                <td className="col-path" title={request.url}>
                  {request.path}
                </td>
                <td className="col-size">{request.body_length} B</td>
                <td className="col-status">
                  <div className="row tight">
                    <button
                      className="button primary"
                      onClick={() => void decide(request.id, "forward")}
                    >
                      <IconPlay size={12} />
                      Forward
                    </button>
                    <button
                      className="button"
                      onClick={() => setOpen(open === request.id ? null : request.id)}
                    >
                      Edit
                    </button>
                    <button className="button" onClick={() => void decide(request.id, "drop")}>
                      <IconClose size={12} />
                      Drop
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  {enabled
                    ? "The proxy is holding every request. The next one shows up here."
                    : "Turn interception on to hold the requests that come in."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {open && (
        <HeldMessageEditor id={open} onDecided={() => setOpen(null)} />
      )}

      {frames.length > 0 && (
        <>
          <div className="pane-header">
            <span>Held WebSocket frames</span>
            <span className="muted">{frames.length} waiting</span>
          </div>
          <div className="table-wrap">
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="col-method">Direction</th>
                  <th className="col-host">Type</th>
                  <th className="col-path">Payload</th>
                  <th className="col-status">Decision</th>
                </tr>
              </thead>
              <tbody>
                {frames.map((frame) => (
                  <tr key={frame.id}>
                    <td className="col-method">
                      <span className={`method method-${frame.direction}`}>{frame.direction}</span>
                    </td>
                    <td className="col-host">{frame.type}</td>
                    <td className="col-path">
                      <textarea
                        className="filter mono"
                        rows={2}
                        value={frameText[frame.id] ?? frame.text}
                        onChange={(event) =>
                          setFrameText({ ...frameText, [frame.id]: event.target.value })
                        }
                      />
                    </td>
                    <td className="col-status">
                      <div className="row tight">
                        <button
                          className="button primary"
                          onClick={() =>
                            void decideFrame(
                              frame.id,
                              "forward",
                              frameText[frame.id] ?? frame.text,
                            )
                          }
                        >
                          <IconPlay size={12} />
                          Forward
                        </button>
                        <button
                          className="button"
                          onClick={() => void decideFrame(frame.id, "drop")}
                        >
                          <IconClose size={12} />
                          Drop
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

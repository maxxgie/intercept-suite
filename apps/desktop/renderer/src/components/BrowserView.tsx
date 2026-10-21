import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useStore } from "../state/store";
import type { RepeaterTab, ResponseDetail } from "../types";
import { bodyBytes } from "../lib/bytes";

interface BrowserHistory {
  url: string;
  status: number;
  reason: string;
  mime: string;
  size: number;
  at: number;
}

/** The body of a response as text, or a note that it is binary. */
function bodyText(response: ResponseDetail): string {
  if (response.body_encoding !== "base64") return response.body;
  const bytes = bodyBytes(response.body, "base64");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return `(${bytes.length} binary bytes)`;
  }
}

/**
 * A small browser that talks through the proxy, so everything it fetches ends
 * up in the same history as the traffic from a real browser.
 */
export default function BrowserView() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [response, setResponse] = useState<ResponseDetail | null>(null);
  const [history, setHistory] = useState<BrowserHistory[]>([]);
  const addTab = useStore((s) => s.addTab);
  const setError = useStore((s) => s.setError);

  useEffect(() => {
    setUrl("http://");
  }, []);

  async function visit(target: string) {
    const address = target.trim();
    if (!address) return;
    setBusy(true);
    setResponse(null);
    try {
      const tab = await api.post<{ id: string }>("/api/repeater/tabs", {
        url: address,
        method: "GET",
        name: address,
      });
      const sent = await api.post<{ response: ResponseDetail | null }>(
        `/api/repeater/tabs/${tab.id}/send`,
        { tab_id: tab.id },
      );
      const result = sent.response;
      setResponse(result);
      if (result) {
        setHistory((current) =>
          [
            {
              url: address,
              status: result.status,
              reason: result.reason,
              mime: result.mime_type,
              size: result.body_length,
              at: Date.now() / 1000,
            },
            ...current,
          ].slice(0, 50),
        );
      }
      await api.delete(`/api/repeater/tabs/${tab.id}`);
    } catch (error) {
      setError((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function openExternally() {
    const address = url.trim();
    if (!address) return;
    window.intercept.openExternal(address);
  }

  async function sendToRepeater() {
    if (!response) return;
    const tab = await api.post<RepeaterTab>("/api/repeater/tabs", {
      url: url.trim(),
      method: "GET",
      name: url.trim(),
    });
    addTab(tab);
  }

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header browser-bar">
          <input
            className="filter mono grow"
            placeholder="http://example.com"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void visit(url);
            }}
          />
          <button className="button primary" disabled={busy} onClick={() => void visit(url)}>
            Go
          </button>
          <button className="button" onClick={() => void openExternally()}>
            System browser
          </button>
        </div>
        <div className="notes-list">
          {history.map((item, index) => (
            <button
              className="browser-history-item"
              key={`${item.url}-${index}`}
              onClick={() => {
                setUrl(item.url);
                void visit(item.url);
              }}
            >
              <span className={`status ${item.status >= 400 ? "warn" : "ok"}`}>
                {item.status}
              </span>
              <span className="mono grow" title={item.url}>
                {item.url}
              </span>
              <span className="muted small">{(item.size / 1024).toFixed(1)} kB</span>
            </button>
          ))}
          {history.length === 0 && (
            <div className="placeholder">
              Type a URL to start. Everything fetched here is recorded in the history.
            </div>
          )}
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span className="grow mono">
            {response ? `${response.status} ${response.reason}` : busy ? "Loading…" : "No page yet"}
          </span>
          <button className="button" disabled={!response} onClick={() => void sendToRepeater()}>
            Send to repeater
          </button>
        </div>
        {response ? (
          <div className="browser-response">
            <div className="browser-meta muted small">
              {response.mime_type} · {response.body_length} bytes · {response.http_version}
            </div>
            <pre className="report-preview mono">
              {bodyText(response) || "(empty body)"}
            </pre>
          </div>
        ) : (
          <div className="placeholder">The response will show up here.</div>
        )}
      </section>
    </div>
  );
}

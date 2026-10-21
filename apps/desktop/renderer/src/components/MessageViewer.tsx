import { useMemo, useState } from "react";
import type { ExchangeDetail, HeadersMap, MessageDetail, ResponseDetail } from "../types";
import { useStore, type MessageTab } from "../state/store";

function prettyJson(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

function HeadersTable({ headers }: { headers: HeadersMap }) {
  const entries = Object.entries(headers);
  if (entries.length === 0) return <div className="placeholder small">No headers</div>;
  return (
    <table className="headers-table">
      <tbody>
        {entries.flatMap(([name, values]) =>
          values.map((value, index) => (
            <tr key={`${name}-${index}`}>
              <td className="header-name">{name}</td>
              <td className="header-value mono">{value}</td>
            </tr>
          )),
        )}
      </tbody>
    </table>
  );
}

function BodyView({ body }: { body: string }) {
  const pretty = useMemo(() => prettyJson(body), [body]);
  if (!body) return <div className="placeholder small">Empty body</div>;
  return (
    <pre className="body-view">
      {pretty ?? body}
    </pre>
  );
}

interface Props {
  request: MessageDetail;
  response: ResponseDetail | null;
}

export function MessageTabs({
  request,
  response,
  tab,
  setTab,
}: Props & { tab: MessageTab; setTab: (tab: MessageTab) => void }) {
  const target = response ?? request;
  const headers = target.headers;
  const body = target.body;
  const raw = target.raw;
  return (
    <>
      <div className="tabs">
        {(["pretty", "headers", "body", "raw"] as MessageTab[]).map((name) => (
          <button
            key={name}
            className={tab === name ? "tab active" : "tab"}
            onClick={() => setTab(name)}
          >
            {name[0].toUpperCase() + name.slice(1)}
          </button>
        ))}
      </div>
      <div className="tab-body">
        {tab === "pretty" && <BodyView body={body} />}
        {tab === "headers" && <HeadersTable headers={headers} />}
        {tab === "body" && <BodyView body={body} />}
        {tab === "raw" && <pre className="body-view raw">{raw || "(empty)"}</pre>}
      </div>
    </>
  );
}

export default function MessageViewer({ exchange }: { exchange: ExchangeDetail }) {
  const [tab, setTab] = useState<MessageTab>("pretty");
  const [side, setSide] = useState<"request" | "response">("response");
  const openInRepeater = useStore((s) => s.openInRepeater);
  const response = exchange.response;

  return (
    <div className="viewer">
      <div className="viewer-header">
        <div className="tabs">
          <button
            className={side === "request" ? "tab active" : "tab"}
            onClick={() => setSide("request")}
          >
            Request
          </button>
          <button
            className={side === "response" ? "tab active" : "tab"}
            onClick={() => setSide("response")}
          >
            Response
          </button>
        </div>
        {side === "response" && response && (
          <span className="muted mono">
            {response.status} {response.reason} · {response.http_version} ·{" "}
            {response.elapsed_ms.toFixed(0)} ms
          </span>
        )}
        <button className="button" onClick={() => void openInRepeater(exchange)}>
          Send to repeater
        </button>
      </div>
      <div className="viewer-body">
        {side === "request" ? (
          <MessageTabs request={exchange.request} response={null} tab={tab} setTab={setTab} />
        ) : response ? (
          <MessageTabs request={exchange.request} response={response} tab={tab} setTab={setTab} />
        ) : (
          <div className="placeholder">This request has no response yet.</div>
        )}
      </div>
    </div>
  );
}

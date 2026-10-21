import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";

interface Token {
  kind: string;
  label: string;
  value: string;
  where: string;
  line: number;
}

interface Pattern {
  kind: string;
  label: string;
  expression: RegExp;
  secret: boolean;
}

const PATTERNS: Pattern[] = [
  {
    kind: "jwt",
    label: "JSON Web Token",
    expression: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g,
    secret: true,
  },
  {
    kind: "authorization",
    label: "Authorization header",
    expression: /\b(?:Bearer|Basic|Token|Digest)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    secret: true,
  },
  {
    kind: "session",
    label: "Session cookie",
    expression: /\b(?:JSESSIONID|PHPSESSID|sessionid|sid|csrf_token|access_token|refresh_token)=([^;,\s"']{6,})/gi,
    secret: true,
  },
  {
    kind: "key",
    label: "API key",
    expression: /\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)\b["'\s:=]+([A-Za-z0-9_\-]{12,})/gi,
    secret: true,
  },
  {
    kind: "basic",
    label: "Basic credentials",
    expression: /\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}/g,
    secret: true,
  },
  {
    kind: "hash",
    label: "Hash",
    expression: /\b[a-f0-9]{32,64}\b/gi,
    secret: false,
  },
];

/**
 * Look through a message for tokens and secrets.
 *
 * The analysis reads the message that is already in the interface; nothing is
 * sent anywhere.
 */
export default function TokenAnalysisView() {
  const traffic = useStore((s) => s.traffic);
  const detail = useStore((s) => s.detail);
  const select = useStore((s) => s.select);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [source, setSource] = useState<"request" | "response">("response");

  useEffect(() => {
    if (!selectedId && detail) setSelectedId(detail.id);
  }, [detail, selectedId]);

  const exchange = useMemo(() => {
    if (detail && detail.id === selectedId) return detail;
    return null;
  }, [detail, selectedId]);

  const text = useMemo(() => {
    if (!exchange) return "";
    if (source === "request") return exchange.request.raw ?? "";
    return exchange.response?.raw ?? "";
  }, [exchange, source]);

  const tokens = useMemo<Token[]>(() => {
    if (!text) return [];
    const lines = text.split("\n");
    const found: Token[] = [];
    for (const pattern of PATTERNS) {
      const expression = new RegExp(pattern.expression.source, pattern.expression.flags);
      for (const match of text.matchAll(expression)) {
        const value = match[0];
        const before = text.slice(0, match.index ?? 0);
        const line = before.split("\n").length;
        found.push({
          kind: pattern.kind,
          label: pattern.label,
          value,
          where: lines[line - 1]?.slice(0, 120) ?? "",
          line,
        });
      }
    }
    return found.sort((a, b) => a.line - b.line);
  }, [text]);

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <span className="grow">Select a message</span>
        </div>
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-time">Time</th>
                <th className="col-method">Method</th>
                <th className="col-host">Host</th>
                <th className="col-path">Path</th>
                <th className="col-status">Status</th>
              </tr>
            </thead>
            <tbody>
              {traffic.slice(0, 200).map((row) => (
                <tr
                  key={row.id}
                  className={row.id === selectedId ? "selected" : undefined}
                  onClick={() => setSelectedId(row.id)}
                >
                  <td className="col-time">
                    {new Date(row.created_at * 1000).toLocaleTimeString(undefined, { hour12: false })}
                  </td>
                  <td className="col-method">
                    <span className={`method method-${row.method.toLowerCase()}`}>{row.method}</span>
                  </td>
                  <td className="col-host">{row.host}</td>
                  <td className="col-path" title={row.url}>
                    {row.path}
                  </td>
                  <td className="col-status">
                    <span className={row.status >= 400 ? "status warn" : "status ok"}>
                      {row.status || "ERR"}
                    </span>
                  </td>
                </tr>
              ))}
              {traffic.length === 0 && (
                <tr>
                  <td colSpan={5} className="empty">
                    No traffic to look at yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <div className="seg">
            <button
              className={source === "request" ? "seg-item active" : "seg-item"}
              onClick={() => setSource("request")}
            >
              Request
            </button>
            <button
              className={source === "response" ? "seg-item active" : "seg-item"}
              onClick={() => setSource("response")}
            >
              Response
            </button>
          </div>
          <span className="grow" />
          <span className="muted">{tokens.length} token(s)</span>
          {exchange && (
            <button className="button" onClick={() => void select(exchange.id)}>
              Open in the history
            </button>
          )}
        </div>

        {exchange ? (
          tokens.length > 0 ? (
            <div className="table-wrap">
              <table className="traffic-table">
                <thead>
                  <tr>
                    <th className="col-time">Line</th>
                    <th className="col-method">Kind</th>
                    <th className="col-path">Value</th>
                    <th className="col-host">Where</th>
                  </tr>
                </thead>
                <tbody>
                  {tokens.map((token, index) => (
                    <tr key={`${token.kind}-${index}`}>
                      <td className="col-time">{token.line}</td>
                      <td className="col-method">
                        <span className="pill">{token.label}</span>
                      </td>
                      <td className="col-path mono" title={token.value}>
                        {token.value.slice(0, 90)}
                      </td>
                      <td className="col-host mono" title={token.where}>
                        {token.where}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="placeholder">
              No token was found in the {source}. Pick another message, or switch between the
              request and the response.
            </div>
          )
        ) : (
          <div className="placeholder">Select a message to analyse it.</div>
        )}
      </section>
    </div>
  );
}

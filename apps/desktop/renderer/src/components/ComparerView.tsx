import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { useStore } from "../state/store";
import type { Comparison } from "../types";

type Part = "request" | "response" | "body";
type Panel = "side" | "differences" | "similarities";

const PARTS: { id: Part; label: string }[] = [
  { id: "request", label: "The request" },
  { id: "response", label: "The response" },
  { id: "body", label: "The body" },
];

const KINDS: { id: string; label: string }[] = [
  { id: "auto", label: "Guess" },
  { id: "text", label: "Text" },
  { id: "json", label: "JSON" },
  { id: "xml", label: "XML" },
  { id: "html", label: "HTML" },
  { id: "tokens", label: "Tokens" },
  { id: "binary", label: "Binary" },
];

/** The line of a row, with the part that changed marked. */
function marked(text: string | null, span: number[] | null) {
  if (text === null) return null;
  if (!span || span.length !== 2) return text;
  const [start, end] = span;
  const before = text.slice(0, start);
  const middle = text.slice(start, end);
  const after = text.slice(end);
  return (
    <>
      {before}
      <mark>{middle}</mark>
      {after}
    </>
  );
}

/**
 * Put two things next to each other.
 *
 * The comparison itself is made by the daemon, which knows the shapes that
 * turn up in web traffic: a request, a response, a body that is JSON, XML or
 * HTML, a set of tokens and a file that is not text.
 */
export default function ComparerView() {
  const traffic = useStore((s) => s.traffic);
  const select = useStore((s) => s.select);

  const [left, setLeft] = useState<string | null>(null);
  const [right, setRight] = useState<string | null>(null);
  const [part, setPart] = useState<Part>("response");
  const [kind, setKind] = useState("auto");
  const [panel, setPanel] = useState<Panel>("side");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [error, setError] = useState("");

  const rows = traffic.slice(0, 200);

  const refresh = useCallback(async () => {
    if (!left || !right) {
      setComparison(null);
      return;
    }
    setError("");
    try {
      const data = await api.post<Comparison>("/api/comparer/exchanges", {
        left_id: left,
        right_id: right,
        kind,
        part,
      });
      setComparison(data);
    } catch (failure) {
      setError((failure as Error).message);
      setComparison(null);
    }
  }, [left, right, kind, part]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  function pick(id: string, slot: "left" | "right") {
    if (slot === "left") setLeft(id);
    else setRight(id);
  }

  const leftRow = rows.find((row) => row.id === left) ?? null;
  const rightRow = rows.find((row) => row.id === right) ?? null;

  return (
    <div className="comparer-view">
      <div className="split">
        <section className="pane list-pane">
          <div className="pane-header">
            <span className="grow">Pick two exchanges</span>
            <select
              className="filter"
              value={part}
              onChange={(event) => setPart(event.target.value as Part)}
            >
              {PARTS.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
            <select
              className="filter"
              value={kind}
              onChange={(event) => setKind(event.target.value)}
            >
              {KINDS.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </div>
          <div className="table-wrap">
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="col-method">A</th>
                  <th className="col-method">B</th>
                  <th className="col-host">Host</th>
                  <th className="col-path">Path</th>
                  <th className="col-status">Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td className="col-method">
                      <input
                        type="radio"
                        name="compare-left"
                        checked={left === row.id}
                        onChange={() => pick(row.id, "left")}
                        aria-label="Use as A"
                      />
                    </td>
                    <td className="col-method">
                      <input
                        type="radio"
                        name="compare-right"
                        checked={right === row.id}
                        onChange={() => pick(row.id, "right")}
                        aria-label="Use as B"
                      />
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
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty">
                      No traffic to compare yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="pane detail-pane">
          <div className="pane-header">
            <span className="mono grow">
              {leftRow && rightRow
                ? `${leftRow.method} ${leftRow.path}  ↔  ${rightRow.method} ${rightRow.path}`
                : "Pick two exchanges to compare"}
            </span>
            {comparison && (
              <>
                <span className="muted small">{comparison.kind}</span>
                <span className={comparison.identical ? "status ok" : "status warn"}>
                  {comparison.summary}
                </span>
              </>
            )}
          </div>

          <div className="pane-header">
            <div className="seg">
              <button
                className={panel === "side" ? "seg-item active" : "seg-item"}
                onClick={() => setPanel("side")}
              >
                Side by side
              </button>
              <button
                className={panel === "differences" ? "seg-item active" : "seg-item"}
                onClick={() => setPanel("differences")}
              >
                Differences
                {comparison ? ` (${comparison.differences.length})` : ""}
              </button>
              <button
                className={panel === "similarities" ? "seg-item active" : "seg-item"}
                onClick={() => setPanel("similarities")}
              >
                Similarities
                {comparison ? ` (${comparison.similarities.length})` : ""}
              </button>
            </div>
            <span className="grow" />
            {comparison && (
              <span className="muted small">
                {comparison.left_size} and {comparison.right_size} bytes
              </span>
            )}
          </div>

          {error && <div className="banner error">{error}</div>}

          {!comparison ? (
            <div className="placeholder">
              Choose one exchange for A and one for B. The differences are marked.
              <button
                className="button"
                onClick={() => {
                  const first = rows[0];
                  const second = rows[1];
                  if (first) setLeft(first.id);
                  if (second) setRight(second.id);
                }}
              >
                Use the first two
              </button>
            </div>
          ) : panel === "side" ? (
            <div className="compare-grid">
              <div className="compare-head">A</div>
              <div className="compare-head">B</div>
              {comparison.rows.map((row, index) => (
                <div className="compare-row" key={index}>
                  <div className={`compare-cell ${row.kind}`}>
                    {marked(row.left, row.left_span)}
                  </div>
                  <div className={`compare-cell ${row.kind}`}>
                    {marked(row.right, row.right_span)}
                  </div>
                </div>
              ))}
            </div>
          ) : panel === "differences" ? (
            <div className="table-wrap">
              <table className="traffic-table">
                <thead>
                  <tr>
                    <th className="col-method">Where</th>
                    <th className="col-host">A</th>
                    <th className="col-host">B</th>
                    <th className="col-path">What</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.differences.map((difference, index) => (
                    <tr key={index}>
                      <td className="col-method" title={difference.kind}>
                        {difference.path}
                      </td>
                      <td className="col-host mono" title={difference.left}>
                        {difference.left.slice(0, 120)}
                      </td>
                      <td className="col-host mono" title={difference.right}>
                        {difference.right.slice(0, 120)}
                      </td>
                      <td className="col-path">{difference.note}</td>
                    </tr>
                  ))}
                  {comparison.differences.length === 0 && (
                    <tr>
                      <td colSpan={4} className="empty">
                        The two are the same.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="traffic-table">
                <thead>
                  <tr>
                    <th className="col-method">Where</th>
                    <th className="col-path">The same</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.similarities.map((similarity, index) => (
                    <tr key={index}>
                      <td className="col-method" title={similarity.kind}>
                        {similarity.path}
                      </td>
                      <td className="col-path mono" title={similarity.value}>
                        {similarity.value.slice(0, 160)}
                      </td>
                    </tr>
                  ))}
                  {comparison.similarities.length === 0 && (
                    <tr>
                      <td colSpan={2} className="empty">
                        Nothing is the same.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {leftRow && (
            <div className="row">
              <button className="button" onClick={() => void select(leftRow.id)}>
                Open A in the history
              </button>
              {rightRow && (
                <button className="button" onClick={() => void select(rightRow.id)}>
                  Open B in the history
                </button>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

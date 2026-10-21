import { useMemo, useState } from "react";
import { useStore } from "../state/store";
import type { ExchangeSummary } from "../types";

type Side = "request" | "response";

/**
 * Put two exchanges next to each other and mark the lines that differ.
 */
export default function ComparerView() {
  const traffic = useStore((s) => s.traffic);
  const select = useStore((s) => s.select);
  const [left, setLeft] = useState<string | null>(null);
  const [right, setRight] = useState<string | null>(null);
  const [side, setSide] = useState<Side>("response");

  const rows = traffic.slice(0, 200);

  const leftRow = rows.find((row) => row.id === left) ?? null;
  const rightRow = rows.find((row) => row.id === right) ?? null;

  const comparison = useMemo(() => {
    if (!leftRow || !rightRow) return null;
    const a = describe(leftRow);
    const b = describe(rightRow);
    const rowsOut: { left: string; right: string; same: boolean }[] = [];
    const length = Math.max(a.length, b.length);
    for (let index = 0; index < length; index += 1) {
      const lineA = a[index] ?? "";
      const lineB = b[index] ?? "";
      rowsOut.push({ left: lineA, right: lineB, same: lineA === lineB });
    }
    return {
      rows: rowsOut,
      different: rowsOut.filter((row) => !row.same).length,
    };
  }, [leftRow, rightRow]);

  function describe(row: ExchangeSummary): string[] {
    if (side === "request") {
      return [
        `${row.method} ${row.url}`,
        `host: ${row.host}`,
        `port: ${row.port}`,
        `scheme: ${row.scheme}`,
        `request length: ${row.request_length}`,
        `type: ${row.mime_type}`,
      ];
    }
    return [
      `status: ${row.status || "ERR"} ${row.reason}`,
      `type: ${row.mime_type}`,
      `length: ${row.response_length}`,
      `time: ${row.elapsed_ms.toFixed(0)} ms`,
      `error: ${row.error || "none"}`,
    ];
  }

  function pick(id: string, slot: "left" | "right") {
    if (slot === "left") setLeft(id);
    else setRight(id);
  }

  return (
    <div className="comparer-view">
      <div className="split">
        <section className="pane list-pane">
          <div className="pane-header">
            <span className="grow">Pick two exchanges</span>
            <div className="seg">
              <button
                className={side === "request" ? "seg-item active" : "seg-item"}
                onClick={() => setSide("request")}
              >
                Request
              </button>
              <button
                className={side === "response" ? "seg-item active" : "seg-item"}
                onClick={() => setSide("response")}
              >
                Response
              </button>
            </div>
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
              <span className={comparison.different ? "status warn" : "status ok"}>
                {comparison.different} difference{comparison.different === 1 ? "" : "s"}
              </span>
            )}
          </div>

          {comparison ? (
            <div className="compare-grid">
              <div className="compare-head">A</div>
              <div className="compare-head">B</div>
              {comparison.rows.map((row, index) => (
                <div className="compare-row" key={index}>
                  <div className={row.same ? "compare-cell" : "compare-cell different"}>
                    {row.left}
                  </div>
                  <div className={row.same ? "compare-cell" : "compare-cell different"}>
                    {row.right}
                  </div>
                </div>
              ))}
            </div>
          ) : (
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

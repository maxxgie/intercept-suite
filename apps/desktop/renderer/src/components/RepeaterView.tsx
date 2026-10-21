import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";
import { MessageTabs } from "./MessageViewer";
import type { MessageTab } from "../state/store";
import type { RepeaterAttempt } from "../types";
import { bodyBytes, hexDump } from "../lib/bytes";

function isWebSocket(headers: Record<string, string[]>): boolean {
  const upgrade = (headers.upgrade ?? []).join(" ").toLowerCase();
  const connection = (headers.connection ?? []).join(" ").toLowerCase();
  return upgrade.includes("websocket") && connection.includes("upgrade");
}

function formatMs(value: number): string {
  if (value >= 1000) return `${(value / 1000).toFixed(2)} s`;
  return `${value.toFixed(0)} ms`;
}

/**
 * The attempts of one tab, with the time each of them took.
 *
 * The bar of an attempt is drawn against the slowest one, so a request that
 * suddenly takes longer stands out.
 */
function AttemptsPanel({
  attempts,
  onResend,
  busy,
}: {
  attempts: RepeaterAttempt[];
  onResend: (index: number) => void;
  busy: boolean;
}) {
  const [left, setLeft] = useState<number | null>(null);
  const [right, setRight] = useState<number | null>(null);

  const slowest = Math.max(1, ...attempts.map((attempt) => attempt.elapsed_ms));

  const comparison = useMemo(() => {
    if (left === null || right === null) return null;
    const a = (attempts[left]?.response?.body ?? "").split("\n");
    const b = (attempts[right]?.response?.body ?? "").split("\n");
    const rows: { left: string; right: string; same: boolean }[] = [];
    const length = Math.max(a.length, b.length);
    for (let index = 0; index < length; index += 1) {
      const lineA = a[index] ?? "";
      const lineB = b[index] ?? "";
      rows.push({ left: lineA, right: lineB, same: lineA === lineB });
    }
    return { rows, different: rows.filter((row) => !row.same).length };
  }, [attempts, left, right]);

  if (attempts.length === 0) {
    return <div className="placeholder small">Send the request to see how long it takes.</div>;
  }

  return (
    <div className="repeater-attempts">
      <table className="traffic-table">
        <thead>
          <tr>
            <th className="col-time">#</th>
            <th className="col-method">Status</th>
            <th className="col-size">Length</th>
            <th className="col-path">Time</th>
            <th className="col-host">Compare</th>
            <th className="col-status">Send again</th>
          </tr>
        </thead>
        <tbody>
          {attempts.map((attempt, index) => (
            <tr key={attempt.id ?? index}>
              <td className="col-time">{index + 1}</td>
              <td className="col-method">
                <span
                  className={
                    (attempt.response?.status ?? 0) >= 400 ? "status warn" : "status ok"
                  }
                >
                  {attempt.response?.status ?? "ERR"}
                </span>
              </td>
              <td className="col-size">{attempt.response?.body_length ?? 0} B</td>
              <td className="col-path">
                <div className="timing-bar">
                  <div
                    className="timing-fill"
                    style={{ width: `${Math.max(2, (attempt.elapsed_ms / slowest) * 100)}%` }}
                  />
                  <span className="muted small">{formatMs(attempt.elapsed_ms)}</span>
                </div>
              </td>
              <td className="col-host">
                <label className="checkline small">
                  <input
                    type="radio"
                    name="attempt-left"
                    checked={left === index}
                    onChange={() => setLeft(index)}
                    aria-label="Use as A"
                  />
                  A
                </label>
                <label className="checkline small">
                  <input
                    type="radio"
                    name="attempt-right"
                    checked={right === index}
                    onChange={() => setRight(index)}
                    aria-label="Use as B"
                  />
                  B
                </label>
              </td>
              <td className="col-status">
                <button
                  className="button"
                  disabled={busy}
                  onClick={() => onResend(index)}
                >
                  Replay
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {comparison && (
        <div className="compare-grid">
          <div className="compare-head">Attempt {Number(left) + 1}</div>
          <div className="compare-head">Attempt {Number(right) + 1}</div>
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
      )}
    </div>
  );
}

/**
 * The WebSocket connection of a tab.
 *
 * The repeater completes the handshake itself, so a request that upgrades the
 * protocol can be used to exchange frames.
 */
function WebSocketPanel({ tabId }: { tabId: string }) {
  const session = useStore((s) => s.websocketSession);
  const open = useStore((s) => s.openWebSocket);
  const send = useStore((s) => s.sendWebSocketFrame);
  const receive = useStore((s) => s.receiveWebSocketFrames);
  const close = useStore((s) => s.closeWebSocket);
  const busy = useStore((s) => s.busy);
  const [payload, setPayload] = useState("");
  const [opcode, setOpcode] = useState("text");
  const [showHex, setShowHex] = useState(false);

  const frames = useMemo(() => {
    if (!session) return [];
    return [
      ...session.sent.map((frame) => ({ ...frame, kind: "sent" })),
      ...session.received.map((frame) => ({ ...frame, kind: "received" })),
    ].sort((a, b) => a.timestamp - b.timestamp);
  }, [session]);

  return (
    <div className="repeater-websocket">
      <div className="pane-header">
        <span>
          {session?.open
            ? `The connection is open${session.status ? ` (${session.status})` : ""}.`
            : "The connection is closed."}
        </span>
        <div className="row tight">
          {session?.open ? (
            <button className="button" onClick={() => void close(tabId)}>
              Close
            </button>
          ) : (
            <button className="button primary" onClick={() => void open(tabId)}>
              Connect
            </button>
          )}
        </div>
      </div>

      {session?.open && (
        <>
          <div className="form inline-form">
            <select
              className="filter"
              value={opcode}
              onChange={(event) => setOpcode(event.target.value)}
            >
              <option value="text">text</option>
              <option value="binary">binary</option>
              <option value="ping">ping</option>
              <option value="pong">pong</option>
            </select>
            <input
              className="filter grow"
              value={payload}
              placeholder="The frame to send"
              onChange={(event) => setPayload(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void send(tabId, payload, opcode);
                }
              }}
            />
            <button
              className="button primary"
              disabled={busy}
              onClick={() => void send(tabId, payload, opcode)}
            >
              Send
            </button>
            <button
              className="button"
              disabled={busy}
              onClick={() => void receive(tabId, 5)}
            >
              Read
            </button>
          </div>

          <div className="table-wrap">
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="col-time">Time</th>
                  <th className="col-method">Way</th>
                  <th className="col-host">Type</th>
                  <th className="col-path">Payload</th>
                  <th className="col-size">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {frames.map((frame, index) => (
                  <tr key={`${frame.timestamp}-${index}`}>
                    <td className="col-time">
                      {new Date(frame.timestamp * 1000).toLocaleTimeString(undefined, {
                        hour12: false,
                      })}
                    </td>
                    <td className="col-method">
                      <span className={`method method-${frame.direction}`}>
                        {frame.kind === "sent" ? "sent" : "received"}
                      </span>
                    </td>
                    <td className="col-host">{frame.type}</td>
                    <td className="col-path mono">
                      {showHex ? (
                        <pre className="body-view mono">
                          {hexDump(bodyBytes(frame.base64, "base64"))}
                        </pre>
                      ) : (
                        frame.text
                      )}
                    </td>
                    <td className="col-size">{frame.size} B</td>
                  </tr>
                ))}
                {frames.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty">
                      No frames yet. Send one and read what comes back.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="pane-header">
            <label className="checkline small">
              <input
                type="checkbox"
                checked={showHex}
                onChange={(event) => setShowHex(event.target.checked)}
              />
              show the payloads as a hex dump
            </label>
          </div>
        </>
      )}
    </div>
  );
}

export default function RepeaterView() {
  const tabs = useStore((s) => s.tabs);
  const activeTabId = useStore((s) => s.activeTabId);
  const busy = useStore((s) => s.busy);
  const http2 = useStore((s) => s.repeaterHttp2);
  const setHttp2 = useStore((s) => s.setRepeaterHttp2);
  const updateTab = useStore((s) => s.updateTab);
  const sendTab = useStore((s) => s.sendTab);
  const resendTab = useStore((s) => s.resendTab);
  const closeTab = useStore((s) => s.closeTab);
  const refreshTabs = useStore((s) => s.refreshTabs);
  const [draft, setDraft] = useState("");
  const [tab, setTab] = useState<MessageTab>("pretty");
  const [showAttempts, setShowAttempts] = useState(false);

  const active = tabs.find((item) => item.id === activeTabId) ?? null;

  useEffect(() => {
    setDraft(active?.request.raw ?? "");
  }, [activeTabId, active?.request.raw]);

  useEffect(() => {
    void refreshTabs();
  }, [refreshTabs]);

  if (tabs.length === 0) {
    return (
      <div className="placeholder">
        <p>No repeater tabs yet.</p>
        <p className="muted">
          Open a request from the traffic list and choose “Send to repeater”, or build a request
          by hand.
        </p>
      </div>
    );
  }

  const websocket = active ? isWebSocket(active.request.headers) : false;

  return (
    <div className="repeater">
      <div className="tab-strip">
        {tabs.map((item) => (
          <div key={item.id} className={item.id === activeTabId ? "strip-item active" : "strip-item"}>
            <button className="strip-label" onClick={() => useStore.setState({ activeTabId: item.id })}>
              {item.name}
            </button>
            <button className="strip-close" onClick={() => void closeTab(item.id)}>
              ×
            </button>
          </div>
        ))}
      </div>

      {active && (
        <div className="repeater-body">
          <div className="repeater-request">
            <div className="pane-header">
              <span className="muted mono grow">Request</span>
              <label className="checkline small">
                <input
                  type="checkbox"
                  checked={http2}
                  onChange={(event) => setHttp2(event.target.checked)}
                />
                HTTP/2
              </label>
              <button className="button" onClick={() => setShowAttempts(!showAttempts)}>
                Attempts {active.attempt_count > 0 ? `(${active.attempt_count})` : ""}
              </button>
              <button className="button primary" disabled={busy} onClick={() => void sendTab(active.id, draft)}>
                {busy ? "Sending…" : "Send"}
              </button>
            </div>
            <textarea
              className="editor mono"
              spellCheck={false}
              value={draft}
              onChange={(event) => {
                setDraft(event.target.value);
                updateTab(active.id, event.target.value);
              }}
            />
            {active.timing.count > 0 && (
              <div className="pane-header">
                <span className="muted small">
                  last {formatMs(active.timing.last)} · fastest {formatMs(active.timing.fastest)} ·
                  slowest {formatMs(active.timing.slowest)} · average{" "}
                  {formatMs(active.timing.average)}
                </span>
              </div>
            )}
          </div>
          <div className="repeater-response">
            {active.response ? (
              <MessageTabs
                request={active.request}
                response={active.response}
                tab={tab}
                setTab={setTab}
              />
            ) : (
              <div className="placeholder">Send the request to see the response.</div>
            )}
          </div>
        </div>
      )}

      {active && showAttempts && (
        <div className="repeater-attempts-panel">
          <div className="pane-header">
            <span>Attempts</span>
            <span className="muted">
              Pick two attempts to see what changed between them.
            </span>
          </div>
          <AttemptsPanel
            attempts={active.attempts ?? []}
            busy={busy}
            onResend={(index) => void resendTab(active.id, index)}
          />
        </div>
      )}

      {active && websocket && <WebSocketPanel tabId={active.id} />}
    </div>
  );
}

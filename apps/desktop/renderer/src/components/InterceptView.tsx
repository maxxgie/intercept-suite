import { useEffect } from "react";
import { useStore } from "../state/store";
import { IconClose, IconPlay } from "./icons";

/**
 * The requests the proxy is holding.
 *
 * Turning interception on makes the proxy hold every request until it is
 * answered here, which is what makes request smuggling and cache poisoning
 * analysis possible.
 */
export default function InterceptView() {
  const enabled = useStore((s) => s.interceptEnabled);
  const setIntercept = useStore((s) => s.setIntercept);
  const held = useStore((s) => s.heldRequests);
  const decide = useStore((s) => s.decideHeldRequest);
  const refresh = useStore((s) => s.refreshHeldRequests);

  useEffect(() => {
    void refresh();
  }, [refresh]);

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
          {held.length === 0
            ? "No request is being held."
            : `${held.length} request${held.length === 1 ? "" : "s"} waiting for an answer.`}
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
            {held.map((request) => (
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
                    <button className="button" onClick={() => void decide(request.id, "drop")}>
                      <IconClose size={12} />
                      Drop
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {held.length === 0 && (
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
    </div>
  );
}

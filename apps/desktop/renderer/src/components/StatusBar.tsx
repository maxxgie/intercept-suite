import { useStore } from "../state/store";

export default function StatusBar() {
  const daemon = useStore((s) => s.daemon);
  const connected = useStore((s) => s.connected);
  const adopted = useStore((s) => s.adopted);
  const filter = useStore((s) => s.filter);
  const total = useStore((s) => s.total);
  const interceptEnabled = useStore((s) => s.interceptEnabled);
  const pending = useStore((s) => s.pendingIntercepts);
  const error = useStore((s) => s.error);
  const setError = useStore((s) => s.setError);

  return (
    <footer className="status-bar">
      <span className={`status-dot ${connected ? "ok" : "bad"}`} />
      <span>{connected ? "Daemon online" : "Daemon offline"}</span>
      {adopted && <span className="muted">attached to a running instance</span>}

      {daemon && (
        <>
          <span className="muted">|</span>
          <span className="mono">
            proxy {daemon.proxy.host}:{daemon.proxy.port}
          </span>
          <span className="muted">|</span>
          <span className="mono">http2 {daemon.proxy.http2 ? "on" : "off"}</span>
        </>
      )}

      <span className="muted">|</span>
      <span className={interceptEnabled ? "status warn" : "muted"}>
        {interceptEnabled ? "intercepting" : "passing through"}
      </span>
      {pending.length > 0 && <span className="status warn">{pending.length} held</span>}

      <span className="grow" />

      {filter && (
        <span className="mono muted" title={filter}>
          filter {filter}
        </span>
      )}
      <span className="muted">{total} exchanges</span>

      {error && (
        <button className="status-error" onClick={() => setError(null)} title="Dismiss">
          {error}
        </button>
      )}
    </footer>
  );
}

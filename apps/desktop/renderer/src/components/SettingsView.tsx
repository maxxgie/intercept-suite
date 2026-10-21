import { useEffect, useState } from "react";
import { api, apiBase } from "../lib/api";
import { useStore } from "../state/store";
import type { ListenerConfig } from "../types";

interface TrustTarget {
  name: string;
  label: string;
  available: boolean;
  reason: string;
  location: string;
  steps: string[];
}

const LISTENER_MODES: { value: ListenerConfig["mode"]; label: string; help: string }[] = [
  {
    value: "explicit",
    label: "HTTP proxy",
    help: "An ordinary forward proxy. Point a client at it and it will send the traffic on.",
  },
  {
    value: "socks",
    label: "SOCKS5 proxy",
    help: "The client speaks SOCKS5 instead of HTTP.",
  },
  {
    value: "transparent",
    label: "Transparent proxy",
    help: "The traffic is redirected here by the network, so the destination is recovered from the socket. Linux only.",
  },
];

export default function SettingsView() {
  const daemon = useStore((s) => s.daemon);
  const connected = useStore((s) => s.connected);
  const adopted = useStore((s) => s.adopted);
  const plugins = useStore((s) => s.plugins);
  const config = useStore((s) => s.config);
  const refreshConfig = useStore((s) => s.refreshConfig);
  const saveConfig = useStore((s) => s.saveConfig);
  const [copied, setCopied] = useState(false);
  const [targets, setTargets] = useState<TrustTarget[]>([]);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const [listener, setListener] = useState<ListenerConfig>({
    name: "",
    host: "127.0.0.1",
    port: 0,
    mode: "explicit",
    enabled: true,
  });

  useEffect(() => {
    if (!connected) return;
    void api
      .get<{ targets: TrustTarget[] }>("/api/ca/targets")
      .then((response) => setTargets(response.targets ?? []))
      .catch(() => setTargets([]));
  }, [connected]);

  useEffect(() => {
    if (!connected) return;
    void refreshConfig();
  }, [connected, refreshConfig]);

  async function copyFingerprint() {
    if (!daemon) return;
    await navigator.clipboard.writeText(daemon.ca.fingerprint);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  async function downloadCa() {
    const pem = await api.text("/api/ca/download");
    const url = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "intercept-ca.crt";
    link.click();
    URL.revokeObjectURL(url);
  }

  async function installCa(target: string) {
    setWorking(true);
    setOutcome(null);
    try {
      const response = await api.post<{
        results: { target: string; ok: boolean; detail: string }[];
      }>("/api/ca/install", { target });
      for (const result of response.results) {
        setOutcome(result.ok ? `${result.target}: ${result.detail}` : `${result.target}: ${result.detail}`);
      }
    } catch (error) {
      setOutcome((error as Error).message);
    } finally {
      setWorking(false);
    }
  }

  async function addListener() {
    if (!config) return;
    const listeners = [...config.proxy.listeners, { ...listener, name: listener.name || `listener-${config.proxy.listeners.length + 1}` }];
    await saveConfig({ proxy: { listeners } });
  }

  async function removeListener(index: number) {
    if (!config) return;
    const listeners = config.proxy.listeners.filter((_, position) => position !== index);
    await saveConfig({ proxy: { listeners } });
  }

  async function setUpstream(changes: Record<string, unknown>) {
    if (!config) return;
    await saveConfig({ proxy: { upstream_proxy: { ...config.proxy.upstream_proxy, ...changes } } });
  }

  async function setProxy(changes: Record<string, unknown>) {
    if (!config) return;
    await saveConfig({ proxy: { ...config.proxy, ...changes } });
  }

  return (
    <div className="settings">
      <section className="card">
        <h2>Daemon</h2>
        <dl>
          <dt>Status</dt>
          <dd>{connected ? "online" : "offline"}</dd>
          <dt>API</dt>
          <dd className="mono">{apiBase() || "—"}</dd>
        </dl>
        {adopted && (
          <p className="muted small">
            Another daemon already owns these ports, so this window attached to it rather than
            starting a second one.
          </p>
        )}
      </section>

      <section className="card">
        <h2>Proxy</h2>
        <dl>
          <dt>Listen address</dt>
          <dd className="mono">
            {daemon ? `${daemon.proxy.host}:${daemon.proxy.port}` : "—"}
          </dd>
          <dt>Upstream verification</dt>
          <dd>{daemon?.proxy.upstream_verify ? "enabled" : "disabled (lab mode)"}</dd>
        </dl>
        {config && (
          <>
            <label className="checkline small">
              <input
                type="checkbox"
                checked={config.proxy.upstream_verify}
                onChange={(event) => void setProxy({ upstream_verify: event.target.checked })}
              />
              verify the certificates of the origins
            </label>
            <label className="checkline small">
              <input
                type="checkbox"
                checked={config.proxy.http2}
                onChange={(event) => void setProxy({ http2: event.target.checked })}
              />
              speak HTTP/2 with the origins
            </label>
            <label className="checkline small">
              <input
                type="checkbox"
                checked={config.proxy.intercept_websockets}
                onChange={(event) => void setProxy({ intercept_websockets: event.target.checked })}
              />
              hold the WebSocket frames
            </label>
            <div className="row wrap">
              <label className="checkline small">
                <input
                  type="checkbox"
                  checked={config.proxy.intercept_websocket_directions.includes("client")}
                  onChange={(event) => {
                    const directions = new Set(config.proxy.intercept_websocket_directions);
                    if (event.target.checked) directions.add("client");
                    else directions.delete("client");
                    void setProxy({
                      intercept_websocket_directions: [...directions],
                    });
                  }}
                />
                hold the frames the client sends
              </label>
              <label className="checkline small">
                <input
                  type="checkbox"
                  checked={config.proxy.intercept_websocket_directions.includes("server")}
                  onChange={(event) => {
                    const directions = new Set(config.proxy.intercept_websocket_directions);
                    if (event.target.checked) directions.add("server");
                    else directions.delete("server");
                    void setProxy({
                      intercept_websocket_directions: [...directions],
                    });
                  }}
                />
                hold the frames the client receives
              </label>
            </div>
          </>
        )}
      </section>

      {config && (
        <section className="card">
          <h2>Listeners</h2>
          <p className="muted">
            Extra listeners can be opened next to the main one, so a phone or a device that cannot
            be told about a proxy can still be routed through it.
          </p>
          {config.proxy.listeners.map((item, index) => (
            <div className="plugin-row" key={`${item.name}-${index}`}>
              <div>
                <strong>{item.name || "(unnamed)"}</strong>
                <div className="muted small mono">
                  {item.host}:{item.port} · {item.mode}
                </div>
              </div>
              <button className="button danger" onClick={() => void removeListener(index)}>
                Remove
              </button>
            </div>
          ))}
          {config.proxy.listeners.length === 0 && (
            <div className="placeholder small">No extra listeners.</div>
          )}
          <div className="row wrap">
            <div className="field">
              <label htmlFor="listener-name">Name</label>
              <input
                id="listener-name"
                className="filter"
                value={listener.name}
                placeholder="phone"
                onChange={(event) => setListener({ ...listener, name: event.target.value })}
              />
            </div>
            <div className="field">
              <label htmlFor="listener-host">Host</label>
              <input
                id="listener-host"
                className="filter"
                value={listener.host}
                onChange={(event) => setListener({ ...listener, host: event.target.value })}
              />
            </div>
            <div className="field">
              <label htmlFor="listener-port">Port</label>
              <input
                id="listener-port"
                className="filter"
                value={listener.port}
                onChange={(event) => setListener({ ...listener, port: Number(event.target.value) })}
              />
            </div>
            <div className="field">
              <label htmlFor="listener-mode">Mode</label>
              <select
                id="listener-mode"
                className="filter"
                value={listener.mode}
                onChange={(event) =>
                  setListener({ ...listener, mode: event.target.value as ListenerConfig["mode"] })
                }
              >
                {LISTENER_MODES.map((mode) => (
                  <option key={mode.value} value={mode.value}>
                    {mode.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <span className="muted small">
            {LISTENER_MODES.find((mode) => mode.value === listener.mode)?.help}
          </span>
          <div className="row">
            <button className="button primary" onClick={() => void addListener()}>
              Add the listener
            </button>
          </div>
        </section>
      )}

      {config && (
        <section className="card">
          <h2>Upstream proxy</h2>
          <p className="muted">
            The traffic is sent to the origin through this proxy instead of directly.
          </p>
          <label className="checkline small">
            <input
              type="checkbox"
              checked={config.proxy.upstream_proxy.enabled}
              onChange={(event) => void setUpstream({ enabled: event.target.checked })}
            />
            chain the traffic through an upstream proxy
          </label>
          <div className="row wrap">
            <div className="field">
              <label htmlFor="upstream-scheme">Kind</label>
              <select
                id="upstream-scheme"
                className="filter"
                value={config.proxy.upstream_proxy.scheme}
                onChange={(event) => void setUpstream({ scheme: event.target.value })}
              >
                <option value="http">HTTP forward proxy</option>
                <option value="socks5">SOCKS5 proxy</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="upstream-host">Host</label>
              <input
                id="upstream-host"
                className="filter"
                value={config.proxy.upstream_proxy.host}
                onChange={(event) => void setUpstream({ host: event.target.value })}
              />
            </div>
            <div className="field">
              <label htmlFor="upstream-port">Port</label>
              <input
                id="upstream-port"
                className="filter"
                value={config.proxy.upstream_proxy.port}
                onChange={(event) => void setUpstream({ port: Number(event.target.value) })}
              />
            </div>
            <div className="field">
              <label htmlFor="upstream-username">User</label>
              <input
                id="upstream-username"
                className="filter"
                value={config.proxy.upstream_proxy.username}
                onChange={(event) => void setUpstream({ username: event.target.value })}
              />
            </div>
            <div className="field">
              <label htmlFor="upstream-password">Password</label>
              <input
                id="upstream-password"
                className="filter"
                type="password"
                value={config.proxy.upstream_proxy.password}
                onChange={(event) => void setUpstream({ password: event.target.value })}
              />
            </div>
          </div>
        </section>
      )}

      <section className="card">
        <h2>Certificate authority</h2>
        <p className="muted">
          Install this certificate in the trust store of the browser or client you want to intercept.
        </p>
        <dl>
          <dt>Subject</dt>
          <dd className="mono">{daemon?.ca.subject ?? "—"}</dd>
          <dt>SHA-256 fingerprint</dt>
          <dd className="mono fingerprint">{daemon?.ca.fingerprint ?? "—"}</dd>
          <dt>Location</dt>
          <dd className="mono">{daemon?.ca.path ?? "—"}</dd>
        </dl>
        <div className="row">
          <button className="button" onClick={() => void copyFingerprint()}>
            {copied ? "Copied" : "Copy fingerprint"}
          </button>
          <button className="button" onClick={() => void downloadCa()}>
            Download certificate
          </button>
        </div>
      </section>

      {targets.length > 0 && (
        <section className="card">
          <h2>Trust in browsers</h2>
          <p className="muted">
            The browser has to trust this certificate authority before it will accept the
            certificates the proxy presents for the sites you intercept.
          </p>
          {targets.map((target) => (
            <div className="plugin-row" key={target.name}>
              <div>
                <strong>{target.label}</strong>
                <div className="muted small mono">{target.location}</div>
                {target.available ? (
                  <div className="muted small">ready to install</div>
                ) : (
                  <div className="muted small">{target.reason}</div>
                )}
                {!target.available && target.steps.length > 0 && (
                  <ol className="muted small steps">
                    {target.steps.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                )}
              </div>
              <button
                className="button"
                disabled={!target.available || working}
                onClick={() => void installCa(target.name)}
              >
                Install
              </button>
            </div>
          ))}
          {outcome && <p className="muted small">{outcome}</p>}
        </section>
      )}

      <section className="card">
        <h2>Plugins</h2>
        {plugins.length === 0 && <div className="placeholder small">No plugins installed.</div>}
        {plugins.map((plugin) => (
          <div className="plugin-row" key={plugin.name}>
            <div>
              <strong>{plugin.label}</strong>
              <span className="muted"> v{plugin.version}</span>
              <div className="muted small">{plugin.description}</div>
              {plugin.error && <div className="small error-text">{plugin.error}</div>}
            </div>
            <span className="muted small">{plugin.tools.length} tool(s)</span>
          </div>
        ))}
        <p className="muted small">
          Drop a plugin directory into the plugins folder of the Intercept home directory and
          restart the daemon.
        </p>
      </section>
    </div>
  );
}

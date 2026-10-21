import { useEffect, useState } from "react";
import { api, apiBase } from "../lib/api";
import { useStore } from "../state/store";

interface TrustTarget {
  name: string;
  label: string;
  available: boolean;
  reason: string;
  location: string;
  steps: string[];
}

export default function SettingsView() {
  const daemon = useStore((s) => s.daemon);
  const connected = useStore((s) => s.connected);
  const adopted = useStore((s) => s.adopted);
  const plugins = useStore((s) => s.plugins);
  const [copied, setCopied] = useState(false);
  const [targets, setTargets] = useState<TrustTarget[]>([]);
  const [outcome, setOutcome] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    if (!connected) return;
    void api
      .get<{ targets: TrustTarget[] }>("/api/ca/targets")
      .then((response) => setTargets(response.targets ?? []))
      .catch(() => setTargets([]));
  }, [connected]);

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
      </section>

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

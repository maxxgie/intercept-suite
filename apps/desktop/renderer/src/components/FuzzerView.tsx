import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";

const SAMPLE = `GET https://example.com/search?q=§term§ HTTP/1.1
Host: example.com
User-Agent: Intercept/0.1
`;

export default function FuzzerView() {
  const fuzzJobs = useStore((s) => s.fuzzJobs);
  const activeFuzzJobId = useStore((s) => s.activeFuzzJobId);
  const busy = useStore((s) => s.busy);
  const refreshFuzzJobs = useStore((s) => s.refreshFuzzJobs);
  const startFuzzJob = useStore((s) => s.startFuzzJob);
  const stopFuzzJob = useStore((s) => s.stopFuzzJob);

  const [raw, setRaw] = useState(SAMPLE);
  const [payloads, setPayloads] = useState("1\n2\nadmin\n' OR 1=1--");
  const [onlyInteresting, setOnlyInteresting] = useState(false);

  const active = fuzzJobs.find((job) => job.id === activeFuzzJobId) ?? null;

  useEffect(() => {
    void refreshFuzzJobs();
  }, [refreshFuzzJobs]);

  const results = useMemo(() => {
    if (!active) return [];
    return onlyInteresting ? active.results.filter((r) => r.interesting) : active.results;
  }, [active, onlyInteresting]);

  const positions = active?.template.positions ?? [];

  const start = () => {
    const lines = raw.split("\n");
    const first = lines[0] ?? "";
    const parts = first.trim().split(" ");
    const method = (parts[0] || "GET").toUpperCase();
    const target = parts[1] || "";
    const url = target.startsWith("http") ? target : `https://example.com${target}`;
    const headers: Record<string, string[]> = {};
    for (const line of lines.slice(1)) {
      if (!line.trim()) break;
      const index = line.indexOf(":");
      if (index < 0) continue;
      const name = line.slice(0, index).trim();
      const value = line.slice(index + 1).trim();
      headers[name] = [...(headers[name] ?? []), value];
    }
    void startFuzzJob({
      raw,
      method,
      url,
      headers,
      payloads: payloads.split("\n").map((p) => p.trim()).filter(Boolean),
    });
  };

  return (
    <div className="fuzzer">
      <div className="fuzzer-input">
        <div className="pane-header">
          <span className="muted mono grow">Request template</span>
          <span className="muted small">
            mark a position with §name§ — it can live in the URL, a header or the body
          </span>
          <button className="button primary" disabled={busy} onClick={start}>
            {busy ? "Starting…" : "Start fuzzing"}
          </button>
        </div>
        <textarea
          className="editor mono"
          spellCheck={false}
          value={raw}
          onChange={(event) => setRaw(event.target.value)}
        />
        <div className="fuzzer-payloads">
          <div className="pane-header">
            <span className="muted mono grow">Payloads (one per line)</span>
          </div>
          <textarea
            className="editor mono"
            spellCheck={false}
            value={payloads}
            onChange={(event) => setPayloads(event.target.value)}
          />
        </div>
      </div>

      <div className="fuzzer-results">
        <div className="pane-header">
          <span className="mono grow">Results</span>
          {active && (
            <span className="muted">
              {active.completed}/{active.total} · {active.status}
            </span>
          )}
          {active?.status === "running" && (
            <button className="button" onClick={() => void stopFuzzJob(active.id)}>
              Stop
            </button>
          )}
          <label className="checkline">
            <input
              type="checkbox"
              checked={onlyInteresting}
              onChange={(event) => setOnlyInteresting(event.target.checked)}
            />
            interesting only
          </label>
        </div>
        {positions.length > 0 && (
          <div className="fuzzer-positions">
            {positions.map((position) => (
              <span key={position.name} className="pill">
                {position.name}
              </span>
            ))}
          </div>
        )}
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-method">Position</th>
                <th className="col-path">Payload</th>
                <th className="col-status">Status</th>
                <th className="col-size">Length</th>
                <th className="col-host">Markers</th>
              </tr>
            </thead>
            <tbody>
              {results.map((result) => (
                <tr key={result.id} className={result.interesting ? "selected" : undefined}>
                  <td className="col-method mono">{result.position}</td>
                  <td className="col-path mono" title={result.url}>
                    {result.payload}
                  </td>
                  <td className="col-status">
                    <span className={result.status >= 400 ? "status warn" : "status ok"}>
                      {result.status || "ERR"}
                    </span>
                  </td>
                  <td className="col-size">
                    {result.length}
                    {result.length_delta !== 0 && (
                      <span className="muted"> ({result.length_delta > 0 ? "+" : ""}{result.length_delta})</span>
                    )}
                  </td>
                  <td className="col-host mono small">{result.markers.join(", ")}</td>
                </tr>
              ))}
              {results.length === 0 && (
                <tr>
                  <td colSpan={5} className="empty">
                    {fuzzJobs.length === 0
                      ? "No fuzzing job yet. Mark a position and press Start fuzzing."
                      : "No results match the current filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

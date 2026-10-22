import { useMemo, useState } from "react";
import { useStore } from "../state/store";
import type { SequencerReport } from "../types";

const KIND_LABELS: Record<string, string> = {
  auto: "Guess from the name and the shape",
  session: "Session identifier",
  jwt: "JSON Web Token",
  csrf: "Anti-CSRF token",
  "api-key": "API key",
  "password-reset": "Password reset token",
  nonce: "Nonce",
  unknown: "Unknown",
};

const VERDICT_LABELS: Record<string, string> = {
  random: "Random",
  weak: "Weak",
  predictable: "Predictable",
  unknown: "Not measured",
};

/** The class the verdict is shown with. */
function verdictClass(verdict: string): string {
  if (verdict === "random") return "badge ok";
  if (verdict === "weak") return "badge warn";
  if (verdict === "predictable") return "badge error";
  return "badge";
}

/**
 * The values in a message that could be a token.
 *
 * The sequencer needs several samples of the same token, so the values are
 * taken out of the message that is open in the history.
 */
function tokenValues(text: string): string[] {
  const found: string[] = [];
  const push = (value: string) => {
    const trimmed = value.trim().replace(/^["']|["']$/g, "");
    if (trimmed.length >= 8 && !found.includes(trimmed)) found.push(trimmed);
  };
  const cookies =
    /(?:^|[\s;,])(?:JSESSIONID|PHPSESSID|sessionid|sid|csrf(?:_token)?|_token|xsrf|api[_-]?key|access[_-]?token|refresh[_-]?token|nonce|auth|token)=([^;,\s"']+)/gi;
  for (const match of text.matchAll(cookies)) push(match[1]);
  const headers = /(?:Bearer|Basic|Token|Digest)\s+([A-Za-z0-9._~+/=-]{8,})/gi;
  for (const match of text.matchAll(headers)) push(match[1]);
  const webTokens = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;
  for (const match of text.matchAll(webTokens)) push(match[0]);
  return found;
}

/** The measures of the report, in the order they are shown. */
function measures(report: SequencerReport): { label: string; value: string }[] {
  const stamp = report.embedded_timestamp
    ? new Date(report.embedded_timestamp * 1000).toLocaleString()
    : "none";
  return [
    { label: "Samples", value: `${report.samples} (${report.unique} different)` },
    { label: "Length", value: `${report.length} characters` },
    {
      label: "Random part",
      value: `${report.random_length} characters`,
    },
    {
      label: "Entropy per character",
      value: `${report.entropy_per_character.toFixed(3)} of ${report.expected_entropy.toFixed(3)} bits`,
    },
    { label: "Bits per token", value: report.total_bits.toFixed(1) },    { label: "Chi square", value: `${report.chi_square.toFixed(2)} (p ${report.chi_square_p.toFixed(4)})` },
    { label: "Serial correlation", value: report.serial_correlation.toFixed(4) },
    { label: "Monte Carlo pi", value: report.monte_carlo_pi.toFixed(4) },
    { label: "Bit bias", value: report.bit_bias.toFixed(4) },
    { label: "Different bytes", value: String(report.unique_bytes) },
    { label: "Longest run", value: String(report.longest_run) },
    { label: "Shared prefix", value: report.common_prefix || "none" },
    { label: "Shared suffix", value: report.common_suffix || "none" },
    { label: "Counter", value: report.sequential ? "yes" : "no" },
    { label: "Repeated samples", value: String(report.duplicates.length) },
    { label: "Clock inside", value: stamp },
  ];
}

export default function SequencerView() {
  const detail = useStore((s) => s.detail);
  const busy = useStore((s) => s.busy);
  const report = useStore((s) => s.sequencerReport);
  const analyzeTokens = useStore((s) => s.analyzeTokens);

  const [text, setText] = useState("");
  const [kind, setKind] = useState("auto");
  const [name, setName] = useState("");

  const samples = useMemo(
    () =>
      text
        .split(/[\n\r]/)
        .map((line) => line.trim())
        .filter(Boolean),
    [text],
  );

  const takeFromMessage = () => {
    if (!detail) return;
    const source = `${detail.request.raw ?? ""}\n${detail.response?.raw ?? ""}`;
    const values = tokenValues(source);
    if (values.length === 0) return;
    setText((current) => {
      const lines = current.split("\n").map((line) => line.trim()).filter(Boolean);
      for (const value of values) if (!lines.includes(value)) lines.push(value);
      return lines.join("\n");
    });
  };

  const analyse = () => {
    void analyzeTokens(samples, kind, name);
  };

  const jwt = report?.jwt ?? {};
  const characters = Object.entries(report?.characters ?? {}).sort(
    (a, b) => b[1] - a[1],
  );

  return (
    <div className="sequencer">
      <div className="sequencer-side">
        <div className="pane-header">
          <span className="muted mono grow">Samples of one token</span>
          <span className="muted small">{samples.length}</span>
        </div>
        <textarea
          className="editor mono"
          spellCheck={false}
          placeholder={"one token per line\n\nPaste several tokens of the same kind,\nthen press Analyse."}
          value={text}
          onChange={(event) => setText(event.target.value)}
        />

        <div className="pane-header">
          <select
            className="filter"
            value={kind}
            onChange={(event) => setKind(event.target.value)}
          >
            {Object.keys(KIND_LABELS).map((value) => (
              <option key={value} value={value}>
                {KIND_LABELS[value]}
              </option>
            ))}
          </select>
          <input
            className="filter"
            placeholder="the name of the token"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <button
            className="button primary"
            disabled={busy || samples.length === 0}
            onClick={analyse}
          >
            {busy ? "Measuring…" : "Analyse"}
          </button>
        </div>

        {detail && (
          <div className="pane-header">
            <span className="muted small grow">from the message in the history</span>
            <button className="button" onClick={takeFromMessage}>
              Take the tokens
            </button>
          </div>
        )}

        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-method">#</th>
                <th className="col-path">Sample</th>
                <th className="col-size">Length</th>
              </tr>
            </thead>
            <tbody>
              {samples.map((sample, index) => (
                <tr key={`${sample}-${index}`}>
                  <td className="col-method">{index + 1}</td>
                  <td className="col-path mono" title={sample}>
                    {sample.slice(0, 80)}
                  </td>
                  <td className="col-size">{sample.length}</td>
                </tr>
              ))}
              {samples.length === 0 && (
                <tr>
                  <td colSpan={3} className="empty">
                    No samples yet. Paste the tokens above, one per line.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="sequencer-main">
        <div className="pane-header">
          <span className="mono grow">Report</span>
          {report && (
            <>
              <span className="muted small">{KIND_LABELS[report.kind] ?? report.kind}</span>
              <span className={verdictClass(report.verdict)}>
                {VERDICT_LABELS[report.verdict] ?? report.verdict}
              </span>
            </>
          )}
        </div>

        {!report ? (
          <div className="placeholder">
            Nothing was measured yet. The sequencer needs several samples of the same token,
            because a token can look random while the way it is built is not.
          </div>
        ) : (
          <>
            <div className="sequencer-verdict">
              <span className={`verdict ${verdictClass(report.verdict)}`}>
                {VERDICT_LABELS[report.verdict] ?? report.verdict}
              </span>
              <span className="muted small">
                {report.samples} samples, {report.unique} of them different
              </span>
              <span className="grow" />
              <span className="muted small">confidence {Math.round(report.score * 100)}%</span>
            </div>

            {report.notes.length > 0 && (
              <div className="sequencer-notes">
                {report.notes.map((note, index) => (
                  <div key={index} className="sequencer-note">
                    <span>—</span>
                    <span>{note}</span>
                  </div>
                ))}
              </div>
            )}

            <div className="sequencer-measures">
              {measures(report).map((measure) => (
                <div key={measure.label} className="measure">
                  <div className="measure-label">{measure.label}</div>
                  <div className="measure-value">{measure.value}</div>
                </div>
              ))}
            </div>

            {Boolean(jwt.algorithm) && (
              <div className="sequencer-jwt">
                <div className="pane-header">
                  <span className="mono grow">The JSON web token</span>
                  {jwt.forgable ? (
                    <span className="badge error">can be forged</span>
                  ) : (
                    <span className="badge ok">signature holds</span>
                  )}
                </div>
                <div className="card">
                  <dl>
                    <dt>Algorithm</dt>
                    <dd>{String(jwt.algorithm)}</dd>
                    {Boolean(jwt.forgable) && (
                      <>
                        <dt>Why</dt>
                        <dd>{String(jwt.reason ?? "the token can be made by hand")}</dd>
                      </>
                    )}
                    {Boolean(jwt.secret) && (
                      <>
                        <dt>Secret</dt>
                        <dd className="mono">{String(jwt.secret)}</dd>
                      </>
                    )}
                    <dt>Claims</dt>
                    <dd>{(jwt.claims as string[] | undefined)?.join(", ") || "none"}</dd>
                    {Boolean(jwt.predictable_claims) && (
                      <>
                        <dt>Predictable</dt>
                        <dd>{(jwt.predictable_claims as string[] | undefined)?.join(", ")}</dd>
                      </>
                    )}
                  </dl>
                </div>
              </div>
            )}

            {characters.length > 0 && (
              <div className="table-wrap">
                <table className="traffic-table">
                  <thead>
                    <tr>
                      <th className="col-method">Character</th>
                      <th className="col-size">Times seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {characters.map(([character, count]) => (
                      <tr key={character}>
                        <td className="col-method mono">{character}</td>
                        <td className="col-size">{count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

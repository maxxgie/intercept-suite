import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { useStore } from "../state/store";

interface KindDescriptor {
  id: string;
  label: string;
}

interface DecoderCatalog {
  kinds: KindDescriptor[];
  algorithms: string[];
  keyed: string[];
}

interface ChainStep {
  kind: string;
  mode: string;
}

interface ChainResult {
  kind: string;
  mode: string;
  output: string;
}

interface SmartCandidate {
  kind: string;
  label: string;
  score: number;
  output: string;
  reason: string;
}

type Panel = "single" | "chain" | "smart" | "hash";

const PANEL_LABELS: Record<Panel, string> = {
  single: "One conversion",
  chain: "Chained",
  smart: "Smart decode",
  hash: "Hashes",
};

const HASH_LABELS: Record<string, string> = {
  md5: "MD5",
  sha1: "SHA-1",
  sha224: "SHA-224",
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
  "sha3-224": "SHA3-224",
  "sha3-256": "SHA3-256",
  "sha3-384": "SHA3-384",
  "sha3-512": "SHA3-512",
  blake2b: "BLAKE2b",
  blake2s: "BLAKE2s",
  crc32: "CRC32",
  adler32: "Adler32",
  "hmac-md5": "HMAC-MD5",
  "hmac-sha1": "HMAC-SHA1",
  "hmac-sha256": "HMAC-SHA256",
  "hmac-sha512": "HMAC-SHA512",
};

const STEP_MODES = [
  { id: "decode", label: "Decode" },
  { id: "encode", label: "Encode" },
];

/**
 * The decoder.
 *
 * The conversions live in the daemon, so the view only asks for them and
 * shows what came back: one conversion, a chain of them, the decodings that
 * make sense on their own, and the digests of a value.
 */
export default function DecoderView() {
  const detail = useStore((s) => s.detail);

  const [catalog, setCatalog] = useState<DecoderCatalog | null>(null);
  const [panel, setPanel] = useState<Panel>("single");
  const [value, setValue] = useState("");
  const [mode, setMode] = useState("decode");
  const [kind, setKind] = useState("base64");
  const [secret, setSecret] = useState("");
  const [steps, setSteps] = useState<ChainStep[]>([
    { kind: "base64", mode: "decode" },
    { kind: "url", mode: "decode" },
  ]);
  const [algorithm, setAlgorithm] = useState("sha256");
  const [key, setKey] = useState("");
  const [output, setOutput] = useState("");
  const [chain, setChain] = useState<ChainResult[]>([]);
  const [candidates, setCandidates] = useState<SmartCandidate[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    api
      .get<DecoderCatalog>("/api/decoder/kinds")
      .then((data) => {
        if (alive) setCatalog(data);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  const kinds = useMemo(() => catalog?.kinds ?? [], [catalog]);
  const needsSecret = kind === "jwt" && mode === "encode";
  const needsKey = (catalog?.keyed ?? []).includes(algorithm);

  async function call<T>(path: string, body: Record<string, unknown>): Promise<T | null> {
    setError("");
    try {
      return await api.post<T>(path, body);
    } catch (failure) {
      setError((failure as Error).message);
      return null;
    }
  }

  const convert = async () => {
    const data = await call<{ output: string }>("/api/decoder/convert", {
      value,
      kind,
      mode,
      options: { secret },
    });
    if (!data) return;
    setOutput(String(data.output ?? ""));
    setChain([]);
    setCandidates([]);
  };

  const runChain = async () => {
    const data = await call<{ output: string; steps: ChainResult[] }>("/api/decoder/chain", {
      value,
      steps,
    });
    if (!data) return;
    setOutput(String(data.output ?? ""));
    setChain(data.steps ?? []);
    setCandidates([]);
  };

  const smart = async () => {
    const data = await call<{ candidates: SmartCandidate[]; best: SmartCandidate | null }>(
      "/api/decoder/smart",
      { value },
    );
    if (!data) return;
    setCandidates(data.candidates ?? []);
    setOutput(data.best ? data.best.output : "");
    setChain([]);
  };

  const digest = async () => {
    const data = await call<{ output: string }>("/api/decoder/hash", { value, algorithm, key });
    if (!data) return;
    setOutput(String(data.output ?? ""));
    setChain([]);
    setCandidates([]);
  };

  const addStep = () => {
    setSteps((current) => [...current, { kind: "base64", mode: "decode" }]);
  };

  const changeStep = (index: number, change: Partial<ChainStep>) => {
    setSteps((current) =>
      current.map((step, position) => (position === index ? { ...step, ...change } : step)),
    );
  };

  const removeStep = (index: number) => {
    setSteps((current) => current.filter((_, position) => position !== index));
  };

  const takeBody = () => {
    if (!detail) return;
    setValue(detail.response?.body ?? detail.request?.body ?? "");
  };

  const takeRaw = () => {
    if (!detail) return;
    setValue(detail.request.raw ?? detail.response?.raw ?? "");
  };

  return (
    <div className="decoder-view">
      <div className="pane-header">
        <div className="seg">
          {(Object.keys(PANEL_LABELS) as Panel[]).map((name) => (
            <button
              key={name}
              className={panel === name ? "seg-item active" : "seg-item"}
              onClick={() => setPanel(name)}
            >
              {PANEL_LABELS[name]}
            </button>
          ))}
        </div>
        <span className="grow" />
        {detail && (
          <>
            <button className="button" onClick={takeBody} title="Take the body of the exchange">
              Take the body
            </button>
            <button className="button" onClick={takeRaw} title="Take the raw message">
              Take the raw
            </button>
          </>
        )}
      </div>

      <div className="decoder-panel">
        <textarea
          className="editor mono"
          spellCheck={false}
          placeholder="Paste the value to convert"
          value={value}
          onChange={(event) => setValue(event.target.value)}
        />

        {panel === "single" && (
          <div className="pane-header">
            <select
              className="filter"
              value={mode}
              onChange={(event) => setMode(event.target.value)}
            >
              {STEP_MODES.map((item) => (
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
              {kinds.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
            {needsSecret && (
              <input
                className="filter"
                placeholder="the secret of the signature"
                value={secret}
                onChange={(event) => setSecret(event.target.value)}
              />
            )}
            <span className="grow" />
            <button className="button primary" onClick={() => void convert()}>
              Convert
            </button>
          </div>
        )}

        {panel === "chain" && (
          <>
            <div className="pane-header">
              <span className="muted small grow">
                the steps run one after the other, from the top down
              </span>
              <button className="button" onClick={addStep}>
                Add a step
              </button>
              <button className="button primary" onClick={() => void runChain()}>
                Run the chain
              </button>
            </div>
            <div className="decoder-steps">
              {steps.map((step, index) => (
                <div key={index} className="decoder-step">
                  <span className="muted small">{index + 1}</span>
                  <select
                    className="filter"
                    value={step.kind}
                    onChange={(event) => changeStep(index, { kind: event.target.value })}
                  >
                    {kinds.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.label}
                      </option>
                    ))}
                  </select>
                  <select
                    className="filter"
                    value={step.mode}
                    onChange={(event) => changeStep(index, { mode: event.target.value })}
                  >
                    {STEP_MODES.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.label}
                      </option>
                    ))}
                  </select>
                  <button className="button" onClick={() => removeStep(index)}>
                    Remove
                  </button>
                </div>
              ))}
            </div>
          </>
        )}

        {panel === "smart" && (
          <div className="pane-header">
            <span className="muted small grow">
              every decoding is tried and the answers that look the most like text come first
            </span>
            <button className="button primary" onClick={() => void smart()}>
              Try every decoding
            </button>
          </div>
        )}

        {panel === "hash" && (
          <div className="pane-header">
            <select
              className="filter"
              value={algorithm}
              onChange={(event) => setAlgorithm(event.target.value)}
            >
              {(catalog?.algorithms ?? []).map((name) => (
                <option key={name} value={name}>
                  {HASH_LABELS[name] ?? name}
                </option>
              ))}
            </select>
            {needsKey && (
              <input
                className="filter"
                placeholder="the key"
                value={key}
                onChange={(event) => setKey(event.target.value)}
              />
            )}
            <span className="grow" />
            <button className="button primary" onClick={() => void digest()}>
              Make the digest
            </button>
          </div>
        )}

        {error && <div className="banner error">{error}</div>}

        {candidates.length > 0 && (
          <div className="table-wrap">
            <table className="traffic-table">
              <thead>
                <tr>
                  <th className="col-method">Decoding</th>
                  <th className="col-status">Score</th>
                  <th className="col-host">Why</th>
                  <th className="col-path">Result</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((candidate) => (
                  <tr
                    key={candidate.kind}
                    onClick={() => setOutput(candidate.output)}
                    title="Put this result in the output"
                  >
                    <td className="col-method">{candidate.label}</td>
                    <td className="col-status">{candidate.score.toFixed(2)}</td>
                    <td className="col-host">{candidate.reason}</td>
                    <td className="col-path mono" title={candidate.output}>
                      {candidate.output.slice(0, 80)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {chain.length > 0 && (
          <div className="decoder-chain">
            {chain.map((step, index) => (
              <div key={index} className="decoder-chain-step">
                <span className="muted small grow">
                  {index + 1}. {step.kind} ({step.mode})
                </span>
                <span className="mono">{step.output.slice(0, 200)}</span>
              </div>
            ))}
          </div>
        )}

        {output && (
          <pre className="body-view" onClick={() => setValue(output)}>
            {output}
          </pre>
        )}
      </div>
    </div>
  );
}

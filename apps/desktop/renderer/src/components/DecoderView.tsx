import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";
import type { ToolDescriptor } from "../types";

const ENCODINGS = ["url", "html", "base64", "hex", "json"];

/**
 * Encode and decode a payload.
 *
 * The conversion itself is the tool the encodings plugin registers; this view
 * only presents it, so the plugin keeps ownership of the logic.
 */
export default function DecoderView() {
  const tools = useStore((s) => s.tools);
  const runTool = useStore((s) => s.runTool);
  const detail = useStore((s) => s.detail);
  const setView = useStore((s) => s.setView);
  const refreshPlugins = useStore((s) => s.refreshPlugins);

  const [value, setValue] = useState("");
  const [mode, setMode] = useState("decode");
  const [encoding, setEncoding] = useState("url");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    void refreshPlugins();
  }, [refreshPlugins]);

  const tool = useMemo<ToolDescriptor | null>(() => {
    const names = new Set(tools.map((item) => item.id));
    if (names.has("encodings.convert")) {
      return tools.find((item) => item.id === "encodings.convert") ?? null;
    }
    return (
      tools.find((item) => {
        const fields = item.fields.map((field) => field.name);
        return fields.includes("value") && fields.includes("mode") && fields.includes("encoding");
      }) ?? null
    );
  }, [tools]);

  async function convert() {
    if (!tool) return;
    const result = await runTool(tool.id, { value, mode, encoding });
    if (result.startsWith("Error:")) {
      setError(result.replace(/^Error:\s*/, ""));
      setOutput("");
      return;
    }
    setError("");
    setOutput(result);
  }

  if (!tool) {
    return (
      <div className="placeholder">
        <p>No encoding tool is registered.</p>
        <p className="muted">
          The encodings plugin provides it. Install the plugin and the decoder appears here.
        </p>
        <button className="button" onClick={() => setView("extensions")}>
          Open the extensions
        </button>
      </div>
    );
  }

  return (
    <div className="decoder-view">
      <div className="pane-header">
        <span className="grow">Decoder</span>
        {detail?.response?.body && (
          <button
            className="button"
            onClick={() => setValue(detail.response?.body ?? "")}
            title="Take the body of the selected exchange"
          >
            Take the selected body
          </button>
        )}
      </div>

      <div className="form">
        <div className="row">
          <select className="filter" value={mode} onChange={(event) => setMode(event.target.value)}>
            <option value="decode">Decode</option>
            <option value="encode">Encode</option>
          </select>
          <select
            className="filter"
            value={encoding}
            onChange={(event) => setEncoding(event.target.value)}
          >
            {ENCODINGS.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>

        <textarea
          className="editor mono"
          rows={8}
          spellCheck={false}
          placeholder="Paste the value to convert"
          value={value}
          onChange={(event) => setValue(event.target.value)}
        />

        <div className="row">
          <button className="button primary" onClick={() => void convert()}>
            Convert
          </button>
        </div>

        {error && <div className="banner error">{error}</div>}
        {output && <pre className="body-view">{output}</pre>}
      </div>
    </div>
  );
}

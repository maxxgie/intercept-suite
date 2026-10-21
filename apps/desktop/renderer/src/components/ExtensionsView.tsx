import { useState } from "react";
import { useStore } from "../state/store";
import type { ToolDescriptor } from "../types";

export default function ExtensionsView() {
  const tools = useStore((s) => s.tools);
  const plugins = useStore((s) => s.plugins);
  const runTool = useStore((s) => s.runTool);
  const [selected, setSelected] = useState<string | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");

  const tool: ToolDescriptor | null = tools.find((item) => item.id === selected) ?? null;

  function selectTool(item: ToolDescriptor) {
    setSelected(item.id);
    const initial: Record<string, unknown> = {};
    for (const field of item.fields) initial[field.name] = field.default;
    setValues(initial);
    setOutput("");
    setError("");
  }

  async function run() {
    if (!tool) return;
    try {
      const result = await runTool(tool.id, values);
      if (result.startsWith("Error:")) {
        setError(result);
        setOutput("");
      } else {
        setError("");
        setOutput(result);
      }
    } catch (caught) {
      setError((caught as Error).message);
    }
  }

  return (
    <div className="extensions">
      <div className="pane-header">
        <span className="grow">Tools provided by installed plugins</span>
        {plugins.length > 0 && (
          <span className="muted">
            {plugins.length} plugin{plugins.length === 1 ? "" : "s"}
          </span>
        )}
      </div>

      <div className="extensions-body">
        <div className="tool-list">
          {tools.map((item) => (
            <button
              key={item.id}
              className={item.id === selected ? "tool-item active" : "tool-item"}
              onClick={() => selectTool(item)}
            >
              <span className="tool-label">{item.label}</span>
              <span className="muted small">{item.id}</span>
            </button>
          ))}
          {tools.length === 0 && <div className="placeholder small">No tools registered.</div>}
        </div>

        <div className="tool-detail">
          {tool ? (
            <>
              <h2>{tool.label}</h2>
              <p className="muted">{tool.description}</p>
              <div className="form">
                {tool.fields.map((field) => (
                  <label key={field.name} className="field">
                    <span>{field.label}</span>
                    {field.type === "textarea" ? (
                      <textarea
                        className="editor mono"
                        rows={5}
                        value={String(values[field.name] ?? "")}
                        onChange={(event) =>
                          setValues({ ...values, [field.name]: event.target.value })
                        }
                      />
                    ) : field.type === "select" ? (
                      <select
                        value={String(values[field.name] ?? "")}
                        onChange={(event) =>
                          setValues({ ...values, [field.name]: event.target.value })
                        }
                      >
                        {field.options.map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type={field.type === "number" ? "number" : "text"}
                        value={String(values[field.name] ?? "")}
                        placeholder={field.placeholder}
                        onChange={(event) =>
                          setValues({ ...values, [field.name]: event.target.value })
                        }
                      />
                    )}
                    {field.help && <small className="muted">{field.help}</small>}
                  </label>
                ))}
                <button className="button primary" onClick={() => void run()}>
                  Run
                </button>
              </div>
              {error && <div className="banner error">{error}</div>}
              {output && <pre className="body-view">{output}</pre>}
            </>
          ) : (
            <div className="placeholder">Pick a tool to run it.</div>
          )}
        </div>
      </div>
    </div>
  );
}

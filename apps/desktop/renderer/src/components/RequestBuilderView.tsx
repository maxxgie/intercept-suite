import { useState } from "react";
import { useStore } from "../state/store";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/**
 * Write a request from scratch and open it in the repeater.
 */
export default function RequestBuilderView() {
  const createTab = useStore((s) => s.createRepeaterTab);
  const setError = useStore((s) => s.setError);
  const busy = useStore((s) => s.busy);

  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");

  async function build() {
    const target = url.trim();
    if (!target) {
      setError("a url is required");
      return;
    }
    const headerMap: Record<string, string[]> = {};
    for (const line of headers.split("\n")) {
      const text = line.trim();
      if (!text) continue;
      const separator = text.indexOf(":");
      if (separator < 1) continue;
      const name = text.slice(0, separator).trim();
      const value = text.slice(separator + 1).trim();
      headerMap[name] = [value];
    }
    try {
      await createTab({
        method,
        url: target,
        headers: Object.keys(headerMap).length ? headerMap : undefined,
        body: body || undefined,
        name: `${method} ${target}`,
      });
    } catch (error) {
      setError((error as Error).message);
    }
  }

  return (
    <div className="builder-view">
      <div className="pane-header">
        <span className="grow">Build a request</span>
        <button className="button primary" disabled={busy} onClick={() => void build()}>
          Open in repeater
        </button>
      </div>

      <div className="form">
        <div className="row">
          <select
            className="filter"
            value={method}
            onChange={(event) => setMethod(event.target.value)}
            style={{ width: 120 }}
          >
            {METHODS.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <input
            className="filter mono grow"
            placeholder="https://example.com/path"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void build();
            }}
          />
        </div>

        <label className="field">
          <span>Headers (one per line, name: value)</span>
          <textarea
            className="editor mono"
            rows={6}
            spellCheck={false}
            placeholder={"Host: example.com\nContent-Type: application/json"}
            value={headers}
            onChange={(event) => setHeaders(event.target.value)}
          />
        </label>

        <label className="field">
          <span>Body</span>
          <textarea
            className="editor mono"
            rows={10}
            spellCheck={false}
            placeholder='{"key": "value"}'
            value={body}
            onChange={(event) => setBody(event.target.value)}
          />
        </label>
      </div>
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";
import type { ExchangeDetail, HeadersMap, MessageDetail, ResponseDetail } from "../types";
import { useStore, type MessageTab } from "../state/store";
import { bodyBytes, hexDump } from "../lib/bytes";
import { IconClose } from "./icons";

function prettyJson(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    return null;
  }
}

function HeadersTable({ headers }: { headers: HeadersMap }) {
  const entries = Object.entries(headers);
  if (entries.length === 0) return <div className="placeholder small">No headers</div>;
  return (
    <table className="headers-table">
      <tbody>
        {entries.flatMap(([name, values]) =>
          values.map((value, index) => (
            <tr key={`${name}-${index}`}>
              <td className="header-name">{name}</td>
              <td className="header-value mono">{value}</td>
            </tr>
          )),
        )}
      </tbody>
    </table>
  );
}

function BodyView({ body, encoding }: { body: string; encoding: string }) {
  const text = useMemo(() => {
    if (encoding !== "base64") return body;
    const bytes = bodyBytes(body, encoding);
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return null;
    }
  }, [body, encoding]);
  if (!body) return <div className="placeholder small">Empty body</div>;
  if (text === null) {
    return (
      <div className="placeholder small">
        This body is binary, {bodyBytes(body, encoding).length} bytes. The hex view shows it byte
        by byte.
      </div>
    );
  }
  const pretty = prettyJson(text);
  return (
    <pre className="body-view">
      {pretty ?? text}
    </pre>
  );
}

function HexView({ body, encoding }: { body: string; encoding: string }) {
  const dump = useMemo(() => hexDump(bodyBytes(body, encoding)), [body, encoding]);
  if (!dump) return <div className="placeholder small">Empty body</div>;
  return <pre className="body-view mono">{dump}</pre>;
}

/**
 * The body as the browser would show it.
 *
 * A page is shown in a frame that may not run scripts, so a page that comes
 * from the target cannot reach the interface. An image is shown as an image.
 */
function RenderView({ body, encoding, mime }: { body: string; encoding: string; mime: string }) {
  if (!body) return <div className="placeholder small">Empty body</div>;
  if (mime.startsWith("image/")) {
    const source = `data:${mime};base64,${body}`;
    return <img className="rendered-image" src={source} alt="The response" />;
  }
  if (!mime.includes("html") && !mime.includes("xml")) {
    return (
      <div className="placeholder small">
        Only a page or an image can be shown this way. This one is {mime || "of an unknown type"}.
      </div>
    );
  }
  const source = encoding === "base64" ? new TextDecoder().decode(bodyBytes(body, encoding)) : body;
  return (
    <iframe
      className="rendered-frame"
      title="The rendered response"
      sandbox=""
      srcDoc={source}
    />
  );
}

interface Props {
  request: MessageDetail;
  response: ResponseDetail | null;
}

export function MessageTabs({
  request,
  response,
  tab,
  setTab,
}: Props & { tab: MessageTab; setTab: (tab: MessageTab) => void }) {
  const target = response ?? request;
  const headers = target.headers;
  const body = target.body;
  const raw = target.raw;
  return (
    <>
      <div className="tabs">
        {(["pretty", "headers", "body", "hex", "render", "raw"] as MessageTab[]).map((name) => (
          <button
            key={name}
            className={tab === name ? "tab active" : "tab"}
            onClick={() => setTab(name)}
          >
            {name[0].toUpperCase() + name.slice(1)}
          </button>
        ))}
      </div>
      <div className="tab-body">
        {tab === "pretty" && (
          <BodyView body={body} encoding={target.body_encoding ?? "utf-8"} />
        )}
        {tab === "headers" && <HeadersTable headers={headers} />}
        {tab === "body" && <BodyView body={body} encoding={target.body_encoding ?? "utf-8"} />}
        {tab === "hex" && (
          <HexView body={body} encoding={target.body_encoding ?? "utf-8"} />
        )}
        {tab === "render" && (
          <RenderView
            body={body}
            encoding={target.body_encoding ?? "utf-8"}
            mime={target.mime_type ?? ""}
          />
        )}
        {tab === "raw" && <pre className="body-view raw">{raw || "(empty)"}</pre>}
      </div>
    </>
  );
}

export default function MessageViewer({ exchange }: { exchange: ExchangeDetail }) {
  const [tab, setTab] = useState<MessageTab>("pretty");
  const [side, setSide] = useState<"request" | "response">("response");
  const openInRepeater = useStore((s) => s.openInRepeater);
  const annotate = useStore((s) => s.annotate);
  const [tagInput, setTagInput] = useState("");
  const [noteInput, setNoteInput] = useState("");
  const [showAnnotation, setShowAnnotation] = useState(false);
  const response = exchange.response;

  const current = side === "request" ? exchange.request : response;
  const tags = current?.tags ?? [];
  const notes = current?.notes ?? [];

  useEffect(() => {
    setTagInput("");
    setNoteInput("");
  }, [side]);

  async function addTag() {
    const value = tagInput.trim();
    if (!value || !current) return;
    await annotate(exchange.id, side, [...tags, value], notes);
    setTagInput("");
  }

  async function removeTag(tag: string) {
    if (!current) return;
    await annotate(
      exchange.id,
      side,
      tags.filter((item) => item !== tag),
      notes,
    );
  }

  async function addNote() {
    const value = noteInput.trim();
    if (!value || !current) return;
    await annotate(exchange.id, side, tags, [...notes, value]);
    setNoteInput("");
  }

  async function removeNote(index: number) {
    if (!current) return;
    await annotate(
      exchange.id,
      side,
      tags,
      notes.filter((_, position) => position !== index),
    );
  }

  return (
    <div className="viewer">
      <div className="viewer-header">
        <div className="tabs">
          <button
            className={side === "request" ? "tab active" : "tab"}
            onClick={() => setSide("request")}
          >
            Request
          </button>
          <button
            className={side === "response" ? "tab active" : "tab"}
            onClick={() => setSide("response")}
          >
            Response
          </button>
        </div>
        {side === "response" && response && (
          <span className="muted mono">
            {response.status} {response.reason} · {response.http_version} ·{" "}
            {response.elapsed_ms.toFixed(0)} ms
          </span>
        )}
        <button className="button" onClick={() => setShowAnnotation(!showAnnotation)}>
          Notes {tags.length + notes.length > 0 ? `(${tags.length + notes.length})` : ""}
        </button>
        <button className="button" onClick={() => void openInRepeater(exchange)}>
          Send to repeater
        </button>
      </div>
      {showAnnotation && (
        <div className="form">
          <div className="field">
            <label htmlFor="annotation-tags">Tags on the {side}</label>
            <div className="row tight wrap">
              {tags.map((tag) => (
                <span className="pill" key={tag}>
                  {tag}
                  <button className="icon-button" onClick={() => void removeTag(tag)}>
                    <IconClose size={10} />
                  </button>
                </span>
              ))}
              <input
                id="annotation-tags"
                className="filter"
                value={tagInput}
                placeholder="Add a tag and press Enter"
                onChange={(event) => setTagInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    void addTag();
                  }
                }}
              />
            </div>
          </div>
          <div className="field">
            <label htmlFor="annotation-notes">Notes on the {side}</label>
            {notes.map((note, index) => (
              <div className="note-card" key={`${note}-${index}`}>
                <div className="note-text">{note}</div>
                <button className="icon-button" onClick={() => void removeNote(index)}>
                  <IconClose size={10} />
                </button>
              </div>
            ))}
            <div className="row tight">
              <input
                id="annotation-notes"
                className="filter"
                value={noteInput}
                placeholder="Write a remark and press Enter"
                onChange={(event) => setNoteInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    void addNote();
                  }
                }}
              />
            </div>
          </div>
        </div>
      )}
      <div className="viewer-body">
        {side === "request" ? (
          <MessageTabs request={exchange.request} response={null} tab={tab} setTab={setTab} />
        ) : response ? (
          <MessageTabs request={exchange.request} response={response} tab={tab} setTab={setTab} />
        ) : (
          <div className="placeholder">This request has no response yet.</div>
        )}
      </div>
    </div>
  );
}

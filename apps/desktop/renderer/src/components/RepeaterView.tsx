import { useEffect, useState } from "react";
import { useStore } from "../state/store";
import { MessageTabs } from "./MessageViewer";
import type { MessageTab } from "../state/store";

export default function RepeaterView() {
  const tabs = useStore((s) => s.tabs);
  const activeTabId = useStore((s) => s.activeTabId);
  const busy = useStore((s) => s.busy);
  const updateTab = useStore((s) => s.updateTab);
  const sendTab = useStore((s) => s.sendTab);
  const closeTab = useStore((s) => s.closeTab);
  const [draft, setDraft] = useState("");
  const [tab, setTab] = useState<MessageTab>("pretty");

  const active = tabs.find((item) => item.id === activeTabId) ?? null;

  useEffect(() => {
    setDraft(active?.request.raw ?? "");
  }, [activeTabId, active?.request.raw]);

  if (tabs.length === 0) {
    return (
      <div className="placeholder">
        <p>No repeater tabs yet.</p>
        <p className="muted">
          Open a request from the traffic list and choose “Send to repeater”, or build a request
          by hand.
        </p>
      </div>
    );
  }

  return (
    <div className="repeater">
      <div className="tab-strip">
        {tabs.map((item) => (
          <div key={item.id} className={item.id === activeTabId ? "strip-item active" : "strip-item"}>
            <button className="strip-label" onClick={() => useStore.setState({ activeTabId: item.id })}>
              {item.name}
            </button>
            <button className="strip-close" onClick={() => void closeTab(item.id)}>
              ×
            </button>
          </div>
        ))}
      </div>

      {active && (
        <div className="repeater-body">
          <div className="repeater-request">
            <div className="pane-header">
              <span className="muted mono grow">Request</span>
              <button className="button primary" disabled={busy} onClick={() => void sendTab(active.id, draft)}>
                {busy ? "Sending…" : "Send"}
              </button>
            </div>
            <textarea
              className="editor mono"
              spellCheck={false}
              value={draft}
              onChange={(event) => {
                setDraft(event.target.value);
                updateTab(active.id, event.target.value);
              }}
            />
          </div>
          <div className="repeater-response">
            {active.response ? (
              <MessageTabs
                request={active.request}
                response={active.response}
                tab={tab}
                setTab={setTab}
              />
            ) : (
              <div className="placeholder">Send the request to see the response.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

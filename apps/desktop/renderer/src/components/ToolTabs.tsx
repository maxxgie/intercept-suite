import { useStore } from "../state/store";
import { NAV_ITEMS, MORE_TOOLS } from "./navigation";
import { IconClose } from "./icons";

/**
 * The strip of open tools, so several can be worked on at once and switched
 * between without losing their place.
 */
export default function ToolTabs() {
  const openTools = useStore((s) => s.openTools);
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const closeTool = useStore((s) => s.closeTool);

  const labels = new Map<string, string>([
    ...NAV_ITEMS.map((item) => [item.id as string, item.label] as [string, string]),
    ...MORE_TOOLS.map((item) => [item.id as string, item.label] as [string, string]),
  ]);

  if (openTools.length === 0) return null;

  return (
    <div className="tool-tabs" role="tablist">
      {openTools.map((id) => (
        <div className={id === view ? "tool-tab active" : "tool-tab"} key={id}>
          <button className="tool-tab-label" onClick={() => setView(id)} role="tab">
            {labels.get(id) ?? id}
          </button>
          <button
            className="tool-tab-close"
            onClick={() => closeTool(id)}
            title={`Close ${labels.get(id) ?? id}`}
            aria-label={`Close ${labels.get(id) ?? id}`}
          >
            <IconClose size={12} />
          </button>
        </div>
      ))}
    </div>
  );
}

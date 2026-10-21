import { useEffect } from "react";
import { useStore } from "../state/store";

/** The right click menu shared by every list in the workspace. */
export default function ContextMenu() {
  const menu = useStore((s) => s.contextMenu);
  const close = useStore((s) => s.closeContextMenu);

  useEffect(() => {
    if (!menu) return;
    const dismiss = () => close();
    window.addEventListener("click", dismiss);
    window.addEventListener("contextmenu", dismiss);
    return () => {
      window.removeEventListener("click", dismiss);
      window.removeEventListener("contextmenu", dismiss);
    };
  }, [menu, close]);

  if (!menu) return null;

  return (
    <div
      className="context-menu"
      style={{ left: menu.x, top: menu.y }}
      onClick={(event) => event.stopPropagation()}
    >
      {menu.items.map((item) =>
        item.separator ? (
          <div className="context-separator" key={item.id} />
        ) : (
          <button
            key={item.id}
            className="context-item"
            disabled={item.disabled}
            onClick={() => {
              close();
              item.run?.();
            }}
          >
            <span>{item.label}</span>
            {item.shortcut && <span className="muted small">{item.shortcut}</span>}
          </button>
        ),
      )}
    </div>
  );
}

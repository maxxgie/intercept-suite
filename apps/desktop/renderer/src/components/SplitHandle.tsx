import { useRef } from "react";

/**
 * The handle between the list and the detail pane of a split view.
 *
 * The width of the list pane is kept on the document, so every split view
 * follows the same setting.
 */
export default function SplitHandle() {
  const last = useRef<number | null>(null);
  const base = useRef(0);

  function onPointerDown(event: React.PointerEvent<HTMLDivElement>) {
    const handle = event.currentTarget;
    const list = handle.previousElementSibling as HTMLElement | null;
    last.current = event.clientX;
    base.current = list?.getBoundingClientRect().width ?? 520;
    handle.setPointerCapture(event.pointerId);
    document.body.classList.add("resizing-x");
  }

  function onPointerMove(event: React.PointerEvent<HTMLDivElement>) {
    if (last.current === null) return;
    const delta = event.clientX - last.current;
    last.current = event.clientX;

    const container = event.currentTarget.parentElement;
    const available = container?.clientWidth ?? 1200;
    const next = Math.max(220, Math.min(available - 220, base.current + delta));
    document.documentElement.style.setProperty("--list-pane", `${Math.round(next)}px`);
  }

  function onPointerUp(event: React.PointerEvent<HTMLDivElement>) {
    last.current = null;
    event.currentTarget.releasePointerCapture(event.pointerId);
    document.body.classList.remove("resizing-x");
  }

  return (
    <div
      className="resizer resizer-vertical split-resizer"
      role="separator"
      aria-label="Resize the panes"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
    />
  );
}

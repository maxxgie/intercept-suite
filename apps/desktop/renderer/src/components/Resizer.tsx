import { useRef } from "react";

interface Props {
  /** The direction the handle moves in. */
  orientation: "vertical" | "horizontal";
  /** Called with the distance the pointer travelled since the drag started. */
  onDelta: (delta: number) => void;
  label: string;
}

/**
 * A drag handle between two panels.
 *
 * The handle keeps the pointer capture while it is dragged, so the cursor
 * does not flicker over the panels underneath it.
 */
export default function Resizer({ orientation, onDelta, label }: Props) {
  const last = useRef<number | null>(null);

  function onPointerDown(event: React.PointerEvent<HTMLDivElement>) {
    last.current = orientation === "vertical" ? event.clientX : event.clientY;
    event.currentTarget.setPointerCapture(event.pointerId);
    document.body.classList.add(orientation === "vertical" ? "resizing-x" : "resizing-y");
  }

  function onPointerMove(event: React.PointerEvent<HTMLDivElement>) {
    if (last.current === null) return;
    const position = orientation === "vertical" ? event.clientX : event.clientY;
    onDelta(position - last.current);
    last.current = position;
  }

  function onPointerUp(event: React.PointerEvent<HTMLDivElement>) {
    last.current = null;
    event.currentTarget.releasePointerCapture(event.pointerId);
    document.body.classList.remove("resizing-x", "resizing-y");
  }

  return (
    <div
      className={`resizer resizer-${orientation}`}
      role="separator"
      aria-label={label}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
    />
  );
}

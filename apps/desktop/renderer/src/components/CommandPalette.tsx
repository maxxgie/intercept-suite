import { useEffect, useMemo, useRef, useState } from "react";
import { useStore } from "../state/store";
import type { CommandDescriptor } from "../types";

function score(command: CommandDescriptor, query: string): number {
  const needle = query.trim().toLowerCase();
  if (!needle) return 0;
  const title = command.title.toLowerCase();
  if (title.startsWith(needle)) return 0;
  if (title.includes(needle)) return 1;
  if (command.keywords.some((word) => word.toLowerCase().startsWith(needle))) return 2;
  if (command.category.toLowerCase().includes(needle)) return 3;
  if (command.description.toLowerCase().includes(needle)) return 4;
  return -1;
}

export default function CommandPalette() {
  const open = useStore((s) => s.paletteOpen);
  const setPalette = useStore((s) => s.setPalette);
  const commands = useStore((s) => s.commands);
  const runCommand = useStore((s) => s.runCommand);
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setIndex(0);
      window.setTimeout(() => inputRef.current?.focus(), 10);
    }
  }, [open]);

  const results = useMemo(() => {
    return commands
      .map((command) => ({ command, rank: score(command, query) }))
      .filter((item) => item.rank >= 0)
      .sort((a, b) => a.rank - b.rank || a.command.title.localeCompare(b.command.title))
      .map((item) => item.command)
      .slice(0, 60);
  }, [commands, query]);

  useEffect(() => {
    setIndex(0);
  }, [query]);

  if (!open) return null;

  async function choose(command: CommandDescriptor) {
    setPalette(false);
    await runCommand(command.id);
  }

  function onKeyDown(event: React.KeyboardEvent) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setIndex((current) => Math.min(current + 1, results.length - 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setIndex((current) => Math.max(current - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      const command = results[index];
      if (command) void choose(command);
    } else if (event.key === "Escape") {
      event.preventDefault();
      setPalette(false);
    }
  }

  let lastCategory = "";

  return (
    <div className="palette-backdrop" onMouseDown={() => setPalette(false)}>
      <div className="palette" onMouseDown={(event) => event.stopPropagation()}>
        <input
          ref={inputRef}
          className="palette-input"
          placeholder="Run a command…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={onKeyDown}
        />
        <div className="palette-results">
          {results.length === 0 && <div className="placeholder small">No command matches.</div>}
          {results.map((command, position) => {
            const showCategory = command.category !== lastCategory;
            lastCategory = command.category;
            return (
              <div key={command.id}>
                {showCategory && <div className="palette-category">{command.category}</div>}
                <button
                  className={`palette-item${position === index ? " active" : ""}`}
                  onMouseEnter={() => setIndex(position)}
                  onClick={() => void choose(command)}
                >
                  <span className="palette-title">{command.title}</span>
                  {command.shortcut && <span className="muted small">{command.shortcut}</span>}
                </button>
              </div>
            );
          })}
        </div>
        <div className="palette-footer muted small">
          <span>↑↓ to move</span>
          <span>↵ to run</span>
          <span>esc to close</span>
        </div>
      </div>
    </div>
  );
}

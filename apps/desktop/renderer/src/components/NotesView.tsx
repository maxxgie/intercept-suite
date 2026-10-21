import { useEffect, useState } from "react";
import { useStore } from "../state/store";

const COLORS = ["red", "orange", "yellow", "green", "blue", "purple", "grey"];

export default function NotesView() {
  const notes = useStore((s) => s.notes);
  const refresh = useStore((s) => s.refreshNotes);
  const create = useStore((s) => s.createNote);
  const remove = useStore((s) => s.deleteNote);
  const [text, setText] = useState("");
  const [color, setColor] = useState("");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function add() {
    if (!text.trim()) return;
    await create(text.trim(), "", color);
    setText("");
    setColor("");
  }

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <span className="muted">{notes.length} notes</span>
        </div>
        <div className="notes-list">
          {notes.map((note) => (
            <div className={`note-card${note.color ? ` note-${note.color}` : ""}`} key={note.id}>
              <div className="note-text">{note.text}</div>
              <div className="note-meta muted small">
                <span>{note.subject}</span>
                {note.subject_id && <span className="mono">{note.subject_id}</span>}
                <span>{new Date(note.updated_at * 1000).toLocaleString()}</span>
                <button className="link" onClick={() => void remove(note.id)}>
                  remove
                </button>
              </div>
            </div>
          ))}
          {notes.length === 0 && (
            <div className="placeholder">
              No notes yet. Write one about anything you have seen.
            </div>
          )}
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span>New note</span>
        </div>
        <div className="form">
          <textarea
            className="editor"
            rows={8}
            placeholder="What did you see?"
            value={text}
            onChange={(event) => setText(event.target.value)}
          />
          <div className="row">
            {COLORS.map((name) => (
              <button
                key={name}
                className={`swatch swatch-${name}${color === name ? " active" : ""}`}
                title={name}
                onClick={() => setColor(color === name ? "" : name)}
              />
            ))}
            <span className="grow" />
            <button className="button primary" onClick={() => void add()}>
              Add note
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

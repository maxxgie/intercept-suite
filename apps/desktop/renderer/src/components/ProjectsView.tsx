import { useEffect, useState } from "react";
import { useStore } from "../state/store";

export default function ProjectsView() {
  const projects = useStore((s) => s.projects);
  const current = useStore((s) => s.currentProject);
  const refresh = useStore((s) => s.refreshProjects);
  const create = useStore((s) => s.createProject);
  const save = useStore((s) => s.saveProject);
  const open = useStore((s) => s.openProject);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <span className="muted">{projects.length} projects</span>
        </div>
        <div className="notes-list">
          {projects.map((project) => (
            <div className={`note-card${project.current ? " active" : ""}`} key={project.id}>
              <div className="note-text">{project.name}</div>
              <div className="note-meta muted small">
                <span className="mono">{project.path}</span>
                <span>{new Date(project.updated_at * 1000).toLocaleString()}</span>
              </div>
              {project.description && <div className="muted small">{project.description}</div>}
              <div className="row">
                <button className="button" onClick={() => void save(project.id)}>
                  Save
                </button>
                <button className="button" onClick={() => void open(project.id)}>
                  Make current
                </button>
              </div>
            </div>
          ))}
          {projects.length === 0 && (
            <div className="placeholder">
              No projects yet. A project keeps the history, the notes, the issues and the
              scope together.
            </div>
          )}
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span>New project</span>
        </div>
        <div className="form">
          <input
            className="filter"
            placeholder="Name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <textarea
            className="editor"
            rows={4}
            placeholder="What is this engagement about?"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
          <div className="row">
            <span className="grow" />
            <button
              className="button primary"
              onClick={async () => {
                if (!name.trim()) return;
                await create(name.trim(), description.trim());
                setName("");
                setDescription("");
              }}
            >
              Create
            </button>
          </div>
        </div>

        {current && (
          <div className="card">
            <h2>Current project</h2>
            <dl>
              <dt>Name</dt>
              <dd>{current.name}</dd>
              <dt>Directory</dt>
              <dd className="mono">{current.path}</dd>
            </dl>
          </div>
        )}
      </section>
    </div>
  );
}

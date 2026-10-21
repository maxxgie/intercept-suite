import { useEffect, useRef, useState } from "react";
import { useStore } from "../state/store";
import {
  IconBroom,
  IconChevron,
  IconFolder,
  IconIntercept,
  IconPlay,
  IconSave,
  IconSearch,
  IconSettings,
  IconSpider,
} from "./icons";

/**
 * The top navigation: the project that is open, the filter that applies to
 * the whole workspace, and the actions that reach the whole engagement.
 */
export default function TopBar() {
  const filter = useStore((s) => s.filter);
  const filterError = useStore((s) => s.filterError);
  const setFilter = useStore((s) => s.setFilter);
  const setPalette = useStore((s) => s.setPalette);
  const interceptEnabled = useStore((s) => s.interceptEnabled);
  const setIntercept = useStore((s) => s.setIntercept);
  const total = useStore((s) => s.total);
  const busy = useStore((s) => s.busy);
  const startSpider = useStore((s) => s.startSpider);
  const clearTraffic = useStore((s) => s.clearTraffic);
  const runCommand = useStore((s) => s.runCommand);
  const setView = useStore((s) => s.setView);
  const connected = useStore((s) => s.connected);

  const projects = useStore((s) => s.projects);
  const currentProject = useStore((s) => s.currentProject);
  const refreshProjects = useStore((s) => s.refreshProjects);
  const saveProject = useStore((s) => s.saveProject);
  const openProject = useStore((s) => s.openProject);
  const createProject = useStore((s) => s.createProject);

  const [draft, setDraft] = useState(filter);
  const [menuOpen, setMenuOpen] = useState(false);
  const [newProject, setNewProject] = useState(false);
  const [projectName, setProjectName] = useState("");
  const menuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setDraft(filter);
  }, [filter]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (draft !== filter) void setFilter(draft);
    }, 350);
    return () => window.clearTimeout(timer);
  }, [draft, filter, setFilter]);

  useEffect(() => {
    if (!menuOpen) return;
    function onClick(event: MouseEvent) {
      if (!menuRef.current?.contains(event.target as Node)) setMenuOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [menuOpen]);

  async function create() {
    const name = projectName.trim();
    if (!name) return;
    await createProject(name, "");
    setProjectName("");
    setNewProject(false);
    await refreshProjects();
  }

  return (
    <header className="top-bar">
      <div className="brand">
        <span className="brand-mark" />
        <span className="brand-name">Intercept</span>
      </div>

      <div className="project-control" ref={menuRef}>
        <button
          className="button ghost"
          onClick={() => {
            setMenuOpen(!menuOpen);
            void refreshProjects();
          }}
          title="The project this work belongs to"
        >
          <IconFolder size={14} />
          <span className="project-name">{currentProject?.name ?? "No project"}</span>
          <IconChevron size={13} />
        </button>

        {menuOpen && (
          <div className="menu">
            {projects.length === 0 && (
              <div className="menu-empty muted small">No project yet</div>
            )}
            {projects.map((project) => (
              <button
                key={project.id}
                className="menu-item"
                onClick={() => {
                  void openProject(project.id);
                  setMenuOpen(false);
                }}
              >
                <span className="grow">{project.name}</span>
                {project.current && <span className="status ok">current</span>}
              </button>
            ))}
            <div className="menu-separator" />
            <button
              className="menu-item"
              onClick={() => {
                setNewProject(!newProject);
              }}
            >
              <span className="grow">New project…</span>
            </button>
            {newProject && (
              <div className="menu-form">
                <input
                  autoFocus
                  placeholder="Project name"
                  value={projectName}
                  onChange={(event) => setProjectName(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") void create();
                    if (event.key === "Escape") setNewProject(false);
                  }}
                />
                <button className="button primary" onClick={() => void create()}>
                  Create
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      <button
        className="button ghost"
        disabled={!currentProject}
        onClick={() => currentProject && void saveProject(currentProject.id)}
        title="Write the current state into the project directory"
      >
        <IconSave size={14} />
        Save
      </button>

      <div className="filter-field">
        <IconSearch size={14} />
        <input
          className="filter mono"
          spellCheck={false}
          placeholder='Filter: host == "example.com" and status >= 400'
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              setDraft("");
              void setFilter("");
            }
          }}
        />
        {filterError && <span className="filter-error small">{filterError}</span>}
      </div>

      <span className="muted small filter-count">{total} shown</span>

      <div className="spacer" />

      <button
        className={`intercept-toggle${interceptEnabled ? " active" : ""}`}
        title="Hold every request so it can be inspected before it is sent"
        onClick={() => void setIntercept(!interceptEnabled)}
      >
        <IconIntercept size={14} />
        {interceptEnabled ? "Intercepting" : "Intercept off"}
      </button>

      <button
        className="button ghost"
        disabled={busy}
        onClick={() => void startSpider()}
        title="Crawl the hosts that have been seen"
      >
        <IconSpider size={14} />
        Crawl
      </button>

      <button
        className="button ghost"
        disabled={busy}
        onClick={() => void runCommand("scanner.scan")}
        title="Scan the hosts that have been seen"
      >
        <IconPlay size={14} />
        Scan
      </button>

      <button
        className="button ghost"
        onClick={() => void clearTraffic()}
        title="Remove every exchange from the history"
      >
        <IconBroom size={14} />
        Clear
      </button>

      <button className="button ghost" onClick={() => setPalette(true)}>
        <IconSearch size={14} />
        Commands
        <span className="muted small">Ctrl K</span>
      </button>

      <button
        className="icon-button"
        title="Settings"
        onClick={() => setView("settings")}
        aria-label="Settings"
      >
        <IconSettings size={16} />
      </button>

      <span className={`status-dot ${connected ? "ok" : "bad"}`} title={connected ? "Daemon online" : "Daemon offline"} />
    </header>
  );
}

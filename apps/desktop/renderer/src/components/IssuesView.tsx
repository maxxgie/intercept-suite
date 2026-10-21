import { useEffect, useState } from "react";
import { useStore } from "../state/store";
import type { Issue } from "../types";

const STATUSES = ["open", "confirmed", "in-progress", "resolved", "ignored", "false-positive"];
const SEVERITIES = ["info", "low", "medium", "high", "critical"];

function severityClass(severity: string): string {
  if (severity === "critical" || severity === "high") return "status error";
  if (severity === "medium") return "status warn";
  return "status info";
}

export default function IssuesView() {
  const issues = useStore((s) => s.issues);
  const refresh = useStore((s) => s.refreshIssues);
  const create = useStore((s) => s.createIssue);
  const update = useStore((s) => s.updateIssue);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState("");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const rows = status ? issues.filter((issue) => issue.status === status) : issues;

  async function add() {
    if (!title.trim()) return;
    await create(title.trim(), severity, description.trim());
    setTitle("");
    setDescription("");
    setSeverity("medium");
  }

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <select
            className="filter"
            value={status}
            onChange={(event) => setStatus(event.target.value)}
          >
            <option value="">every status</option>
            {STATUSES.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <span className="muted">
            {rows.length}/{issues.length}
          </span>
        </div>
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-method">Severity</th>
                <th className="col-path">Title</th>
                <th className="col-status">Status</th>
                <th className="col-time">Opened</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((issue) => (
                <tr key={issue.id}>
                  <td className="col-method">
                    <span className={severityClass(issue.severity)}>{issue.severity}</span>
                  </td>
                  <td className="col-path" title={issue.description}>
                    {issue.title}
                  </td>
                  <td className="col-status">
                    <select
                      className="inline-select"
                      value={issue.status}
                      onChange={(event) => void update(issue.id, { status: event.target.value } as Partial<Issue>)}
                    >
                      {STATUSES.map((name) => (
                        <option key={name} value={name}>
                          {name}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="col-time">
                    {new Date(issue.created_at * 1000).toLocaleDateString()}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={4} className="empty">
                    No issues raised yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span>Raise an issue</span>
        </div>
        <div className="form">
          <input
            className="filter"
            placeholder="Title"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
          <select
            className="filter"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            {SEVERITIES.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <textarea
            className="editor"
            rows={8}
            placeholder="What is wrong, and how did you find it?"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
          <div className="row">
            <span className="grow" />
            <button className="button primary" onClick={() => void add()}>
              Raise issue
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}

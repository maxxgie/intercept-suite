import { useEffect, useState } from "react";
import { useStore } from "../state/store";

export default function TasksView() {
  const tasks = useStore((s) => s.tasks);
  const refresh = useStore((s) => s.refreshTasks);
  const create = useStore((s) => s.createTask);
  const run = useStore((s) => s.runTask);
  const remove = useStore((s) => s.deleteTask);
  const commands = useStore((s) => s.commands);
  const [name, setName] = useState("");
  const [command, setCommand] = useState("");
  const [interval, setInterval] = useState("60");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const runnable = commands.filter(
    (item) => !item.id.startsWith("view.") && !item.id.startsWith("issue.") && !item.id.startsWith("note."),
  );

  async function add() {
    if (!command) return;
    await create(name.trim() || command, command, Number(interval) || 60);
    setName("");
  }

  return (
    <div className="split">
      <section className="pane list-pane">
        <div className="pane-header">
          <span className="muted">{tasks.length} tasks</span>
        </div>
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-host">Name</th>
                <th className="col-path">Command</th>
                <th className="col-method">Every</th>
                <th className="col-status">Runs</th>
                <th className="col-time">Last error</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task) => (
                <tr key={task.id}>
                  <td className="col-host">{task.name}</td>
                  <td className="col-path mono">{task.command}</td>
                  <td className="col-method">{Math.round(task.interval)}s</td>
                  <td className="col-status">{task.run_count}</td>
                  <td className="col-time error-text">{task.last_error}</td>
                </tr>
              ))}
              {tasks.length === 0 && (
                <tr>
                  <td colSpan={5} className="empty">
                    No scheduled tasks.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="pane detail-pane">
        <div className="pane-header">
          <span>Schedule a task</span>
        </div>
        <div className="form">
          <input
            className="filter"
            placeholder="Name"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <select
            className="filter"
            value={command}
            onChange={(event) => setCommand(event.target.value)}
          >
            <option value="">pick a command</option>
            {runnable.map((item) => (
              <option key={item.id} value={item.id}>
                {item.title}
              </option>
            ))}
          </select>
          <input
            className="filter"
            placeholder="Interval in seconds"
            value={interval}
            onChange={(event) => setInterval(event.target.value)}
          />
          <div className="row">
            <span className="grow" />
            <button className="button primary" onClick={() => void add()}>
              Schedule
            </button>
          </div>
        </div>

        {tasks.length > 0 && (
          <div className="card">
            <h2>Manage</h2>
            {tasks.map((task) => (
              <div className="plugin-row" key={task.id}>
                <div>
                  <strong>{task.name}</strong>
                  <div className="muted small mono">{task.command}</div>
                </div>
                <div className="row">
                  <button className="button" onClick={() => void run(task.id)}>
                    Run now
                  </button>
                  <button className="link" onClick={() => void remove(task.id)}>
                    remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

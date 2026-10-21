import { useEffect, useState } from "react";
import { useStore } from "../state/store";
import { IconTrash } from "./icons";

/**
 * The rules that decide what the proxy and the spider are allowed to touch.
 * With no include rule the scope is closed, so a target has to be opened
 * deliberately.
 */
export default function ScopeView() {
  const rules = useStore((s) => s.scopeRules);
  const refresh = useStore((s) => s.refreshScope);
  const addRule = useStore((s) => s.addScopeRule);
  const removeRule = useStore((s) => s.removeScopeRule);
  const setError = useStore((s) => s.setError);

  const [pattern, setPattern] = useState("");
  const [kind, setKind] = useState("include");
  const [target, setTarget] = useState("host");

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function add() {
    const value = pattern.trim();
    if (!value) return;
    try {
      await addRule({ pattern: value, kind, target });
      setPattern("");
    } catch (error) {
      setError((error as Error).message);
    }
  }

  return (
    <div className="scope-view">
      <div className="pane-header">
        <span className="grow">Scope rules</span>
        <span className="muted">{rules.length} rules</span>
        <button className="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </div>

      <div className="form inline-form">
        <input
          className="filter mono grow"
          placeholder="example.com  ·  *.example.com  ·  re:^https://api\\."
          value={pattern}
          onChange={(event) => setPattern(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void add();
          }}
        />
        <select className="filter" value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value="include">include</option>
          <option value="exclude">exclude</option>
        </select>
        <select className="filter" value={target} onChange={(event) => setTarget(event.target.value)}>
          <option value="host">host</option>
          <option value="url">url</option>
        </select>
        <button className="button primary" onClick={() => void add()}>
          Add rule
        </button>
      </div>

      <div className="table-wrap">
        <table className="traffic-table">
          <thead>
            <tr>
              <th className="col-host">Pattern</th>
              <th className="col-method">Kind</th>
              <th className="col-status">Applies to</th>
              <th className="col-status">Enabled</th>
              <th className="col-time" />
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={`${rule.pattern}-${rule.kind}-${rule.target}`}>
                <td className="col-host mono">{rule.pattern}</td>
                <td className="col-method">
                  <span className={rule.kind === "include" ? "status ok" : "status warn"}>
                    {rule.kind}
                  </span>
                </td>
                <td className="col-status">{rule.target}</td>
                <td className="col-status">{rule.enabled ? "yes" : "no"}</td>
                <td className="col-time">
                  <button
                    className="icon-button danger"
                    title="Remove the rule"
                    onClick={() => void removeRule(rule.pattern)}
                  >
                    <IconTrash size={14} />
                  </button>
                </td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={5} className="empty">
                  The scope is closed. Add an include rule to let the spider visit a host.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

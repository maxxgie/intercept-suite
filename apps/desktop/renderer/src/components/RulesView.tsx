import { useEffect, useState } from "react";
import { useStore } from "../state/store";
import type { ProxyRule, RuleDraft, RuleKind, RulePhase, RulePlace, RuleTarget } from "../types";

const EMPTY_RULE: RuleDraft = {
  name: "",
  kind: "intercept",
  enabled: true,
  host: "",
  path: "",
  method: "",
  phase: "request",
  target: "request",
  place: "header",
  field: "",
  match: "",
  replace: "",
  regex: true,
};

const KIND_LABELS: Record<RuleKind, string> = {
  intercept: "Intercept",
  forward: "Auto forward",
  replace: "Match and replace",
};

const KIND_HELP: Record<RuleKind, string> = {
  intercept: "Hold the matching request or response so you can decide what happens to it.",
  forward: "Let the matching request through without asking, even while interception is on.",
  replace: "Rewrite a part of the matching request or response.",
};

/**
 * The proxy rules.
 *
 * A rule narrows down what interception applies to, lets traffic through
 * without asking, or rewrites it on the way past.
 */
export default function RulesView() {
  const rules = useStore((s) => s.rules);
  const refresh = useStore((s) => s.refreshRules);
  const createRule = useStore((s) => s.createRule);
  const updateRule = useStore((s) => s.updateRule);
  const deleteRule = useStore((s) => s.deleteRule);

  const [draft, setDraft] = useState<RuleDraft>(EMPTY_RULE);
  const [editing, setEditing] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  function reset() {
    setDraft(EMPTY_RULE);
    setEditing(null);
  }

  async function save() {
    if (editing) {
      await updateRule(editing, draft);
    } else {
      await createRule(draft);
    }
    reset();
    setShowForm(false);
  }

  async function edit(rule: ProxyRule) {
    setEditing(rule.id);
    setDraft({
      name: rule.name,
      kind: rule.kind,
      enabled: rule.enabled,
      host: rule.host,
      path: rule.path,
      method: rule.method,
      phase: rule.phase,
      target: rule.target,
      place: rule.place,
      field: rule.field,
      match: rule.match,
      replace: rule.replace,
      regex: rule.regex,
    });
    setShowForm(true);
  }

  async function toggle(rule: ProxyRule) {
    await updateRule(rule.id, {
      name: rule.name,
      kind: rule.kind,
      enabled: !rule.enabled,
      host: rule.host,
      path: rule.path,
      method: rule.method,
      phase: rule.phase,
      target: rule.target,
      place: rule.place,
      field: rule.field,
      match: rule.match,
      replace: rule.replace,
      regex: rule.regex,
    });
  }

  return (
    <div className="scope-view">
      <div className="pane-header">
        <button
          className={showForm ? "button primary" : "button"}
          onClick={() => {
            if (showForm) {
              reset();
              setShowForm(false);
              return;
            }
            setShowForm(true);
          }}
        >
          {showForm ? "Close" : "New rule"}
        </button>
        <span className="muted">
          {rules.length === 0
            ? "No rules yet. Without a rule the switch holds every request."
            : `${rules.filter((rule) => rule.enabled).length} of ${rules.length} rules are on.`}
        </span>
      </div>

      {showForm && (
        <div className="form">
          <div className="field">
            <label htmlFor="rule-kind">Kind</label>
            <select
              id="rule-kind"
              className="filter"
              value={draft.kind}
              onChange={(event) => setDraft({ ...draft, kind: event.target.value as RuleKind })}
            >
              {(Object.keys(KIND_LABELS) as RuleKind[]).map((kind) => (
                <option key={kind} value={kind}>
                  {KIND_LABELS[kind]}
                </option>
              ))}
            </select>
            <span className="muted small">{KIND_HELP[draft.kind]}</span>
          </div>

          <div className="field">
            <label htmlFor="rule-name">Name</label>
            <input
              id="rule-name"
              className="filter"
              value={draft.name}
              placeholder="What this rule is for"
              onChange={(event) => setDraft({ ...draft, name: event.target.value })}
            />
          </div>

          <div className="row wrap">
            <div className="field grow">
              <label htmlFor="rule-host">Host</label>
              <input
                id="rule-host"
                className="filter"
                value={draft.host}
                placeholder="*.example.com"
                onChange={(event) => setDraft({ ...draft, host: event.target.value })}
              />
            </div>
            <div className="field grow">
              <label htmlFor="rule-path">Path</label>
              <input
                id="rule-path"
                className="filter"
                value={draft.path}
                placeholder="/api/*"
                onChange={(event) => setDraft({ ...draft, path: event.target.value })}
              />
            </div>
            <div className="field grow">
              <label htmlFor="rule-method">Method</label>
              <input
                id="rule-method"
                className="filter"
                value={draft.method}
                placeholder="POST"
                onChange={(event) => setDraft({ ...draft, method: event.target.value })}
              />
            </div>
          </div>

          {draft.kind === "intercept" && (
            <div className="field">
              <label htmlFor="rule-phase">Hold</label>
              <select
                id="rule-phase"
                className="filter"
                value={draft.phase}
                onChange={(event) => setDraft({ ...draft, phase: event.target.value as RulePhase })}
              >
                <option value="request">the request</option>
                <option value="response">the response</option>
                <option value="both">both</option>
              </select>
            </div>
          )}

          {draft.kind === "replace" && (
            <>
              <div className="row wrap">
                <div className="field grow">
                  <label htmlFor="rule-target">Message</label>
                  <select
                    id="rule-target"
                    className="filter"
                    value={draft.target}
                    onChange={(event) => setDraft({ ...draft, target: event.target.value as RuleTarget })}
                  >
                    <option value="request">the request</option>
                    <option value="response">the response</option>
                  </select>
                </div>
                <div className="field grow">
                  <label htmlFor="rule-place">Part</label>
                  <select
                    id="rule-place"
                    className="filter"
                    value={draft.place}
                    onChange={(event) => setDraft({ ...draft, place: event.target.value as RulePlace })}
                  >
                    <option value="header">a header</option>
                    <option value="header-add">add a header</option>
                    <option value="body">the body</option>
                    <option value="url">the URL</option>
                  </select>
                </div>
                <div className="field grow">
                  <label htmlFor="rule-field">Header</label>
                  <input
                    id="rule-field"
                    className="filter"
                    value={draft.field}
                    placeholder="X-Forwarded-For"
                    onChange={(event) => setDraft({ ...draft, field: event.target.value })}
                  />
                </div>
              </div>
              <div className="row wrap">
                <div className="field grow">
                  <label htmlFor="rule-match">Look for</label>
                  <input
                    id="rule-match"
                    className="filter"
                    value={draft.match}
                    placeholder="value"
                    onChange={(event) => setDraft({ ...draft, match: event.target.value })}
                  />
                </div>
                <div className="field grow">
                  <label htmlFor="rule-replace">Put in its place</label>
                  <input
                    id="rule-replace"
                    className="filter"
                    value={draft.replace}
                    placeholder="replacement"
                    onChange={(event) => setDraft({ ...draft, replace: event.target.value })}
                  />
                </div>
              </div>
              <label className="checkline small">
                <input
                  type="checkbox"
                  checked={draft.regex}
                  onChange={(event) => setDraft({ ...draft, regex: event.target.checked })}
                />
                Treat the pattern as a regular expression
              </label>
            </>
          )}

          <div className="row">
            <button className="button primary" onClick={() => void save()}>
              {editing ? "Save the rule" : "Add the rule"}
            </button>
            <button className="button" onClick={() => { reset(); setShowForm(false); }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="table-wrap grow">
        <table className="traffic-table">
          <thead>
            <tr>
              <th className="col-method">Kind</th>
              <th className="col-host">Name</th>
              <th className="col-path">Matches</th>
              <th className="col-host">Action</th>
              <th className="col-status">On</th>
              <th className="col-size">Edit</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id}>
                <td className="col-method">{KIND_LABELS[rule.kind]}</td>
                <td className="col-host">{rule.name || "—"}</td>
                <td className="col-path mono">
                  {[rule.host || "*", rule.method || "*", rule.path || "*"].join("  ")}
                </td>
                <td className="col-host mono">
                  {rule.kind === "replace"
                    ? `${rule.place} ${rule.field || ""} ${rule.match} → ${rule.replace}`.trim()
                    : rule.kind === "forward"
                      ? "let through"
                      : `hold the ${rule.phase}`}
                </td>
                <td className="col-status">
                  <button className="button ghost" onClick={() => void toggle(rule)}>
                    {rule.enabled ? "on" : "off"}
                  </button>
                </td>
                <td className="col-size">
                  <div className="row tight">
                    <button className="button" onClick={() => void edit(rule)}>
                      Edit
                    </button>
                    <button className="button danger" onClick={() => void deleteRule(rule.id)}>
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {rules.length === 0 && (
              <tr>
                <td colSpan={6} className="empty">
                  No rules yet. A rule decides what the intercept switch holds, what it lets
                  through, and what it rewrites.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

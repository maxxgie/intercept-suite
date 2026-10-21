import { useEffect, useMemo, useState } from "react";
import { useStore } from "../state/store";
import type {
  AttackType,
  Generator,
  GeneratorKind,
  ProcessingRule,
  ProcessingRuleKind,
} from "../types";

const SAMPLE = `GET https://example.com/search?q=§term§ HTTP/1.1
Host: example.com
User-Agent: Intercept/0.1
`;

const ATTACK_LABELS: Record<AttackType, string> = {
  sniper: "Sniper",
  "battering-ram": "Battering ram",
  pitchfork: "Pitchfork",
  "cluster-bomb": "Cluster bomb",
};

const ATTACK_HELP: Record<AttackType, string> = {
  sniper: "One payload in one position at a time. The other positions are left empty.",
  "battering-ram": "The same payload in every position at once.",
  pitchfork: "One payload of each list at the same time, the lists walking together.",
  "cluster-bomb": "Every combination of the payload lists.",
};

const GENERATOR_LABELS: Record<GeneratorKind, string> = {
  list: "Simple list",
  numbers: "Numbers",
  dates: "Dates",
  bruteforce: "Brute force",
  substitution: "Character substitution",
  grep: "Recursive grep",
  file: "Runtime file",
  custom: "Custom generator",
};

const RULE_LABELS: Record<ProcessingRuleKind, string> = {
  "url-encode": "URL encode",
  base64: "Base64",
  hash: "Hashing",
  prefix: "Prefix",
  suffix: "Suffix",
  replace: "Replace",
  extract: "Regex extraction",
};

/** The options a generator starts with, the same ones the daemon assumes. */
const GENERATOR_DEFAULTS: Record<GeneratorKind, Record<string, unknown>> = {
  list: {},
  numbers: { start: 1, end: 100, step: 1 },
  dates: { start: "2024-01-01", count: 10, step: 1, unit: "days" },
  bruteforce: { charset: "abcdefghijklmnopqrstuvwxyz0123456789", length: 3 },
  substitution: { base: "", substitutions: [] },
  grep: { path: ".", pattern: "" },
  file: { path: "" },
  custom: {
    template: "§a§§a§",
    charset: "abcdefghijklmnopqrstuvwxyz0123456789",
    count: 100,
  },
};

/** The fields a generator needs, and how they are read. */
function GeneratorOptions({
  kind,
  options,
  onChange,
}: {
  kind: GeneratorKind;
  options: Record<string, unknown>;
  onChange: (options: Record<string, unknown>) => void;
}) {
  const text = (key: string, fallback = "") => String(options[key] ?? fallback);
  const number = (key: string, fallback: number) => Number(options[key] ?? fallback);

  if (kind === "numbers") {
    const start = number("start", Number(GENERATOR_DEFAULTS.numbers.start));
    const end = number("end", Number(GENERATOR_DEFAULTS.numbers.end));
    const step = number("step", Number(GENERATOR_DEFAULTS.numbers.step));
    return (
      <div className="row wrap">
        <div className="field grow">
          <label>From</label>
          <input
            className="filter"
            value={start}
            onChange={(event) => onChange({ ...options, start: Number(event.target.value) })}
          />
        </div>
        <div className="field grow">
          <label>To</label>
          <input
            className="filter"
            value={end}
            onChange={(event) => onChange({ ...options, end: Number(event.target.value) })}
          />
        </div>
        <div className="field grow">
          <label>Step</label>
          <input
            className="filter"
            value={step}
            onChange={(event) => onChange({ ...options, step: Number(event.target.value) })}
          />
        </div>
      </div>
    );
  }

  if (kind === "dates") {
    const start = text("start", String(GENERATOR_DEFAULTS.dates.start));
    const count = number("count", Number(GENERATOR_DEFAULTS.dates.count));
    const step = number("step", Number(GENERATOR_DEFAULTS.dates.step));
    const unit = text("unit", String(GENERATOR_DEFAULTS.dates.unit));
    return (
      <div className="row wrap">
        <div className="field grow">
          <label>Start</label>
          <input
            className="filter"
            value={start}
            onChange={(event) => onChange({ ...options, start: event.target.value })}
          />
        </div>
        <div className="field grow">
          <label>How many</label>
          <input
            className="filter"
            value={count}
            onChange={(event) => onChange({ ...options, count: Number(event.target.value) })}
          />
        </div>
        <div className="field grow">
          <label>Step</label>
          <input
            className="filter"
            value={step}
            onChange={(event) => onChange({ ...options, step: Number(event.target.value) })}
          />
        </div>
        <div className="field grow">
          <label>Unit</label>
          <select
            className="filter"
            value={unit}
            onChange={(event) => onChange({ ...options, unit: event.target.value })}
          >
            <option value="days">days</option>
            <option value="months">months</option>
            <option value="seconds">seconds</option>
          </select>
        </div>
      </div>
    );
  }

  if (kind === "bruteforce") {
    const charset = text(
      "charset",
      String(GENERATOR_DEFAULTS.bruteforce.charset),
    );
    const length = number("length", Number(GENERATOR_DEFAULTS.bruteforce.length));
    return (
      <div className="row wrap">
        <div className="field grow">
          <label>Characters</label>
          <input
            className="filter"
            value={charset}
            onChange={(event) => onChange({ ...options, charset: event.target.value })}
          />
        </div>
        <div className="field grow">
          <label>Length</label>
          <input
            className="filter"
            value={length}
            onChange={(event) => onChange({ ...options, length: Number(event.target.value) })}
          />
        </div>
      </div>
    );
  }

  if (kind === "substitution") {
    const base = text("base", String(GENERATOR_DEFAULTS.substitution.base));
    const pairs = (options.substitutions as string[] | undefined) ?? [];
    return (
      <div className="row wrap">
        <div className="field grow">
          <label>Base text</label>
          <input
            className="filter"
            value={base}
            onChange={(event) => onChange({ ...options, base: event.target.value })}
          />
        </div>
        <div className="field grow">
          <label>Replacements</label>
          <input
            className="filter"
            placeholder="a=b, c=d"
            value={pairs.join(", ")}
            onChange={(event) =>
              onChange({
                ...options,
                substitutions: event.target.value
                  .split(",")
                  .map((pair) => pair.trim())
                  .filter(Boolean),
              })
            }
          />
        </div>
      </div>
    );
  }

  if (kind === "grep") {
    const path = text("path", String(GENERATOR_DEFAULTS.grep.path));
    const pattern = text("pattern", String(GENERATOR_DEFAULTS.grep.pattern));
    return (
      <div className="row wrap">
        <div className="field grow">
          <label>Folder</label>
          <input
            className="filter"
            value={path}
            onChange={(event) => onChange({ ...options, path: event.target.value })}
          />
        </div>
        <div className="field grow">
          <label>Pattern</label>
          <input
            className="filter"
            value={pattern}
            onChange={(event) => onChange({ ...options, pattern: event.target.value })}
          />
        </div>
      </div>
    );
  }

  if (kind === "file") {
    const path = text("path", String(GENERATOR_DEFAULTS.file.path));
    return (
      <div className="row wrap">
        <div className="field grow">
          <label>File</label>
          <input
            className="filter"
            placeholder="/usr/share/wordlists/common.txt"
            value={path}
            onChange={(event) => onChange({ ...options, path: event.target.value })}
          />
        </div>
      </div>
    );
  }

  if (kind === "custom") {
    const template = text("template", String(GENERATOR_DEFAULTS.custom.template));
    const charset = text("charset", String(GENERATOR_DEFAULTS.custom.charset));
    const count = number("count", Number(GENERATOR_DEFAULTS.custom.count));
    return (
      <div className="row wrap">
        <div className="field grow">
          <label>Template</label>
          <input
            className="filter"
            value={template}
            onChange={(event) => onChange({ ...options, template: event.target.value })}
          />
        </div>
        <div className="field grow">
          <label>Characters</label>
          <input
            className="filter"
            value={charset}
            onChange={(event) => onChange({ ...options, charset: event.target.value })}
          />
        </div>
        <div className="field grow">
          <label>How many</label>
          <input
            className="filter"
            value={count}
            onChange={(event) => onChange({ ...options, count: Number(event.target.value) })}
          />
        </div>
      </div>
    );
  }

  return null;
}

/** The fields a processing rule needs. */
function RuleOptions({
  rule,
  onChange,
}: {
  rule: ProcessingRule;
  onChange: (rule: ProcessingRule) => void;
}) {
  const options = rule.options;
  const text = (key: string, fallback = "") => String(options[key] ?? fallback);

  if (rule.kind === "url-encode") {
    return (
      <label className="checkline small">
        <input
          type="checkbox"
          checked={Boolean(options.form)}
          onChange={(event) => onChange({ ...rule, options: { ...options, form: event.target.checked } })}
        />
        as a form value
      </label>
    );
  }

  if (rule.kind === "hash") {
    return (
      <select
        className="filter"
        value={text("algorithm", "md5")}
        onChange={(event) => onChange({ ...rule, options: { ...options, algorithm: event.target.value } })}
      >
        <option value="md5">md5</option>
        <option value="sha1">sha1</option>
        <option value="sha256">sha256</option>
        <option value="sha512">sha512</option>
      </select>
    );
  }

  if (rule.kind === "prefix" || rule.kind === "suffix") {
    return (
      <input
        className="filter"
        placeholder="the text"
        value={text("text")}
        onChange={(event) => onChange({ ...rule, options: { ...options, text: event.target.value } })}
      />
    );
  }

  if (rule.kind === "replace") {
    return (
      <div className="row tight">
        <input
          className="filter"
          placeholder="the pattern"
          value={text("pattern")}
          onChange={(event) => onChange({ ...rule, options: { ...options, pattern: event.target.value } })}
        />
        <input
          className="filter"
          placeholder="the replacement"
          value={text("replacement")}
          onChange={(event) =>
            onChange({ ...rule, options: { ...options, replacement: event.target.value } })
          }
        />
      </div>
    );
  }

  if (rule.kind === "extract") {
    return (
      <div className="row tight">
        <input
          className="filter"
          placeholder="the pattern"
          value={text("pattern")}
          onChange={(event) => onChange({ ...rule, options: { ...options, pattern: event.target.value } })}
        />
        <input
          className="filter"
          style={{ width: 70 }}
          value={String(options.group ?? 0)}
          onChange={(event) => onChange({ ...rule, options: { ...options, group: Number(event.target.value) } })}
        />
      </div>
    );
  }

  return null;
}

export default function FuzzerView() {
  const fuzzJobs = useStore((s) => s.fuzzJobs);
  const activeFuzzJobId = useStore((s) => s.activeFuzzJobId);
  const busy = useStore((s) => s.busy);
  const refreshFuzzJobs = useStore((s) => s.refreshFuzzJobs);
  const startFuzzJob = useStore((s) => s.startFuzzJob);
  const stopFuzzJob = useStore((s) => s.stopFuzzJob);
  const generatePayloads = useStore((s) => s.generatePayloads);

  const [raw, setRaw] = useState(SAMPLE);
  const [attackType, setAttackType] = useState<AttackType>("sniper");
  const [sets, setSets] = useState<string[][]>([["1\n2\nadmin\n' OR 1=1--"]]);
  const [activeSet, setActiveSet] = useState(0);
  const [generatorKind, setGeneratorKind] = useState<GeneratorKind>("list");
  const [generatorOptions, setGeneratorOptions] = useState<Record<string, unknown>>({});
  const [generatorCount, setGeneratorCount] = useState(0);
  const [rules, setRules] = useState<ProcessingRule[]>([]);
  const [grepMatch, setGrepMatch] = useState("");
  const [grepExtract, setGrepExtract] = useState("");
  const [positionFilter, setPositionFilter] = useState("");
  const [onlyInteresting, setOnlyInteresting] = useState(false);

  const active = fuzzJobs.find((job) => job.id === activeFuzzJobId) ?? null;

  useEffect(() => {
    void refreshFuzzJobs();
  }, [refreshFuzzJobs]);

  /** The positions the template marks, so the sets can follow them. */
  const positionNames = useMemo(() => {
    const found: string[] = [];
    const pattern = /§([^§]*)§/g;
    let match: RegExpExecArray | null = pattern.exec(raw);
    while (match !== null) {
      const name = match[1].trim() || `pos${found.length + 1}`;
      if (!found.includes(name)) found.push(name);
      match = pattern.exec(raw);
    }
    return found;
  }, [raw]);

  useEffect(() => {
    setSets((current) => {
      if (current.length === positionNames.length) return current;
      if (current.length < positionNames.length) {
        const extra = positionNames.slice(current.length).map(() => [] as string[]);
        return [...current, ...extra];
      }
      return current.slice(0, positionNames.length);
    });
    setActiveSet((current) => Math.min(current, Math.max(0, positionNames.length - 1)));
  }, [positionNames]);

  const results = useMemo(() => {
    if (!active) return [];
    return onlyInteresting ? active.results.filter((r) => r.interesting) : active.results;
  }, [active, onlyInteresting]);

  const positions = active?.template.positions ?? [];

  const setActiveSetText = (text: string) => {
    setSets((current) =>
      current.map((group, index) => (index === activeSet ? text.split("\n") : group)),
    );
  };

  async function runGenerator() {
    if (generatorKind === "list") return;
    const generator: Generator = {
      kind: generatorKind,
      options: { ...GENERATOR_DEFAULTS[generatorKind], ...generatorOptions },
    };
    const { payloads, count } = await generatePayloads(generator, rules);
    setSets((current) =>
      current.map((group, index) => (index === activeSet ? payloads : group)),
    );
    setGeneratorCount(count);
  }

  const start = () => {
    // The daemon reads the template itself, so the body and the headers of a
    // hand written request are kept as they are.
    void startFuzzJob({
      raw,
      payloads: sets[0] ?? [],
      attack_type: attackType,
      payload_sets: sets.map((group) => group.filter((item) => item.trim() !== "")),
      rules,
      grep_match: grepMatch,
      grep_extract: grepExtract,
      positions: positionFilter,
    });
  };

  return (
    <div className="fuzzer">
      <div className="fuzzer-input">
        <div className="pane-header">
          <span className="muted mono grow">Request template</span>
          <span className="muted small">
            mark a position with §name§ — it can live in the URL, a header or the body
          </span>
          <button className="button primary" disabled={busy} onClick={start}>
            {busy ? "Starting…" : "Start fuzzing"}
          </button>
        </div>
        <textarea
          className="editor mono"
          spellCheck={false}
          value={raw}
          onChange={(event) => setRaw(event.target.value)}
        />

        <div className="fuzzer-payloads">
          <div className="pane-header">
            <span className="muted mono grow">Payloads</span>
            <select
              className="filter"
              value={attackType}
              onChange={(event) => setAttackType(event.target.value as AttackType)}
            >
              {(Object.keys(ATTACK_LABELS) as AttackType[]).map((kind) => (
                <option key={kind} value={kind}>
                  {ATTACK_LABELS[kind]}
                </option>
              ))}
            </select>
            <input
              className="filter"
              style={{ width: 160 }}
              placeholder="positions, e.g. term,id"
              value={positionFilter}
              onChange={(event) => setPositionFilter(event.target.value)}
            />
          </div>
          <div className="muted small">{ATTACK_HELP[attackType]}</div>

          <div className="pane-header">
            {sets.map((group, index) => (
              <button
                key={index}
                className={index === activeSet ? "tab active" : "tab"}
                onClick={() => setActiveSet(index)}
                title={positionNames[index] ?? `Set ${index + 1}`}
              >
                {positionNames[index] ?? `Set ${index + 1}`} ({group.length})
              </button>
            ))}
            <span className="muted small grow">one list per marked position</span>
          </div>

          <div className="pane-header">
            <span className="muted small grow">Generator</span>
            <select
              className="filter"
              value={generatorKind}
              onChange={(event) => setGeneratorKind(event.target.value as GeneratorKind)}
            >
              {(Object.keys(GENERATOR_LABELS) as GeneratorKind[]).map((kind) => (
                <option key={kind} value={kind}>
                  {GENERATOR_LABELS[kind]}
                </option>
              ))}
            </select>
            {generatorKind !== "list" && (
              <button className="button" onClick={() => void runGenerator()}>
                Fill the set
              </button>
            )}
          </div>
          <GeneratorOptions
            kind={generatorKind}
            options={generatorOptions}
            onChange={setGeneratorOptions}
          />

          <textarea
            className="editor mono"
            spellCheck={false}
            value={(sets[activeSet] ?? []).join("\n")}
            onChange={(event) => setActiveSetText(event.target.value)}
          />
          {generatorCount > (sets[activeSet] ?? []).length && (
            <div className="muted small">
              the generator made {generatorCount} payloads, the first{" "}
              {(sets[activeSet] ?? []).length} are in the list
            </div>
          )}

          <div className="pane-header">
            <span className="muted small grow">Processing rules</span>
            <button
              className="button"
              onClick={() => setRules([...rules, { kind: "url-encode", options: {} }])}
            >
              Add a rule
            </button>
          </div>
          {rules.map((rule, index) => (
            <div className="row wrap" key={index}>
              <select
                className="filter"
                value={rule.kind}
                onChange={(event) =>
                  setRules(
                    rules.map((item, position) =>
                      position === index
                        ? { kind: event.target.value as ProcessingRuleKind, options: {} }
                        : item,
                    ),
                  )
                }
              >
                {(Object.keys(RULE_LABELS) as ProcessingRuleKind[]).map((kind) => (
                  <option key={kind} value={kind}>
                    {RULE_LABELS[kind]}
                  </option>
                ))}
              </select>
              <RuleOptions
                rule={rule}
                onChange={(updated) =>
                  setRules(rules.map((item, position) => (position === index ? updated : item)))
                }
              />
              <button
                className="button danger"
                onClick={() => setRules(rules.filter((_, position) => position !== index))}
              >
                Remove
              </button>
            </div>
          ))}

          <div className="row wrap">
            <div className="field grow">
              <label htmlFor="grep-match">Grep match</label>
              <input
                id="grep-match"
                className="filter"
                placeholder="a string that has to be in the answer"
                value={grepMatch}
                onChange={(event) => setGrepMatch(event.target.value)}
              />
            </div>
            <div className="field grow">
              <label htmlFor="grep-extract">Grep extract</label>
              <input
                id="grep-extract"
                className="filter"
                placeholder="a pattern to take out of the answer"
                value={grepExtract}
                onChange={(event) => setGrepExtract(event.target.value)}
              />
            </div>
          </div>
        </div>
      </div>

      <div className="fuzzer-results">
        <div className="pane-header">
          <span className="mono grow">Results</span>
          {active && (
            <span className="muted">
              {active.completed}/{active.total} · {active.status}
            </span>
          )}
          {active?.status === "running" && (
            <button className="button" onClick={() => void stopFuzzJob(active.id)}>
              Stop
            </button>
          )}
          <label className="checkline">
            <input
              type="checkbox"
              checked={onlyInteresting}
              onChange={(event) => setOnlyInteresting(event.target.checked)}
            />
            interesting only
          </label>
        </div>
        {positions.length > 0 && (
          <div className="fuzzer-positions">
            {positions.map((position) => (
              <span key={position.name} className="pill">
                {position.name}
              </span>
            ))}
          </div>
        )}
        <div className="table-wrap">
          <table className="traffic-table">
            <thead>
              <tr>
                <th className="col-method">Position</th>
                <th className="col-path">Payload</th>
                <th className="col-status">Status</th>
                <th className="col-size">Length</th>
                <th className="col-time">Time</th>
                <th className="col-host">Grep</th>
                <th className="col-host">Markers</th>
              </tr>
            </thead>
            <tbody>
              {results.map((result) => (
                <tr key={result.id} className={result.interesting ? "selected" : undefined}>
                  <td className="col-method mono">{result.position}</td>
                  <td className="col-path mono" title={result.url}>
                    {result.payload}
                  </td>
                  <td className="col-status">
                    <span className={result.status >= 400 ? "status warn" : "status ok"}>
                      {result.status || "ERR"}
                    </span>
                  </td>
                  <td className="col-size">
                    {result.length}
                    {result.length_delta !== 0 && (
                      <span className="muted"> ({result.length_delta > 0 ? "+" : ""}{result.length_delta})</span>
                    )}
                  </td>
                  <td className="col-time">{result.elapsed_ms.toFixed(0)} ms</td>
                  <td className="col-host mono small">
                    {result.hit && <span className="status ok">hit</span>}
                    {result.extracted && (
                      <span className="muted"> {result.extracted}</span>
                    )}
                  </td>
                  <td className="col-host mono small">{result.markers.join(", ")}</td>
                </tr>
              ))}
              {results.length === 0 && (
                <tr>
                  <td colSpan={7} className="empty">
                    {fuzzJobs.length === 0
                      ? "No fuzzing job yet. Mark a position and press Start fuzzing."
                      : "No results match the current filter."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

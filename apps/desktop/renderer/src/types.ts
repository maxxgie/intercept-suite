export interface HeadersMap {
  [name: string]: string[];
}

export interface MessageSummary {
  id: string;
  method: string;
  url: string;
  host: string;
  port: number;
  path: string;
  query: string;
  http_version: string;
  origin: string;
  created_at: number;
  body_length: number;
  mime_type: string;
}

export interface MessageDetail extends MessageSummary {
  headers: HeadersMap;
  body: string;
  body_encoding: string;
  tls: boolean;
  client: string;
  tags: string[];
  notes: string[];
  raw: string;
}

export interface ResponseSummary {
  id: string;
  status: number;
  reason: string;
  http_version: string;
  mime_type: string;
  body_length: number;
  elapsed_ms: number;
  error: string;
}

export interface ResponseDetail extends ResponseSummary {
  headers: HeadersMap;
  body: string;
  body_encoding: string;
  tls: boolean;
  raw: string;
  tags: string[];
  notes: string[];
}

export interface ExchangeSummary {
  id: string;
  created_at: number;
  elapsed_ms: number;
  origin: string;
  method: string;
  url: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  query: string;
  status: number;
  reason: string;
  mime_type: string;
  request_length: number;
  response_length: number;
  error: string;
  tags: string[];
  highlighted: boolean;
}

export interface ExchangeDetail {
  id: string;
  created_at: number;
  elapsed_ms: number;
  request: MessageDetail;
  response: ResponseDetail | null;
  tags: string[];
  notes: string[];
  highlighted: boolean;
}

export interface RepeaterAttempt {
  id: string;
  created_at: number;
  elapsed_ms: number;
  request: MessageDetail;
  response: ResponseDetail | null;
}

export interface RepeaterTiming {
  count: number;
  last: number;
  fastest: number;
  slowest: number;
  average: number;
}

export interface RepeaterTab {
  id: string;
  name: string;
  color: string;
  target: string;
  created_at: number;
  request: MessageDetail;
  response: ResponseDetail | null;
  attempt_count: number;
  attempts: RepeaterAttempt[];
  timing: RepeaterTiming;
}

export interface WebSocketFrame {
  direction: string;
  opcode: number;
  type: string;
  text: string;
  size: number;
  timestamp: number;
  base64: string;
}

export interface WebSocketSession {
  open: boolean;
  closed: boolean;
  error: string;
  status: number;
  reason: string;
  headers: HeadersMap;
  sent: WebSocketFrame[];
  received: WebSocketFrame[];
}

export interface SiteNode {
  name: string;
  path: string;
  methods: string[];
  hits: number;
  status: number;
  last_seen: number;
  children: SiteNode[];
}

export interface SiteHost {
  host: string;
  scheme: string;
  hits: number;
  last_seen: number;
  nodes: SiteNode[];
}

export interface ToolField {
  name: string;
  label: string;
  type: "text" | "textarea" | "number" | "select" | "boolean";
  default: unknown;
  options: string[];
  placeholder: string;
  help: string;
}

export interface ToolDescriptor {
  id: string;
  label: string;
  description: string;
  icon: string;
  fields: ToolField[];
}

export interface PluginInfo {
  name: string;
  label: string;
  version: string;
  description: string;
  path: string;
  builtin: boolean;
  enabled: boolean;
  error: string;
  tools: string[];
}

export interface InterceptState {
  enabled: boolean;
  pending: string[];
  pending_count: number;
  updated_at: number;
  items: HeldItem[];
  frames: HeldFrame[];
}

export interface HeldItem {
  id: string;
  phase: "request" | "response";
  method: string;
  url: string;
  host: string;
  path: string;
  body_length: number;
  mime_type: string;
  created_at: number;
  status?: number;
  response_length?: number;
  response_mime_type?: string;
}

export interface HeldFrame {
  id: string;
  direction: "client" | "server";
  type: string;
  text: string;
  size: number;
}

export interface HeldMessage {
  id: string;
  phase: "request" | "response";
  created_at: number;
  request: MessageDetail;
  response: ResponseDetail | null;
}

/* -------------------------------------------------------------------- rules */

export type RuleKind = "intercept" | "forward" | "replace";
export type RulePhase = "request" | "response" | "both";
export type RuleTarget = "request" | "response";
export type RulePlace = "header" | "header-add" | "body" | "url";

export interface ProxyRule {
  id: string;
  name: string;
  kind: RuleKind;
  enabled: boolean;
  host: string;
  path: string;
  method: string;
  phase: RulePhase;
  target: RuleTarget;
  place: RulePlace;
  field: string;
  match: string;
  replace: string;
  regex: boolean;
  created_at: number;
  updated_at: number;
}

export type RuleDraft = Omit<ProxyRule, "id" | "created_at" | "updated_at">;

/* ------------------------------------------------------------------ config */

export interface ListenerConfig {
  name: string;
  host: string;
  port: number;
  mode: "explicit" | "transparent" | "socks";
  enabled: boolean;
}

export interface UpstreamProxyConfig {
  enabled: boolean;
  scheme: "http" | "socks5";
  host: string;
  port: number;
  username: string;
  password: string;
}

export interface ProxyConfig {
  host: string;
  port: number;
  upstream_verify: boolean;
  upstream_ca: string;
  intercept_enabled: boolean;
  intercept_timeout: number;
  max_body_size: number;
  max_header_size: number;
  upstream_timeout: number;
  follow_redirects: boolean;
  user_agent: string;
  bypass: string[];
  http2: boolean;
  listeners: ListenerConfig[];
  upstream_proxy: UpstreamProxyConfig;
  socks: { username: string; password: string };
  intercept_websockets: boolean;
  intercept_websocket_directions: string[];
}

export interface ApiConfig {
  host: string;
  port: number;
  cors_origins: string[];
}

export interface ScanConfig {
  concurrency: number;
  timeout: number;
  max_pages: number;
  max_depth: number;
}

export interface AppConfig {
  proxy: ProxyConfig;
  api: ApiConfig;
  scan: ScanConfig;
  home: string;
  log_level: string;
}

export interface DaemonState {
  proxy: { host: string; port: number; upstream_verify: boolean; http2: boolean };
  ca: { subject: string; fingerprint: string; path: string };
  intercept: InterceptState;
  plugins: PluginInfo[];
  tools: ToolDescriptor[];
  checks: CheckDescriptor[];
}

export interface CheckDescriptor {
  id: string;
  label: string;
  description: string;
  severity: string;
  category: string;
  kind: "active" | "passive";
  scope: "host" | "endpoint";
  enabled: boolean;
}

export interface FuzzPosition {
  name: string;
  start: number;
  end: number;
}

export interface FuzzTemplate {
  request: MessageDetail;
  positions: FuzzPosition[];
  url: string;
  method: string;
}

export interface FuzzResult {
  id: string;
  job_id: string;
  url: string;
  method: string;
  payload: string;
  position: string;
  status: number;
  length: number;
  elapsed_ms: number;
  content_type: string;
  markers: string[];
  diff: string;
  status_delta: number;
  length_delta: number;
  error: string;
  interesting: boolean;
  hit: boolean;
  extracted: string;
  created_at: number;
}

export type AttackType = "sniper" | "battering-ram" | "pitchfork" | "cluster-bomb";

export type GeneratorKind =
  | "list"
  | "numbers"
  | "dates"
  | "bruteforce"
  | "substitution"
  | "grep"
  | "file"
  | "custom";

export type ProcessingRuleKind =
  | "url-encode"
  | "base64"
  | "hash"
  | "prefix"
  | "suffix"
  | "replace"
  | "extract";

export interface Generator {
  kind: GeneratorKind;
  options: Record<string, unknown>;
}

export interface ProcessingRule {
  kind: ProcessingRuleKind;
  options: Record<string, unknown>;
}

export interface FuzzJob {
  id: string;
  status: "pending" | "running" | "finished" | "stopped" | "failed";
  created_at: number;
  finished_at: number;
  error: string;
  total: number;
  completed: number;
  payloads: string[];
  position_filter: string;
  attack_type: AttackType;
  payload_sets: string[][];
  rules: ProcessingRule[];
  grep_match: string;
  grep_extract: string;
  template: FuzzTemplate;
  results: FuzzResult[];
}

export interface Finding {
  id: string;
  created_at: number;
  check_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  url: string;
  host: string;
  evidence: string;
  remediation: string;
  request_id: string;
  source: string;
  acknowledged: boolean;
  tags: string[];
}

export interface ScanResult {
  id: string;
  job_id: string;
  check_id: string;
  target: string;
  findings: Finding[];
  error: string;
  elapsed_ms: number;
  scope: "host" | "endpoint";
}

export interface ScanEndpoint {
  url: string;
  method: string;
  parameters: { name: string; value: string; location: string }[];
  body_fields: Record<string, string>;
  cookies: Record<string, string>;
  content_type: string;
  source: string;
  depth: number;
}

export interface ScanOptions {
  crawl: boolean;
  max_pages: number;
  max_depth: number;
  max_endpoints: number;
}

export interface ScanJob {
  id: string;
  status: "pending" | "running" | "finished" | "stopped" | "failed";
  created_at: number;
  finished_at: number;
  error: string;
  total: number;
  completed: number;
  targets: string[];
  check_ids: string[];
  options: ScanOptions;
  endpoints: ScanEndpoint[];
  results: ScanResult[];
  findings: Finding[];
}

/* ---------------------------------------------------------------- sequencer */

export interface SequencerReport {
  kind: string;
  samples: number;
  length: number;
  random_length: number;
  unique: number;
  verdict: "random" | "weak" | "predictable" | "unknown";
  score: number;
  entropy: number;
  entropy_per_character: number;
  expected_entropy: number;
  total_bits: number;
  chi_square: number;
  chi_square_p: number;
  serial_correlation: number;
  monte_carlo_pi: number;
  bit_bias: number;
  unique_bytes: number;
  longest_run: number;
  common_prefix: string;
  common_suffix: string;
  sequential: boolean;
  duplicates: string[];
  embedded_timestamp: number;
  characters: Record<string, number>;
  jwt: Record<string, unknown>;
  notes: string[];
}

/* --------------------------------------------------------------- comparer */

export interface CompareDifference {
  kind: string;
  path: string;
  left: string;
  right: string;
  note: string;
}

export interface CompareSimilarity {
  kind: string;
  path: string;
  value: string;
}

export interface CompareRow {
  left: string | null;
  right: string | null;
  kind: string;
  left_span: number[] | null;
  right_span: number[] | null;
}

export interface Comparison {
  kind: string;
  identical: boolean;
  left_size: number;
  right_size: number;
  differences: CompareDifference[];
  similarities: CompareSimilarity[];
  rows: CompareRow[];
  summary: string;
}

/* ------------------------------------------------------------------ workspace */
export interface CommandDescriptor {
  id: string;
  title: string;
  category: string;
  description: string;
  keywords: string[];
  shortcut: string;
  icon: string;
  hidden: boolean;
}

export interface LogEntry {
  id: number;
  created_at: number;
  level: "debug" | "info" | "warning" | "error" | "critical";
  source: string;
  message: string;
  data: Record<string, unknown>;
}

export interface Note {
  id: string;
  created_at: number;
  updated_at: number;
  subject: string;
  subject_id: string;
  text: string;
  color: string;
  tags: string[];
}

export interface Issue {
  id: string;
  created_at: number;
  updated_at: number;
  title: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: "open" | "confirmed" | "in-progress" | "resolved" | "ignored" | "false-positive";
  category: string;
  source: string;
  source_id: string;
  exchange_ids: string[];
  tags: string[];
}

export interface Session {
  id: string;
  name: string;
  created_at: number;
  updated_at: number;
  live: boolean;
  members: string[];
  count: number;
  meta: Record<string, unknown>;
}

export interface Target {
  id: string;
  created_at: number;
  updated_at: number;
  name: string;
  host: string;
  port: number;
  scheme: string;
  in_scope: boolean;
  notes: string;
  tags: string[];
  url: string;
}

export interface Task {
  id: string;
  created_at: number;
  updated_at: number;
  name: string;
  command: string;
  args: Record<string, unknown>;
  interval: number;
  enabled: boolean;
  last_run: number;
  next_run: number;
  run_count: number;
  last_error: string;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  path: string;
  created_at: number;
  updated_at: number;
  current: boolean;
}

export interface WebSocketConnection {
  id: string;
  created_at: number;
  url: string;
  host: string;
  method: string;
  headers: Record<string, string>;
  closed: boolean;
  closed_at: number;
}

export interface WebSocketMessage {
  id: number;
  connection_id: string;
  created_at: number;
  direction: "client" | "server";
  opcode: string;
  payload: string;
  size: number;
}

export interface OrganizerHost {
  host: string;
  count: number;
  size: number;
  statuses: Record<string, number>;
  paths: Record<string, { path: string; count: number; statuses: Record<string, number>; methods: Record<string, number> }>;
}

export interface DashboardData {
  traffic: { exchanges: number; hosts: number; dropped: number; database: string };
  findings: { total: number; by_severity: Record<string, number> };
  issues: { total: number; by_status: Record<string, number>; by_severity: Record<string, number> };
  notes: number;
  targets: Target[];
  sessions: Session[];
  websockets: number;
  log: { total: number; levels: Record<string, number> };
  tasks: Task[];
  filter: { expression: string; error: string };
}

export interface TrustTarget {
  name: string;
  label: string;
  available: boolean;
  reason: string;
  location: string;
  steps: string[];
}

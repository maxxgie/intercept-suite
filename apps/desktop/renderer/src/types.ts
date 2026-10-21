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

export interface RepeaterTab {
  id: string;
  name: string;
  color: string;
  target: string;
  created_at: number;
  request: MessageDetail;
  response: ResponseDetail | null;
  attempt_count: number;
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

export interface DaemonState {
  proxy: { host: string; port: number; upstream_verify: boolean; http2: boolean };
  ca: { subject: string; fingerprint: string; path: string };
  intercept: { enabled: boolean; pending: string[]; pending_count: number };
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
  created_at: number;
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
  results: ScanResult[];
  findings: Finding[];
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

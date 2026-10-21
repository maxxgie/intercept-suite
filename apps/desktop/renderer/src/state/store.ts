import { create } from "zustand";
import { api, setApiBase } from "../lib/api";
import type {
  AppConfig,
  CheckDescriptor,
  CommandDescriptor,
  DashboardData,
  DaemonState,
  ExchangeDetail,
  ExchangeSummary,
  Finding,
  FuzzJob,
  HeldFrame,
  HeldItem,
  InterceptState,
  Issue,
  LogEntry,
  Note,
  OrganizerHost,
  PluginInfo,
  Project,
  ProxyRule,
  RepeaterTab,
  RuleDraft,
  ScanJob,
  Session,
  SiteHost,
  Target,
  Task,
  ToolDescriptor,
  WebSocketConnection,
  WebSocketMessage,
  WebSocketSession,
} from "../types";

export type View =
  | "dashboard"
  | "activity"
  | "scan-status"
  | "traffic"
  | "websockets"
  | "intercept"
  | "rules"
  | "repeater"
  | "fuzzer"
  | "builder"
  | "scanner"
  | "findings"
  | "decoder"
  | "comparer"
  | "tokens"
  | "issues"
  | "notes"
  | "organizer"
  | "sites"
  | "scope"
  | "endpoints"
  | "targets"
  | "logger"
  | "tasks"
  | "reports"
  | "export"
  | "browser"
  | "projects"
  | "extensions"
  | "settings";
export type MessageTab = "pretty" | "headers" | "body" | "hex" | "render" | "raw";
export type BottomTab = "logs" | "events" | "alerts" | "status";

export interface ScopeRule {
  pattern: string;
  kind: "include" | "exclude";
  target: "host" | "url";
  enabled: boolean;
}

export interface HeldRequest {
  id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  body_length: number;
  mime_type: string;
  created_at: number;
}

export interface DaemonEventEntry {
  id: number;
  type: string;
  ts: number;
  data: Record<string, unknown>;
}


interface Store {
  apiBase: string;
  connected: boolean;
  view: View;
  traffic: ExchangeSummary[];
  total: number;
  selectedId: string | null;
  detail: ExchangeDetail | null;
  tabs: RepeaterTab[];
  activeTabId: string | null;
  repeaterHttp2: boolean;
  websocketSession: WebSocketSession | null;
  sites: SiteHost[];
  tools: ToolDescriptor[];
  plugins: PluginInfo[];
  daemon: DaemonState | null;
  adopted: boolean;
  interceptEnabled: boolean;
  pendingIntercepts: string[];
  error: string | null;
  busy: boolean;
  fuzzJobs: FuzzJob[];
  activeFuzzJobId: string | null;
  scanJobs: ScanJob[];
  activeScanJobId: string | null;
  checks: CheckDescriptor[];
  findings: Finding[];
  /* workspace */
  filter: string;
  filterError: string;
  commands: CommandDescriptor[];
  paletteOpen: boolean;
  logEntries: LogEntry[];
  notes: Note[];
  issues: Issue[];
  sessions: Session[];
  targets: Target[];
  tasks: Task[];
  projects: Project[];
  currentProject: Project | null;
  websocketConnections: WebSocketConnection[];
  websocketMessages: WebSocketMessage[];
  organizer: OrganizerHost[];
  dashboard: DashboardData | null;
  contextMenu: { x: number; y: number; items: ContextMenuItem[] } | null;
  /* layout */
  openTools: View[];
  sidebarWidth: number;
  sidebarCollapsed: boolean;
  bottomHeight: number;
  bottomCollapsed: boolean;
  bottomTab: BottomTab;
  /* scope and interception */
  scopeRules: ScopeRule[];
  heldRequests: HeldRequest[];
  heldItems: HeldItem[];
  heldFrames: HeldFrame[];
  daemonEvents: DaemonEventEntry[];
  /* rules */
  rules: ProxyRule[];
  /* configuration */
  config: AppConfig | null;

  bootstrap(): Promise<void>;
  setView(view: View): void;
  openTool(view: View): void;
  closeTool(view: View): void;
  setSidebarWidth(width: number): void;
  toggleSidebar(): void;
  setBottomHeight(height: number): void;
  toggleBottom(): void;
  setBottomTab(tab: BottomTab): void;
  refreshScope(): Promise<void>;
  addScopeRule(rule: { pattern: string; kind: string; target: string }): Promise<void>;
  removeScopeRule(pattern: string): Promise<void>;
  refreshHeldRequests(): Promise<void>;
  pushHeldRequest(request: HeldRequest): void;
  decideHeldRequest(id: string, action: "forward" | "drop"): Promise<void>;
  decideHeldRequestWith(
    id: string,
    payload: Record<string, unknown>,
  ): Promise<void>;
  decideHeldFrame(id: string, action: "forward" | "drop", text?: string): Promise<void>;
  annotate(
    exchangeId: string,
    side: "request" | "response",
    tags: string[],
    notes: string[],
  ): Promise<void>;
  refreshRules(): Promise<void>;
  createRule(rule: RuleDraft): Promise<void>;
  updateRule(id: string, rule: RuleDraft): Promise<void>;
  deleteRule(id: string): Promise<void>;
  refreshConfig(): Promise<void>;
  saveConfig(patch: Record<string, unknown>): Promise<void>;
  pushDaemonEvent(type: string, data: Record<string, unknown>): void;
  clearDaemonEvents(): void;
  createRepeaterTab(payload: {
    method?: string;
    url?: string;
    headers?: Record<string, string[]>;
    body?: string;
    name?: string;
  }): Promise<RepeaterTab>;
  refreshTabs(): Promise<void>;
  setRepeaterHttp2(enabled: boolean): void;
  refreshTraffic(): Promise<void>;
  select(id: string | null): Promise<void>;
  clearTraffic(): Promise<void>;
  refreshSites(): Promise<void>;
  refreshPlugins(): Promise<void>;
  setIntercept(enabled: boolean): Promise<void>;
  startSpider(): Promise<void>;
  openInRepeater(exchange: ExchangeDetail | ExchangeSummary): Promise<void>;
  addTab(tab: RepeaterTab): void;
  updateTab(tabId: string, raw: string): void;
  sendTab(tabId: string, raw?: string): Promise<void>;
  resendTab(tabId: string, attempt: number): Promise<void>;
  closeTab(tabId: string): Promise<void>;
  openWebSocket(tabId: string): Promise<void>;
  sendWebSocketFrame(tabId: string, text: string, opcode: string): Promise<void>;
  receiveWebSocketFrames(tabId: string, timeout: number): Promise<void>;
  closeWebSocket(tabId: string): Promise<void>;
  runTool(toolId: string, values: Record<string, unknown>): Promise<string>;
  pushExchange(exchange: ExchangeSummary): void;
  setError(message: string | null): void;
  refreshFuzzJobs(): Promise<void>;
  startFuzzJob(request: {
    raw?: string;
    method?: string;
    url?: string;
    headers?: Record<string, string[]>;
    body?: string;
    payloads: string[];
  }): Promise<void>;
  stopFuzzJob(jobId: string): Promise<void>;
  refreshScanJobs(): Promise<void>;
  refreshChecks(): Promise<void>;
  startScanJob(targets: string[], checks: string[]): Promise<void>;
  stopScanJob(jobId: string): Promise<void>;
  refreshFindings(): Promise<void>;
  acknowledgeFinding(id: string): Promise<void>;
  clearFindings(): Promise<void>;
  /* workspace */
  setFilter(expression: string): Promise<void>;
  refreshCommands(): Promise<void>;
  runCommand(id: string, args?: Record<string, unknown>): Promise<unknown>;
  setPalette(open: boolean): void;
  refreshLog(): Promise<void>;
  clearLog(): Promise<void>;
  refreshNotes(): Promise<void>;
  createNote(text: string, subjectId: string, color: string): Promise<void>;
  deleteNote(id: string): Promise<void>;
  refreshIssues(): Promise<void>;
  createIssue(title: string, severity: string, description: string): Promise<void>;
  updateIssue(id: string, changes: Partial<Issue>): Promise<void>;
  refreshSessions(): Promise<void>;
  createSession(name: string): Promise<void>;
  refreshTargets(): Promise<void>;
  createTarget(name: string, host: string, port?: number, scheme?: string): Promise<void>;
  updateTarget(id: string, changes: Partial<Target>): Promise<void>;
  deleteTarget(id: string): Promise<void>;
  refreshTasks(): Promise<void>;
  createTask(name: string, command: string, interval: number): Promise<void>;
  runTask(id: string): Promise<void>;
  deleteTask(id: string): Promise<void>;
  refreshProjects(): Promise<void>;
  createProject(name: string, description: string): Promise<void>;
  saveProject(id: string): Promise<void>;
  openProject(id: string): Promise<void>;
  refreshWebsockets(): Promise<void>;
  refreshOrganizer(): Promise<void>;
  refreshDashboard(): Promise<void>;
  openContextMenu(event: { clientX: number; clientY: number }, items: ContextMenuItem[]): void;
  closeContextMenu(): void;
}

export interface ContextMenuItem {
  id: string;
  label: string;
  separator?: boolean;
  shortcut?: string;
  disabled?: boolean;
  run?: () => void;
}

/** The panel sizes survive a restart of the window. */
function storedNumber(key: string, fallback: number): number {
  try {
    const value = Number(window.localStorage.getItem(key));
    return Number.isFinite(value) && value > 0 ? value : fallback;
  } catch {
    return fallback;
  }
}

function rawOf(exchange: ExchangeDetail | ExchangeSummary): string {
  if ("request" in exchange) return exchange.request.raw ?? "";
  return "raw" in exchange && typeof exchange.raw === "string" ? exchange.raw : "";
}

function urlOf(exchange: ExchangeDetail | ExchangeSummary): string {
  return "url" in exchange ? exchange.url : exchange.request.url;
}

function methodOf(exchange: ExchangeDetail | ExchangeSummary): string {
  return "method" in exchange ? exchange.method : exchange.request.method;
}

function pathOf(exchange: ExchangeDetail | ExchangeSummary): string {
  return "path" in exchange ? exchange.path : exchange.request.path;
}

export const useStore = create<Store>((set, get) => ({
  apiBase: "",
  connected: false,
  view: "traffic",
  traffic: [],
  total: 0,
  selectedId: null,
  detail: null,
  tabs: [],
  activeTabId: null,
  repeaterHttp2: false,
  websocketSession: null,
  sites: [],
  tools: [],
  plugins: [],
  daemon: null,
  adopted: false,
  interceptEnabled: false,
  pendingIntercepts: [],
  error: null,
  busy: false,
  fuzzJobs: [],
  activeFuzzJobId: null,
  scanJobs: [],
  activeScanJobId: null,
  checks: [],
  findings: [],
  filter: "",
  filterError: "",
  commands: [],
  paletteOpen: false,
  logEntries: [],
  notes: [],
  issues: [],
  sessions: [],
  targets: [],
  tasks: [],
  projects: [],
  currentProject: null,
  websocketConnections: [],
  websocketMessages: [],
  organizer: [],
  dashboard: null,
  contextMenu: null,
  openTools: ["traffic"],
  sidebarWidth: storedNumber("intercept.sidebarWidth", 232),
  sidebarCollapsed: false,
  bottomHeight: storedNumber("intercept.bottomHeight", 210),
  bottomCollapsed: false,
  bottomTab: "logs",
  scopeRules: [],
  heldRequests: [],
  heldItems: [],
  heldFrames: [],
  daemonEvents: [],
  rules: [],
  config: null,

  async bootstrap() {
    try {
      const info = await window.intercept.info();
      if (!info.apiBase) {
        set({ connected: false });
        return;
      }
      setApiBase(info.apiBase);
      set({ apiBase: info.apiBase, connected: true });
      await Promise.all([
        get().refreshTraffic(),
        get().refreshSites(),
        get().refreshPlugins(),
        get().refreshCommands(),
      ]);
      const daemon = await api.get<DaemonState>("/api/state");
      set({ daemon, interceptEnabled: daemon.intercept.enabled });
    } catch (error) {
      set({ connected: false, error: (error as Error).message });
    }
  },

  setView(view) {
    get().openTool(view);
  },

  openTool(view) {
    const open = get().openTools;
    set({ view, openTools: open.includes(view) ? open : [...open, view] });
    if (view === "sites" || view === "endpoints") void get().refreshSites();
    if (view === "extensions" || view === "decoder") void get().refreshPlugins();
    if (view === "fuzzer") void get().refreshFuzzJobs();
    if (view === "scanner" || view === "scan-status") {
      void get().refreshScanJobs();
      void get().refreshChecks();
    }
    if (view === "findings") void get().refreshFindings();
    if (view === "dashboard") void get().refreshDashboard();
    if (view === "logger" || view === "activity") void get().refreshLog();
    if (view === "notes") void get().refreshNotes();
    if (view === "issues") void get().refreshIssues();
    if (view === "targets") void get().refreshTargets();
    if (view === "tasks") void get().refreshTasks();
    if (view === "projects") void get().refreshProjects();
    if (view === "websockets") void get().refreshWebsockets();
    if (view === "organizer") void get().refreshOrganizer();
    if (view === "scope") void get().refreshScope();
    if (view === "intercept") void get().refreshHeldRequests();
    if (view === "rules") void get().refreshRules();
    if (view === "settings") {
      void get().refreshConfig();
      void get().refreshPlugins();
    }
  },

  closeTool(view) {
    const open = get().openTools.filter((item) => item !== view);
    const current = get().view;
    if (current === view) {
      const next = open[open.length - 1] ?? "traffic";
      set({ openTools: open, view: next });
      get().openTool(next);
      return;
    }
    set({ openTools: open });
  },

  setSidebarWidth(width) {
    const clamped = Math.max(160, Math.min(460, Math.round(width)));
    set({ sidebarWidth: clamped });
    window.localStorage.setItem("intercept.sidebarWidth", String(clamped));
  },

  toggleSidebar() {
    set({ sidebarCollapsed: !get().sidebarCollapsed });
  },

  setBottomHeight(height) {
    const clamped = Math.max(110, Math.min(620, Math.round(height)));
    set({ bottomHeight: clamped });
    window.localStorage.setItem("intercept.bottomHeight", String(clamped));
  },

  toggleBottom() {
    set({ bottomCollapsed: !get().bottomCollapsed });
  },

  setBottomTab(tab) {
    set({ bottomTab: tab, bottomCollapsed: false });
  },

  async refreshScope() {
    try {
      const response = await api.get<{ rules: ScopeRule[] }>("/api/scope");
      set({ scopeRules: response.rules ?? [] });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async addScopeRule(rule) {
    await api.post("/api/scope/rules", rule);
    await get().refreshScope();
  },

  async removeScopeRule(pattern) {
    await api.delete(`/api/scope/rules?pattern=${encodeURIComponent(pattern)}`);
    await get().refreshScope();
  },

  async refreshHeldRequests() {
    try {
      const response = await api.get<InterceptState>("/api/intercept");
      const pending = response.pending ?? [];
      const held = get().heldRequests.filter((item) => pending.includes(item.id));
      set({
        heldRequests: held,
        heldItems: response.items ?? [],
        heldFrames: response.frames ?? [],
        interceptEnabled: response.enabled === true,
      });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  pushHeldRequest(request) {
    const held = get().heldRequests.filter((item) => item.id !== request.id);
    set({ heldRequests: [...held, request] });
  },

  async decideHeldRequest(id, action) {
    await api.post(`/api/intercept/${id}`, { action });
    set({ heldRequests: get().heldRequests.filter((item) => item.id !== id) });
    await get().refreshHeldRequests();
  },

  async decideHeldRequestWith(id, payload) {
    await api.post(`/api/intercept/${id}`, payload);
    set({ heldRequests: get().heldRequests.filter((item) => item.id !== id) });
    await get().refreshHeldRequests();
  },

  async decideHeldFrame(id, action, text) {
    const payload: Record<string, unknown> = { action };
    if (text !== undefined) payload.text = text;
    await api.post(`/api/intercept/frames/${id}`, payload);
    set({ heldFrames: get().heldFrames.filter((frame) => frame.id !== id) });
    await get().refreshHeldRequests();
  },

  async annotate(exchangeId, side, tags, notes) {
    await api.put(`/api/traffic/${exchangeId}/annotation`, { side, tags, notes });
    await get().select(exchangeId);
  },

  async refreshRules() {
    try {
      const response = await api.get<{ rules: ProxyRule[] }>("/api/rules");
      set({ rules: response.rules ?? [] });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async createRule(rule) {
    await api.post("/api/rules", rule);
    await get().refreshRules();
  },

  async updateRule(id, rule) {
    await api.put(`/api/rules/${id}`, rule);
    await get().refreshRules();
  },

  async deleteRule(id) {
    await api.delete(`/api/rules/${id}`);
    await get().refreshRules();
  },

  async refreshConfig() {
    try {
      const config = await api.get<AppConfig>("/api/config");
      set({ config });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async saveConfig(patch) {
    try {
      const config = await api.put<AppConfig>("/api/config", patch);
      set({ config });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  pushDaemonEvent(type, data) {
    const events = get().daemonEvents;
    set({
      daemonEvents: [
        ...events,
        { id: events.length ? events[events.length - 1].id + 1 : 1, type, ts: Date.now() / 1000, data },
      ].slice(-400),
    });
  },

  clearDaemonEvents() {
    set({ daemonEvents: [] });
  },

  async createRepeaterTab(payload) {
    const tab = await api.post<RepeaterTab>("/api/repeater/tabs", payload);
    get().addTab(tab);
    return tab;
  },

  async refreshTraffic() {
    try {
      const filter = get().filter;
      const query = filter ? `&filter=${encodeURIComponent(filter)}` : "";
      const response = await api.get<{ items: ExchangeSummary[]; total: number }>(
        `/api/traffic?limit=500${query}`,
      );
      set({ traffic: response.items, total: response.total });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async select(id) {
    if (!id) {
      set({ selectedId: null, detail: null });
      return;
    }
    set({ selectedId: id });
    try {
      const detail = await api.get<ExchangeDetail>(`/api/traffic/${id}`);
      set({ detail });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async clearTraffic() {
    await api.delete("/api/traffic");
    set({ traffic: [], selectedId: null, detail: null, total: 0 });
  },

  async refreshSites() {
    try {
      const response = await api.get<{ hosts: SiteHost[]; tree: SiteHost[] }>("/api/sites");
      set({ sites: response.tree });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async refreshPlugins() {
    try {
      const response = await api.get<{ plugins: PluginInfo[]; tools: ToolDescriptor[] }>(
        "/api/plugins",
      );
      set({ plugins: response.plugins, tools: response.tools });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async setIntercept(enabled) {
    const state = await api.post<{ enabled: boolean }>("/api/intercept/toggle", { enabled });
    set({ interceptEnabled: state.enabled });
  },

  async startSpider() {
    set({ busy: true });
    try {
      await api.post("/api/spider/start", { use_known_hosts: true });
      await get().refreshSites();
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ busy: false });
    }
  },

  async openInRepeater(exchange) {
    const raw = rawOf(exchange);
    const tab = await api.post<RepeaterTab>("/api/repeater/tabs", {
      raw: raw || undefined,
      method: methodOf(exchange),
      url: urlOf(exchange),
      name: pathOf(exchange),
    });
    const tabs = [...get().tabs, tab];
    set({ tabs, activeTabId: tab.id, view: "repeater" });
  },

  addTab(tab) {
    const tabs = [...get().tabs, tab];
    set({ tabs, activeTabId: tab.id, view: "repeater" });
  },

  updateTab(tabId, raw) {
    set({
      tabs: get().tabs.map((tab) => (tab.id === tabId ? { ...tab, request: { ...tab.request, raw } } : tab)),
    });
  },

  async sendTab(tabId, raw) {
    set({ busy: true });
    try {
      const response = await api.post<{ response: RepeaterTab["response"]; tab: RepeaterTab }>(
        `/api/repeater/tabs/${tabId}/send`,
        { tab_id: tabId, raw, http2: get().repeaterHttp2 },
      );
      set({
        tabs: get().tabs.map((tab) => (tab.id === tabId ? response.tab : tab)),
        activeTabId: tabId,
      });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ busy: false });
    }
  },

  async resendTab(tabId, attempt) {
    set({ busy: true });
    try {
      const response = await api.post<{ response: RepeaterTab["response"]; tab: RepeaterTab }>(
        `/api/repeater/tabs/${tabId}/resend`,
        { attempt },
      );
      set({
        tabs: get().tabs.map((tab) => (tab.id === tabId ? response.tab : tab)),
        activeTabId: tabId,
      });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ busy: false });
    }
  },

  async refreshTabs() {
    try {
      const response = await api.get<{ tabs: RepeaterTab[] }>("/api/repeater/tabs");
      set({ tabs: response.tabs });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  setRepeaterHttp2(enabled) {
    set({ repeaterHttp2: enabled });
  },

  async openWebSocket(tabId) {
    set({ busy: true });
    try {
      const session = await api.post<WebSocketSession>(
        `/api/repeater/tabs/${tabId}/websocket/open`,
        {},
      );
      set({ websocketSession: session });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ busy: false });
    }
  },

  async sendWebSocketFrame(tabId, text, opcode) {
    try {
      await api.post(`/api/repeater/tabs/${tabId}/websocket/send`, { text, opcode });
      const session = await api.get<WebSocketSession>(`/api/repeater/tabs/${tabId}/websocket`);
      set({ websocketSession: session });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async receiveWebSocketFrames(tabId, timeout) {
    set({ busy: true });
    try {
      await api.post(`/api/repeater/tabs/${tabId}/websocket/receive`, { timeout });
      const session = await api.get<WebSocketSession>(`/api/repeater/tabs/${tabId}/websocket`);
      set({ websocketSession: session });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ busy: false });
    }
  },

  async closeWebSocket(tabId) {
    try {
      await api.post(`/api/repeater/tabs/${tabId}/websocket/close`, {});
      set({ websocketSession: null });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async closeTab(tabId) {
    await api.delete(`/api/repeater/tabs/${tabId}`);
    const tabs = get().tabs.filter((tab) => tab.id !== tabId);
    set({ tabs, activeTabId: get().activeTabId === tabId ? (tabs[0]?.id ?? null) : get().activeTabId });
  },

  async runTool(toolId, values) {
    const result = await api.post<Record<string, unknown>>(`/api/tools/${toolId}/run`, { values });
    if (result.error) return `Error: ${String(result.error)}`;
    const output = result.output ?? result.result ?? result;
    return typeof output === "string" ? output : JSON.stringify(output, null, 2);
  },

  pushExchange(exchange) {
    const current = get().traffic;
    if (current.some((item) => item.id === exchange.id)) return;
    set({ traffic: [exchange, ...current].slice(0, 1000), total: get().total + 1 });
  },

  async refreshFuzzJobs() {
    try {
      const response = await api.get<{ jobs: FuzzJob[] }>("/api/fuzz/jobs");
      set({
        fuzzJobs: response.jobs,
        activeFuzzJobId: get().activeFuzzJobId ?? response.jobs[0]?.id ?? null,
      });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async startFuzzJob(request) {
    set({ busy: true });
    try {
      const job = await api.post<FuzzJob>("/api/fuzz/jobs", { ...request, start: true });
      set({ fuzzJobs: [job, ...get().fuzzJobs], activeFuzzJobId: job.id });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ busy: false });
    }
  },

  async stopFuzzJob(jobId) {
    await api.post(`/api/fuzz/jobs/${jobId}/stop`, {});
    await get().refreshFuzzJobs();
  },

  async refreshScanJobs() {
    try {
      const response = await api.get<{ jobs: ScanJob[] }>("/api/scanner/jobs");
      set({
        scanJobs: response.jobs,
        activeScanJobId: get().activeScanJobId ?? response.jobs[0]?.id ?? null,
      });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async refreshChecks() {
    try {
      const response = await api.get<{ checks: CheckDescriptor[] }>("/api/scanner/checks");
      set({ checks: response.checks });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async startScanJob(targets, checks) {
    set({ busy: true });
    try {
      const job = await api.post<ScanJob>("/api/scanner/jobs", { targets, checks, start: true });
      set({ scanJobs: [job, ...get().scanJobs], activeScanJobId: job.id });
    } catch (error) {
      set({ error: (error as Error).message });
    } finally {
      set({ busy: false });
    }
  },

  async stopScanJob(jobId) {
    await api.post(`/api/scanner/jobs/${jobId}/stop`, {});
    await get().refreshScanJobs();
  },

  async refreshFindings() {
    try {
      const response = await api.get<{ items: Finding[] }>("/api/findings?limit=500");
      set({ findings: response.items });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async acknowledgeFinding(id) {
    await api.put(`/api/findings/${id}/acknowledge`, {});
    await get().refreshFindings();
  },

  async clearFindings() {
    await api.delete("/api/findings");
    set({ findings: [] });
  },

  /* ------------------------------------------------------------- workspace */

  async setFilter(expression) {
    const trimmed = expression.trim();
    if (!trimmed) {
      set({ filter: "", filterError: "" });
      await get().refreshTraffic();
      return;
    }
    try {
      await api.put("/api/filter", { filter: trimmed });
      set({ filter: trimmed, filterError: "" });
    } catch (error) {
      set({ filterError: (error as Error).message });
      return;
    }
    await get().refreshTraffic();
  },

  async refreshCommands() {
    try {
      const response = await api.get<{ commands: CommandDescriptor[] }>("/api/commands");
      set({ commands: response.commands });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async runCommand(id, args) {
    try {
      const response = await api.post<{ result: unknown }>(`/api/commands/${id}/run`, {
        args: args ?? {},
      });
      const result = response.result as { view?: View } | undefined;
      if (result && typeof result === "object" && "view" in result && result.view) {
        get().setView(result.view);
      }
      set({ error: null });
      return response.result;
    } catch (error) {
      set({ error: (error as Error).message });
      return null;
    }
  },

  setPalette(open) {
    set({ paletteOpen: open });
  },

  async refreshLog() {
    try {
      const response = await api.get<{ entries: LogEntry[] }>("/api/log?limit=500");
      set({ logEntries: response.entries });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async clearLog() {
    await api.delete("/api/log");
    set({ logEntries: [] });
  },

  async refreshNotes() {
    try {
      const response = await api.get<{ notes: Note[] }>("/api/notes?limit=500");
      set({ notes: response.notes });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async createNote(text, subjectId, color) {
    await api.post("/api/notes", {
      subject: "exchange",
      subject_id: subjectId,
      text,
      color,
    });
    await get().refreshNotes();
  },

  async deleteNote(id) {
    await api.delete(`/api/notes/${id}`);
    await get().refreshNotes();
  },

  async refreshIssues() {
    try {
      const response = await api.get<{ issues: Issue[] }>("/api/issues?limit=500");
      set({ issues: response.issues });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async createIssue(title, severity, description) {
    await api.post("/api/issues", { title, severity, description });
    await get().refreshIssues();
  },

  async updateIssue(id, changes) {
    await api.put(`/api/issues/${id}`, changes);
    await get().refreshIssues();
  },

  async refreshSessions() {
    try {
      const response = await api.get<{ sessions: Session[] }>("/api/sessions");
      set({ sessions: response.sessions });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async createSession(name) {
    await api.post("/api/sessions", { name });
    await get().refreshSessions();
  },

  async refreshTargets() {
    try {
      const response = await api.get<{ targets: Target[] }>("/api/targets");
      set({ targets: response.targets });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async createTarget(name, host, port, scheme) {
    await api.post("/api/targets", {
      name,
      host,
      port: port ?? 443,
      scheme: scheme ?? "https",
    });
    await get().refreshTargets();
  },

  async updateTarget(id, changes) {
    await api.put(`/api/targets/${id}`, changes);
    await get().refreshTargets();
  },

  async deleteTarget(id) {
    await api.delete(`/api/targets/${id}`);
    await get().refreshTargets();
  },

  async refreshTasks() {
    try {
      const response = await api.get<{ tasks: Task[] }>("/api/tasks");
      set({ tasks: response.tasks });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async createTask(name, command, interval) {
    await api.post("/api/tasks", { name, command, interval });
    await get().refreshTasks();
  },

  async runTask(id) {
    await api.post(`/api/tasks/${id}/run`, {});
    await get().refreshTasks();
  },

  async deleteTask(id) {
    await api.delete(`/api/tasks/${id}`);
    await get().refreshTasks();
  },

  async refreshProjects() {
    try {
      const response = await api.get<{ projects: Project[]; current: Project | null }>(
        "/api/projects",
      );
      set({ projects: response.projects, currentProject: response.current });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async createProject(name, description) {
    await api.post("/api/projects", { name, description });
    await get().refreshProjects();
  },

  async saveProject(id) {
    await api.post(`/api/projects/${id}/save`, {});
    await get().refreshProjects();
  },

  async openProject(id) {
    await api.post(`/api/projects/${id}/open`, {});
    await get().refreshProjects();
  },

  async refreshWebsockets() {
    try {
      const [connections, messages] = await Promise.all([
        api.get<{ connections: WebSocketConnection[] }>("/api/websockets/connections"),
        api.get<{ messages: WebSocketMessage[] }>("/api/websockets/messages?limit=500"),
      ]);
      set({
        websocketConnections: connections.connections,
        websocketMessages: messages.messages,
      });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async refreshOrganizer() {
    try {
      const response = await api.get<{ hosts: OrganizerHost[] }>("/api/organizer?limit=500");
      set({ organizer: response.hosts });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  async refreshDashboard() {
    try {
      const response = await api.get<DashboardData>("/api/dashboard");
      set({ dashboard: response });
    } catch (error) {
      set({ error: (error as Error).message });
    }
  },

  openContextMenu(event, items) {
    set({ contextMenu: { x: event.clientX, y: event.clientY, items } });
  },

  closeContextMenu() {
    set({ contextMenu: null });
  },

  setError(message) {
    set({ error: message });
  },
}));

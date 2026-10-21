import { useEffect } from "react";
import ActivityView from "./components/ActivityView";
import BottomPanel from "./components/BottomPanel";
import BrowserView from "./components/BrowserView";
import CommandPalette from "./components/CommandPalette";
import ComparerView from "./components/ComparerView";
import ContextMenu from "./components/ContextMenu";
import DashboardView from "./components/DashboardView";
import DecoderView from "./components/DecoderView";
import EndpointsView from "./components/EndpointsView";
import ExportView from "./components/ExportView";
import ExtensionsView from "./components/ExtensionsView";
import FindingsView from "./components/FindingsView";
import FuzzerView from "./components/FuzzerView";
import InterceptView from "./components/InterceptView";
import IssuesView from "./components/IssuesView";
import LoggerView from "./components/LoggerView";
import NotesView from "./components/NotesView";
import OrganizerView from "./components/OrganizerView";
import ProjectsView from "./components/ProjectsView";
import RepeaterView from "./components/RepeaterView";
import ReportsView from "./components/ReportsView";
import RequestBuilderView from "./components/RequestBuilderView";
import Resizer from "./components/Resizer";
import RulesView from "./components/RulesView";
import ScanStatusView from "./components/ScanStatusView";
import ScannerView from "./components/ScannerView";
import ScopeView from "./components/ScopeView";
import SettingsView from "./components/SettingsView";
import Sidebar from "./components/Sidebar";
import SiteMapView from "./components/SiteMapView";
import TargetsView from "./components/TargetsView";
import TasksView from "./components/TasksView";
import TokenAnalysisView from "./components/TokenAnalysisView";
import ToolTabs from "./components/ToolTabs";
import TopBar from "./components/TopBar";
import TrafficView from "./components/TrafficView";
import WebSocketView from "./components/WebSocketView";
import { useStore } from "./state/store";
import type { ExchangeSummary } from "./types";

export default function App() {
  const view = useStore((s) => s.view);
  const connected = useStore((s) => s.connected);
  const error = useStore((s) => s.error);
  const setError = useStore((s) => s.setError);
  const setPalette = useStore((s) => s.setPalette);
  const pushExchange = useStore((s) => s.pushExchange);
  const refreshSites = useStore((s) => s.refreshSites);
  const refreshWebsockets = useStore((s) => s.refreshWebsockets);
  const pushDaemonEvent = useStore((s) => s.pushDaemonEvent);
  const pushHeldRequest = useStore((s) => s.pushHeldRequest);
  const refreshHeldRequests = useStore((s) => s.refreshHeldRequests);

  const sidebarWidth = useStore((s) => s.sidebarWidth);
  const setSidebarWidth = useStore((s) => s.setSidebarWidth);
  const bottomHeight = useStore((s) => s.bottomHeight);
  const setBottomHeight = useStore((s) => s.setBottomHeight);

  useEffect(() => {
    void useStore.getState().bootstrap();
    const off = window.intercept.onEvent((event) => {
      const data = event.data as {
        exchange?: ExchangeSummary;
        id?: string;
        request?: Record<string, unknown>;
      };
      pushDaemonEvent(event.type, data ?? {});
      switch (event.type) {
        case "response":
          if (data.exchange) pushExchange(data.exchange);
          break;
        case "intercept.request":
          useStore.setState((s) => ({
            pendingIntercepts: data.id ? [...s.pendingIntercepts, data.id] : s.pendingIntercepts,
          }));
          if (data.id && data.request) {
            pushHeldRequest({
              id: data.id,
              method: String(data.request.method ?? "GET"),
              url: String(data.request.url ?? ""),
              host: String(data.request.host ?? ""),
              path: String(data.request.path ?? ""),
              body_length: Number(data.request.body_length ?? 0),
              mime_type: String(data.request.mime_type ?? ""),
              created_at: Number(data.request.created_at ?? Date.now() / 1000),
            });
          }
          break;
        case "intercept.dropped":
          useStore.setState((s) => ({
            pendingIntercepts: s.pendingIntercepts.filter((id) => id !== data.id),
          }));
          break;
        case "intercept.response":
        case "intercept.frame":
          void refreshHeldRequests();
          break;
        case "spider.finished":
          void refreshSites();
          break;
        case "websocket.opened":
        case "websocket.message":
          void refreshWebsockets();
          break;
        default:
          break;
      }
    });
    const offStatus = window.intercept.onStatus((status) => {
      if (status.state === "running") {
        // The daemon became reachable (it may have been adopted), so pull the
        // current state across.
        useStore.setState({ adopted: status.adopted === true });
        void useStore.getState().bootstrap();
        return;
      }
      if (status.state === "stopped") {
        useStore.setState({ connected: false });
      }
    });
    return () => {
      off();
      offStatus();
    };
  }, [pushExchange, refreshSites, refreshWebsockets, pushDaemonEvent, pushHeldRequest, refreshHeldRequests]);

  useEffect(() => {
    if (!error) return;
    const timer = setTimeout(() => setError(null), 6000);
    return () => clearTimeout(timer);
  }, [error, setError]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const typing =
        target &&
        (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);

      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPalette(true);
        return;
      }
      if (typing) return;

      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
        event.preventDefault();
        document.querySelector<HTMLInputElement>(".top-bar .filter")?.focus();
        return;
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "i") {
        event.preventDefault();
        void useStore.getState().setIntercept(!useStore.getState().interceptEnabled);
        return;
      }
      if ((event.ctrlKey || event.metaKey) && event.shiftKey && event.key.toLowerCase() === "k") {
        event.preventDefault();
        void useStore.getState().runCommand("traffic.clear");
        void useStore.getState().refreshTraffic();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setPalette]);

  return (
    <div className="app">
      <TopBar />

      <div className="workspace">
        <Sidebar />
        <Resizer
          orientation="vertical"
          label="Resize the navigation"
          onDelta={(delta) => setSidebarWidth(sidebarWidth + delta)}
        />

        <div className="center">
          <ToolTabs />

          <main className="content">
            {error && (
              <div className="banner error" onClick={() => setError(null)}>
                {error}
              </div>
            )}
            {view === "dashboard" && <DashboardView />}
            {view === "activity" && <ActivityView />}
            {view === "scan-status" && <ScanStatusView />}
            {view === "intercept" && <InterceptView />}
            {view === "rules" && <RulesView />}
            {view === "traffic" && <TrafficView />}
            {view === "websockets" && <WebSocketView />}
            {view === "sites" && <SiteMapView />}
            {view === "scope" && <ScopeView />}
            {view === "endpoints" && <EndpointsView />}
            {view === "repeater" && <RepeaterView />}
            {view === "fuzzer" && <FuzzerView />}
            {view === "builder" && <RequestBuilderView />}
            {view === "scanner" && <ScannerView />}
            {view === "findings" && <FindingsView />}
            {view === "decoder" && <DecoderView />}
            {view === "comparer" && <ComparerView />}
            {view === "tokens" && <TokenAnalysisView />}
            {view === "issues" && <IssuesView />}
            {view === "notes" && <NotesView />}
            {view === "organizer" && <OrganizerView />}
            {view === "targets" && <TargetsView />}
            {view === "logger" && <LoggerView />}
            {view === "tasks" && <TasksView />}
            {view === "reports" && <ReportsView />}
            {view === "export" && <ExportView />}
            {view === "browser" && <BrowserView />}
            {view === "projects" && <ProjectsView />}
            {view === "extensions" && <ExtensionsView />}
            {view === "settings" && <SettingsView />}
          </main>
        </div>
      </div>

      <Resizer
        orientation="horizontal"
        label="Resize the panel"
        onDelta={(delta) => setBottomHeight(bottomHeight - delta)}
      />

      <BottomPanel />

      <CommandPalette />
      <ContextMenu />
      {!connected && (
        <div className="offline-banner">
          The daemon is not reachable. Start it with <code>intercept serve</code>.
        </div>
      )}
    </div>
  );
}

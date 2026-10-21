import { contextBridge, ipcRenderer } from "electron";

export interface DaemonEvent {
  type: string;
  ts: number;
  data: Record<string, unknown>;
}

export interface DaemonRequest {
  method: string;
  path: string;
  body?: unknown;
}

/**
 * The bridge between the renderer and the daemon.
 *
 * The renderer never performs network calls itself: every request is made by
 * the main process and handed back over IPC. That keeps the daemon's CORS
 * policy closed and lets the page keep a strict content security policy.
 */
contextBridge.exposeInMainWorld("intercept", {
  info: () => ipcRenderer.invoke("daemon:info") as Promise<{ apiBase: string; state: string }>,
  request: (method: string, path: string, body?: unknown) =>
    ipcRenderer.invoke("daemon:request", { method, path, body }) as Promise<unknown>,
  text: (path: string) => ipcRenderer.invoke("daemon:text", path) as Promise<string>,
  onEvent: (callback: (event: DaemonEvent) => void) => {
    const listener = (_event: unknown, payload: DaemonEvent) => callback(payload);
    ipcRenderer.on("daemon-event", listener);
    return () => ipcRenderer.off("daemon-event", listener);
  },
  onStatus: (callback: (status: { state: string; code?: number; adopted?: boolean }) => void) => {
    const listener = (
      _event: unknown,
      payload: { state: string; code?: number; adopted?: boolean },
    ) => callback(payload);
    ipcRenderer.on("daemon-status", listener);
    return () => ipcRenderer.off("daemon-status", listener);
  },
  openExternal: (url: string) => ipcRenderer.send("shell:open", url),
});

import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { app, BrowserWindow, ipcMain, shell } from "electron";
import WebSocket from "ws";

const DEV_SERVER = process.env.INTERCEPT_DEV_SERVER;

interface DaemonRequest {
  method: string;
  path: string;
  body?: unknown;
}

let mainWindow: BrowserWindow | null = null;
type DaemonProcess = ChildProcessByStdio<null, Readable, Readable>;

let daemon: DaemonProcess | null = null;
let apiBase = "";
let socket: WebSocket | null = null;
let restartTimer: NodeJS.Timeout | null = null;
let daemonLog = "";
let adopted = false;

/**
 * The daemon refuses to start when its ports are taken, and says which ones.
 */
function busyApiPort(log: string): number | null {
  if (!log.includes("already in use")) return null;
  const match = /api port (\d+)/.exec(log);
  return match ? Number(match[1]) : null;
}

/**
 * Locate the daemon. A packaged build ships it as a frozen binary next to the
 * app; a source checkout falls back to the project virtualenv.
 */
function resolveDaemon(): {
  command: string;
  args: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
} {
  const override = process.env.INTERCEPT_DAEMON;
  if (override) {
    return { command: override, args: [] };
  }

  const packaged = join(process.resourcesPath ?? "", "daemon", "intercept");
  if (existsSync(packaged)) {
    return { command: packaged, args: [] };
  }

  // Walk up from the bundle looking for the python package.
  let dir = __dirname;
  for (let depth = 0; depth < 8; depth += 1) {
    const candidate = join(dir, "src", "intercept", "__init__.py");
    if (existsSync(candidate)) {
      const venvPython = join(dir, ".venv", "bin", "python");
      const python = existsSync(venvPython) ? venvPython : "python3";
      return {
        command: python,
        args: ["-m", "intercept", "serve"],
        cwd: dir,
        env: { ...process.env, PYTHONPATH: join(dir, "src") },
      };
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return { command: "intercept", args: ["serve"] };
}

function startDaemon(): void {
  const { command, args, cwd, env } = resolveDaemon();
  const child = spawn(command, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
  daemon = child;
  daemonLog = "";
  adopted = false;

  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    process.stdout.write(`[daemon] ${chunk}`);
    for (const line of chunk.split("\n")) {
      if (!line.trim().startsWith("{")) continue;
      try {
        const message = JSON.parse(line);
        if (message.event === "api-ready") {
          apiBase = message.url;
          connectStream();
          mainWindow?.webContents.send("daemon-status", { state: "running" });
        }
      } catch {
        /* not a status line */
      }
    }
  });

  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    daemonLog = (daemonLog + chunk).slice(-4000);
    process.stderr.write(`[daemon] ${chunk}`);
  });

  child.on("exit", (code) => {
    if (daemon === child) daemon = null;

    const port = busyApiPort(daemonLog);
    if (port !== null) {
      void adoptRunningDaemon(port);
      return;
    }

    mainWindow?.webContents.send("daemon-status", { state: "stopped", code });
    if (restartTimer) clearTimeout(restartTimer);
    restartTimer = setTimeout(startDaemon, 1500);
  });
}

/**
 * Another daemon already owns the ports. Attach to it instead of restarting
 * forever against a port it can never win.
 */
async function adoptRunningDaemon(port: number): Promise<void> {
  const candidate = `http://127.0.0.1:${port}`;
  try {
    const response = await fetch(`${candidate}/api/health`);
    if (!response.ok) throw new Error(String(response.status));
  } catch {
    mainWindow?.webContents.send("daemon-status", { state: "stopped", code: 1 });
    if (restartTimer) clearTimeout(restartTimer);
    restartTimer = setTimeout(startDaemon, 1500);
    return;
  }

  apiBase = candidate;
  adopted = true;
  connectStream();
  mainWindow?.webContents.send("daemon-status", { state: "running", adopted: true });
}

function connectStream(): void {
  if (!apiBase) return;
  const url = apiBase.replace(/^http/, "ws") + "/ws";
  socket = new WebSocket(url);

  socket.on("message", (data) => {
    let payload: unknown;
    try {
      payload = JSON.parse(data.toString());
    } catch {
      return;
    }
    mainWindow?.webContents.send("daemon-event", payload);
  });

  socket.on("close", () => {
    socket = null;
    if (daemon || adopted) setTimeout(connectStream, 1000);
  });

  socket.on("error", () => {
    socket?.close();
  });
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 950,
    backgroundColor: "#0f1115",
    title: "Intercept",
    webPreferences: {
      preload: join(__dirname, "..", "preload", "index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  if (DEV_SERVER) {
    void mainWindow.loadURL(DEV_SERVER);
  } else {
    void mainWindow.loadFile(join(__dirname, "..", "..", "renderer", "index.html"));
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

ipcMain.handle("daemon:info", () => ({
  apiBase,
  state: apiBase ? "running" : "stopped",
}));

ipcMain.handle("daemon:request", async (_event, payload: DaemonRequest) => {
  if (!apiBase) throw new Error("the daemon is not reachable yet");
  const response = await fetch(`${apiBase}${payload.path}`, {
    method: payload.method,
    headers: { "Content-Type": "application/json" },
    body: payload.body === undefined ? undefined : JSON.stringify(payload.body),
  });
  const text = await response.text();
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const parsed = JSON.parse(text);
      detail = parsed.detail ?? detail;
    } catch {
      if (text) detail = text;
    }
    throw new Error(detail);
  }
  return text ? JSON.parse(text) : undefined;
});

ipcMain.handle("daemon:text", async (_event, path: string) => {
  if (!apiBase) throw new Error("the daemon is not reachable yet");
  const response = await fetch(`${apiBase}${path}`);
  if (!response.ok) throw new Error(response.statusText);
  return response.text();
});

ipcMain.on("shell:open", (_event, url: string) => {
  void shell.openExternal(url);
});

app.whenReady().then(() => {
  startDaemon();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  socket?.close();
  daemon?.kill();
});

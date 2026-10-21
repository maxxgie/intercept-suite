// Manual check of the desktop shell's "attach to a running daemon" logic.
//
// It starts one daemon, starts a second one against the same ports, and
// replays the parsing and health check the Electron main process performs.
const { spawn } = require("node:child_process");
const path = require("node:path");

const DAEMON = process.argv[2] ?? path.join(__dirname, "..", "dist", "intercept", "intercept");
const API_PORT = Number(process.argv[3] ?? 9087);
const PROXY_PORT = Number(process.argv[4] ?? 8087);

function busyApiPort(log) {
  if (!log.includes("already in use")) return null;
  const match = /api port (\d+)/.exec(log);
  return match ? Number(match[1]) : null;
}

function startDaemon(args) {
  const child = spawn(DAEMON, args, { stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  return child;
}

async function waitForApi(port, seconds = 20) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (response.ok) return await response.json();
    } catch {
      /* not up yet */
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`the daemon did not answer on port ${port}`);
}

async function main() {
  const first = startDaemon(["serve", "--port", String(PROXY_PORT), "--api-port", String(API_PORT)]);
  const health = await waitForApi(API_PORT);
  console.log("first daemon:", health.status);

  const second = startDaemon(["serve", "--port", String(PROXY_PORT), "--api-port", String(API_PORT)]);
  let log = "";
  second.stdout.setEncoding("utf8");
  second.stdout.on("data", (chunk) => process.stdout.write(`[daemon] ${chunk}`));
  second.stderr.setEncoding("utf8");
  second.stderr.on("data", (chunk) => {
    log += chunk;
    process.stderr.write(`[daemon] ${chunk}`);
  });

  const code = await new Promise((resolve) => second.on("exit", resolve));
  const port = busyApiPort(log);
  console.log("second daemon exit code:", code);
  console.log("parsed api port:", port);

  if (port !== API_PORT) {
    console.log("FAIL: the api port was not parsed");
    process.exitCode = 1;
  } else {
    const adopted = await waitForApi(port);
    console.log("adopted health:", adopted.status);
    if (adopted.status !== "ok") {
      console.log("FAIL: the running daemon is not usable");
      process.exitCode = 1;
    } else {
      console.log("PASS: the running daemon can be adopted");
    }
  }

  first.kill("SIGTERM");
}

main().catch((error) => {
  console.log("FAIL:", error.message);
  process.exitCode = 1;
});

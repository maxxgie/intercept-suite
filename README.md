# Intercept

An extensible web application security proxy and testing workbench, built from
scratch: a Python engine that intercepts and replays HTTP traffic, and an
Electron desktop shell that drives it.

The design goal is a *workbench*, not a single tool. The proxy, the repeater,
the site map and every future scanner share one request model, one event bus
and one history, and any of them can be extended with a plugin.

```
browser  ──HTTP(S)/2──▶  proxy engine  ──HTTP(S)/2──▶  origin
                          │
                          ├── history (SQLite)
                          ├── event bus ──▶ WebSocket ──▶ desktop UI
                          └── tools (repeater, fuzzer, scanner, spider, plugins)
```

## What it does today

| Capability | Status |
| --- | --- |
| Forward proxy with absolute-form requests | Working |
| `CONNECT` tunnels terminated with a locally issued certificate | Working |
| HTTP/2: ALPN negotiation, multiplexed streams, HTTP/2 to the origin | Working |
| Traffic history with byte-level raw requests and responses | Working |
| Live traffic view with pretty/headers/body/raw inspectors | Working |
| Repeater: edit a request, resend it, keep every attempt | Working |
| Fuzzer (Intruder): mark positions, send payloads, diff the answers | Working |
| Scanner: active and passive checks, findings with severities | Working |
| Site map built from observed traffic, with scope rules | Working |
| Spider: crawl in-scope links | Working |
| Interactive interception: hold a request and decide what happens | Working |
| WebSocket history: connections and every frame, in both directions | Working |
| Filter language over the whole workspace, with a command palette | Working |
| Notes, issues, targets, sessions, tasks and project files | Working |
| Report generator: Markdown, HTML and JSON | Working |
| Plugin API for tools, checks and event hooks | Working |
| Frozen daemon binary and packaged desktop application | Working |

## Quick start

```bash
git clone <this repo> && cd intercept
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Run the daemon on its own:

```bash
.venv/bin/intercept serve
# proxy listening on 127.0.0.1:8080
# ca fingerprint 8A1F...
# api listening on http://127.0.0.1:9000
```

If a daemon is already holding the ports, it says so in one line instead of
failing with a traceback:

```
cannot start: proxy port 8080 and api port 9000 is already in use.
Another daemon is probably running. Stop it, or start this one on
different ports, for example:
  intercept serve --port 8081 --api-port 9001
```

The desktop shell handles that case on its own: when the daemon reports the
ports are taken, it attaches to the instance that is already running instead of
restarting in a loop.

Then point a browser at the proxy and trust the certificate authority:

```bash
.venv/bin/intercept ca export --out ~/intercept-ca.crt
```

### Trusting the certificate in a browser

The proxy presents its own certificate for every site it intercepts, so the
browser has to trust the root CA before it will show the real page. Ask the
tool which trust stores it can reach on this machine:

```bash
.venv/bin/intercept ca install --list
```

and install it into all of them:

```bash
.venv/bin/intercept ca install
```

That writes the certificate into the stores the browsers on this machine
actually read:

| Target | Browsers | How |
| --- | --- | --- |
| `nss` | Chrome, Chromium, Brave, Edge on Linux | `certutil` into `~/.pki/nssdb` |
| `system` | Everything that reads the operating system store | `/etc/pki/ca-trust/source/anchors` on Fedora, `/usr/local/share/ca-certificates` on Debian, the login keychain on macOS, the root store on Windows |
| `firefox` | Firefox | the profile's `cert9.db`, or the import button in the settings |

When a store cannot be written the command says so and prints the exact
command to run by hand, for example:

```
sudo dnf install nss-tools
certutil -d sql:/home/you/.pki/nssdb -A -n Intercept -t CT,C,C -i /home/you/.intercept/ca.crt
```

`intercept ca install --deps` installs the missing system packages for you
(it uses `sudo`). The desktop shell offers the same thing under
**Settings → Trust in browsers**, next to the button that downloads the
certificate.

Finally, point the browser at the proxy:

| Browser | Setting |
| --- | --- |
| Chrome, Chromium, Brave, Edge | Settings → System → Open your computer's proxy settings |
| Firefox | Settings → Network → Manual proxy, HTTP and HTTPS `127.0.0.1`, port `8080` |

Run the desktop shell (it starts and supervises the daemon itself):

```bash
cd apps/desktop
npm install
npm run dev
```

## Using it

The sidebar groups the work into five groups. The command bar at the top holds
the filter that applies to the whole workspace, the intercept switch and the
command palette (`Ctrl K`).

**Workspace**

* **Dashboard** summarises the engagement: exchanges, findings, issues, notes,
  websocket frames and the state of the event log.
* **Organizer** groups the traffic by host and path. One click turns a row into
  a filter, so a host can be narrowed down without typing an expression.
* **Project files** keeps the history, the notes, the issues and the scope of an
  engagement together in one directory that can be saved and reopened.

**Traffic**

* **HTTP history** lists every exchange the proxy has seen. Click one to inspect
  the request and the response, or send it to the repeater.
* **WebSocket history** shows the connections that were upgraded and every frame
  that crossed them, in both directions.
* **Site map** shows the hosts and paths that have been discovered, with scope
  rules deciding what the spider is allowed to visit.
* **Targets** records the hosts under test, the ports that matter and whether
  each one is in scope.

**Attack**

* **Repeater** lets you edit a request and resend it. Every attempt is kept, so
  two responses can be compared.
* **Fuzzer** fires many payloads at one request. Mark the interesting spot with
  `§name§` in the URL, a header value or the body, list the payloads and the
  fuzzer sends one request per payload and points out the answers that differ.
* **Scanner** runs checks against a target. Active checks send their own
  requests, passive checks read the traffic that was already observed.
* **Findings** collects everything the scanner reported, filterable by severity.

**Work**

* **Issue tracker** holds the problems that were found, with a severity and a
  status that can be moved as the investigation goes on.
* **Notes** attaches remarks and highlights to the things that were seen.
* **Task scheduler** runs a command on an interval. Every run is counted and
  the last error is kept.
* **Reports** collects the findings, the issues, the notes and the scope into a
  report that can be read as Markdown, HTML or JSON.
* **Event log** records what the daemon did, filterable by level and source.

**Tools**

* **Browser** fetches a page through the proxy, so everything it loads ends up
  in the same history as the traffic from a real browser.
* **Extensions** lists the tools contributed by plugins.
* **Settings** shows the proxy, the certificate authority and the trust stores
  the certificate can be installed into.

Turn on **Intercept** in the command bar to hold every request. The daemon will
not forward a held request until it is answered through the API, which is what
makes request smuggling and cache poisoning analysis possible.

### The filter

The filter uses a small expression language. Bare words match case
insensitively, quoted words match exactly:

```
host == "example.com" and status >= 400
method == POST and not path contains "/logout"
request =~ "(?i)password"
highlighted
```

The fields are `host`, `path`, `method`, `status`, `mime`, `size`, `time`,
`extension`, `tags`, `notes`, `request`, `response`, `highlighted`, `level`,
`component` and `message`. A broken expression is reported in the command bar
and the last working one keeps applying.

## HTTP/2

The proxy offers `h2` and `http/1.1` through ALPN, so a browser negotiates
HTTP/2 with it just like with a normal web server. Every stream of a tunnelled
connection is forwarded independently, so a slow origin only blocks its own
stream. The upstream leg stays HTTP/2 when the origin advertises it and falls
back to HTTP/1.x when it does not.

Set `proxy.http2` to `false` in the configuration to turn the whole thing off.

## Packaging

```bash
make package
```

This freezes the daemon with PyInstaller into `dist/intercept/` and builds the
Electron application around it. The desktop shell ships the frozen daemon as
`resources/daemon/intercept` and starts it automatically.

## Layout

```
src/intercept/        the engine
  core/               request and response model, filters, commands, reports, event bus
  crypto/             certificate authority and trust store installation
  proxy/              the proxy engine: parser, HTTP/2, upstream pool, interception, websockets
  store/              traffic history, findings, notes, issues, targets, tasks, projects, sessions
  tools/              repeater, fuzzer, spider, shared client
  scanner/            check framework and scan engine
  plugins/            plugin API and manager
  api/                REST and WebSocket API
apps/desktop/         the Electron shell and React interface
packaging/            the PyInstaller specification for the daemon
plugins/examples/     a worked example plugin
docs/                 architecture and plugin authoring notes
```

## Documentation

* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how the pieces fit together
* [docs/PLUGINS.md](docs/PLUGINS.md) — writing your own tools
* [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — running, testing and debugging

## Scope and safety

This tool is built for testing systems you are authorised to test. It
intercepts TLS by design, which means it must be installed into the trust
store of the client you want to intercept — treat the generated CA key as
sensitive material. The daemon binds to `127.0.0.1` and the API is reachable
only from the local machine.

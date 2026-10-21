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
| Repeater: compare two attempts and read how long each of them took | Working |
| Repeater: send over HTTP/2 and hold a WebSocket connection | Working |
| Hex view of a body, and a body that is not text keeps its bytes | Working |
| Fuzzer (Intruder): mark positions, send payloads, diff the answers | Working |
| Scanner: active and passive checks, findings with severities | Working |
| Scanner: crawls the target and probes the places that take input | Working |
| Scanner: injection, auth, token, GraphQL and web hardening checks | Working |
| Site map built from observed traffic, with scope rules | Working |
| Spider: crawl in-scope links | Working |
| Interactive interception: hold a request and decide what happens | Working |
| Interception of the response, with the status, headers and body edited | Working |
| Rules: intercept, auto-forward and match and replace, with globs | Working |
| WebSocket history: connections and every frame, in both directions | Working |
| WebSocket frame interception, with the payload edited or the frame dropped | Working |
| Listeners: an HTTP proxy, a SOCKS5 proxy and a Linux transparent proxy | Working |
| Chaining the traffic through an HTTP or a SOCKS5 upstream proxy | Working |
| Tags and notes on the request and on the response of an exchange | Working |
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
  Four attack types spread the payloads over the positions: **sniper** works on
  one position at a time, **battering ram** sends the same payload everywhere,
  **pitchfork** walks the positions together and **cluster bomb** tries every
  combination. Payloads come from generators (a list, numbers, dates, brute
  force, character substitution, a recursive grep over a folder, a wordlist file
  or a custom template) and processing rules rewrite them before they are sent
  (URL encoding, base64, hashing, a prefix, a suffix, a replacement or a regex
  extraction). A **grep match** marks the answers that hold a string and a
  **grep extract** takes a pattern out of them. The table shows the status, the
  length, the time, the difference against the baseline and the words that only
  appear in the answer.
* **Scanner** runs checks against a target. Active checks send their own
  requests, passive checks read the traffic that was already observed.
  A scan first crawls the target to find the pages, the forms and the
  parameters that take input, and then runs the checks against them. The
  checks cover SQL injection, cross site scripting, XML external entities,
  server side request forgery, server side template injection, OS command
  injection, LDAP and NoSQL injection, path traversal, local and remote file
  inclusion, open redirects, prototype pollution, unsafe deserialization,
  GraphQL (open introspection, batching, field suggestions), authentication
  and user enumeration, JWT (alg=none, weak secrets, tokens that never
  expire, secrets in the claims), OAuth (an open redirect in the redirect URI,
  a missing state, a missing PKCE), IDOR, clickjacking, weak content security
  policies, cookie weaknesses, cache poisoning, HTTP request smuggling,
  prototype and header misconfigurations, file upload flaws, XML issues and
  DOM based XSS. Every finding carries a severity, the evidence that was seen
  and the way to fix it.
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

### The repeater

**Repeater** holds the requests you want to try again. Every tab keeps its own
request, its latest answer and the whole list of attempts, so a change can be
tried and compared with what came before.

* The request is edited as raw HTTP, and the answer is shown as pretty text,
  headers, body, a hex dump or the raw message.
* **HTTP/2** sends the request over HTTP/2 when the origin offers it through
  ALPN, and over HTTP/1.1 when it does not.
* **Attempts** lists every send with the time it took, draws the time as a bar
  against the slowest one, and marks the lines that differ between two
  attempts. An earlier attempt can be sent again from there.
* A request that asks for a WebSocket upgrade opens a connection of its own.
  The frames that are sent and the frames that come back are shown side by
  side, with the payload as text or as a hex dump.

A body that is not text keeps its bytes: it travels as base64 and reaches the
interface unchanged, so the hex view shows what was really on the wire.

### Rules

**Proxy Rules** decides what the intercept switch does. A rule matches on the
host, the path and the method, and each field is a glob, so `*.example.com` and
`/api/*` cover most of what is needed. An empty field matches everything.

| Kind | What it does |
| --- | --- |
| Intercept | Holds the matching request, the matching response, or both |
| Auto forward | Lets the matching request through without asking |
| Match and replace | Rewrites a header, a body or a URL on the way past |

Without a single intercept rule the switch holds everything, which is the
behaviour the tool has always had. A replace rule may use a regular expression
and may refer to the text it matched with `\1`.

### Listeners and upstream proxies

**Settings** opens extra listeners next to the main one. An HTTP listener is an
ordinary forward proxy, a SOCKS5 listener speaks SOCKS, and the transparent
listener is for Linux, where the traffic is redirected to it by the network and
the original destination is recovered from the socket. A listener that is added
or removed takes effect at once, without a restart.

The same page chains the traffic through an upstream proxy, which is either an
HTTP forward proxy or a SOCKS5 one. An encrypted origin is reached by opening a
tunnel through the proxy first and running the TLS handshake on top of it, so
the origin still sees an ordinary client.

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

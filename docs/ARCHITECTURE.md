# Architecture

## The shape of the system

Intercept is two processes that talk over a local HTTP API.

```
┌─────────────────────────────────────────────────────────────────┐
│ Electron shell (apps/desktop)                                   │
│   main process ── spawns and supervises the daemon              │
│   main process ── owns the HTTP client and the event stream     │
│   renderer    ── pure view, no network access                   │
└───────────────┬─────────────────────────────────────────────────┘
                │  REST + WebSocket on 127.0.0.1:9000
┌───────────────▼─────────────────────────────────────────────────┐
│ Daemon (src/intercept)                                          │
│   api/          REST + WebSocket                               │
│   proxy/        listener, CONNECT handling, HTTP/2, upstream pool│
│   tools/        repeater, fuzzer, spider                        │
│   scanner/      check framework and scan engine                 │
│   plugins/      registry and execution                         │
│   store/        history, findings, workspace stores, scope      │
│   core/         model, events, config, filters, commands        │
└───────────────┬─────────────────────────────────────────────────┘
                │
        ┌───────┴────────┐
        │                │
   origin server     SQLite history
```

The renderer never opens a socket. Every call it makes is forwarded to the
main process over IPC, and the main process performs the request. That keeps
the daemon's CORS policy closed, lets the page keep a strict content security
policy, and means the UI cannot be tricked by a hostile page into talking to
the daemon on the user's behalf.

The daemon refuses to start when its ports are taken and says which ones. The
main process reads that answer, health checks the daemon that is already
running and attaches to it instead of restarting against a port it can never
win; the status bar then shows that the window is attached to another
instance.

## The engine

### The request model

`core/models.py` defines `Headers`, `Request`, `Response` and `Exchange`.
`Headers` is an ordered, case-insensitive, multi-value collection that keeps
duplicates, because the tool shows the user exactly what went over the wire.
`Exchange` pairs a request with its response and is the unit of storage.

### The parser

`proxy/http1.py` is a hand written HTTP/1.x parser. It was written rather
than taken from a library for two reasons:

* **Fidelity.** The parser keeps the original header block *and* the original
  body bytes, including chunk framing, so the "raw" view is the real wire
  format rather than a re-serialisation of a decoded body.
* **Hostility.** A security tool is pointed at malformed input, so the parser
  is written to survive it. Conflicting `Content-Length` headers are reported
  as warnings rather than being silently resolved, because that ambiguity is
  itself a finding.

`proxy/stream.py` provides a buffered reader with pushback. The `CONNECT`
handler needs it: the header block must be consumed without swallowing the
first bytes of the TLS handshake that follows.

### Interception

`proxy/server.py` handles both entry paths — absolute-form forward proxy
requests and `CONNECT` tunnels — and converges on one code path:

1. Frame the request.
2. Optionally hold it for the user (`proxy/intercept.py`).
3. Forward it through the upstream pool.
4. Record the exchange.

For `CONNECT`, the tunnel is terminated locally with a certificate issued by
`crypto/ca.py` and the inner requests are handled exactly as plain ones. The
upstream side of a tunnel is re-encrypted with the origin's own certificate,
so the origin sees an ordinary client.

Upstream connections are pooled per origin in `proxy/upstream.py` and reused
while the origin allows keep-alive.

### HTTP/2

`proxy/h2.py` wraps `hyper-h2` in two roles:

* `H2ServerConnection` terminates the client side of a tunnelled connection.
  The browser speaks HTTP/2 to us over the TLS tunnel we opened.
* `H2ClientConnection` speaks HTTP/2 to the origin, so the upstream leg stays
  HTTP/2 when the origin offers it.

The CA offers `h2` and `http/1.1` through ALPN, so a browser negotiates HTTP/2
with the proxy exactly as it would with a web server. The negotiated protocol
is read back from the TLS session and decides which code path the connection
takes.

Every stream of a tunnelled connection is forwarded independently: a request
arrives, its stream is forwarded, and the response is written back on the same
stream. A slow origin therefore only blocks its own stream.

The upstream side follows the same idea. `UpstreamPool.send_h2` opens one
multiplexed HTTP/2 connection per origin when the origin advertises `h2` and
falls back to the HTTP/1.x pool when it does not. The fallback is only taken
when the origin never offered HTTP/2 — a request that was already sent over a
broken HTTP/2 connection is never replayed, because that could repeat a side
effect.

Pseudo-headers are kept in the model so the user can see them, and stripped
before the request goes on the wire. HTTP/2 forbids connection-specific
headers, so `Connection`, `Keep-Alive`, `Transfer-Encoding` and `Upgrade` are
dropped on the way out.

### Tools share the proxy's machinery

The repeater, the fuzzer, the spider and the scanner do not use a separate HTTP
client. They send through the same `UpstreamPool` the proxy uses, which means:

* a request produced by the repeater is framed exactly like one a browser
  sent;
* tool traffic lands in the same history as browser traffic, distinguished by
  its `origin` field (`proxy`, `repeater`, `fuzzer` or `spider`);
* `Content-Length` is re-derived from the body on every send, so a body
  edited in the repeater is sent with a length that matches.

### The fuzzer

`tools/fuzzer.py` works on a *template*: a request in which the user marked
positions with `§name§`. A position may live in the URL, in a header value or
in the body. The fuzzer sends one request per payload for every position and
compares each answer with the first one it received. A response that changes
the status code, changes the length or contains words the baseline did not have
is marked as interesting.

The template is a normal `Request`, so the fuzzer reuses the request model
rather than inventing a second one.

### The scanner

`scanner/checks.py` holds the checks and `scanner/engine.py` runs them. There
are two kinds:

* an *active* check sends its own requests to the target;
* a *passive* check looks at a request and response that were already observed.

Passive checks run over every exchange the proxy records, so a plain browsing
session already produces findings. Active checks run as part of a scan job,
which is a background task that reports progress on the event bus.

Both kinds produce `plugins.api.Finding` objects, so a plugin that registers a
check behaves exactly like a built in one. `store/findings.py` keeps the
findings in their own table so a scan history survives a restart.

### Storage

`store/history.py` writes exchanges to SQLite. Writes are queued and performed
by a background task so the proxy hot path never blocks on disk, and the batch
is committed as soon as the queue drains so the interface stays live. The
traffic list is served from this table, not from memory, so it survives a
restart.

`store/sitemap.py` derives the site map from the same table and holds the
scope rules. Scope rules are glob patterns (with an optional `re:` prefix) and
are evaluated with excludes winning over includes; with no include rule a
scope is closed, so a target has to be opened deliberately.

`store/findings.py` keeps the scanner findings in a second table. The two
stores are separate on purpose: traffic is a high volume, append-only log
that is cleared often, findings are a low volume record that is kept.

### The workspace stores

Everything the analyst produces around the traffic lives in its own store, each
one a thin table on top of `store/sqlite.py`:

| Module | Holds |
| --- | --- |
| `store/logger.py` | the event log, bounded, filterable by level and source |
| `store/notes.py` | notes and highlights attached to an exchange, finding or site |
| `store/issues.py` | the issues that were raised, with a severity and a status |
| `store/targets.py` | the hosts under test, their ports and their scope |
| `store/sessions.py` | named groups of exchanges, plus the permanent live session |
| `store/tasks.py` | scheduled commands and the scheduler that runs them |
| `store/project.py` | the project registry and the files a project is saved as |
| `store/websockets.py` | the WebSocket connections and the frames that crossed them |

The workspace is driven by three pieces of shared machinery. `core/filters.py`
parses the filter expression and evaluates it against an exchange row;
`core/commands.py` is the registry the command palette, the context menus, the
keyboard shortcuts and the scheduler all call into; `core/reports.py` collects
the findings, issues, notes and scope into one document that can be rendered as
Markdown, HTML or JSON.

The commands live in `intercept/commands.py` rather than in the registry, so
the built-ins are listed next to each other and a plugin can add its own
through the same registry.

### Events

`core/events.py` is a small publish/subscribe bus with a bounded replay
buffer. The proxy emits on it; the API forwards to WebSocket clients. The bus
is deliberately synchronous and never blocks: a slow consumer loses the oldest
event instead of stalling the proxy.

## The plugin system

`plugins/api.py` defines the contract and `plugins/manager.py` implements it.
A plugin is a directory with a `plugin.toml` manifest and a `register(api)`
function. The API it receives can add tools, add active checks and subscribe
to event hooks.

Tool descriptors carry their own field definitions, so the desktop shell
generates a form for a plugin it has never seen. A plugin that raises during
loading is reported and skipped; it can never take the daemon down.

See [PLUGINS.md](PLUGINS.md) for the details.

## Design decisions worth knowing

**The daemon owns the network, the shell owns the process.** The daemon could
have served the interface itself, but keeping the UI in a separate process
means a crash in the interface cannot lose the proxy, and the proxy can be
driven by scripts with no UI at all.

**Raw bytes are preserved, not reconstructed.** Every place where a message
could be re-serialised instead keeps the original bytes.

**Failures are data.** A connection error becomes a 502 exchange with the
error recorded, not a dropped connection. A malformed request becomes a 400
with the reason attached. The history should show what actually happened.

**Tools are ordinary requests.** The fuzzer, the scanner and the comparator are
built on the same `ToolClient` and the same `Exchange` model, so the interface
does not need a new concept for each of them.

## Packaging

`packaging/intercept.spec` freezes the daemon with PyInstaller into
`dist/intercept/`. The example plugins travel with the bundle as data, and
`plugins/manager.py` looks for them next to the bundle when it runs frozen and
in the repository otherwise.

The desktop shell ships that folder as `resources/daemon/` and starts
`resources/daemon/intercept` as a child process. The frozen binary starts the
proxy and the API when it is run without arguments, which is why the command
line defaults to the `serve` subcommand.

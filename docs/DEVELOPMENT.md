# Development

## Setting up

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e ".[dev]"
cd apps/desktop && npm install
```

The `--system-site-packages` flag is only needed on machines where the
required libraries are already installed system wide. A plain virtualenv works
just as well.

## Running

| Command | What it does |
| --- | --- |
| `.venv/bin/intercept serve` | Runs the daemon on its own |
| `cd apps/desktop && npm run dev` | Runs the shell, which starts the daemon |
| `cd apps/desktop && npm run build` | Builds the interface and the Electron bundles |
| `cd apps/desktop && npm run typecheck` | Type checks the renderer |
| `bash scripts/build_daemon.sh` | Freezes the daemon into `dist/intercept/` |
| `make package` | Freezes the daemon and builds the distributable app |

The shell looks for the daemon by walking up from the bundle until it finds
`src/intercept`, then uses the virtualenv in that directory. A packaged build
ships the frozen binary as `resources/daemon/intercept` instead. Set
`INTERCEPT_DAEMON` to point at a different executable, or `INTERCEPT_HOME` to
move the certificate authority and database.

### When the ports are already taken

The daemon checks its ports before it binds and reports a conflict in one line
rather than raising:

```
cannot start: proxy port 8080 and api port 9000 is already in use.
```

The desktop shell reads that message. If the API answers a health check on the
port the daemon complained about, the shell attaches to the instance that is
already running and keeps the interface usable. Only when nothing answers does
it fall back to restarting the daemon.

### Trust stores

`intercept/crypto/install.py` knows how each platform stores trust:

| Platform | System store | Command |
| --- | --- | --- |
| Fedora, RHEL | `/etc/pki/ca-trust/source/anchors` | `update-ca-trust extract` |
| Debian, Ubuntu | `/usr/local/share/ca-certificates` | `update-ca-certificates` |
| SUSE | `/usr/share/ca-certificates` | `update-ca-certificates` |
| Arch | `/etc/ca-certificates/trust-source/anchors` | `trust extract-compat` |
| macOS | the login keychain | `security add-trusted-cert` |
| Windows | the root store | `certutil -addstore -f Root` |

Chrome, Chromium, Brave and Edge on Linux read the NSS database in
`~/.pki/nssdb` instead, which is written with `certutil` from the `nss-tools`
package. Firefox keeps its own `cert9.db` in every profile.

Every target reports whether it can be written on this machine and carries the
exact commands to run by hand, so the tool is still useful without `certutil`
or root access.

## Testing

```bash
.venv/bin/python -m pytest            # the whole suite
.venv/bin/python -m pytest tests/test_proxy.py -v
.venv/bin/python -m ruff check src tests plugins scripts
.venv/bin/python scripts/smoke.py      # end to end against a live daemon
node scripts/check_adopt.js            # the desktop shell's attach-to-a-running-daemon path
```

The suite starts real servers on loopback: a tiny origin server for the proxy
to talk to, and the daemon itself. Nothing reaches the network.

`tests/test_proxy.py` is the important one. It covers plain forwarding, the
`CONNECT` interception path with a real TLS handshake, holding a request and
answering it, dropping a request, and the repeater.

`tests/test_http2.py` does the same for HTTP/2: it runs a real HTTP/2 origin
and drives the proxy with an HTTP/2 client over a `CONNECT` tunnel, including
the fallback to HTTP/1.x against an origin that does not speak HTTP/2.

`tests/test_tools_fuzz.py` covers the fuzzer, the scanner and the findings
store.

`tests/test_sequencer.py` covers the sequencer: the measures (entropy, the chi
square, the serial correlation, the Monte Carlo estimate of pi, the bit bias and
the longest run), the verdicts for random samples, counters, repeated tokens and
tokens that hold a clock, and the forgery of a JSON web token.

`tests/test_decoder.py` covers the decoder: every conversion in both
directions, the digests, the recognition of a hash, the chains and the smart
decode.

`tests/test_workspace.py` covers the workspace layer: the filter language, the
command registry, the event log, the notes, the issues, the sessions, the
targets, the tasks, the projects, the report generator, the WebSocket framing
and the API endpoints that sit on top of them.

`scripts/smoke.py` starts a real daemon against a real origin and walks
through every capability, from plain forwarding to the workspace endpoints the
interface calls. Run it after a change that touches the API.

## Debugging

Run the daemon in a terminal to see its logs:

```bash
.venv/bin/intercept --log-level DEBUG serve
```

The API is browsable at `http://127.0.0.1:9000/docs` while the daemon runs.

Useful checks:

```bash
.venv/bin/intercept doctor            # dependency and port check
.venv/bin/intercept ca fingerprint    # the CA your client has to trust
curl -x http://127.0.0.1:8080 http://example.com/   # a request through the proxy
```

## Adding a tool to the engine

Tools live in `src/intercept/tools/` and are wired up in `app.py`. A tool
gets a `ToolClient`, which sends through the same upstream pool the proxy
uses, so its traffic is recorded in the same history and framed the same way.

A tool that produces its own requests should:

* build a `Request` from `core.models`;
* send it with `ToolClient.send`;
* let the client record the exchange, rather than writing to the store itself.

To surface a tool in the interface, expose it through the REST API and add a
view under `apps/desktop/renderer/src/components/`.

## Adding a measure to the sequencer

The sequencer lives in `src/intercept/tools/sequencer.py`. It works on a list
of samples of the same token: every sample is measured on its own and the
samples are looked at together.

A measure is a plain function over bytes that returns a number, and it is added
to `Sequencer.analyse` and to the report:

```python
def longest_run(data: bytes) -> int:
    """The longest run of the same byte in the data."""
    ...
```

The report is the only thing the API and the interface see, so a new measure
belongs in `SequencerReport` as well, with its value in `to_dict()`. A note
that explains what the measure means goes into `_judge`, where the notes and
the score are worked out.

The measures are taken over the part of the samples that changes, which
`_random_parts` works out from the prefix and the suffix that all the samples
share. A measure that says something is wrong takes points off the score, and
the note that goes with it tells the reader why.

The verdicts are `random`, `weak` and `predictable`. A measure that says
something is wrong takes points off the score, and the note that goes with it
tells the reader why.

## Adding a decoding to the decoder

The decoder lives in `src/intercept/tools/decoder.py`. A conversion is a
function that takes the text and gives the text back, and it is put in the two
maps that hold them:

```python
def _decode_base32(value: str) -> str:
    """Take a base32 value apart."""
    ...


_DECODERS = {
    ...
    "base32": _decode_base32,
}

_ENCODERS = {
    ...
    "base32": _encode_base32,
}
```

A decoder that cannot make sense of the value raises `DecoderError`, and the
API turns that into a message that says why. A kind that is added to
`TRANSFORM_KINDS` and to `KIND_LABELS` shows up in the interface, in the
example plugin and in the smart decode, which tries every kind and ranks the
answers.

## Adding a scanner check

Checks live in `src/intercept/scanner/`. A check that asks the server about
itself lives in `checks.py`, one that probes a place that takes input lives in
`injection.py`, `appsec.py`, `authsec.py` or `graphql.py`. An active check
sends its own requests, a passive check inspects traffic that was already
observed.

An active check says where it belongs with `scope`:

* `scope = "host"` runs once per target, which suits the questions about the
  server itself (the headers it sets, the files it serves);
* `scope = "endpoint"` runs for every endpoint the crawl found, which suits
  the checks that need input to work with.

```python
class MyCheck(ActiveCheck):
    id = "my.check"
    label = "My check"
    severity = "medium"
    category = "custom"
    scope = "host"

    async def run(self, client: ToolClient, target: Endpoint) -> list[Finding]:
        response = await client.send(Request(method="GET", url=target.url))
        if response.status == 0:
            return []
        return [Finding(check_id=self.id, title="...", url=target.url)]
```

An endpoint check gets an `Endpoint`, which carries the URL, the method, the
query parameters, the form fields and the cookies of the place. Replacing one
of them is a copy of the endpoint:

```python
probe = target.with_parameter("id", "' OR '1'='1")
response = await client.send(probe.request())
```

The base class `InjectionCheck` in `injection.py` does that for you: it sends
the endpoint unchanged to get a baseline, sends it again with one parameter
replaced and calls `detect` to judge the answer.

Register a check by adding an instance to `BUILTIN_CHECKS`. A plugin can
register a check through `api.add_check(...)` instead; the scanner picks up
every registered check when the daemon starts.

## Packaging

```bash
bash scripts/build_daemon.sh
```

PyInstaller freezes `src/intercept/__main__.py` into `dist/intercept/`. The
example plugins are bundled as data, so the frozen daemon finds them through
`sys._MEIPASS`. The desktop shell copies that folder into
`resources/daemon/` at package time.

## The desktop shell

The renderer is a pure view. It never makes a network request: it calls
`window.intercept.request(method, path, body)`, which the preload script
forwards to the main process over IPC, and the main process performs the
call. Events travel the other way, from the daemon's WebSocket, through the
main process, to the renderer.

Keeping the renderer network-free means the daemon's CORS policy can stay
closed and the page can keep a strict content security policy. It also means
a new API call needs a preload change, which keeps the surface the interface
can reach small and explicit.

### The views

The sidebar is built from `NAV_GROUPS` in `renderer/src/state/store.ts`, and
every view lives in `renderer/src/components/`. A view is a plain React
component that reads from the store and writes through it; the store owns the
API calls, so a view never talks to the daemon directly.

`npm run typecheck` checks the renderer. `npm run build:renderer` produces the
bundle in `apps/desktop/dist/renderer`.

To look at a view without the daemon, point a browser at a built bundle with a
stand in for `window.intercept`; every call then returns an empty result and
the layout can be checked on its own.

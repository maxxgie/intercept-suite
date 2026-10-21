# Writing a plugin

A plugin is a directory containing a manifest and a Python module. The daemon
loads every plugin it finds at start-up, registers whatever it exposes, and
ignores anything that fails.

## Layout

```
plugins/
  my-tool/
    plugin.toml
    plugin.py
```

Plugins can live in the repository (for bundled plugins, as
`plugins/examples/` does) or in the plugins directory of the Intercept home
directory, which defaults to `~/.intercept/plugins`. A plugin in the home
directory takes precedence if the names collide.

## The manifest

```toml
name = "my-tool"
label = "My Tool"
version = "0.1.0"
description = "Does a useful thing with a request."
entry = "plugin.py"
```

Only `name` and `entry` are required. `name` is the identifier everything else
is namespaced under.

## Registering a tool

```python
from intercept.plugins.api import Field, PluginAPI, PluginContext, Tool


class MyTool(Tool):
    id = "summary"
    label = "Summarise a request"
    description = "Prints the interesting parts of the selected request."
    fields = [
        Field(name="include_body", label="Include body", type="boolean", default=False),
    ]

    async def run(self, context: PluginContext, values: dict) -> dict:
        return {"output": "hello"}


def register(api: PluginAPI) -> None:
    api.add_tool(MyTool())
```

The tool is registered as `my-tool.summary`. The desktop shell builds a form
from `fields`, so a plugin it has never seen still gets a usable interface.
`run` must return a JSON-serialisable dictionary; a key of `output` is shown
as the result, and a key of `error` is shown as a failure.

Field types are `text`, `textarea`, `number`, `select` and `boolean`. A
`select` field carries its options in the `options` list.

## Sending requests

`PluginContext` gives a plugin access to the shared client, so a tool can
send its own traffic and have it recorded in the same history as everything
else:

```python
from intercept.core.models import Headers, Request

async def run(self, context, values):
    request = Request(
        method="GET",
        url=values["url"],
        headers=Headers([("User-Agent", "my-tool/1.0")]),
    )
    response = await context.send(request)
    return {"output": response.body.decode("utf-8", "replace")}
```

`context.client`, `context.store`, `context.scope` and `context.config` are
also available. `context.log("...")` emits a message the interface shows in
the log.

## Adding a check

Checks probe a target and report what they find. There are two kinds:

* an **active** check sends its own requests to the target;
* a **passive** check inspects traffic that was already observed.

Both produce `Finding` objects and both end up in the findings list, so a
plugin check behaves exactly like a built in one.

```python
from intercept.core.models import Request
from intercept.plugins.api import Finding
from intercept.scanner.checks import ActiveCheck
from intercept.scanner.target import Endpoint


class MissingHeadersCheck(ActiveCheck):
    id = "missing-headers"
    label = "Missing security headers"
    description = "Looks for a Content-Security-Policy header."
    severity = "low"
    category = "headers"

    async def run(self, client, target: Endpoint) -> list[Finding]:
        url = target.url
        response = await client.send(Request(method="GET", url=url))
        if response.status == 0:
            return []
        if response.headers.get("content-security-policy"):
            return []
        return [
            Finding(
                check_id=self.id,
                title="Missing Content-Security-Policy",
                severity="low",
                description=f"{url} does not set a Content-Security-Policy.",
                url=url,
                remediation="Set a Content-Security-Policy header.",
            )
        ]


def register(api: PluginAPI) -> None:
    api.add_check(MissingHeadersCheck())
```

The check is registered as `my-tool.missing-headers` and shows up in the
scanner's check list, where it can be selected for a scan.

The `target` an active check is given is an `Endpoint`: the URL, the method,
the query parameters, the form fields and the cookies of the place. A check
with `scope = "host"` runs once per target, a check with `scope = "endpoint"`
runs for every place that takes input.

A passive check looks the same but takes a request and a response instead of a
client:

```python
from intercept.scanner.checks import PassiveCheck


class VerboseBannerCheck(PassiveCheck):
    id = "verbose-banner"
    label = "Verbose banner"

    def run(self, request, response) -> list[Finding]:
        server = response.headers.get("server")
        if not server or not server.startswith("Apache/2.4.49"):
            return []
        return [Finding(check_id=self.id, title="Outdated server banner", url=request.url)]
```

## Subscribing to events

```python
def register(api: PluginAPI) -> None:
    api.on("response", handle_response)


async def handle_response(payload: dict) -> None:
    ...
```

The hooks that exist today are the ones the daemon emits: `request`,
`response`, `intercept.request`, `intercept.dropped`, `spider.*`,
`fuzz.*`, `scan.*` and `plugin.log`.

## Failure is contained

A plugin that raises while loading is reported on the plugin list in the
interface and skipped. A plugin that raises while running a tool returns an
error to the caller rather than taking the daemon down. Both behaviours are
covered by the test suite.

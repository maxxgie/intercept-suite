"""An example plugin.

It registers a single tool that converts text between URL, HTML, base64, hex
and JSON encodings. Copy this directory into ``<home>/plugins`` to install it.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
from urllib.parse import quote, unquote

from intercept.plugins.api import Field, PluginAPI, PluginContext, Tool

ENCODERS = ("url", "html", "base64", "hex", "json")


def _encode(value: str, kind: str) -> str:
    if kind == "url":
        return quote(value, safe="")
    if kind == "html":
        return html.escape(value)
    if kind == "base64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if kind == "hex":
        return value.encode("utf-8").hex()
    if kind == "json":
        return json.dumps(value)
    raise ValueError(f"unknown encoding {kind!r}")


def _decode(value: str, kind: str) -> str:
    if kind == "url":
        return unquote(value)
    if kind == "html":
        return html.unescape(value)
    if kind == "base64":
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding).decode("utf-8", "replace")
    if kind == "hex":
        return bytes.fromhex(value.replace(" ", "")).decode("utf-8", "replace")
    if kind == "json":
        return json.dumps(json.loads(value), indent=2)
    raise ValueError(f"unknown encoding {kind!r}")


class EncodingTool(Tool):
    id = "convert"
    label = "Encode / Decode"
    description = "Convert text between URL, HTML, base64, hex and JSON."
    fields = [
        Field(name="value", label="Value", type="textarea", default=""),
        Field(
            name="mode",
            label="Mode",
            type="select",
            default="decode",
            options=["decode", "encode"],
        ),
        Field(
            name="encoding",
            label="Encoding",
            type="select",
            default="url",
            options=list(ENCODERS),
        ),
    ]

    async def run(self, context: PluginContext, values: dict) -> dict:
        value = str(values.get("value", ""))
        mode = str(values.get("mode", "decode"))
        encoding = str(values.get("encoding", "url"))
        if not value:
            return {"output": ""}
        try:
            output = _encode(value, encoding) if mode == "encode" else _decode(value, encoding)
        except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
            return {"error": str(exc), "output": ""}
        return {"output": output}


def register(api: PluginAPI) -> None:
    api.add_tool(EncodingTool())

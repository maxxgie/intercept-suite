"""An example plugin.

It registers a single tool that converts text between the encodings that turn
up in web traffic. The conversions themselves live in the engine, so the
plugin only shows how a tool is put together. Copy this directory into
``<home>/plugins`` to install it.
"""

from __future__ import annotations

from intercept.plugins.api import Field, PluginAPI, PluginContext, Tool
from intercept.tools.decoder import KIND_LABELS, TRANSFORM_KINDS, Decoder, DecoderError


class EncodingTool(Tool):
    id = "convert"
    label = "Encode / Decode"
    description = "Convert text between the common web encodings."
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
            options=list(TRANSFORM_KINDS),
        ),
    ]

    async def run(self, context: PluginContext, values: dict) -> dict:
        value = str(values.get("value", ""))
        mode = str(values.get("mode", "decode"))
        encoding = str(values.get("encoding", "url"))
        if not value:
            return {"output": ""}
        try:
            result = Decoder().convert(value, encoding, mode)
        except DecoderError as exc:
            return {"error": str(exc), "output": ""}
        return {"output": f"{result['output']}", "label": KIND_LABELS.get(encoding, encoding)}


def register(api: PluginAPI) -> None:
    api.add_tool(EncodingTool())

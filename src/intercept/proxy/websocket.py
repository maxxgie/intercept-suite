"""WebSocket frame parsing.

A protocol upgrade is tunnelled as raw bytes, which is the right thing to do
for the traffic but useless for the interface. This module reads the RFC 6455
framing out of the tunnel so every message can be shown, searched and
highlighted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

__all__ = ["WebSocketFrame", "FrameParser", "OPCODE_NAMES"]

#: The opcodes a frame can carry.
OPCODE_NAMES = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}


@dataclass(slots=True)
class WebSocketFrame:
    direction: str
    opcode: int
    payload: bytes
    fin: bool = True
    timestamp: float = field(default_factory=time.time)

    @property
    def name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f"opcode-{self.opcode:#x}")

    @property
    def text(self) -> str:
        return self.payload.decode("utf-8", "replace")

    def to_dict(self) -> dict[str, object]:
        return {
            "direction": self.direction,
            "opcode": self.opcode,
            "type": self.name,
            "text": self.text,
            "size": len(self.payload),
            "timestamp": self.timestamp,
        }


class FrameParser:
    """Turns a stream of bytes into WebSocket frames."""

    def __init__(self, direction: str) -> None:
        self.direction = direction
        self._buffer = bytearray()
        self._fragments: list[bytes] = []
        self._fragment_opcode = 0

    def feed(self, data: bytes) -> list[WebSocketFrame]:
        """Add bytes and return whatever complete frames they finished."""
        self._buffer.extend(data)
        frames: list[WebSocketFrame] = []
        while True:
            frame = self._next()
            if frame is None:
                break
            frames.append(frame)
        return frames

    def _next(self) -> WebSocketFrame | None:
        buffer = self._buffer
        if len(buffer) < 2:
            return None
        first, second = buffer[0], buffer[1]
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        offset = 2

        if length == 126:
            if len(buffer) < offset + 2:
                return None
            length = int.from_bytes(buffer[offset : offset + 2], "big")
            offset += 2
        elif length == 127:
            if len(buffer) < offset + 8:
                return None
            length = int.from_bytes(buffer[offset : offset + 8], "big")
            offset += 8

        mask = b""
        if masked:
            if len(buffer) < offset + 4:
                return None
            mask = bytes(buffer[offset : offset + 4])
            offset += 4

        if len(buffer) < offset + length:
            return None

        payload = bytes(buffer[offset : offset + length])
        if masked and mask:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        del buffer[: offset + length]

        if opcode == 0x0:
            self._fragments.append(payload)
            if not fin:
                return None
            payload = b"".join(self._fragments)
            self._fragments.clear()
            opcode = self._fragment_opcode
        elif not fin:
            self._fragment_opcode = opcode
            self._fragments = [payload]
            return None

        return WebSocketFrame(direction=self.direction, opcode=opcode, payload=payload, fin=fin)

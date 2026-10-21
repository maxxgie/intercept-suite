/**
 * The bytes of a body, and a hex dump of them.
 *
 * A body that is not valid UTF-8 travels as base64, so the bytes that were on
 * the wire can be shown exactly, byte by byte.
 */

export function bodyBytes(body: string, encoding: string): Uint8Array {
  if (encoding === "base64") {
    let binary = "";
    try {
      binary = atob(body);
    } catch {
      return new Uint8Array(0);
    }
    const out = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      out[index] = binary.charCodeAt(index);
    }
    return out;
  }
  return new TextEncoder().encode(body);
}

export function hexDump(bytes: Uint8Array, width = 16): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += width) {
    const slice = bytes.slice(offset, offset + width);
    const hex = Array.from(slice, (byte) => byte.toString(16).padStart(2, "0")).join(" ");
    const text = Array.from(slice, (byte) =>
      byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".",
    ).join("");
    lines.push(
      `${offset.toString(16).padStart(8, "0")}  ${hex.padEnd(width * 3 - 1, " ")}  ${text}`,
    );
  }
  return lines.join("\n");
}

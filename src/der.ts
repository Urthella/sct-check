// Just enough DER to walk a certificate and splice one extension out of it.

export interface Tlv {
  tag: number;
  at: number; // first byte of the header
  start: number; // first content byte
  end: number; // one past the last content byte
}

export function read(der: Uint8Array, at: number): Tlv {
  const tag = der[at];
  let length = der[at + 1];
  if (tag === undefined || length === undefined) throw new Error("truncated DER");
  if ((tag & 0x1f) === 0x1f) throw new Error("unexpected multi-byte DER tag");
  let start = at + 2;
  if (length & 0x80) {
    const bytes = length & 0x7f;
    if (bytes === 0 || bytes > 4) throw new Error("unsupported DER length");
    length = 0;
    for (let i = 0; i < bytes; i++) {
      const byte = der[start + i];
      if (byte === undefined) throw new Error("truncated DER");
      length = length * 256 + byte;
    }
    start += bytes;
  }
  const end = start + length;
  if (end > der.length) throw new Error("truncated DER");
  return { tag, at, start, end };
}

export function children(der: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  for (let at = parent.start; at < parent.end; ) {
    const child = read(der, at);
    if (child.end > parent.end) throw new Error("DER element overruns its parent");
    out.push(child);
    at = child.end;
  }
  return out;
}

/** A DER element with the given tag around the given content. */
export function encode(tag: number, content: Uint8Array): Buffer {
  const n = content.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : n < 0x10000 ? [0x82, n >> 8, n & 0xff] : [0x83, n >> 16, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Uint8Array.of(tag, ...length), content]);
}

export const SEQUENCE = 0x30;
export const OID = 0x06;
export const OCTET_STRING = 0x04;
export const VERSION = 0xa0; // [0] EXPLICIT
export const EXTENSIONS = 0xa3; // [3] EXPLICIT

export const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

// RFC 6962 Merkle trees: checking an inclusion proof against a signed root (RFC 9162 section
// 2.1.3.2), and building the proof from a static-ct-api log's tiles, which store the hashes of
// whole subtrees 8 levels at a time.

import { createHash } from "node:crypto";

const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();
export const node = (left: Uint8Array, right: Uint8Array) => sha256(Uint8Array.of(1), left, right);

/** Whether `path` proves the leaf with hash `leaf` is entry `index` of the tree with `root`. */
export function verifyInclusion(leaf: Buffer, index: number, size: number, path: Buffer[], root: Buffer): boolean {
  if (index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = node(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = node(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.equals(root);
}

/** Fetches tile `n` of `level`, `width` hashes wide (256 for a full tile). */
export type TileFetcher = (level: number, n: number, width: number) => Promise<Buffer>;

const largestPowerOfTwoBelow = (n: number) => 2 ** Math.floor(Math.log2(n - 1));

/** How many hashes tile `n` of `level` holds in a tree of `size` leaves (0 if it doesn't exist). */
export function tileWidth(level: number, n: number, size: number): number {
  const entries = Math.floor(size / 256 ** level);
  return Math.max(0, Math.min(256, entries - n * 256));
}

/** The tile path element for index `n`: 1234067 is x001/x234/067. */
export function tileIndexPath(n: number): string {
  const parts: string[] = [];
  do {
    parts.unshift(String(n % 1000).padStart(3, "0"));
    n = Math.floor(n / 1000);
  } while (n > 0);
  return parts.map((part, i) => (i < parts.length - 1 ? `x${part}` : part)).join("/");
}

/** The inclusion proof for entry `index` of a tree of `size` leaves, read from its tiles. */
export async function proofFromTiles(index: number, size: number, fetchTile: TileFetcher): Promise<Buffer[]> {
  const tiles = new Map<string, Promise<Buffer>>();
  const tile = (level: number, n: number) => {
    const key = `${level}/${n}`;
    if (!tiles.has(key)) tiles.set(key, fetchTile(level, n, tileWidth(level, n, size)));
    return tiles.get(key)!;
  };

  /** The hash of the full subtree of height `height` whose leftmost leaf is `start`. */
  async function perfect(height: number, start: number): Promise<Buffer> {
    const level = Math.floor(height / 8);
    const span = 2 ** (height % 8); // tile entries under this subtree
    const first = start / 256 ** level; // index of its first entry within the level
    const data = await tile(level, Math.floor(first / 256));
    let hashes: Buffer[] = [];
    for (let i = 0; i < span; i++) {
      const at = ((first % 256) + i) * 32;
      if (at + 32 > data.length) throw new Error(`tile ${level}/${Math.floor(first / 256)} is too short`);
      hashes.push(data.subarray(at, at + 32));
    }
    while (hashes.length > 1) hashes = hashes.flatMap((hash, i) => (i % 2 ? [] : [node(hash, hashes[i + 1])]));
    return hashes[0];
  }

  /** MTH(D[start:end]) for a range the RFC 6962 recursion produces. */
  async function hash(start: number, end: number): Promise<Buffer> {
    const n = end - start;
    if (Number.isInteger(Math.log2(n))) return perfect(Math.log2(n), start); // not n & (n - 1): sizes pass 2^31
    const k = largestPowerOfTwoBelow(n);
    return node(await hash(start, start + k), await hash(start + k, end));
  }

  /** PATH(m, D[start:end]) from RFC 6962 section 2.1.1, leaf end first. */
  async function path(m: number, start: number, end: number): Promise<Buffer[]> {
    const n = end - start;
    if (n === 1) return [];
    const k = largestPowerOfTwoBelow(n);
    return m < start + k
      ? [...(await path(m, start, start + k)), await hash(start + k, end)]
      : [...(await path(m, start + k, end)), await hash(start, start + k)];
  }

  if (index >= size) throw new Error(`entry ${index} is beyond the tree's ${size} entries`);
  return path(index, 0, size);
}

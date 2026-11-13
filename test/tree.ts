// A plain RFC 6962 Merkle tree for tests, written straight from section 2.1 and independent of
// src/merkle.ts: the tree hash, the audit path, and the static-ct-api tiles of a tree.

import { createHash } from "node:crypto";

export const sha256 = (...parts: Uint8Array[]) => createHash("sha256").update(Buffer.concat(parts)).digest();
const node = (left: Buffer, right: Buffer) => sha256(Uint8Array.of(1), left, right);
const split = (n: number) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

const memos = new WeakMap<Buffer[], Map<string, Buffer>>();

/** MTH(D[start:end]) over leaf hashes, remembered per tree so big trees stay quick. */
function range(leaves: Buffer[], start: number, end: number): Buffer {
  if (end - start === 1) return leaves[start];
  if (!memos.has(leaves)) memos.set(leaves, new Map());
  const memo = memos.get(leaves)!;
  const key = `${start}:${end}`;
  if (!memo.has(key)) {
    const k = split(end - start);
    memo.set(key, node(range(leaves, start, start + k), range(leaves, start + k, end)));
  }
  return memo.get(key)!;
}

/** MTH over leaf hashes. */
export const mth = (leaves: Buffer[]) => range(leaves, 0, leaves.length);

/** PATH(m, D[n]). */
export function auditPath(m: number, leaves: Buffer[], start = 0, end = leaves.length): Buffer[] {
  if (end - start === 1) return [];
  const k = split(end - start);
  return m < start + k
    ? [...auditPath(m, leaves, start, start + k), range(leaves, start + k, end)]
    : [...auditPath(m, leaves, start + k, end), range(leaves, start, start + k)];
}

/** The hashes static-ct-api tiles hold at each level: level l entry j is MTH of 256^l leaves. */
export function tileLevels(leaves: Buffer[]): Buffer[][] {
  const levels = [leaves];
  for (let size = 256; size <= leaves.length; size *= 256) {
    const below = levels[levels.length - 1];
    const level: Buffer[] = [];
    for (let j = 0; (j + 1) * 256 <= below.length; j++) level.push(range(below, j * 256, (j + 1) * 256));
    levels.push(level);
  }
  return levels;
}

export const randomLeaves = (n: number): Buffer[] => Array.from({ length: n }, (_, i) => sha256(Buffer.from(`leaf ${i}`)));

import assert from "node:assert/strict";
import { test } from "node:test";

import { proofFromTiles, tileIndexPath, tileWidth, verifyInclusion } from "../src/merkle.ts";
import { auditPath, mth, randomLeaves, tileLevels } from "./tree.ts";

/** Serves a tree's tiles, and checks that only tiles that exist are asked for, at their width. */
function tilesOf(leaves: ReturnType<typeof randomLeaves>) {
  const levels = tileLevels(leaves);
  return async (level: number, n: number, width: number) => {
    const entries = levels[level] ?? [];
    const expected = Math.min(256, entries.length - n * 256);
    assert.ok(expected > 0, `tile ${level}/${n} doesn't exist in a tree of ${leaves.length}`);
    assert.equal(width, expected, `width of tile ${level}/${n}`);
    return Buffer.concat(entries.slice(n * 256, n * 256 + width));
  };
}

test("tile indexes are written in 3-digit path elements", () => {
  assert.equal(tileIndexPath(0), "000");
  assert.equal(tileIndexPath(5), "005");
  assert.equal(tileIndexPath(999), "999");
  assert.equal(tileIndexPath(1000), "x001/000");
  assert.equal(tileIndexPath(1234067), "x001/x234/067"); // the spec's example
});

test("tile widths follow the spec's example tree of 70,000 entries", () => {
  assert.equal(tileWidth(0, 272, 70_000), 256);
  assert.equal(tileWidth(0, 273, 70_000), 112);
  assert.equal(tileWidth(0, 274, 70_000), 0);
  assert.equal(tileWidth(1, 0, 70_000), 256);
  assert.equal(tileWidth(1, 1, 70_000), 17);
  assert.equal(tileWidth(2, 0, 70_000), 1);
  assert.equal(tileWidth(1, 0, 256), 1); // a tree of 256 has a partial level 1 tile of width 1
});

test("proofs built from tiles match RFC 6962's audit path, for every entry of small trees", async () => {
  for (let size = 1; size <= 70; size++) {
    const leaves = randomLeaves(size);
    const root = mth(leaves);
    for (let m = 0; m < size; m++) {
      const path = await proofFromTiles(m, size, tilesOf(leaves));
      assert.deepEqual(path, auditPath(m, leaves), `entry ${m} of ${size}`);
      assert.ok(verifyInclusion(leaves[m], m, size, path, root), `entry ${m} of ${size} verifies`);
    }
  }
});

test("proofs built from tiles match across full and partial tiles of larger trees", async () => {
  for (const size of [255, 256, 257, 511, 513, 65_536, 65_537, 70_000]) {
    const leaves = randomLeaves(size);
    const root = mth(leaves);
    for (const m of [0, 1, 255, 256, size - 257, size - 2, size - 1, Math.floor(size / 3)]) {
      if (m < 0 || m >= size) continue;
      const path = await proofFromTiles(m, size, tilesOf(leaves));
      assert.deepEqual(path, auditPath(m, leaves), `entry ${m} of ${size}`);
      assert.ok(verifyInclusion(leaves[m], m, size, path, root), `entry ${m} of ${size} verifies`);
    }
  }
});

test("an inclusion proof fails for the wrong root, entry, leaf or path", () => {
  const leaves = randomLeaves(13);
  const root = mth(leaves);
  const path = auditPath(6, leaves);
  assert.ok(verifyInclusion(leaves[6], 6, 13, path, root));
  assert.ok(!verifyInclusion(leaves[6], 6, 13, path, mth(leaves.slice(1))), "wrong root");
  assert.ok(!verifyInclusion(leaves[6], 7, 13, path, root), "wrong index");
  assert.ok(!verifyInclusion(leaves[7], 6, 13, path, root), "wrong leaf");
  assert.ok(!verifyInclusion(leaves[6], 6, 13, path.slice(1), root), "path too short");
  assert.ok(!verifyInclusion(leaves[6], 6, 13, [...path, leaves[0]], root), "path too long");
  assert.ok(!verifyInclusion(leaves[6], 6, 7, path, root), "a size that changes the path's shape");
  assert.ok(!verifyInclusion(leaves[12], 13, 13, [], root), "index beyond the tree");
  assert.ok(verifyInclusion(leaves[0], 0, 1, [], leaves[0]), "a tree of one");
  assert.ok(!verifyInclusion(leaves[0], 1, 1, [], leaves[0]), "index beyond a tree of one");
  assert.ok(!verifyInclusion(leaves[6], 6, 13, path.slice(0, 2), mth(leaves.slice(4, 8))), "a proof that stops at a subtree");
  assert.ok(!verifyInclusion(leaves[0], 0, 13, [], leaves[0]), "an empty proof for a bigger tree");
});

test("asking for an entry beyond the tree is refused", async () => {
  await assert.rejects(proofFromTiles(5, 5, tilesOf(randomLeaves(5))), /beyond the tree/);
});

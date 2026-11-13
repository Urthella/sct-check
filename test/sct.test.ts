// Real certificates and real logs, saved by scripts/fetch-fixtures.ts: every SCT must verify under
// its log's real key, and the hashes rebuilt here must match what the logs actually store.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { readChain } from "../src/check.ts";
import { parseLogList, treeHeadData, verifyCheckpoint, verifySignature } from "../src/logs.ts";
import { verifyInclusion } from "../src/merkle.ts";
import { embedded, issuerKeyHash, leafHash, parseList, signedData } from "../src/sct.ts";

const fixture = (name: string) => new URL(`fixtures/${name}`, import.meta.url);
const logs = parseLogList(readFileSync(fixture("log_list.json"), "utf8"));
const logOf = (logId: Buffer) => logs.get(logId.toString("base64"))!;

async function load(host: string) {
  const [leaf, issuer] = await readChain(fileURLToPath(fixture(`${host}.pem`)));
  return { leaf, issuer, ...embedded(leaf), issuerKey: issuerKeyHash(issuer) };
}

const EXPECTED = {
  "letsencrypt.org": ["Cloudflare Nimbus2027", "DigiCert Sphinx2027h1"],
  "www.google.com": ["DigiCert Wyvern2027h1", "Let's Encrypt Willow2027h1 @910883989"],
  "github.com": ["DigiCert Sphinx2027h1", "Let's Encrypt Willow2027h1 @840886514"],
  "en.wikipedia.org": ["Sectigo Tiger2027h1", "IPng Networks Gouda2027h1 @88798019"],
};

test("every SCT in real certificates verifies under its log's key", async () => {
  for (const [host, expected] of Object.entries(EXPECTED)) {
    const { scts, tbs, issuerKey } = await load(host);
    const seen = scts.map((sct) => logOf(sct.logId).description + (sct.leafIndex === undefined ? "" : ` @${sct.leafIndex}`));
    assert.deepEqual(seen.sort(), [...expected].sort(), host);
    for (const sct of scts) assert.ok(verifySignature(logOf(sct.logId).key, signedData(sct, issuerKey, tbs), sct.signature), `${host}: ${logOf(sct.logId).description}`);
  }
});

test("a changed TBSCertificate, issuer key or timestamp breaks the signature", async () => {
  const { scts, tbs, issuerKey } = await load("letsencrypt.org");
  const sct = scts[0];
  const key = logOf(sct.logId).key;
  const flipped = Buffer.from(tbs);
  flipped[flipped.length - 40] ^= 1;
  assert.ok(!verifySignature(key, signedData(sct, issuerKey, flipped), sct.signature));
  assert.ok(!verifySignature(key, signedData(sct, Buffer.alloc(32), tbs), sct.signature));
  assert.ok(!verifySignature(key, signedData({ ...sct, timestamp: sct.timestamp + 1 }, issuerKey, tbs), sct.signature));
  assert.ok(verifySignature(key, signedData(sct, issuerKey, tbs), sct.signature), "unchanged");
  assert.ok(!verifySignature(key, signedData(sct, issuerKey, tbs), Buffer.concat([Buffer.of(5), sct.signature.subarray(1)])), "SHA-384 isn't allowed");
});

test("malformed DER is refused", () => {
  assert.throws(() => embedded(Buffer.from([0x30, 0x08, 0x30, 0x02, 0x02, 0x04, 0x05, 0x00, 0x05, 0x00])), /overruns its parent/);
  assert.throws(() => embedded(Buffer.from([0x30, 0x02, 0x30, 0x00, 0x00])), /not a DER certificate/);
  assert.throws(() => embedded(Buffer.from([0x30, 0x05, 0x30])), /truncated DER/);
});

test("a certificate without SCTs has none, and keeps its TBSCertificate whole", async () => {
  const { issuer } = await load("letsencrypt.org");
  const { scts, tbs } = embedded(issuer);
  assert.deepEqual(scts, []);
  assert.equal(issuer.indexOf(tbs), 4, "the issuer's own TBSCertificate, right after the certificate's header");
});

test("the leaf hash of a real static-ct-api entry matches the log's level 0 tile", async () => {
  const { scts, tbs, issuerKey } = await load("www.google.com");
  const sct = scts.find((sct) => sct.leafIndex !== undefined)!;
  const at = (sct.leafIndex! % 256) * 32;
  assert.deepEqual(leafHash(sct, issuerKey, tbs), readFileSync(fixture("static-tile")).subarray(at, at + 32));
});

test("a real checkpoint verifies by its log signature, among grease and other signatures", () => {
  const willow = [...logs.values()].find((log) => log.description === "Let's Encrypt Willow2027h1")!;
  const text = readFileSync(fixture("static-checkpoint.txt"), "utf8");
  const head = verifyCheckpoint(willow, text);
  assert.ok(head.size > 910_883_989, "the tree has the entry");
  assert.match(text, /grease\.invalid/);

  const [origin, size] = text.split("\n");
  assert.throws(() => verifyCheckpoint(willow, text.replace(`\n${size}\n`, `\n${Number(size) + 1}\n`)), /signature on its checkpoint doesn't verify/);
  const otherLog = [...logs.values()].find((log) => log.monitoringUrl && log !== willow)!;
  assert.throws(() => verifyCheckpoint(otherLog, text), /no signature by this log/);
  assert.throws(() => verifyCheckpoint(willow, text.split("\n").filter((line) => !line.startsWith(`— ${origin} `)).join("\n")), /no signature by this log/);
  assert.throws(() => verifyCheckpoint(willow, "nonsense"), /malformed checkpoint/);
});

test("a real RFC 6962 inclusion proof verifies against the log's signed tree head", async () => {
  const { scts, tbs, issuerKey } = await load("letsencrypt.org");
  const sct = scts.find((sct) => logOf(sct.logId).description === "Cloudflare Nimbus2027")!;
  const log = logOf(sct.logId);
  const sth = JSON.parse(readFileSync(fixture("rfc6962-sth.json"), "utf8"));
  const proof = JSON.parse(readFileSync(fixture("rfc6962-proof.json"), "utf8"));
  const root = Buffer.from(sth.sha256_root_hash, "base64");
  assert.ok(verifySignature(log.key, treeHeadData(sth.timestamp, sth.tree_size, root), Buffer.from(sth.tree_head_signature, "base64")), "tree head");
  const path = proof.audit_path.map((hash: string) => Buffer.from(hash, "base64"));
  const leaf = leafHash(sct, issuerKey, tbs);
  assert.ok(verifyInclusion(leaf, proof.leaf_index, sth.tree_size, path, root), "inclusion");
  assert.ok(!verifyInclusion(leaf, proof.leaf_index + 1, sth.tree_size, path, root), "another entry");
});

test("malformed SCT lists are refused", () => {
  const sct = Buffer.concat([Buffer.alloc(1), Buffer.alloc(32, 7), Buffer.alloc(8), Buffer.from([0, 0, 4, 3, 0, 1, 0x30])]);
  const list = (body: Buffer) => Buffer.concat([Buffer.from([body.length >> 8, body.length & 0xff]), body]);
  assert.equal(parseList(list(list(sct))).length, 1);
  assert.throws(() => parseList(Buffer.concat([list(list(sct)), Buffer.alloc(1)])), /length doesn't match/);
  assert.throws(() => parseList(list(list(sct.subarray(0, 45)))), /malformed SCT signature/);
  assert.throws(() => parseList(list(list(sct.subarray(0, 30)))), /truncated SCT list/);
  assert.throws(() => parseList(list(list(Buffer.concat([Buffer.from([1]), sct.subarray(1)])))), /unknown SCT version 1/);
  const badIndex = Buffer.concat([Buffer.alloc(1), Buffer.alloc(32, 7), Buffer.alloc(8), Buffer.from([0, 7, 0, 0, 4, 0, 0, 0, 1]), Buffer.from([4, 3, 0, 1, 0x30])]);
  assert.throws(() => parseList(list(list(badIndex))), /leaf_index/);
});

test("a leaf_index is read as all 40 bits, after any other extension", () => {
  const extensions = Buffer.from([9, 0, 1, 0xff, 0, 0, 5, 0x12, 0x34, 0x56, 0x78, 0x9a]); // an unknown extension, then leaf_index
  const sct = Buffer.concat([Buffer.alloc(1), Buffer.alloc(32, 7), Buffer.alloc(8), Buffer.from([0, extensions.length]), extensions, Buffer.from([4, 3, 0, 1, 0x30])]);
  const list = (body: Buffer) => Buffer.concat([Buffer.from([body.length >> 8, body.length & 0xff]), body]);
  assert.equal(parseList(list(list(sct)))[0].leafIndex, 0x123456789a);
});

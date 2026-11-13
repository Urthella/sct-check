// Runs the real CLI against fake CT logs of both kinds, with certificates whose SCTs are built
// here by hand from RFC 6962's structures, independently of src/sct.ts.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import type { AddressInfo, Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { createServer as createTlsServer } from "node:tls";
import { fileURLToPath } from "node:url";

import "reflect-metadata"; // @peculiar/x509 needs it loaded first
import * as x509 from "@peculiar/x509";

import { auditPath, mth, randomLeaves, sha256, tileLevels } from "./tree.ts";

const MAIN = fileURLToPath(new URL("../src/main.ts", import.meta.url));
x509.cryptoProvider.set(globalThis.crypto);

// --- TLS encoding, by hand ---
const u8 = (n: number) => Buffer.of(n);
const u16 = (n: number) => Buffer.of(n >> 8, n & 0xff);
const u24 = (n: number) => Buffer.of(n >> 16, (n >> 8) & 0xff, n & 0xff);
const u40 = (n: number) => Buffer.from(n.toString(16).padStart(10, "0"), "hex");
const u64 = (n: number) => Buffer.from(n.toString(16).padStart(16, "0"), "hex");
const vec16 = (body: Buffer) => Buffer.concat([u16(body.length), body]);
const derLength = (n: number) => (n < 0x80 ? Buffer.of(n) : n < 0x100 ? Buffer.of(0x81, n) : Buffer.of(0x82, n >> 8, n & 0xff));
const pem = (der: Buffer, type = "CERTIFICATE") => `-----BEGIN ${type}-----\n${der.toString("base64").replace(/.{64}/g, "$&\n").trim()}\n-----END ${type}-----\n`;

/** The TBSCertificate: the first element inside the certificate's outer SEQUENCE. */
function tbsOf(der: Buffer): Buffer {
  const at = der[1] & 0x80 ? 2 + (der[1] & 0x7f) : 2;
  const lengthBytes = der[at + 1] & 0x80 ? der[at + 1] & 0x7f : 0;
  const length = lengthBytes ? der.readUIntBE(at + 2, lengthBytes) : der[at + 1];
  return der.subarray(at, at + 2 + lengthBytes + length);
}

// --- a test CA and certificates with SCTs ---
const ALGORITHM = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const NOT_BEFORE = new Date(Date.now() - 86_400_000);
const NOT_AFTER = new Date(Date.now() + 90 * 86_400_000);
const caKeys = await crypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"]);
const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=sct-check test CA", notBefore: NOT_BEFORE, notAfter: NOT_AFTER, keys: caKeys, signingAlgorithm: ALGORITHM });
const issuerKeyHash = sha256(Buffer.from(await crypto.subtle.exportKey("spki", caKeys.publicKey)));
const leafKeys = await crypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"]);
const leafKeyPem = pem(Buffer.from(await crypto.subtle.exportKey("pkcs8", leafKeys.privateKey)), "PRIVATE KEY");

interface FakeLog {
  key: KeyObject;
  spki: Buffer;
  id: Buffer;
}
function makeLog(): FakeLog {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  return { key: privateKey, spki, id: sha256(spki) };
}
const digitallySigned = (key: KeyObject, data: Buffer) => Buffer.concat([u8(4), u8(3), vec16(sign("sha256", data, key))]);

interface SctSpec {
  log: FakeLog;
  index?: number;
  timestamp?: number;
  signWith?: KeyObject;
}

/** Issues a certificate whose SCTs cover its precertificate, and returns their Merkle leaf hashes. */
async function issue(serial: string, specs: SctSpec[]): Promise<{ chain: string; leaves: Buffer[] }> {
  const make = (extensions: x509.Extension[]) =>
    x509.X509CertificateGenerator.create({
      serialNumber: serial,
      subject: "CN=localhost",
      issuer: ca.subject,
      notBefore: NOT_BEFORE,
      notAfter: NOT_AFTER,
      publicKey: leafKeys.publicKey,
      signingKey: caKeys.privateKey,
      signingAlgorithm: ALGORITHM,
      extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "localhost" }, { type: "ip", value: "127.0.0.1" }]), ...extensions],
    });
  const tbs = tbsOf(Buffer.from((await make([])).rawData));
  const leaves: Buffer[] = [];
  const scts = specs.map(({ log, index, timestamp = Date.now() - 3_600_000, signWith }) => {
    const extensions = index === undefined ? Buffer.alloc(0) : Buffer.concat([u8(0), u16(5), u40(index)]);
    const entry = Buffer.concat([u64(timestamp), u16(1), issuerKeyHash, u24(tbs.length), tbs, vec16(extensions)]);
    leaves.push(sha256(u8(0), u8(0), u8(0), entry));
    const signature = digitallySigned(signWith ?? log.key, Buffer.concat([u8(0), u8(0), entry]));
    return vec16(Buffer.concat([u8(0), log.id, u64(timestamp), vec16(extensions), signature]));
  });
  const list = vec16(Buffer.concat(scts));
  const value = Buffer.concat([u8(0x04), derLength(list.length), list]); // an OCTET STRING inside extnValue
  const certificate = await make(specs.length ? [new x509.Extension("1.3.6.1.4.1.11129.2.4.2", false, value)] : []);
  return { chain: certificate.toString("pem") + "\n" + ca.toString("pem") + "\n", leaves };
}

// --- fake logs ---
const treeHeadSignature = (log: FakeLog, timestamp: number, size: number, root: Buffer) =>
  digitallySigned(log.key, Buffer.concat([u8(0), u8(1), u64(timestamp), u64(size), root]));

const staticLog = makeLog();
const rfcLog = makeLog();
const badCheckpointLog = makeLog(); // its checkpoint is signed by another key
const unknownLog = makeLog(); // not in the log list
const SIZE = 1000; // 3 full level 0 tiles, a partial one, and a partial level 1 tile
const staticLeaves = randomLeaves(SIZE);
const rfcLeaves = randomLeaves(40);

let port = 0;
const origin = (path: string) => `127.0.0.1:${port}/${path}`;
function checkpoint(log: FakeLog, signer: FakeLog, path: string, leaves: Buffer[]) {
  const timestamp = Date.now();
  const root = mth(leaves);
  const keyId = sha256(Buffer.from(`${origin(path)}\n`), u8(5), log.id).subarray(0, 4);
  const signature = Buffer.concat([keyId, u64(timestamp), treeHeadSignature(signer, timestamp, leaves.length, root)]);
  const grease = `— grease.invalid ${Buffer.alloc(40, 1).toString("base64")}\n`;
  return `${origin(path)}\n${leaves.length}\n${root.toString("base64")}\n\n${grease}— ${origin(path)} ${signature.toString("base64")}\n`;
}
function tile(leaves: Buffer[], url: string) {
  const match = /tile\/(\d)\/((?:x\d{3}\/)*\d{3})(?:\.p\/(\d+))?$/.exec(url);
  if (!match) return undefined;
  const level = tileLevels(leaves)[Number(match[1])] ?? [];
  const n = Number(match[2].replaceAll("x", "").replaceAll("/", ""));
  const width = Math.min(256, level.length - n * 256);
  if (width <= 0 || (match[3] === undefined) !== (width === 256) || (match[3] !== undefined && Number(match[3]) !== width)) return undefined;
  return Buffer.concat(level.slice(n * 256, n * 256 + width));
}

let logListOk = true;
let tilesBroken = false;
let sthForged = false; // the RFC 6962 log signs its tree head with another log's key
let rateLimits = 0; // how many more tile requests get a 429
const asked: string[] = [];
const agents: string[] = [];
const server: Server = createHttpServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://localhost");
  asked.push(url.pathname);
  agents.push(request.headers["user-agent"] ?? "");
  if (url.pathname.startsWith("/static/tile/")) {
    if (tilesBroken) return void response.writeHead(500).end();
    if (rateLimits > 0) {
      rateLimits--;
      return void response.writeHead(429, { "retry-after": "1" }).end("Please slow down.\n");
    }
  }
  const send = (body: string | Buffer | undefined, type = "application/octet-stream") => {
    if (body === undefined) response.writeHead(404).end();
    else response.writeHead(200, { "content-type": type }).end(body);
  };
  if (url.pathname === "/log_list.json") {
    if (!logListOk) return void response.writeHead(500).end();
    const entry = (log: FakeLog, description: string, mmd: number, more: object) => ({ description, log_id: log.id.toString("base64"), key: log.spki.toString("base64"), mmd, state: { usable: { timestamp: "2026-01-01T00:00:00Z" } }, ...more });
    return send(JSON.stringify({
      version: "test",
      operators: [{
        name: "Test",
        logs: [entry(rfcLog, "Test RFC 6962 log", 86_400, { url: `http://${origin("rfc/")}` })],
        tiled_logs: [
          entry(staticLog, "Test static log", 60, { monitoring_url: `http://${origin("static")}` }),
          entry(badCheckpointLog, "Test badly signed log", 60, { monitoring_url: `http://${origin("bad/")}` }),
        ],
      }],
    }), "application/json");
  }
  if (url.pathname === "/static/checkpoint") return send(checkpoint(staticLog, staticLog, "static", staticLeaves), "text/plain");
  if (url.pathname === "/bad/checkpoint") return send(checkpoint(badCheckpointLog, staticLog, "bad", staticLeaves), "text/plain");
  if (url.pathname.startsWith("/static/tile/")) return send(tile(staticLeaves, url.pathname));
  if (url.pathname === "/rfc/ct/v1/get-sth") {
    const timestamp = Date.now();
    const root = mth(rfcLeaves);
    return send(JSON.stringify({ tree_size: rfcLeaves.length, timestamp, sha256_root_hash: root.toString("base64"), tree_head_signature: treeHeadSignature(sthForged ? staticLog : rfcLog, timestamp, rfcLeaves.length, root).toString("base64") }), "application/json");
  }
  if (url.pathname === "/rfc/ct/v1/get-proof-by-hash") {
    const index = rfcLeaves.findIndex((leaf) => leaf.toString("base64") === url.searchParams.get("hash"));
    if (index < 0 || Number(url.searchParams.get("tree_size")) !== rfcLeaves.length) return void response.writeHead(400).end();
    return send(JSON.stringify({ leaf_index: index, audit_path: auditPath(index, rfcLeaves).map((hash) => hash.toString("base64")) }), "application/json");
  }
  send(undefined);
});
await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
server.unref();
port = (server.address() as AddressInfo).port;

// --- the certificates ---
const good = await issue("10", [{ log: staticLog, index: 300 }, { log: rfcLog }]);
staticLeaves[300] = good.leaves[0];
rfcLeaves[7] = good.leaves[1];
const badSignature = await issue("11", [{ log: staticLog, index: 301, signWith: rfcLog.key }]);
staticLeaves[301] = badSignature.leaves[0];
const unknown = await issue("12", [{ log: unknownLog }]);
const missingLong = await issue("13", [{ log: staticLog, index: SIZE + 5, timestamp: Date.now() - 86_400_000 }, { log: rfcLog, timestamp: Date.now() - 2 * 86_400_000 }]);
const missingNew = await issue("14", [{ log: staticLog, index: SIZE + 6, timestamp: Date.now() }]);
const wrongEntry = await issue("15", [{ log: staticLog, index: 999 }]); // the tree holds something else there
const noIndex = await issue("16", [{ log: staticLog }]);
const badCheckpoint = await issue("17", [{ log: badCheckpointLog, index: 5 }]);
const noScts = await issue("18", []);

const dir = mkdtempSync(join(tmpdir(), "sct-check-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const file = (name: string, content: string) => {
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
};

/** Runs the CLI without blocking: the fake logs live in this process. */
function run(...args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(process.execPath, [MAIN, "--log-list", `http://${origin("log_list.json")}`, ...args], (error, stdout, stderr) =>
      resolve({ code: error ? Number(error.code) : 0, out: stdout + stderr }),
    );
  });
}
const statuses = (out: string) =>
  JSON.parse(out).map((result: { error?: string; scts?: { status: string; detail: string }[] }) =>
    result.error ?? result.scts!.map((sct) => `${sct.status}: ${sct.detail}`.replace(/\d{4}-\d\d-\d\d \d\d:\d\d UTC/g, "T")),
  );

test("SCTs from both kinds of log that are signed and included pass, exit 0", async () => {
  const { code, out } = await run("--file", file("good.pem", good.chain));
  assert.equal(code, 0, out);
  assert.match(out, /ok {4}Test static log \(static-ct-api\), SCT of .+: entry 300 is in the log's tree of 1000 entries/);
  assert.match(out, /ok {4}Test RFC 6962 log \(rfc6962\), SCT of .+: entry 7 is in the log's tree of 40 entries/);
  assert.ok(asked.some((path) => path.startsWith("/static/tile/0/003.p/232")), "the partial level 0 tile");
});

test("a host's certificate is checked the same way, using the issuer it sends", async () => {
  const tls = createTlsServer({ cert: good.chain, key: leafKeyPem }, (socket) => socket.end());
  await new Promise<void>((done) => tls.listen(0, "127.0.0.1", done));
  try {
    const { code, out } = await run(`127.0.0.1:${(tls.address() as AddressInfo).port}`);
    assert.equal(code, 0, out);
    assert.match(out, /localhost, issued by sct-check test CA/);
  } finally {
    tls.close();
  }
});

test("each way an SCT can fail is reported, exit 1", async () => {
  const cases = { badSignature, unknown, missingLong, wrongEntry, noIndex, badCheckpoint, noScts };
  const { code, out } = await run("--json", ...Object.entries(cases).flatMap(([name, { chain }]) => ["--file", file(`${name}.pem`, chain)]));
  assert.equal(code, 1, out);
  assert.deepEqual(statuses(out), [
    ["fail: the log's signature on the SCT doesn't verify"],
    ["fail: the log isn't in the log list"],
    ["fail: not in the log's tree of 1000 entries, signed T, past the log's merge deadline", "fail: not in the log's tree of 40 entries, signed T, past the log's merge deadline"],
    ["fail: the proof for entry 999 doesn't lead to the log's signed root"],
    ["fail: the SCT has no leaf_index, which a static-ct-api log must include"],
    ["fail: the log's signature on its checkpoint doesn't verify"],
    [],
  ]);
  const text = await run("--file", file("none.pem", noScts.chain));
  assert.equal(text.code, 1);
  assert.match(text.out, /FAIL {2}no embedded SCTs/);
});

test("an entry the log hasn't merged yet, within its merge delay, is pending, exit 0", async () => {
  const { code, out } = await run("--file", file("new.pem", missingNew.chain));
  assert.equal(code, 0, out);
  assert.match(out, /wait {2}Test static log .+: not in the log's tree of 1000 entries yet, signed .+; it has until /);
});

test("a rate-limited log is asked again, with the contact given", async () => {
  rateLimits = 1;
  agents.length = 0;
  const { code, out } = await run("--contact", "ops@example.com", "--file", file("again.pem", good.chain));
  assert.equal(code, 0, out);
  assert.equal(rateLimits, 0, "the 429 was served");
  assert.ok(agents.every((agent) => agent === "sct-check (ops@example.com)"), agents.join(", "));
});

test("exits 2 when a log can't be read, a log keeps rate limiting, or the list can't be loaded", async () => {
  tilesBroken = true;
  try {
    const broken = await run("--file", file("broken.pem", good.chain));
    assert.equal(broken.code, 2, broken.out);
    assert.match(broken.out, /ERROR Test static log .+: http:\/\/127\.0\.0\.1:\d+\/static\/tile\/.+: HTTP 500/);
  } finally {
    tilesBroken = false;
  }
  rateLimits = 99;
  try {
    const limited = await run("--file", file("limited.pem", good.chain));
    assert.equal(limited.code, 2, limited.out);
    assert.match(limited.out, /HTTP 429, rate limited: "Please slow down\."; --contact EMAIL may help/);
  } finally {
    rateLimits = 0;
  }
  logListOk = false;
  try {
    const noList = await run("--file", file("nolist.pem", good.chain));
    assert.equal(noList.code, 2, noList.out);
    assert.match(noList.out, /can't load the log list: .+HTTP 500/);
  } finally {
    logListOk = true;
  }
});

test("exits 2 for a chain without its issuer, a file that isn't one, a closed port, or no targets", async () => {
  const leafOnly = await run("--file", file("leaf.pem", /-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/.exec(good.chain)![0]), "--file", file("junk.pem", "junk"));
  assert.equal(leafOnly.code, 2, leafOnly.out);
  assert.match(leafOnly.out, /leaf\.pem {2}error: the file has no issuer certificate after the first one/);
  assert.match(leafOnly.out, /junk\.pem {2}error: no PEM certificate in the file/);
  const selfSigned = createTlsServer({ cert: ca.toString("pem"), key: pem(Buffer.from(await crypto.subtle.exportKey("pkcs8", caKeys.privateKey)), "PRIVATE KEY") }, (socket) => socket.end());
  await new Promise<void>((done) => selfSigned.listen(0, "127.0.0.1", done));
  try {
    const alone = await run(`127.0.0.1:${(selfSigned.address() as AddressInfo).port}`);
    assert.equal(alone.code, 2, alone.out);
    assert.match(alone.out, /error: the server sent no issuer certificate/);
  } finally {
    selfSigned.close();
  }
  const closed = await run("127.0.0.1:1");
  assert.equal(closed.code, 2, closed.out);
  assert.match(closed.out, /127\.0\.0\.1:1 {2}error:/);
  const usage = await run();
  assert.equal(usage.code, 2);
  assert.match(usage.out, /usage: sct-check/);
});

test("an RFC 6962 tree head with a forged signature fails, exit 1", async () => {
  sthForged = true;
  try {
    const { code, out } = await run("--file", file("forged-sth.pem", good.chain));
    assert.equal(code, 1, out);
    assert.match(out, /FAIL {2}Test RFC 6962 log \(rfc6962\), SCT of .+: the log's signature on its tree head doesn't verify/);
  } finally {
    sthForged = false;
  }
});

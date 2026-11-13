// CT logs: Chrome's log list, each log's signed tree head, and inclusion proofs, for RFC 6962
// logs (get-sth, get-proof-by-hash) and static-ct-api logs (checkpoint and tiles).

import { createHash, verify } from "node:crypto";

import { proofFromTiles, tileIndexPath } from "./merkle.ts";

export const CHROME_LOG_LIST = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const TIMEOUT_MS = 15_000;

export interface Log {
  description: string;
  operator: string;
  logId: string; // base64, as in the list
  key: Buffer; // SubjectPublicKeyInfo, DER
  state: string; // usable, readonly, retired, qualified, pending or rejected
  mmdSeconds: number;
  /** An RFC 6962 log's base URL. */
  url?: string;
  /** A static-ct-api log's monitoring prefix. */
  monitoringUrl?: string;
}

export interface TreeHead {
  size: number;
  root: Buffer;
  timestamp: number; // milliseconds since the epoch
}

/** Something the log got wrong, as opposed to a network failure. */
export class LogFailure extends Error {}

export class HttpError extends Error {
  readonly status: number;
  constructor(url: string, status: number, note?: string) {
    super(`${url}: HTTP ${status}${note ? `, ${note}` : ""}`);
    this.status = status;
  }
}

let userAgent = "sct-check";

/** Puts contact details in the User-Agent: some logs, such as Geomys', rate-limit anonymous clients. */
export function setContact(contact: string) {
  userAgent = `sct-check (${contact})`;
}

const RETRIES = 2;
const MAX_WAIT_MS = 10_000;

async function get(url: string): Promise<Buffer> {
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(url, { headers: { "user-agent": userAgent }, signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (response.ok) return Buffer.from(await response.arrayBuffer());
    if (response.status !== 429) throw new HttpError(url, response.status);
    const reason = (await response.text()).trim().split("\n")[0]?.slice(0, 200);
    if (attempt === RETRIES) throw new HttpError(url, 429, `rate limited${reason ? `: "${reason}"` : ""}; --contact EMAIL may help`);
    const seconds = Number(response.headers.get("retry-after"));
    await new Promise((done) => setTimeout(done, Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds * 1000, MAX_WAIT_MS) : 2000 * (attempt + 1)));
  }
}

const slash = (url: string) => (url.endsWith("/") ? url : `${url}/`);

interface ListedLog {
  description: string;
  log_id: string;
  key: string;
  mmd: number;
  state?: Record<string, unknown>;
  url?: string;
  monitoring_url?: string;
}

export const loadLogList = async (url = CHROME_LOG_LIST) => parseLogList((await get(url)).toString("utf8"));

/** The logs in a v3 log list, by base64 log ID. */
export function parseLogList(json: string): Map<string, Log> {
  const list = JSON.parse(json) as { operators: { name: string; logs?: ListedLog[]; tiled_logs?: ListedLog[] }[] };
  const logs = new Map<string, Log>();
  for (const operator of list.operators) {
    for (const log of [...(operator.logs ?? []), ...(operator.tiled_logs ?? [])]) {
      logs.set(log.log_id, {
        description: log.description,
        operator: operator.name,
        logId: log.log_id,
        key: Buffer.from(log.key, "base64"),
        state: Object.keys(log.state ?? {})[0] ?? "unknown",
        mmdSeconds: log.mmd,
        url: log.url && slash(log.url),
        monitoringUrl: log.monitoring_url && slash(log.monitoring_url),
      });
    }
  }
  return logs;
}

/** Checks a TLS DigitallySigned value: SHA-256 with ECDSA or RSA, the two RFC 6962 allows. */
export function verifySignature(key: Buffer, data: Buffer, signed: Buffer): boolean {
  if (signed.length < 4 || signed[0] !== 4 || (signed[1] !== 3 && signed[1] !== 1)) return false;
  if (signed.readUInt16BE(2) !== signed.length - 4) return false;
  try {
    return verify("sha256", data, { key, format: "der", type: "spki" }, signed.subarray(4));
  } catch {
    return false;
  }
}

function u64(n: number) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(n));
  return out;
}

/** The signed tree head's signed data: version v1, signature_type tree_hash, then the head. */
export const treeHeadData = (timestamp: number, size: number, root: Buffer) => Buffer.concat([Uint8Array.of(0, 1), u64(timestamp), u64(size), root]);

/** The latest tree head the log has signed, with its signature checked. */
export async function treeHead(log: Log): Promise<TreeHead> {
  if (log.monitoringUrl) return verifyCheckpoint(log, (await get(`${log.monitoringUrl}checkpoint`)).toString("utf8"));
  if (!log.url) throw new Error(`${log.description} has no URL in the log list`);
  const sth = JSON.parse((await get(`${log.url}ct/v1/get-sth`)).toString("utf8"));
  const head = { size: Number(sth.tree_size), root: Buffer.from(String(sth.sha256_root_hash), "base64"), timestamp: Number(sth.timestamp) };
  if (!Number.isSafeInteger(head.size) || head.root.length !== 32) throw new LogFailure("get-sth returned a malformed tree head");
  if (!verifySignature(log.key, treeHeadData(head.timestamp, head.size, head.root), Buffer.from(String(sth.tree_head_signature), "base64"))) {
    throw new LogFailure("the log's signature on its tree head doesn't verify");
  }
  return head;
}

/**
 * A static-ct-api checkpoint: a signed note whose log signature is an RFC6962NoteSignature, the
 * tree head's timestamp and then its TLS signature. The key ID is the first 4 bytes of
 * SHA-256(origin, "\n", 0x05, log ID); other signatures, such as witnesses', are skipped.
 */
export function verifyCheckpoint(log: Log, text: string): TreeHead {
  const blank = text.indexOf("\n\n");
  if (blank < 0) throw new LogFailure("malformed checkpoint");
  const [origin, sizeText, rootText] = text.slice(0, blank).split("\n");
  const size = Number(sizeText);
  const root = Buffer.from(rootText ?? "", "base64");
  if (!origin || !/^\d+$/.test(sizeText ?? "") || !Number.isSafeInteger(size) || root.length !== 32) throw new LogFailure("malformed checkpoint");

  const keyId = createHash("sha256").update(`${origin}\n`).update(Uint8Array.of(5)).update(Buffer.from(log.logId, "base64")).digest().subarray(0, 4);
  for (const line of text.slice(blank + 2).split("\n")) {
    const match = /^— (\S+) (\S+)$/.exec(line);
    if (match?.[1] !== origin) continue;
    const body = Buffer.from(match[2], "base64");
    if (body.length < 12 || !body.subarray(0, 4).equals(keyId)) continue;
    const timestamp = Number(body.readBigUInt64BE(4));
    if (!verifySignature(log.key, treeHeadData(timestamp, size, root), body.subarray(12))) {
      throw new LogFailure("the log's signature on its checkpoint doesn't verify");
    }
    return { size, root, timestamp };
  }
  throw new LogFailure("the checkpoint carries no signature by this log");
}

/** A static-ct-api tile; a partial tile that has since filled up is fetched whole instead. */
async function tile(prefix: string, level: number, n: number, width: number): Promise<Buffer> {
  const url = `${prefix}tile/${level}/${tileIndexPath(n)}`;
  if (width === 256) return get(url);
  try {
    return await get(`${url}.p/${width}`);
  } catch (error) {
    if (error instanceof HttpError && error.status === 404) return get(url);
    throw error;
  }
}

/** The inclusion proof for an entry, or undefined if the log doesn't have it in this tree. */
export async function inclusionProof(log: Log, leaf: Buffer, leafIndex: number | undefined, head: TreeHead): Promise<{ index: number; path: Buffer[] } | undefined> {
  if (log.monitoringUrl) {
    if (leafIndex === undefined) throw new LogFailure("the SCT has no leaf_index, which a static-ct-api log must include");
    if (leafIndex >= head.size) return undefined;
    const prefix = log.monitoringUrl;
    return { index: leafIndex, path: await proofFromTiles(leafIndex, head.size, (level, n, width) => tile(prefix, level, n, width)) };
  }
  const url = `${log.url}ct/v1/get-proof-by-hash?hash=${encodeURIComponent(leaf.toString("base64"))}&tree_size=${head.size}`;
  let proof;
  try {
    proof = JSON.parse((await get(url)).toString("utf8"));
  } catch (error) {
    // RFC 6962 logs answer an unknown hash with 404 or 400, depending on the implementation.
    if (error instanceof HttpError && (error.status === 404 || error.status === 400)) return undefined;
    throw error;
  }
  if (!Number.isSafeInteger(proof.leaf_index) || !Array.isArray(proof.audit_path)) throw new LogFailure("get-proof-by-hash returned a malformed proof");
  return { index: proof.leaf_index, path: proof.audit_path.map((hash: string) => Buffer.from(hash, "base64")) };
}

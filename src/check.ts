// Checks one certificate, served by a host or kept in a chain file: every embedded SCT must be
// signed by a log in the list, and the log must prove the certificate is in its signed tree.

import { X509Certificate } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { connect } from "node:tls";

import { type Log, type TreeHead, LogFailure, inclusionProof, treeHead, verifySignature } from "./logs.ts";
import { verifyInclusion } from "./merkle.ts";
import { type Sct, embedded, issuerKeyHash, leafHash, signedData } from "./sct.ts";

const TIMEOUT_MS = 10_000;

/** ok: signed and included; pending: signed, not merged yet but within the log's MMD. */
export type Status = "ok" | "pending" | "fail" | "error";

export interface SctResult {
  logId: string;
  log?: string;
  operator?: string;
  state?: string;
  api?: "static-ct-api" | "rfc6962";
  timestamp: Date;
  leafIndex?: number;
  status: Status;
  detail: string;
}

export interface Result {
  target: string;
  error?: string;
  subject?: string;
  issuer?: string;
  notAfter?: Date;
  scts?: SctResult[];
}

export function parseTarget(target: string): { host: string; port: number } {
  const match = /^\[([^\]]+)\](?::(\d+))?$/.exec(target) ?? /^([^:[\]]+)(?::(\d+))?$/.exec(target);
  const port = Number(match?.[2] ?? 443);
  if (!match || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`not a host or host:port: ${target}`);
  return { host: match[1], port };
}

/** The certificate a host serves and the one that issued it, from the chain it sends. */
function fetchChain(host: string, port: number): Promise<[Buffer, Buffer]> {
  return new Promise((resolve, reject) => {
    // Untrusted chains are still read: their CT is worth checking too.
    const socket = connect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: TIMEOUT_MS }, () => {
      const leaf = socket.getPeerCertificate(true);
      socket.end();
      const issuer = leaf?.issuerCertificate;
      if (!leaf?.raw) reject(new Error("the server sent no certificate"));
      else if (!issuer?.raw || issuer.raw.equals(leaf.raw)) reject(new Error("the server sent no issuer certificate"));
      else resolve([leaf.raw, issuer.raw]);
    });
    socket.on("timeout", () => socket.destroy(new Error("timed out")));
    socket.on("error", reject);
  });
}

/** The first two certificates of a PEM chain file, such as fullchain.pem: the leaf and its issuer. */
export async function readChain(path: string): Promise<[Buffer, Buffer]> {
  const pem = (await readFile(path, "latin1")).matchAll(/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/g);
  const [leaf, issuer] = [...pem].map((match) => Buffer.from(match[1].replace(/\s+/g, ""), "base64"));
  if (!leaf) throw new Error("no PEM certificate in the file");
  if (!issuer) throw new Error("the file has no issuer certificate after the first one; use the full chain, such as fullchain.pem");
  return [leaf, issuer];
}

/** Checks SCTs against one log list, fetching each log's tree head once. */
export class Checker {
  private heads = new Map<string, Promise<TreeHead>>();
  private logs: Map<string, Log>;

  constructor(logs: Map<string, Log>) {
    this.logs = logs;
  }

  check(target: string): Promise<Result> {
    return this.examine(target, async () => {
      const { host, port } = parseTarget(target);
      return fetchChain(host, port);
    });
  }

  checkFile(path: string): Promise<Result> {
    return this.examine(path, () => readChain(path));
  }

  private async examine(target: string, load: () => Promise<[Buffer, Buffer]>): Promise<Result> {
    try {
      const [leaf, issuer] = await load();
      const x509 = new X509Certificate(leaf);
      const { scts, tbs } = embedded(leaf);
      const issuerKey = issuerKeyHash(issuer);
      return {
        target,
        subject: x509.subject.split("\n").find((line) => line.startsWith("CN="))?.slice(3) ?? x509.subjectAltName ?? "",
        issuer: x509.issuer.split("\n").filter((line) => /^(O|CN)=/.test(line)).map((line) => line.slice(line.indexOf("=") + 1)).join(" "),
        notAfter: x509.validToDate,
        scts: await Promise.all(scts.map((sct) => this.checkSct(sct, issuerKey, tbs))),
      };
    } catch (error) {
      return { target, error: (error as Error).message };
    }
  }

  private async checkSct(sct: Sct, issuerKey: Buffer, tbs: Buffer): Promise<SctResult> {
    const logId = sct.logId.toString("base64");
    const base = { logId, timestamp: new Date(sct.timestamp), leafIndex: sct.leafIndex };
    const log = this.logs.get(logId);
    if (!log) return { ...base, status: "fail", detail: "the log isn't in the log list" };
    const about = { ...base, log: log.description, operator: log.operator, state: log.state, api: log.monitoringUrl ? ("static-ct-api" as const) : ("rfc6962" as const) };
    if (!verifySignature(log.key, signedData(sct, issuerKey, tbs), sct.signature)) {
      return { ...about, status: "fail", detail: "the log's signature on the SCT doesn't verify" };
    }
    try {
      const head = await this.head(log);
      const leaf = leafHash(sct, issuerKey, tbs);
      const proof = await inclusionProof(log, leaf, sct.leafIndex, head);
      const signed = `signed ${when(new Date(head.timestamp))}`;
      if (!proof) {
        // The SCT promised inclusion within the maximum merge delay of its timestamp.
        const deadline = sct.timestamp + log.mmdSeconds * 1000;
        return head.timestamp < deadline
          ? { ...about, status: "pending", detail: `not in the log's tree of ${head.size} entries yet, ${signed}; it has until ${when(new Date(deadline))}` }
          : { ...about, status: "fail", detail: `not in the log's tree of ${head.size} entries, ${signed}, past the log's merge deadline` };
      }
      if (!verifyInclusion(leaf, proof.index, head.size, proof.path, head.root)) {
        return { ...about, status: "fail", detail: `the proof for entry ${proof.index} doesn't lead to the log's signed root` };
      }
      return { ...about, status: "ok", detail: `entry ${proof.index} is in the log's tree of ${head.size} entries, ${signed}` };
    } catch (error) {
      return { ...about, status: error instanceof LogFailure ? "fail" : "error", detail: (error as Error).message };
    }
  }

  private head(log: Log): Promise<TreeHead> {
    if (!this.heads.has(log.logId)) this.heads.set(log.logId, treeHead(log));
    return this.heads.get(log.logId)!;
  }
}

/** 0 when every SCT checks out, 1 when one doesn't or there are none, 2 when something couldn't be checked. */
export function exitCode(result: Result): number {
  if (result.error || result.scts?.some((sct) => sct.status === "error")) return 2;
  if (!result.scts?.length || result.scts.some((sct) => sct.status === "fail")) return 1;
  return 0;
}

const when = (date: Date) => date.toISOString().slice(0, 16).replace("T", " ") + " UTC";

/** A few lines describing a result for a person. */
export function describe(result: Result): string {
  if (result.error || !result.scts) return `${result.target}  error: ${result.error}`;
  const lines = [`${result.target}  ${result.subject}, issued by ${result.issuer}, expires ${when(result.notAfter!)}`];
  if (result.scts.length === 0) lines.push("  FAIL  no embedded SCTs");
  for (const sct of result.scts) {
    const label = { ok: "ok   ", pending: "wait ", fail: "FAIL ", error: "ERROR" }[sct.status];
    const log = sct.log ? `${sct.log} (${sct.api}${sct.state === "usable" ? "" : `, ${sct.state}`})` : `log ${sct.logId}`;
    lines.push(`  ${label} ${log}, SCT of ${when(sct.timestamp)}: ${sct.detail}`);
  }
  return lines.join("\n");
}

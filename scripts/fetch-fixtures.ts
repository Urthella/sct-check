// Saves the real-world test fixtures: certificate chains served by a few hosts, the part of
// Chrome's log list their SCTs need, and enough of two logs to check one entry in each offline:
// a static-ct-api checkpoint and the level 0 tile holding an entry, and an RFC 6962 signed tree
// head with an inclusion proof. Run it again to refresh them, then update the expected values.

import { writeFileSync } from "node:fs";
import { connect } from "node:tls";

import { CHROME_LOG_LIST, loadLogList } from "../src/logs.ts";
import { tileIndexPath } from "../src/merkle.ts";
import { embedded, issuerKeyHash, leafHash } from "../src/sct.ts";

const HOSTS = ["letsencrypt.org", "www.google.com", "github.com", "en.wikipedia.org"];
const dir = new URL("../test/fixtures/", import.meta.url);
const pem = (der: Buffer) => `-----BEGIN CERTIFICATE-----\n${der.toString("base64").replace(/.{64}/g, "$&\n").trim()}\n-----END CERTIFICATE-----\n`;

function chain(host: string): Promise<[Buffer, Buffer]> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port: 443, servername: host }, () => {
      const leaf = socket.getPeerCertificate(true);
      socket.end();
      resolve([leaf.raw, leaf.issuerCertificate.raw]);
    });
    socket.on("error", reject);
  });
}

const get = async (url: string) => Buffer.from(await (await fetch(url, { headers: { "user-agent": "sct-check" } })).arrayBuffer());

const logs = await loadLogList();
const used = new Set<string>();
const chains = new Map<string, [Buffer, Buffer]>();
for (const host of HOSTS) {
  const [leaf, issuer] = await chain(host);
  chains.set(host, [leaf, issuer]);
  writeFileSync(new URL(`${host}.pem`, dir), pem(leaf) + pem(issuer));
  for (const sct of embedded(leaf).scts) used.add(sct.logId.toString("base64"));
}

// The log list, cut down to the logs these certificates use.
const list = (await (await fetch(CHROME_LOG_LIST)).json()) as { operators: { logs: { log_id: string }[]; tiled_logs?: { log_id: string }[] }[] };
for (const operator of list.operators) {
  operator.logs = operator.logs.filter((log) => used.has(log.log_id));
  operator.tiled_logs = (operator.tiled_logs ?? []).filter((log) => used.has(log.log_id));
}
list.operators = list.operators.filter((operator) => operator.logs.length + (operator.tiled_logs?.length ?? 0));
writeFileSync(new URL("log_list.json", dir), JSON.stringify(list, null, 1) + "\n");

// One static-ct-api entry and one RFC 6962 entry, with what's needed to check them offline.
const saved = { static: false, rfc6962: false };
for (const host of HOSTS) {
  const [leaf, issuer] = chains.get(host)!;
  const { scts, tbs } = embedded(leaf);
  for (const sct of scts) {
    const log = logs.get(sct.logId.toString("base64"))!;
    const hash = leafHash(sct, issuerKeyHash(issuer), tbs);
    if (host === "www.google.com" && log.monitoringUrl && sct.leafIndex !== undefined && !saved.static) {
      saved.static = true;
      writeFileSync(new URL("static-checkpoint.txt", dir), await get(`${log.monitoringUrl}checkpoint`));
      writeFileSync(new URL("static-tile", dir), await get(`${log.monitoringUrl}tile/0/${tileIndexPath(Math.floor(sct.leafIndex / 256))}`));
      console.log(`${host}: ${log.description} entry ${sct.leafIndex}`);
    }
    if (host === "letsencrypt.org" && log.url && !saved.rfc6962) {
      saved.rfc6962 = true;
      const sth = JSON.parse((await get(`${log.url}ct/v1/get-sth`)).toString("utf8"));
      const proof = await get(`${log.url}ct/v1/get-proof-by-hash?hash=${encodeURIComponent(hash.toString("base64"))}&tree_size=${sth.tree_size}`);
      writeFileSync(new URL("rfc6962-sth.json", dir), JSON.stringify(sth, null, 1) + "\n");
      writeFileSync(new URL("rfc6962-proof.json", dir), proof);
      console.log(`${host}: ${log.description} tree of ${sth.tree_size}`);
    }
  }
}

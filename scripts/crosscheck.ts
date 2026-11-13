// Checks real hosts against Chrome's live log list and tallies the results by log API. A signature
// that verifies under the log's key and a proof that leads to the log's signed root can't come
// out right by accident, so every "ok" here is the logs agreeing with this tool's reading.
//
//   node scripts/crosscheck.ts [--contact EMAIL] [host ...]

import { parseArgs } from "node:util";

import { Checker } from "../src/check.ts";
import { loadLogList, setContact } from "../src/logs.ts";

const HOSTS = [
  "letsencrypt.org", "www.google.com", "github.com", "cloudflare.com", "en.wikipedia.org", "www.digicert.com",
  "sectigo.com", "www.mozilla.org", "www.apple.com", "www.microsoft.com", "aws.amazon.com", "www.harica.gr",
];

const { values, positionals } = parseArgs({ allowPositionals: true, options: { contact: { type: "string" } } });
if (values.contact) setContact(values.contact);
const checker = new Checker(await loadLogList());
const tally = new Map<string, number>();
const problems: string[] = [];
for (const host of positionals.length ? positionals : HOSTS) {
  const result = await checker.check(host); // one host at a time, to go easy on the logs
  if (result.error) problems.push(`${host}: ${result.error}`);
  for (const sct of result.scts ?? []) {
    const key = `${sct.api ?? "unknown log"} ${sct.status}: ${sct.operator ?? "?"}`;
    tally.set(key, (tally.get(key) ?? 0) + 1);
    if (sct.status !== "ok") problems.push(`${host}: ${sct.log ?? sct.logId}: ${sct.status}: ${sct.detail}`);
  }
}
for (const [key, count] of [...tally].sort()) console.log(`${count.toString().padStart(3)}  ${key}`);
for (const problem of problems) console.log(problem);

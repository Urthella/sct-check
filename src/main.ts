#!/usr/bin/env node
// sct-check: checks the Certificate Transparency of each host's certificate, or of a certificate
// chain file. Every embedded SCT must carry a valid signature from a log in Chrome's log list,
// and that log must prove the certificate is in its signed tree. Exits 1 if any SCT fails and 2
// if something couldn't be checked, so it can run from cron or a monitoring check.

import { parseArgs } from "node:util";

import { Checker, describe, exitCode } from "./check.ts";
import { CHROME_LOG_LIST, loadLogList, setContact } from "./logs.ts";

const USAGE = "usage: sct-check [--json] [--contact EMAIL] [--log-list URL] [--file CHAIN_PEM]... [host[:port]]...";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    json: { type: "boolean" },
    contact: { type: "string" },
    "log-list": { type: "string", default: CHROME_LOG_LIST },
    file: { type: "string", multiple: true, default: [] },
    help: { type: "boolean", short: "h" },
  },
});

if (values.help || positionals.length + values.file.length === 0) {
  console.error(USAGE);
  process.exitCode = values.help ? 0 : 2;
} else {
  if (values.contact) setContact(values.contact);
  try {
    const checker = new Checker(await loadLogList(values["log-list"]));
    const results = await Promise.all([...positionals.map((target) => checker.check(target)), ...values.file.map((path) => checker.checkFile(path))]);
    console.log(values.json ? JSON.stringify(results, null, 2) : results.map(describe).join("\n\n"));
    // Not process.exit(): it can trip a libuv assertion on Windows.
    process.exitCode = Math.max(...results.map(exitCode));
  } catch (error) {
    console.error(`sct-check: can't load the log list: ${(error as Error).message}`);
    process.exitCode = 2;
  }
}

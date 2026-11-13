// Chrome's CT policy for embedded SCTs, as published at
// https://googlechrome.github.io/CertificateTransparency/ct_policy.html (read 2026-11-14):
//
// 1. at least one SCT from a log that is Qualified, Usable or ReadOnly;
// 2. SCTs from at least N distinct logs that are Qualified, Usable, ReadOnly or Retired, where N
//    is 2 for a lifetime of up to 180 days and 3 beyond that; a Retired log only counts if the
//    earliest SCT presented was issued before it retired;
// 3. among those, SCTs from at least two distinct operators, each SCT's operator being the one
//    that ran the log when the SCT was issued.
//
// Only SCTs whose signatures verify are passed in, as Chrome counts no others.

export interface PolicyLog {
  logId: string;
  operator: string;
  state: string;
  /** When the log entered its current state, in milliseconds since the epoch. */
  stateSince?: number;
  /** Operators that ran the log before, with when each stopped. */
  previousOperators?: { name: string; endTime: number }[];
}

export interface PolicyResult {
  met: boolean;
  /** How many distinct logs this certificate's lifetime calls for. */
  required: number;
  logs: number;
  operators: number;
  detail: string;
}

const CURRENT = new Set(["qualified", "usable", "readonly"]);
const DAY_MS = 86_400_000;

/** The operator that ran the log at `timestamp`. */
export function operatorAt(log: PolicyLog, timestamp: number): string {
  const previous = [...(log.previousOperators ?? [])].sort((a, b) => a.endTime - b.endTime).find((operator) => timestamp < operator.endTime);
  return previous?.name ?? log.operator;
}

export function chromePolicy(lifetimeMs: number, scts: { log: PolicyLog; timestamp: number }[]): PolicyResult {
  const required = lifetimeMs > 180 * DAY_MS ? 3 : 2;
  const earliest = Math.min(...scts.map((sct) => sct.timestamp));
  const counted = scts.filter(({ log }) => CURRENT.has(log.state) || (log.state === "retired" && log.stateSince !== undefined && earliest < log.stateSince));
  const logs = new Set(counted.map(({ log }) => log.logId)).size;
  const operators = new Set(counted.map(({ log, timestamp }) => operatorAt(log, timestamp))).size;
  const days = Math.ceil(lifetimeMs / DAY_MS); // up, so a lifetime just past 180 days doesn't read as 180
  const problems = [
    scts.some(({ log }) => CURRENT.has(log.state)) ? "" : "no SCT from a log that's qualified, usable or read-only",
    logs >= required ? "" : `SCTs from ${logs} counted logs, and a certificate of ${days} days needs ${required}`,
    operators >= 2 ? "" : `SCTs from ${operators} counted operators, and it needs 2`,
  ].filter(Boolean);
  return {
    met: problems.length === 0,
    required,
    logs,
    operators,
    detail: problems.length ? problems.join("; ") : `SCTs from ${logs} logs and ${operators} operators, and a certificate of ${days} days needs ${required} logs and 2 operators`,
  };
}

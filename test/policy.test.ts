import assert from "node:assert/strict";
import { test } from "node:test";

import { type PolicyLog, chromePolicy, operatorAt } from "../src/policy.ts";

const DAY = 86_400_000;
const T = Date.parse("2026-11-01T00:00:00Z");
const log = (logId: string, operator: string, state = "usable", more: Partial<PolicyLog> = {}): PolicyLog => ({ logId, operator, state, ...more });
const sct = (l: PolicyLog, timestamp = T) => ({ log: l, timestamp });

test("a certificate of up to 180 days needs 2 logs from 2 operators", () => {
  assert.ok(chromePolicy(90 * DAY, [sct(log("a", "A")), sct(log("b", "B"))]).met);
  assert.ok(chromePolicy(180 * DAY, [sct(log("a", "A")), sct(log("b", "B", "qualified"))]).met, "exactly 180 days");
  const one = chromePolicy(90 * DAY, [sct(log("a", "A"))]);
  assert.ok(!one.met);
  assert.equal(one.detail, "SCTs from 1 counted logs, and a certificate of 90 days needs 2; SCTs from 1 counted operators, and it needs 2");
  const sameOperator = chromePolicy(90 * DAY, [sct(log("a", "A")), sct(log("b", "A"))]);
  assert.ok(!sameOperator.met);
  assert.equal(sameOperator.detail, "SCTs from 1 counted operators, and it needs 2");
  const sameLog = chromePolicy(90 * DAY, [sct(log("a", "A")), sct(log("a", "A"), T + 1)]);
  assert.equal(sameLog.logs, 1, "two SCTs from one log count once");
});

test("a longer-lived certificate needs 3 logs", () => {
  const two = chromePolicy(180 * DAY + 1000, [sct(log("a", "A")), sct(log("b", "B"))]);
  assert.ok(!two.met);
  assert.equal(two.required, 3);
  assert.match(two.detail, /a certificate of 181 days needs 3/);
  assert.ok(chromePolicy(398 * DAY, [sct(log("a", "A")), sct(log("b", "B")), sct(log("c", "A", "readonly"))]).met);
});

test("a retired log counts only if the earliest SCT predates its retirement", () => {
  const retiredLater = log("r", "R", "retired", { stateSince: T + DAY });
  const retiredBefore = log("r", "R", "retired", { stateSince: T - DAY });
  assert.ok(chromePolicy(90 * DAY, [sct(log("a", "A")), sct(retiredLater)]).met);
  assert.ok(!chromePolicy(90 * DAY, [sct(log("a", "A")), sct(retiredBefore)]).met);
  assert.ok(!chromePolicy(90 * DAY, [sct(log("a", "A"), T + 2 * DAY), sct(retiredLater, T + 2 * DAY)]).met, "every SCT after retirement");
  assert.ok(chromePolicy(90 * DAY, [sct(log("a", "A"), T - DAY), sct(retiredLater, T + 2 * DAY)]).met, "the earliest SCT decides");
  assert.ok(!chromePolicy(90 * DAY, [sct(log("r", "R", "retired"))]).met, "a retired log without a timestamp doesn't count");
});

test("at least one SCT must come from a log that's still current", () => {
  const retired = (id: string, operator: string) => log(id, operator, "retired", { stateSince: T + DAY });
  const result = chromePolicy(90 * DAY, [sct(retired("x", "X")), sct(retired("y", "Y"))]);
  assert.ok(!result.met);
  assert.equal(result.detail, "no SCT from a log that's qualified, usable or read-only");
});

test("pending and rejected logs don't count", () => {
  assert.ok(!chromePolicy(90 * DAY, [sct(log("a", "A")), sct(log("p", "P", "pending"))]).met);
  assert.ok(!chromePolicy(90 * DAY, [sct(log("a", "A")), sct(log("j", "J", "rejected"))]).met);
  assert.ok(!chromePolicy(90 * DAY, []).met, "no SCTs at all");
});

test("an SCT counts for the operator that ran the log when it was issued", () => {
  const moved = log("m", "New", "usable", { previousOperators: [{ name: "Middle", endTime: T }, { name: "Old", endTime: T - 10 * DAY }] });
  assert.equal(operatorAt(moved, T - 20 * DAY), "Old");
  assert.equal(operatorAt(moved, T - DAY), "Middle");
  assert.equal(operatorAt(moved, T), "New");
  assert.ok(!chromePolicy(90 * DAY, [sct(moved, T - DAY), sct(log("b", "Middle"))]).met, "the same operator at the time");
  assert.ok(chromePolicy(90 * DAY, [sct(moved, T + DAY), sct(log("b", "Middle"))]).met);
});

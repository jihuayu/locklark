import test from "node:test";
import assert from "node:assert/strict";
import { parseSummary } from "../lib/summary.ts";
const sample = {
  version: 1,
  mode: "active",
  freshness: "local-verified",
  observedAt: "2026-11-05T00:00:00Z",
  checkpoint: { scope: "a".repeat(64), hash: "b".repeat(64), version: 1 },
  members: [{ id: "1".repeat(32), role: "reader", devices: ["2".repeat(32)] }],
};
test("projection never preserves unknown upstream secrets", () => {
  const result = parseSummary({
    ...sample,
    password: "never-web",
    snapshot: { database: "private" },
    members: [{ ...sample.members[0], signing: "secret" }],
  });
  const text = JSON.stringify(result);
  assert.ok(!text.includes("secret"));
  assert.ok(!text.includes("never-web"));
  assert.ok(!text.includes("database"));
});
test("invalid and duplicate identities, invalid roles and frozen rosters are rejected", () => {
  assert.throws(() => parseSummary({ ...sample, mode: "frozen" }));
  assert.throws(() =>
    parseSummary({
      ...sample,
      members: [{ ...sample.members[0], role: "owner" }],
    }),
  );
  assert.throws(() =>
    parseSummary({
      ...sample,
      members: [sample.members[0], sample.members[0]],
    }),
  );
  assert.throws(() =>
    parseSummary({
      ...sample,
      members: [{ ...sample.members[0], devices: [sample.members[0].id] }],
    }),
  );
  assert.throws(() =>
    parseSummary({
      ...sample,
      checkpoint: { ...sample.checkpoint, version: NaN },
    }),
  );
});

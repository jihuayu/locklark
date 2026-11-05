import test from "node:test";
import assert from "node:assert/strict";
import {
  SessionRegistry,
  validRequest,
  parseConnection,
} from "../lib/security.ts";
const origin = "http://127.0.0.1:3417";
test("connection codes are single-use, expiring and cannot be session cookies", () => {
  let now = 1000;
  const code = "a".repeat(64),
    r = new SessionRegistry(code, () => now);
  assert.equal(r.exchange("b".repeat(64)), null);
  assert.equal(r.verify(code), null);
  const session = r.exchange(code);
  assert.ok(session);
  assert.equal(r.exchange(code), null);
  assert.ok(r.verify(session.id));
  r.revoke(session.id);
  assert.equal(r.verify(session.id), null);
  const expired = new SessionRegistry(code, () => now);
  now += 5 * 60 * 1000 + 1;
  assert.equal(expired.exchange(code), null);
});
test("expired session and connection attempts fail closed", () => {
  let now = 1000;
  const r = new SessionRegistry("a".repeat(64), () => now);
  const s = r.exchange("a".repeat(64));
  assert.ok(s);
  now += 30 * 60 * 1000;
  assert.equal(r.verify(s.id), null);
});
test("exact Host, Origin and fetch metadata are enforced", () => {
  const h = new Headers({
    host: "127.0.0.1:3417",
    origin,
    "sec-fetch-site": "same-origin",
  });
  assert.equal(validRequest(h, origin, true), true);
  for (const [key, value] of [
    ["host", "evil.test"],
    ["origin", "null"],
    ["origin", "http://127.0.0.1:9999"],
    ["sec-fetch-site", "cross-site"],
  ]) {
    const changed = new Headers(h);
    changed.set(key, value);
    assert.equal(validRequest(changed, origin, true), false);
  }
  h.delete("origin");
  assert.equal(validRequest(h, origin, true), false);
});
test("broker destination cannot become an SSRF URL or malformed credential", () => {
  const good = {
    version: 1,
    url: "http://127.0.0.1:3418",
    token: "b".repeat(64),
  };
  assert.equal(parseConnection(JSON.stringify(good)).url, good.url);
  for (const url of [
    "http://example.test",
    "http://127.0.0.1:3418/path",
    "http://user@127.0.0.1:3418",
    "https://127.0.0.1:3418",
    "http://127.0.0.1:3418?token=x",
  ]) {
    assert.throws(() => parseConnection(JSON.stringify({ ...good, url })));
  }
  assert.throws(() =>
    parseConnection(JSON.stringify({ ...good, token: "short" })),
  );
});
test("startup deadline is not reset by the first visitor", () => {
  const r = new SessionRegistry("a".repeat(64), () => 400_000, 1000);
  assert.equal(r.exchange("a".repeat(64)), null);
});
test("only one racing exchange can create a session", async () => {
  const r = new SessionRegistry("a".repeat(64));
  const results = await Promise.all(
    Array.from({ length: 8 }, async () => r.exchange("a".repeat(64))),
  );
  assert.equal(results.filter(Boolean).length, 1);
});

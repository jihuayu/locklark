// Strict core.validResponse schema for the native `match-profiles` reply.
//
// Native host: internal/browserhost/vault_ops.go handleMatchProfiles returns
// Response{Type: "profiles"} and protocol.go always marshals the exact frame
// {v, id, type, profiles} (an empty list is `[]`, never omitted). Each row is
// types_v2.go BrowserProfileSummary: metadata only, with `omitempty` on the
// display hints. Before this schema existed the native port listener treated
// every profile list as a protocol error and dropped the connection.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const core = require(path.join(__dirname, "..", "core.js"));

const id = "fedcba9876543210fedcba9876543210";
const id2 = "abcdef0123456789abcdef0123456789";
const rev =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const clone = (value) => JSON.parse(JSON.stringify(value));
const hexID = (n) => n.toString(16).padStart(32, "0");
const frame = (profiles, extra = {}) => ({
  v: 1,
  id,
  type: "profiles",
  profiles,
  ...extra,
});
const card = (overrides = {}) => ({
  id,
  revision: rev,
  category: "credit_card",
  title: "Synthetic Card",
  subtitle: "Visa •••• 1111",
  card_brand: "visa",
  card_last4: "1111",
  card_exp: "2030-01",
  ...overrides,
});
const identity = (overrides = {}) => ({
  id: id2,
  revision: rev,
  category: "identity",
  title: "Synthetic Identity",
  subtitle: "Ada Lovelace · ada@example.test",
  ...overrides,
});

const wire = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, "fixtures", "match-profiles-wire.json"),
    "utf8",
  ),
);

test("exact native match-profiles wire fixture is accepted and stays exact", () => {
  assert.deepEqual(Object.keys(wire.responses).sort(), [
    "card",
    "empty",
    "identity",
    "mixed",
  ]);
  for (const [name, response] of Object.entries(wire.responses)) {
    assert.deepEqual(
      Object.keys(response).sort(),
      ["id", "profiles", "type", "v"],
      name,
    );
    assert.equal(response.v, 1, name);
    assert.equal(response.type, "profiles", name);
    assert.equal(core.validResponse(response), true, name);
  }
  // Go struct tags: BrowserProfileSummary always emits id/revision/category/
  // title; subtitle/card_brand/card_last4/card_exp are omitempty.
  assert.deepEqual(Object.keys(wire.responses.card.profiles[0]).sort(), [
    "card_brand",
    "card_exp",
    "card_last4",
    "category",
    "id",
    "revision",
    "subtitle",
    "title",
  ]);
  assert.deepEqual(Object.keys(wire.responses.identity.profiles[0]).sort(), [
    "category",
    "id",
    "revision",
    "subtitle",
    "title",
  ]);
  assert.deepEqual(Object.keys(wire.responses.mixed.profiles[1]).sort(), [
    "category",
    "id",
    "revision",
    "subtitle",
    "title",
  ]);
  assert.deepEqual(wire.responses.empty.profiles, []);
  assert.deepEqual(Object.keys(wire.responses.card).sort(), [
    "id",
    "profiles",
    "type",
    "v",
  ]);
});

test("profiles header is exact, typed and bounded", () => {
  assert.equal(core.validResponse({ v: 1, id, type: "profiles" }), false);
  for (const profiles of [null, undefined, {}, "list", 7, { 0: card() }])
    assert.equal(core.validResponse(frame(profiles)), false, String(profiles));
  for (const bad of [
    frame([card()], { extra: 1 }),
    frame([card()], { profiles_meta: [] }),
    frame([card()], { category: "credit_card" }),
    frame([card()], { capabilities: [] }),
    { ...frame([card()]), id: "A".repeat(32) },
    { ...frame([card()]), id: "a".repeat(31) },
    { ...frame([card()]), id: 1 },
    { ...frame([card()]), v: 2 },
    { ...frame([card()]), type: "profile-list" },
    { ...frame([card()]), type: "match-profiles" },
  ])
    assert.equal(core.validResponse(bad), false, JSON.stringify(bad));
});

test("private card or user data can never ride along", () => {
  const forbidden = [
    "number",
    "card_number",
    "cardNumber",
    "cc_number",
    "cvv",
    "cvc",
    "csc",
    "verification",
    "pin",
    "cc_pin",
    "ssn",
    "social_security_number",
    "user_id",
    "user_handle",
    "username",
    "password",
    "otp",
    "notes",
    "fields",
    "credit_card",
    "identity",
    "raw_user_id",
    "item",
    "vault_id",
  ];
  for (const key of forbidden) {
    assert.equal(
      core.validResponse(frame([card({ [key]: "synthetic-private-value" })])),
      false,
      key,
    );
    assert.equal(
      core.validResponse(frame([identity({ [key]: "synthetic-private-value" })])),
      false,
      key,
    );
  }
  // A top-level secret envelope is just as unknown as a row-level one.
  assert.equal(
    core.validResponse(frame([card()], { credit_card: { number: "4111" } })),
    false,
  );
  assert.equal(
    core.validResponse(frame([card()], { identity: { email: "a@b.test" } })),
    false,
  );
});

test("identifiers, categories and required text are strict", () => {
  for (const bad of [
    card({ id: id.toUpperCase() }),
    card({ id: "a".repeat(31) }),
    card({ id: "g".repeat(32) }),
    card({ id: 7 }),
    card({ id: undefined }),
    card({ revision: rev.slice(0, 63) }),
    card({ revision: rev.toUpperCase() }),
    card({ revision: rev.slice(0, 63) + "z" }),
    card({ revision: 7 }),
    card({ revision: undefined }),
    card({ category: "login" }),
    card({ category: "Credit_Card" }),
    card({ category: "" }),
    card({ category: undefined }),
    card({ title: 7 }),
    card({ title: undefined }),
    card({ title: "x".repeat(1025) }),
    identity({ title: "x".repeat(1025) }),
    identity({ category: "login" }),
    identity({ id: id.toUpperCase() }),
  ])
    assert.equal(core.validResponse(frame([bad])), false, JSON.stringify(bad));
  for (const row of [null, undefined, 7, "row", [], [card()], true])
    assert.equal(core.validResponse(frame([row])), false, String(row));
  // The documented boundary lengths remain accepted.
  assert.equal(
    core.validResponse(frame([card({ title: "x".repeat(1024) })])),
    true,
  );
});

test("optional metadata hints are bounded and category-scoped", () => {
  for (const bad of [
    card({ subtitle: 7 }),
    card({ subtitle: "x".repeat(1025) }),
    card({ card_brand: 7 }),
    card({ card_brand: "x".repeat(65) }),
    card({ card_last4: 7 }),
    card({ card_last4: "11111" }),
    card({ card_last4: "ab12" }),
    card({ card_last4: "" }),
    card({ card_exp: 7 }),
    card({ card_exp: "x".repeat(33) }),
    // Card hints never belong to an identity picker row.
    identity({ card_brand: "visa" }),
    identity({ card_last4: "1111" }),
    identity({ card_exp: "2030-01" }),
  ])
    assert.equal(core.validResponse(frame([bad])), false, JSON.stringify(bad));
  // All optional hints are absent-capable and the exact bounds are inclusive.
  assert.equal(
    core.validResponse(
      frame([{ id, revision: rev, category: "identity", title: "Ada" }]),
    ),
    true,
  );
  assert.equal(
    core.validResponse(frame([card({ subtitle: "x".repeat(1024) })])),
    true,
  );
  assert.equal(
    core.validResponse(frame([card({ card_brand: "x".repeat(64) })])),
    true,
  );
  assert.equal(
    core.validResponse(frame([card({ card_exp: "x".repeat(32) })])),
    true,
  );
  assert.equal(core.validResponse(frame([card({ card_last4: "1" })])), true);
});

test("profile lists are capped at 100 and metadata ids stay unambiguous", () => {
  const rows = (count) =>
    Array.from({ length: count }, (_, n) =>
      card({ id: hexID(n), title: "Card " + n, card_last4: "1111" }),
    );
  assert.equal(rows(100).length, 100);
  assert.equal(core.validResponse(frame(rows(100))), true);
  assert.equal(core.validResponse(frame(rows(101))), false);
  assert.equal(core.validResponse(frame([card(), card()])), false);
  assert.equal(
    core.validResponse(frame([card(), card({ revision: "f".repeat(64) })])),
    false,
  );
  assert.equal(
    core.validResponse(
      frame([card(), identity(), card({ id: hexID(3), title: "Newer" })]),
    ),
    true,
  );
});

test("all other v2 response validators still apply", () => {
  assert.equal(
    core.validResponse({
      v: 1,
      id,
      type: "items",
      items: [{ id, revision: rev, category: "login", title: "Example" }],
      vaults: [{ id: "personal", name: "Personal" }],
    }),
    true,
  );
  assert.equal(
    core.validResponse({
      v: 1,
      id,
      type: "profile-fill",
      profile_fill: {
        item_id: id,
        revision: rev,
        category: "identity",
        fields: { "address.city": "Example City" },
      },
    }),
    true,
  );
  assert.equal(
    core.validResponse({
      v: 1,
      id,
      type: "field-value",
      item_id: id,
      revision: rev,
      field: "password",
      value: "synthetic",
      copied: false,
      expires_in_seconds: 30,
    }),
    true,
  );
  assert.equal(
    core.validResponse({
      v: 1,
      id,
      type: "items",
      items: [],
      vaults: [],
      profiles: [],
    }),
    false,
  );
  assert.equal(
    core.validResponse({
      v: 1,
      id,
      type: "profile-fill",
      profile_fill: { item_id: id, revision: rev, category: "identity", fields: [] },
    }),
    false,
  );
});

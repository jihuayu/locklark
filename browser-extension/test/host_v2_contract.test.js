// Contract between the extension and the native host v2 vault protocol
// (internal/browserhost/vault_ops.go). The frames below are the exact key sets
// the Go host marshals; if either side drifts, the extension would treat the
// reply as a protocol error and drop the native connection.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const core = require(path.join(root, "core.js"));
const backgroundJS = fs.readFileSync(path.join(root, "background.js"), "utf8");

const id = "fedcba9876543210fedcba9876543210";
const rev = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test("host v2 vault replies are valid extension responses", () => {
  const frames = [
    {
      v: 1,
      id,
      type: "items",
      items: [
        {
          id,
          revision: rev,
          category: "login",
          vault_id: "personal",
          title: "Example",
          state: "active",
        },
      ],
      vaults: [{ id: "personal", name: "Personal" }],
    },
    {
      v: 1,
      id,
      type: "item-detail",
      item: {
        id,
        revision: rev,
        category: "login",
        vault_id: "",
        title: "Example",
        state: "active",
      },
    },
    {
      v: 1,
      id,
      type: "item-saved",
      item_id: id,
      revision: rev,
      state: "archived",
      favorite: true,
    },
    {
      v: 1,
      id,
      type: "item-saved",
      item_id: id,
      revision: rev,
      item_summary: { id },
    },
    {
      v: 1,
      id,
      type: "profile-fill",
      profile_fill: {
        item_id: id,
        revision: rev,
        category: "identity",
        fields: { "address.city": "Example City" },
      },
    },
  ];
  for (const frame of frames)
    assert.equal(core.validResponse(frame), true, frame.type);
});

test("host v2 vault replies stay strictly bounded", () => {
  const bad = [
    { v: 1, id, type: "items", items: [], vaults: [], extra: 1 },
    { v: 1, id, type: "items", items: [], vaults: "x" },
    { v: 1, id, type: "item-saved", item_id: id, revision: "x" },
    { v: 1, id, type: "item-saved", item_id: id, revision: rev, state: "gone" },
    {
      v: 1,
      id,
      type: "profile-fill",
      profile_fill: { item_id: id, revision: rev, category: "identity", fields: [] },
    },
  ];
  for (const frame of bad)
    assert.equal(core.validResponse(frame), false, JSON.stringify(frame));
});

test("background only sends request types the host accepts", () => {
  assert.doesNotMatch(backgroundJS, /"fill-item"/);
  assert.match(backgroundJS, /"fill-profile"/);
  assert.match(backgroundJS, /state_action: action/);
});

test("desktop broker unlocked push is accepted and strictly bounded", () => {
  const cap = "0123456789abcdef0123456789abcdef";
  const push = {
    v: 1,
    type: "unlocked",
    capability: cap,
    quick_fill: true,
    desktop_connected: true,
    unlocked: true,
    session_epoch: 3,
    capabilities: ["vault-v2", "fill-profile"],
  };
  assert.equal(core.validResponse(push), true);
  assert.equal(core.validResponse({ v: 1, type: "unlocked", capability: cap }), true);
  for (const bad of [
    { ...push, capability: "short" },
    { ...push, id },
    { ...push, extra: 1 },
    { ...push, unlocked: false },
    { ...push, session_epoch: -1 },
    { ...push, capabilities: ["UPPER"] },
    { ...push, v: 2 },
  ])
    assert.equal(core.validResponse(bad), false, JSON.stringify(bad));
  assert.match(backgroundJS, /message\.type === "unlocked"/);
});

test("flat popup item maps to the exact v2 mutation whitelist", () => {
  const item = {
    category: "card",
    title: "Card",
    cardholder: "Ada Lovelace",
    brand: "Visa",
    card_number: "4111111111111111",
    expiry: "12/30",
    cvv: "123",
    urls: ["https://example.test/login"],
    fields: [],
    otp_secret: "",
    notes: "",
  };
  const mutation = core.itemToNativeMutation(item);
  assert.deepEqual(Object.keys(mutation).sort(), [
    "category",
    "credit_card",
    "notes",
    "title",
    "urls",
  ]);
  assert.equal(mutation.category, "credit_card");
  assert.deepEqual(mutation.credit_card, {
    cardholder_name: "Ada Lovelace",
    type: "Visa",
    number: "4111111111111111",
    verification: "123",
    expiry_date: "12/30",
  });
  assert.deepEqual(mutation.urls, [
    { url: "https://example.test/login", primary: true, match_mode: "origin" },
  ]);
  for (const forbidden of ["fields", "otp_secret", "card_number", "cardholder", "brand", "expiry", "cvv"])
    assert.equal(Object.hasOwn(mutation, forbidden), false, forbidden);
});

test("native aliases, stable section ids and omitted blank secrets are preserved", () => {
  for (const [alias, canonical] of [
    ["card", "credit_card"],
    ["credit_card", "credit_card"],
    ["note", "secure_note"],
    ["secure_note", "secure_note"],
    ["ssh", "ssh_key"],
    ["ssh_key", "ssh_key"],
  ])
    assert.equal(core.itemToNativeMutation({ category: alias, title: "T" }).category, canonical);
  const original = {
    sections: [{
      id: "sec1",
      title: "Extra",
      fields: [{ id: "f1", label: "Recovery", type: "concealed", value: "", concealed: true, has_value: true }],
    }],
  };
  const edited = core.itemToNativeMutation({
    category: "login",
    title: "Login",
    username: "ada",
    password: "",
    otp_secret: "",
    notes: "changed notes",
    urls: ["https://example.test/login"],
    sections: original.sections,
    fields: [{ id: "f1", label: "Recovery", type: "concealed", value: "" }],
  }, { original });
  assert.equal(Object.hasOwn(edited, "password"), false);
  assert.equal(Object.hasOwn(edited, "otp"), false);
  assert.equal(edited.sections.length, 1, "supplied sections keep one stable structure");
  assert.equal(edited.sections[0].id, "sec1");
  const maskedField = edited.sections[0].fields.find((field) => field.id === "f1");
  assert.equal(maskedField.concealed, true);
  assert.equal(
    Object.hasOwn(maskedField, "value"),
    false,
    "masked concealed values must not be rewritten",
  );
  assert.equal(edited.notes, "changed notes");
  const first = core.itemToNativeMutation({
    category: "note",
    title: "Note",
    content: "body",
    fields: [{ label: "Recovery", type: "text", value: "one" }],
  });
  const second = core.itemToNativeMutation({
    category: "note",
    title: "Note",
    content: "body",
    fields: [{ label: "Recovery", type: "text", value: "two" }],
  });
  assert.equal(first.fields, undefined);
  assert.equal(first.sections[0].id, "custom-fields");
  assert.match(first.sections[0].fields[0].id, /^f[0-9a-f]{8}$/);
  assert.equal(first.sections[0].fields[0].id, second.sections[0].fields[0].id);
  assert.equal(first.sections[0].fields[0].type, "text");
  assert.equal(first.sections[0].fields[0].value, "one");
  assert.equal(first.notes, "body");
});

test("native field-value responses require the exact bounded shape", () => {
  const frame = {
    v: 1,
    id,
    type: "field-value",
    item_id: id,
    revision: rev,
    field: "password",
    value: "secret",
    copied: false,
    expires_in_seconds: 30,
  };
  assert.equal(core.validResponse(frame), true);
  assert.equal(core.validResponse({ ...frame, field: "unknown" }), false);
  assert.equal(core.validResponse({ ...frame, value: 7 }), false);
  assert.equal(core.validResponse({ ...frame, field_value: "alias" }), false);
  assert.equal(core.validResponse({ ...frame, expires_in_seconds: -1 }), false);
  assert.equal(core.validResponse({ ...frame, extra: 1 }), false);
  assert.equal(core.validResponse({ ...frame, field: "section:sec1:f1" }), true);
});


test("cross-language field-value wire fixture is exact and strictly consumed", () => {
  const wire = JSON.parse(
    fs.readFileSync(path.join(__dirname, "fixtures", "field-value-wire.json"), "utf8"),
  );
  assert.deepEqual(Object.keys(wire.requests).sort(), ["copy", "reveal", "reveal_otp"]);
  assert.deepEqual(Object.keys(wire.responses).sort(), ["copy", "reveal", "reveal_otp"]);
  assert.deepEqual(Object.keys(wire.requests.reveal).sort(), [
    "action", "capability", "field", "id", "item_id", "revision", "type", "v",
  ]);
  assert.equal(wire.requests.reveal.action, "reveal");
  assert.equal(wire.requests.copy.action, "copy");
  assert.equal(Object.hasOwn(wire.requests.reveal, "field_action"), false);
  for (const response of Object.values(wire.responses)) {
    assert.deepEqual(Object.keys(response).sort(), [
      "copied", "expires_in_seconds", "field", "id", "item_id", "revision", "type", "v", "value",
    ]);
    assert.equal(Object.hasOwn(response, "field_value"), false);
    assert.equal(core.validResponse(response), true, response.field);
  }
  const reveal = wire.responses.reveal;
  assert.equal(reveal.value, "Synthetic-Secret-1");
  assert.equal(reveal.expires_in_seconds, 0);
  assert.equal(wire.responses.copy.copied, true);
  assert.equal(wire.responses.copy.expires_in_seconds, 30);
  const alias = { ...reveal, field_value: reveal.value };
  delete alias.value;
  assert.equal(core.validResponse(alias), false);
  assert.equal(core.validResponse({ ...reveal, extra: 1 }), false);
});


test("flatten preserves native metadata, qualifies section ids once, and keeps generic fields", () => {
  const detail = {
    id: "b".repeat(32),
    revision: "c".repeat(64),
    title: "Example",
    category: "login",
    fields: [
      { id: "password", label: "密码", type: "concealed", value: "", concealed: true, has_value: true, revealable: true },
      { id: "otp", label: "OTP", type: "totp", value: "", concealed: false, has_value: true, revealable: true },
      { id: "section:sec1:f1", label: "Recovery", type: "concealed", value: "", concealed: true, has_value: true, section_id: "sec1", section_title: "Extra" },
    ],
    sections: [{ id: "sec1", title: "Extra", fields: [{ id: "f1", label: "Recovery", type: "concealed", value: "", concealed: true }] }],
  };
  const fields = core.flattenItemFields(detail);
  const password = fields.find((field) => field.id === "password");
  assert.equal(password.has_value, true);
  assert.equal(password.revealable, true);
  assert.equal(fields.find((field) => field.id === "otp").revealable, true);
  assert.equal(fields.filter((field) => field.id === "section:sec1:f1").length, 1);
  assert.equal(fields.some((field) => field.id === "f1"), false);
  assert.equal(fields.find((field) => field.id === "section:sec1:f1").section_id, "sec1");
  const generic = core.flattenItemFields({ fields: [{ id: "custom", label: "Custom", type: "text", value: "kept" }] });
  assert.deepEqual(generic[0], { id: "custom", label: "Custom", type: "text", value: "kept", concealed: false });
});


test("metadata edit omits blank masked notes but sends explicit replacements", () => {
  const original = {
    id: "b".repeat(32),
    revision: "c".repeat(64),
    title: "Old title",
    notes: "",
    has_notes: true,
    fields: [
      { id: "notes", label: "备注", type: "concealed", value: "", concealed: true, has_value: true, revealable: true },
    ],
    sections: [{ id: "sec1", title: "Extra", fields: [{ id: "f1", label: "Recovery", type: "concealed", value: "", concealed: true, has_value: true }] }],
  };
  const metadataOnly = core.itemToNativeMutation(
    { category: "login", title: "New title", notes: "" },
    { original },
  );
  assert.equal(Object.hasOwn(metadataOnly, "notes"), false, "blank masked notes must be omitted");
  assert.equal(Object.hasOwn(metadataOnly, "sections"), false);
  const replaced = core.itemToNativeMutation(
    { category: "login", title: "New title", notes: "replacement note" },
    { original },
  );
  assert.equal(replaced.notes, "replacement note");
  const created = core.itemToNativeMutation({ category: "login", title: "New", notes: "" });
  assert.equal(created.notes, "");
  const plaintextLoaded = { ...original, notes: "visible old" };
  const cleared = core.itemToNativeMutation(
    { category: "login", title: "New title", notes: "" },
    { original: plaintextLoaded },
  );
  assert.equal(cleared.notes, "");
});

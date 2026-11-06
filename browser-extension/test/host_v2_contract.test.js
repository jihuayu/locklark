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

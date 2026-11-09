const test = require("node:test");
const assert = require("node:assert/strict");
const core = require("../core.js");

const CRED_A = core.base64URLEncode(new Uint8Array(32).fill(11));
const CRED_B = core.base64URLEncode(new Uint8Array(32).fill(12));
const CHILD_A = "a".repeat(64);
const CHILD_B = "b".repeat(64);
const ITEM = "1".repeat(32);
const PARENT = "2".repeat(64);

function candidate(overrides = {}) {
  return {
    item_id: ITEM,
    revision: PARENT,
    title: "Item",
    credential_id: CRED_A,
    rp_id: "example.test",
    user_name: "ada@example.test",
    display_name: "Ada",
    ...overrides,
  };
}

test("conditional candidate accepts an optional canonical child revision only", () => {
  assert.equal(core.validConditionalPasskeyEntry(candidate()), true);
  assert.equal(
    core.validConditionalPasskeyEntry(candidate({ credential_revision: CHILD_A })),
    true,
  );
  for (const bad of [
    CHILD_A.slice(1),
    CHILD_A.toUpperCase(),
    "z".repeat(64),
    CHILD_A + "0",
    64,
    null,
    "",
  ])
    assert.equal(
      core.validConditionalPasskeyEntry(candidate({ credential_revision: bad })),
      false,
      "non-canonical child revision accepted: " + String(bad),
    );
  for (const extra of [
    { user_handle: "x" },
    { private_key: "x" },
    { raw_record: "x" },
    { credential_revisions: CHILD_A },
  ])
    assert.equal(
      core.validConditionalPasskeyEntry(candidate(extra)),
      false,
      "unknown public field accepted: " + Object.keys(extra)[0],
    );
});

test("sibling candidates with distinct credentials and child revisions stay valid", () => {
  const list = [
    candidate({ credential_id: CRED_A, credential_revision: CHILD_A }),
    candidate({ credential_id: CRED_B, credential_revision: CHILD_B }),
  ];
  assert.equal(core.validConditionalPasskeyList(list), true);
  assert.equal(
    core.validConditionalPasskeyList([list[0], candidate({ credential_revision: CHILD_B })]),
    false,
    "one credential may never be listed twice",
  );
});

test("passkey detail metadata accepts the optional child revision and no private fields", () => {
  const metadata = {
    credential_id: CRED_A,
    rp_id: "example.test",
    user_name: "ada@example.test",
    display_name: "Ada",
  };
  assert.equal(core.validPasskeyMetadata(metadata), true);
  assert.equal(
    core.validPasskeyMetadata({ ...metadata, credential_revision: CHILD_A }),
    true,
  );
  for (const bad of [CHILD_A.toUpperCase(), "abc", 12, null])
    assert.equal(
      core.validPasskeyMetadata({ ...metadata, credential_revision: bad }),
      false,
    );
  for (const extra of [{ user_id: "x" }, { private_key: "x" }, { raw_record: "x" }])
    assert.equal(
      core.validPasskeyMetadata({ ...metadata, ...extra }),
      false,
      "private field accepted: " + Object.keys(extra)[0],
    );
  assert.equal(core.validCredentialRevision(CHILD_A), true);
  assert.equal(core.validCredentialRevision("A".repeat(64)), false);
});

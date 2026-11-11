// Pure, fixture-free regression tests for the shared browser privacy scanner
// and the checkout top-page title. No browser, X11 helper or acceptance fixture
// is used here; every value below is synthetic and safe to print on failure.
const test = require("node:test");
const assert = require("node:assert/strict");
const { mkdirSync, mkdtempSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const loadSaveAcceptance = () => import("../../scripts/browser_save_acceptance.mjs");
const loadCheckoutAcceptance = () =>
  import("../../scripts/browser_checkout_acceptance.mjs");

function syntheticFixture() {
  return {
    Password: "SyntheticPasswordCanary",
    Secret: "Synthetic Secret/Canary",
    Username: "synthetic-user@example.test",
    Value: "SyntheticValueCanary",
    SaveUsername: "synthetic-save-user@example.test",
    SaveValue: "SyntheticSaveValueCanary",
    UpdateUsername: "synthetic-update-user@example.test",
    UpdateValue: "SyntheticUpdateValueCanary",
    RejectedUsername: "synthetic-rejected-user@example.test",
    RejectedValue: "SyntheticRejectedValueCanary",
    OTPSeed: "SyntheticOtpSeedCanary",
    OTPURI: "otpauth://totp/synthetic?secret=SyntheticOtpSeedCanary",
    CardNumber: "4111111111111111",
    CardHolder: "Synthetic \u00dcnicode Holder",
    CardVerification: "317",
    CardExpiry: "11/30",
    CardPIN: "8642",
    OTPCodes: ["012345"],
  };
}

// Builds a throwaway diagnostic tree with the authenticated fixture path
// excluded, exactly as the real scanner expects. Each call gets a fresh state.
function withArtifacts(contents, run) {
  const state = mkdtempSync(join(tmpdir(), "locklark-privacy-"));
  try {
    mkdirSync(join(state, "vault"));
    writeFileSync(join(state, "vault", "fixture.json"), "{}");
    const profile = join(state, "profile");
    mkdirSync(profile);
    for (const [name, content] of Object.entries(contents)) {
      writeFileSync(join(profile, name), content);
    }
    return run(state);
  } finally {
    rmSync(state, { recursive: true, force: true });
  }
}

test("3-digit card verification and 4-digit PIN values are rejected as whole tokens", async () => {
  const { assertPrivateText } = await loadSaveAcceptance();
  for (const text of [
    '{"card_verification":"317"}',
    '{"card_pin":"8642"}',
    "card_verification: 317",
    "card_pin=8642\n",
    "CVV 317",
    "PIN 8642",
  ]) {
    assert.throws(
      () => assertPrivateText(text, syntheticFixture()),
      /card verification or PIN/,
    );
  }
});

test("unrelated alphanumeric metadata is not mistaken for a short card token", async () => {
  const { assertPrivateText } = await loadSaveAcceptance();
  for (const text of [
    "profile id abc317def",
    "revision aa8642bb",
    "hex 0x317f",
    "nonce=aa8642bb",
    '{"id":"abc317def","revision":"aa8642bb"}',
    "token a317b; other 8642c",
  ]) {
    assert.doesNotThrow(() => assertPrivateText(text, syntheticFixture()));
  }
});

test("long PAN, factor, holder and OTP seed canaries keep exact substring checks", async () => {
  const { assertPrivateText } = await loadSaveAcceptance();
  for (const text of [
    "4111111111111111",
    '{"card_number":"4111111111111111"}',
    "SyntheticPasswordCanary",
    "Synthetic Secret/Canary",
    "Synthetic \u00dcnicode Holder",
    "SyntheticOtpSeedCanary",
  ]) {
    assert.throws(() => assertPrivateText(text, syntheticFixture()));
  }
});

test("embedded short digits in diagnostic metadata do not fail artifact scanning", async () => {
  const { assertPrivateArtifacts } = await loadSaveAcceptance();
  withArtifacts(
    {
      "profile.json":
        '{"id":"abc317def","revision":"aa8642bb","nonce":"a317b8642c"}',
      "browser.log": "profile abc317def started; revision aa8642bb\n",
    },
    (state) => {
      assert.equal(assertPrivateArtifacts(state, syntheticFixture()), 2);
    },
  );
});

test("serialized and literal short card values fail artifact scanning", async () => {
  const { assertPrivateArtifacts } = await loadSaveAcceptance();
  for (const content of [
    '{"card_verification":"317"}',
    '{"card_pin":"8642"}',
    "card_verification 317\n",
    "PIN: 8642\n",
  ]) {
    withArtifacts({ "diagnostics.json": content }, (state) => {
      assert.throws(
        () => assertPrivateArtifacts(state, syntheticFixture()),
        /card verification or PIN/,
      );
    });
  }
});

test("full PAN and raw, JSON-escaped or percent-encoded long factors still fail artifact scanning", async () => {
  const { assertPrivateArtifacts } = await loadSaveAcceptance();
  const fixture = syntheticFixture();
  for (const content of [
    '{"card_number":"4111111111111111"}',
    "SyntheticPasswordCanary\n",
    `{"secret":${JSON.stringify(fixture.Secret)}}`,
    `{"secret":"${encodeURIComponent(fixture.Secret)}"}`,
    '{"holder":"Synthetic \\u00dcnicode Holder"}',
    `{"holder":${JSON.stringify(fixture.CardHolder)}}`,
  ]) {
    withArtifacts({ "diagnostics.json": content }, (state) => {
      assert.throws(() => assertPrivateArtifacts(state, fixture));
    });
  }
});

// Independent 8-digit fixture used only by the regression cases below. The
// existing fixture keeps its historical short values, so both shapes stay
// covered without changing the scanner.
const eightDigitFixture = {
  ...syntheticFixture(),
  CardVerification: "93716428",
  CardPIN: "85172936",
};

// Raw Buffer content with non-UTF8 delimiter bytes on both boundaries. The
// bytes are passed unchanged to assertPrivateArtifacts so its original
// raw-byte token scan is what rejects them.
function rawDelimited(value) {
  return Buffer.concat([
    Buffer.from([0xff]),
    Buffer.from(value, "utf8"),
    Buffer.from([0xfe]),
  ]);
}

// Builds a throwaway state whose nested directories (relative to state) are
// created verbatim, then writes one artifact. Nested entries use "/" so the
// same layout is built on every platform.
function withNestedArtifact(relativePath, content, run) {
  const state = mkdtempSync(join(tmpdir(), "locklark-privacy-"));
  try {
    mkdirSync(join(state, "vault"));
    writeFileSync(join(state, "vault", "fixture.json"), "{}");
    const parts = relativePath.split("/");
    const name = parts.pop();
    const directory = join(state, ...parts);
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, name), content);
    return run(state);
  } finally {
    rmSync(state, { recursive: true, force: true });
  }
}

const GENERIC_PATH_WORDS = new Set(["leveldb", "Default"]);

const PRIVATE_ARTIFACT_PREFIX =
  "Synthetic card verification or PIN token persisted in diagnostics";

// Runs one artifact rejection and returns its message plus everything else a
// failure could expose. Only fixed field/category tokens may appear.
function privateArtifactFailure(
  scanner,
  relativePath,
  content,
  fixture = eightDigitFixture,
) {
  const { assertPrivateArtifacts } = scanner;
  return withNestedArtifact(relativePath, content, (state) => {
    let error;
    try {
      assertPrivateArtifacts(state, fixture);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error, "artifact containing a short card token was not rejected");
    assert.equal(error.name, "AssertionError");
    return { error, state };
  });
}

test("short numeric artifact rejection carries only the fixed field and category", async (t) => {
  const scanner = await loadSaveAcceptance();
  // Every private fixture string is forbidden verbatim. Unrelated filler in
  // the artifact must not surface either.
  const forbidden = Object.values(eightDigitFixture).filter(
    (value) => typeof value === "string",
  );
  const cases = [
    {
      path: "profile/Default/Local Storage/leveldb/LOG",
      category: "browser-leveldb-log",
      field: "CardVerification",
    },
    {
      path: "profile/Default/Local Storage/leveldb/LOG.old",
      category: "browser-leveldb-log",
      field: "CardPIN",
    },
    {
      // Numbered Chromium logs count anywhere below profile/Default, not only
      // in directories literally named LevelDB.
      path: "profile/Default/Local Storage/leveldb/000017.log",
      category: "browser-leveldb-log",
      field: "CardPIN",
    },
    {
      path: "profile/Default/IndexedDB/https_example_0.indexeddb.leveldb/000003.log",
      category: "browser-leveldb-log",
      field: "CardVerification",
    },
    {
      path: "profile/Default/shared_proto_db/000003.log",
      category: "browser-leveldb-log",
      field: "CardVerification",
    },
    {
      path: "profile/Default/shared_proto_db/metadata/000005.log",
      category: "browser-leveldb-log",
      field: "CardPIN",
    },
    {
      // dotless basenames with a .json/.jsonl suffix are still JSON diagnostics
      path: "diagnostics-abc/failure.json",
      category: "json-diagnostic",
      field: "CardVerification",
    },
    {
      path: "diagnostics-abc/nested/viewer.v2.jsonl",
      category: "json-diagnostic",
      field: "CardPIN",
    },
    {
      path: "controller.log",
      category: "controller-diagnostic",
      field: "CardVerification",
    },
    {
      path: "controller.JSON",
      category: "controller-diagnostic",
      field: "CardPIN",
    },
    {
      path: "diagnostics-abc/native-save-new.txt",
      category: "other",
      field: "CardPIN",
    },
    {
      // LOG outside profile/Default is not browser LevelDB.
      path: "diagnostics-abc/LOG",
      category: "other",
      field: "CardVerification",
    },
    {
      path: "LOG.old",
      category: "other",
      field: "CardPIN",
    },
    {
      // Numbered Chromium LOGs outside profile/Default are not browser LevelDB.
      path: "diagnostics-abc/000003.log",
      category: "other",
      field: "CardVerification",
    },
    {
      path: "Other/Default/shared_proto_db/000003.log",
      category: "other",
      field: "CardPIN",
    },
    {
      // Numbered logs count anywhere below profile/Default, so even a folder
      // without an obvious store name is browser LevelDB.
      path: "profile/Default/Shared/000003.log",
      category: "browser-leveldb-log",
      field: "CardPIN",
    },
    {
      // Pinned to the browser profile: a harness-local profile tree is not it.
      path: "browser/profile/Default/shared_proto_db/000003.log",
      category: "other",
      field: "CardVerification",
    },
  ];
  for (const { path, category, field } of cases) {
    await t.test(`classifies ${field} in ${category}`, () => {
      const value = eightDigitFixture[field];
      const { error, state } = privateArtifactFailure(
        scanner,
        path,
        rawDelimited(value),
      );
      const message = error.message;
      assert.ok(message.startsWith(PRIVATE_ARTIFACT_PREFIX));
      assert.equal(
        message,
        `${PRIVATE_ARTIFACT_PREFIX} field=${field} category=${category}`,
      );
      // The tail is exactly two fixed tokens from the allowlist.
      assert.match(
        message.slice(PRIVATE_ARTIFACT_PREFIX.length),
        /^ field=(?:CardVerification|CardPIN) category=(?:browser-leveldb-log|controller-diagnostic|json-diagnostic|other)$/,
      );
      // Neither fixture canary nor any location/content detail is present.
      for (const token of forbidden) assert.ok(!message.includes(token));
      assert.ok(!message.includes(path));
      assert.ok(!message.includes(state));
      assert.ok(!message.includes(tmpdir()));
      // No path component leaks. Short directory names that happen to be
      // generic words ("leveldb", "Default") are exempt; filenames never are.
      const parts = path.split("/");
      const fileName = parts.pop();
      assert.ok(!message.includes(fileName));
      for (const part of parts) {
        if (part.length >= 3 && !GENERIC_PATH_WORDS.has(part))
          assert.ok(!message.includes(part));
      }
      assert.ok(!message.includes("offset"));
      assert.ok(!message.includes("bytes"));
      assert.ok(!/\/|\\/.test(message.slice(PRIVATE_ARTIFACT_PREFIX.length)));
    });
  }
});

test("short numeric field names are derived from the fixture, not the artifact", async () => {
  const { assertPrivateArtifacts } = await loadSaveAcceptance();
  // Only the PIN is a short numeric canary here; the verification value is a
  // long exact canary, so a verification-only artifact must not claim
  // field=CardVerification.
  const fixture = { ...eightDigitFixture, CardVerification: "9371x6428" };
  withNestedArtifact(
    "profile/Default/Local Storage/leveldb/LOG",
    rawDelimited(eightDigitFixture.CardPIN),
    (state) => {
      assert.throws(
        () => assertPrivateArtifacts(state, fixture),
        (error) =>
          error.message ===
          `${PRIVATE_ARTIFACT_PREFIX} field=CardPIN category=browser-leveldb-log`,
      );
    },
  );
});

test("generic output-scan message stays unchanged", async () => {
  const { assertPrivateText } = await loadSaveAcceptance();
  assert.throws(
    () => assertPrivateText(eightDigitFixture.CardPIN, eightDigitFixture),
    (error) =>
      error.message ===
      "Synthetic card verification or PIN token leaked in output",
  );
});

test("historical 3-digit verification and 4-digit PIN fail text and raw byte scanning", async () => {
  const { assertPrivateText, assertPrivateArtifacts } = await loadSaveAcceptance();
  const fixture = syntheticFixture();
  for (const key of ["CardVerification", "CardPIN"]) {
    const value = fixture[key];
    for (const text of [
      value,
      `"${value}"`,
      `{"${key}":"${value}"}`,
      `${key}: ${value}\n`,
      `\u0000${value}\u0000`,
      `--${value}--`,
      `\u00ff${value}\u00fe`,
    ]) {
      assert.throws(
        () => assertPrivateText(text, fixture),
        /card verification or PIN/,
        "historical short card token in text was not rejected",
      );
    }
    // The raw byte scan has its own "...persisted in diagnostics" message;
    // matching it exactly proves the bytes, not the decoded-text fallback,
    // were what assertPrivateArtifacts rejected.
    withArtifacts({ "diagnostics.log": rawDelimited(value) }, (state) => {
      assert.throws(
        () => assertPrivateArtifacts(state, fixture),
        /card verification or PIN token persisted in diagnostics/,
        "raw byte scan did not reject historical short card token",
      );
    });
  }
});

test("8-digit verification and PIN fail text, serialized and raw byte scanning", async () => {
  const { assertPrivateText, assertPrivateArtifacts } = await loadSaveAcceptance();
  for (const key of ["CardVerification", "CardPIN"]) {
    const value = eightDigitFixture[key];
    for (const text of [
      value,
      `"${value}"`,
      `{"${key}":"${value}"}`,
      `${key}: ${value}\n`,
    ]) {
      assert.throws(
        () => assertPrivateText(text, eightDigitFixture),
        /card verification or PIN/,
        "8-digit card token in text was not rejected",
      );
    }
    // Each extension gets its own tree because assertPrivateArtifacts stops at
    // the first rejected file; sharing a directory would only prove the first.
    withArtifacts({ "diagnostics.json": `{"${key}":"${value}"}` }, (state) => {
      assert.throws(
        () => assertPrivateArtifacts(state, eightDigitFixture),
        /card verification or PIN/,
        "serialized 8-digit card token in JSON was not rejected",
      );
    });
    withArtifacts({ "diagnostics.log": `${key} ${value}\n` }, (state) => {
      assert.throws(
        () => assertPrivateArtifacts(state, eightDigitFixture),
        /card verification or PIN/,
        "serialized 8-digit card token in LOG was not rejected",
      );
    });
    // The raw byte scan has its own "...persisted in diagnostics" message;
    // matching it exactly proves the bytes, not the decoded-text fallback,
    // were what assertPrivateArtifacts rejected.
    withArtifacts({ "diagnostics.log": rawDelimited(value) }, (state) => {
      assert.throws(
        () => assertPrivateArtifacts(state, eightDigitFixture),
        /card verification or PIN token persisted in diagnostics/,
        "raw byte scan did not reject 8-digit card token",
      );
    });
  }
});

test("unrelated short metadata stays protected only by the short fixture canaries", async () => {
  const { assertPrivateArtifacts } = await loadSaveAcceptance();
  const contents = { "metadata.json": '{"count":317,"port":8642}' };
  withArtifacts(contents, (state) => {
    assert.equal(assertPrivateArtifacts(state, eightDigitFixture), 1);
  });
  withArtifacts(contents, (state) => {
    assert.throws(
      () => assertPrivateArtifacts(state, syntheticFixture()),
      /card verification or PIN/,
      "short fixture canary was not rejected",
    );
  });
});

test("checkout stages never allow screenshots", async () => {
  const { browserScreenshotsAllowed } = await loadSaveAcceptance();
  for (const stage of [
    "checkout",
    "checkout:top",
    "checkout-card:positive",
    "checkout-card:approve",
  ]) {
    assert.equal(browserScreenshotsAllowed(stage), false);
  }
  assert.equal(
    browserScreenshotsAllowed("save-new:positive:native-screenshot"),
    true,
  );
});

test("checkout top page carries the accepted X11 title prefix", async () => {
  const { checkoutTopHTML, checkoutCardHTML } =
    await loadCheckoutAcceptance();
  const top = checkoutTopHTML(8443);
  assert.match(top, /<title>Locklark acceptance \u00b7 checkout<\/title>/);
  assert.ok(!top.includes("<title>Locklark checkout acceptance</title>"));
  assert.match(
    checkoutCardHTML(),
    /<title>Locklark checkout card frame<\/title>/,
  );
});

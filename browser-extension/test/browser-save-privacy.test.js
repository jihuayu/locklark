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

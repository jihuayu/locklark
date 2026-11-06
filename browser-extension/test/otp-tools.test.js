const test = require("node:test");
const assert = require("node:assert/strict");
test("private OTP canary scan catches standalone codes without matching metadata IDs", async () => {
  const { assertPrivateText } = await import(
    "../../scripts/browser_save_acceptance.mjs"
  );
  const fixture = {
    OTPSeed: "SyntheticSeedCanary",
    OTPCodes: ["012345", "01234567"],
  };
  for (const text of [
    '{"code":"012345"}',
    "code=01234567\n",
    "SyntheticSeedCanary",
  ])
    assert.throws(() => assertPrivateText(text, fixture));
  assert.doesNotThrow(() =>
    assertPrivateText(
      "revision:a012345b; nonce:aa01234567bb; fixed PASS",
      fixture,
    ),
  );
});

test("OTP diagnostics never permit a screenshot after code may exist", async () => {
  const { browserScreenshotsAllowed } = await import(
    "../../scripts/browser_save_acceptance.mjs"
  );
  for (const stage of [
    "otp:reconnect",
    "otp-6:positive:driver-arguments-failure",
    "otp-8:positive:approve",
    "otp:original-window-exhausted",
    null,
  ])
    assert.equal(browserScreenshotsAllowed(stage), false);
  assert.equal(
    browserScreenshotsAllowed("save-new:positive:native-screenshot"),
    true,
  );
});

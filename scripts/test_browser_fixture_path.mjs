// Unit tests for the prebuilt browser fixture parameter. They only verify that
// LOCKLARK_BROWSER_FIXTURE is reused or refused with a fixed error and that the
// OTP configure step executes it; the real Chromium/Firefox acceptance still
// runs the fixture against the product.
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { browserFixtureExecutable } from "./browser_save_acceptance.mjs";
import { configureOTPFixture } from "./browser_otp_acceptance.mjs";

const state = mkdtempSync(join(tmpdir(), "locklark-browser-fixture-test-"));
process.on("exit", () => rmSync(state, { recursive: true, force: true }));

// Any attempt to fall back to go build/build through a fake tool must fail the
// test instead of silently rebuilding.
const go = "/nonexistent-go-must-not-run";
const context = { go, root: state, env: { ...process.env }, state };

function withFixture(value, fn) {
  if (value === undefined) delete process.env.LOCKLARK_BROWSER_FIXTURE;
  else process.env.LOCKLARK_BROWSER_FIXTURE = value;
  try {
    fn();
  } finally {
    delete process.env.LOCKLARK_BROWSER_FIXTURE;
  }
}

test("explicit executable fixture is reused without go", () => {
  const executable = join(state, "fixture-observer");
  writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  withFixture(executable, () => {
    assert.equal(browserFixtureExecutable(context), executable);
  });
});

test("missing explicit fixture is refused", () => {
  withFixture(join(state, "absent-fixture"), () => {
    assert.throws(() => browserFixtureExecutable(context), {
      message: "LOCKLARK_BROWSER_FIXTURE must name an executable built fixture",
    });
  });
});

test("non-executable explicit fixture is refused", () => {
  const executable = join(state, "not-executable");
  writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o600 });
  withFixture(executable, () => {
    assert.throws(() => browserFixtureExecutable(context), {
      message: "LOCKLARK_BROWSER_FIXTURE must name an executable built fixture",
    });
  });
});

test("unset fixture keeps the historical go build path", () => {
  withFixture(undefined, () => {
    assert.throws(() => browserFixtureExecutable(context));
  });
});

test("configureOTPFixture runs the prebuilt fixture while state has no fixture-observer", () => {
  const prebuilt = mkdtempSync(join(tmpdir(), "locklark-browser-fixture-otp-"));
  process.on("exit", () => rmSync(prebuilt, { recursive: true, force: true }));
  const executable = join(prebuilt, "browser-acceptance-fixture");
  const calls = join(prebuilt, "calls.jsonl");
  // Stand-in for the real fixture CLI: records the argv of each invocation.
  writeFileSync(
    executable,
    "#!/bin/sh\n" +
      `printf '%s\\n' "$*" >> ${JSON.stringify(calls)}\n` +
      "exit 0\n",
    { mode: 0o700 },
  );
  const otpState = join(prebuilt, "state");
  mkdirSync(join(otpState, "vault"), { mode: 0o700, recursive: true });
  writeFileSync(join(otpState, "vault", "fixture.json"), "{}\n", {
    mode: 0o600,
  });
  const driver = {
    root: process.cwd(),
    state: otpState,
    env: { ...process.env },
    go,
  };
  assert.equal(existsSync(join(otpState, "fixture-observer")), false);
  withFixture(executable, () => {
    configureOTPFixture(driver, 8);
    configureOTPFixture(driver, 0);
    configureOTPFixture(driver, 6);
  });
  assert.deepEqual(readFileSync(calls, "utf8").trim().split("\n"), [
    `-configure-otp ${join(otpState, "vault/fixture.json")} -digits 8`,
    `-configure-otp ${join(otpState, "vault/fixture.json")} -digits 0`,
    `-configure-otp ${join(otpState, "vault/fixture.json")} -digits 6`,
  ]);
  assert.equal(existsSync(join(otpState, "fixture-observer")), false);
});

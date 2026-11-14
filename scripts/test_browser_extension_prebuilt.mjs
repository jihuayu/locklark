import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { requirePrebuiltChromium } from "./browser_extension_prebuilt.mjs";

const root = new URL("..", import.meta.url).pathname;
function probe(env) {
  return () => requirePrebuiltChromium(root, env);
}

test("missing prebuilt inputs fail fixed", () => {
  assert.throws(probe({}), /prebuilt Chromium input rejected/);
});

test("non-executable register fails fixed", () => {
  const dir = mkdtempSync(join(tmpdir(), "locklark-prebuilt-test-"));
  const register = join(dir, "register");
  writeFileSync(register, "fixture");
  chmodSync(register, 0o600);
  assert.throws(
    probe({ LOCKLARK_BROWSER_REGISTER: register }),
    /prebuilt Chromium input rejected/,
  );
});

test("missing extension receipt fails fixed", () => {
  const dir = mkdtempSync(join(tmpdir(), "locklark-prebuilt-test-"));
  const register = join(dir, "register");
  const dist = join(dir, "dist");
  writeFileSync(register, "fixture");
  chmodSync(register, 0o700);
  // A directory is enough to reach the receipt requirement; no build occurs.
  mkdirSync(dist);
  assert.throws(
    probe({
      LOCKLARK_BROWSER_REGISTER: register,
      LOCKLARK_BROWSER_EXTENSION_CHROMIUM: dist,
    }),
    /prebuilt Chromium input rejected/,
  );
});

test("stale receipt source fails fixed", () => {
  const dir = mkdtempSync(join(tmpdir(), "locklark-prebuilt-test-"));
  const register = join(dir, "register");
  const dist = join(dir, "dist");
  const receipt = join(dir, "receipt.json");
  writeFileSync(register, "fixture");
  chmodSync(register, 0o700);
  mkdirSync(dist);
  writeFileSync(receipt, JSON.stringify({
    schema: "locklark-browser-extension-unsigned-receipt/v2",
    product: "chromium", unsigned: true, signed: false,
    identity: "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/",
    source_commit: "0".repeat(40), entries: [],
  }));
  assert.throws(
    probe({
      LOCKLARK_BROWSER_REGISTER: register,
      LOCKLARK_BROWSER_EXTENSION_CHROMIUM: dist,
      LOCKLARK_BROWSER_EXTENSION_RECEIPT: receipt,
    }),
    /prebuilt Chromium input rejected/,
  );
});

test("incomplete receipt entries fail fixed", () => {
  const dir = mkdtempSync(join(tmpdir(), "locklark-prebuilt-test-"));
  const register = join(dir, "register");
  const dist = join(dir, "dist");
  const receipt = join(dir, "receipt.json");
  const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  writeFileSync(register, "fixture");
  chmodSync(register, 0o700);
  mkdirSync(dist);
  writeFileSync(receipt, JSON.stringify({
    schema: "locklark-browser-extension-unsigned-receipt/v2",
    product: "chromium", unsigned: true, signed: false,
    identity: "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/",
    source_commit: head, entries: [],
  }));
  assert.throws(
    probe({
      LOCKLARK_BROWSER_REGISTER: register,
      LOCKLARK_BROWSER_EXTENSION_CHROMIUM: dist,
      LOCKLARK_BROWSER_EXTENSION_RECEIPT: receipt,
    }),
    /prebuilt Chromium input rejected/,
  );
});

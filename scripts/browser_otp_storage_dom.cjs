// Minimal real-extension smoke: full-channel headless Chromium, real service
// worker/storage.onChanged, and exact production content.js. The only test-only
// content script is a fixture decoder plus a delegating MutationObserver count.
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const sourceRoot = path.resolve(__dirname, "..");
const sourceExtension = path.join(sourceRoot, "browser-extension");
const distExtension = path.join(sourceExtension, "dist/chromium");
const bootstrap = path.join(__dirname, "browser_otp_fixture_bootstrap.js");

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function fixedFailure(message) {
  throw Error(message);
}

module.exports = async function run() {
  if (!fs.existsSync(path.join(distExtension, "manifest.json")))
    fixedFailure("OTP storage smoke: built dist/chromium is required");
  for (const name of ["content.js", "core.js"]) {
    const source = path.join(sourceExtension, name);
    const built = path.join(distExtension, name);
    if (!fs.existsSync(built) || sha256(source) !== sha256(built))
      fixedFailure("OTP storage smoke: production source/bundle SHA mismatch");
  }

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "locklark-otp-storage-"));
  fs.chmodSync(root, 0o700);
  const bundle = path.join(root, "extension");
  const profile = path.join(root, "profile");
  fs.mkdirSync(profile, 0o700);
  fs.cpSync(distExtension, bundle, { recursive: true });
  fs.copyFileSync(bootstrap, path.join(bundle, "browser_otp_fixture_bootstrap.js"));

  const manifestPath = path.join(bundle, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const originalPermissions = JSON.stringify(manifest.permissions || []);
  const originalHosts = JSON.stringify(manifest.host_permissions || []);
  assert.ok(Array.isArray(manifest.content_scripts) && manifest.content_scripts.length > 0);
  manifest.content_scripts[0].js = [
    "browser_otp_fixture_bootstrap.js",
    ...(manifest.content_scripts[0].js || []),
  ];
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  assert.equal(JSON.stringify(manifest.permissions || []), originalPermissions);
  assert.equal(JSON.stringify(manifest.host_permissions || []), originalHosts);
  for (const name of ["content.js", "core.js"])
    assert.equal(sha256(path.join(bundle, name)), sha256(path.join(distExtension, name)));

  const playwright = require(
    process.env.LOCKLARK_TEST_PLAYWRIGHT || path.join(sourceRoot, "web/node_modules/playwright"),
  );
  let context = null;
  try {
    context = await playwright.chromium.launchPersistentContext(profile, {
      headless: true,
      channel: "chromium",
      args: [
        "--no-sandbox",
        "--disable-extensions-except=" + bundle,
        "--load-extension=" + bundle,
        "--no-proxy-server",
      ],
    });
    const worker =
      context.serviceWorkers()[0] || (await context.waitForEvent("serviceworker"));
    const permissions = await worker.evaluate(
      () => chrome.runtime.getManifest().permissions || [],
    );
    assert.equal(JSON.stringify(permissions), originalPermissions);

    const page = await context.newPage();
    await page.route("**/*", (route) =>
      route.fulfill({
        contentType: "text/html",
        body: "<!doctype html><html><body><h1>Fixture setup</h1></body></html>",
      }),
    );
    await page.goto("https://otp-storage.fixture.test/settings/2fa");
    await page.waitForFunction(
      () => Number(document.documentElement.dataset.locklarkOtpFixtureObserved || 0) >= 1,
      null,
      { timeout: 5000 },
    );
    const initial = await page.evaluate(() => ({
      decode: Number(document.documentElement.dataset.locklarkOtpFixtureDecode || 0),
      observed: Number(document.documentElement.dataset.locklarkOtpFixtureObserved || 0),
    }));
    assert.equal(initial.decode, 0);

    await worker.evaluate(
      async () => chrome.storage.local.set({ otpCapture: false }),
    );
    await page.waitForFunction(
      () => Number(document.documentElement.dataset.locklarkOtpFixtureDisconnected || 0) >= 1,
      null,
      { timeout: 5000 },
    );
    const afterDisable = await page.evaluate(() => ({
      decode: Number(document.documentElement.dataset.locklarkOtpFixtureDecode || 0),
      disconnected: Number(document.documentElement.dataset.locklarkOtpFixtureDisconnected || 0),
    }));
    assert.equal(afterDisable.decode, 0);

    await worker.evaluate(
      async () => chrome.storage.local.set({ otpCapture: true }),
    );
    await page.waitForFunction(
      () => Number(document.documentElement.dataset.locklarkOtpFixtureObserved || 0) >= 2,
      null,
      { timeout: 5000 },
    );
    const afterEnable = await page.evaluate(() => ({
      decode: Number(document.documentElement.dataset.locklarkOtpFixtureDecode || 0),
      observed: Number(document.documentElement.dataset.locklarkOtpFixtureObserved || 0),
    }));
    assert.equal(afterEnable.decode, 0);
    assert.ok(afterEnable.observed >= 2);
    console.log("OTP storage smoke: decode=0 initial_observed=true disconnected=true rearmed=true");
  } finally {
    if (context) await context.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
};

// Real-extension OTP case smoke: full-channel headless Chromium, real service
// worker/storage.onChanged, exact production content.js, and a single copied
// fixture bundle. The bootstrap is the only test-only content script.
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

async function waitFixed(page, predicate, arg, category) {
  try {
    await page.waitForFunction(predicate, arg, { timeout: 5000 });
  } catch {
    fixedFailure("OTP storage smoke: " + category);
  }
}

async function state(page) {
  return await page.evaluate(() => {
    const data = document.documentElement.dataset;
    return {
      decode: Number(data.locklarkOtpFixtureDecode || 0),
      observed: Number(data.locklarkOtpFixtureObserved || 0),
      disconnected: Number(data.locklarkOtpFixtureDisconnected || 0),
      active: Number(data.locklarkOtpFixtureActive || 0),
      target: data.locklarkOtpFixtureTarget,
      bodyRead: Number(data.locklarkOtpFixtureBodyRead || 0),
      bodyReady: data.locklarkOtpFixtureBodyReady,
      pending: Number(data.locklarkOtpFixturePending || 0),
    };
  });
}

async function openCase(context, spec) {
  const page = await context.newPage();
  const title = spec.title ? "<title>" + spec.title + "</title>" : "";
  const heading = spec.heading ? "<h1>" + spec.heading + "</h1>" : "";
  const html =
    "<!doctype html><html><head>" +
    title +
    "</head><body>" +
    heading +
    (spec.body || "") +
    "</body></html>";
  await page.route("**/*", (route) =>
    route.fulfill({ contentType: "text/html", body: html }),
  );
  await page.goto("https://otp-storage.fixture.test" + spec.path);
  await waitFixed(
    page,
    () => {
      const data = document.documentElement.dataset;
      return (
        data.locklarkOtpFixtureTarget === "identified" &&
        data.locklarkOtpFixtureBodyReady === "ready"
      );
    },
    null,
    "fixture target or body read unavailable",
  );
  return page;
}

async function addCandidates(page, count) {
  await page.evaluate((amount) => {
    for (let index = 0; index < amount; index++) {
      const canvas = document.createElement("canvas");
      canvas.width = 128;
      canvas.height = 128;
      canvas.style.cssText = "display:block;width:128px;height:128px";
      document.body.append(canvas);
    }
  }, count);
}

async function waitDecode(page, count, category) {
  await waitFixed(
    page,
    (wanted) =>
      Number(document.documentElement.dataset.locklarkOtpFixtureDecode || 0) >=
      wanted,
    count,
    category,
  );
}

async function setOtpCapture(worker, enabled) {
  await worker.evaluate(
    async (value) => chrome.storage.local.set({ otpCapture: value }),
    enabled,
  );
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

    const empty = await openCase(context, {
      path: "/ordinary/empty",
      body: "<p>No candidate</p>",
    });
    await empty.waitForTimeout(2300);
    let current = await state(empty);
    assert.equal(current.decode, 0);
    assert.equal(current.bodyRead, 0);
    await setOtpCapture(worker, false);
    await waitFixed(
      empty,
      () => Number(document.documentElement.dataset.locklarkOtpFixtureActive || 0) === 0,
      null,
      "empty case did not disconnect",
    );
    await setOtpCapture(worker, true);
    await waitFixed(
      empty,
      () => Number(document.documentElement.dataset.locklarkOtpFixtureActive || 0) === 1,
      null,
      "empty case did not rearm",
    );
    current = await state(empty);
    assert.equal(current.decode, 0);
    assert.equal(current.bodyRead, 0);
    await empty.close();

    const bodyOnly = await openCase(context, {
      path: "/ordinary/body-only",
      body:
        "<p>Scan this QR code with your authenticator app</p>" +
        '<canvas width="128" height="128" style="display:block;width:128px;height:128px"></canvas>',
    });
    await bodyOnly.waitForTimeout(2300);
    current = await state(bodyOnly);
    assert.equal(current.decode, 0);
    assert.equal(current.bodyRead, 0);
    await bodyOnly.close();

    const title = await openCase(context, {
      path: "/ordinary/title",
      title: "Scan this QR code with your authenticator app",
    });
    await addCandidates(title, 1);
    await waitDecode(title, 1, "title case did not decode");
    current = await state(title);
    assert.ok(current.decode > 0);
    assert.equal(current.bodyRead, 0);
    await title.close();

    const heading = await openCase(context, {
      path: "/ordinary/heading",
      heading: "Scan this QR code with your authenticator app",
    });
    await addCandidates(heading, 1);
    await waitDecode(heading, 1, "heading case did not decode");
    current = await state(heading);
    assert.ok(current.decode > 0);
    assert.equal(current.bodyRead, 0);
    await heading.close();

    const limit = await openCase(context, {
      path: "/ordinary/limit",
      title: "Scan this QR code with your authenticator app",
    });
    await addCandidates(limit, 7);
    await waitDecode(limit, 7, "limit batch 7");
    await addCandidates(limit, 8);
    await waitDecode(limit, 15, "limit batch 15");
    await addCandidates(limit, 8);
    await waitDecode(limit, 23, "limit batch 23");
    await addCandidates(limit, 3);
    await waitDecode(limit, 24, "limit batch 24");
    current = await state(limit);
    assert.equal(current.decode, 24);
    assert.equal(current.active, 0);
    assert.ok(current.disconnected >= 1);
    await addCandidates(limit, 1);
    await setOtpCapture(worker, false);
    await setOtpCapture(worker, true);
    await limit.waitForTimeout(500);
    current = await state(limit);
    assert.equal(current.decode, 24);
    assert.equal(current.active, 0);
    await limit.close();

    const pending = await openCase(context, {
      path: "/ordinary/pending",
      title: "Scan this QR code with your authenticator app",
    });
    await pending.evaluate(() => {
      document.documentElement.dataset.locklarkOtpFixtureDefer = "1";
    });
    await addCandidates(pending, 1);
    await waitDecode(pending, 1, "pending decode did not start");
    current = await state(pending);
    assert.equal(current.pending, 1);
    await setOtpCapture(worker, false);
    await setOtpCapture(worker, true);
    await pending.waitForTimeout(1500);
    await pending.evaluate(() =>
      document.dispatchEvent(new Event("locklark-otp-fixture-release")),
    );
    await waitDecode(pending, 2, "fresh scan did not start");
    current = await state(pending);
    assert.equal(current.pending, 1);
    await pending.evaluate(() =>
      document.dispatchEvent(new Event("locklark-otp-fixture-release")),
    );
    await pending.waitForTimeout(500);
    current = await state(pending);
    assert.equal(current.decode, 2);
    assert.equal(current.pending, 0);
    assert.equal(current.active, 1);
    assert.equal(current.target, "identified");
    await pending.close();

    console.log(
      "OTP storage smoke: empty=true body_only=0 title_positive=true heading_positive=true limit=24 limit_disconnect=true limit_no_rearm=true pending_old=1 pending_fresh=1",
    );
  } finally {
    if (context) await context.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
};

const runSmoke = module.exports;
module.exports = async function runFixed() {
  try {
    return await runSmoke();
  } catch {
    throw Error("OTP storage smoke failed");
  }
};
if (require.main === module) {
  module.exports().catch(() => {
    console.error("OTP storage smoke failed");
    process.exitCode = 1;
  });
}

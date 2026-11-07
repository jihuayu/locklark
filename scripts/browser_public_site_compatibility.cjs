// Issue 39 public-site compatibility: synthetic fixtures checked against the
// real shipped browser-extension/core.js inside a controlled HTTPS origin.
// DOM component compatibility only: no product hooks, no extension privileges,
// no real github.com/webauthn.io requests, no browser->native or production
// login/E2E claim. Values are synthetic and are never logged.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ORIGIN = "https://public-sites.fixture.test";
const CORE = path.resolve(__dirname, "../browser-extension/core.js");
const FIXTURES = path.resolve(__dirname, "../tests/fixtures/public-sites");

function fixture(name) {
  return fs.readFileSync(path.join(FIXTURES, name), "utf8");
}

// One browser for all scenarios; each scenario gets a fresh isolated profile.
async function scenario(browser, pathname, html, check) {
  const context = await browser.newContext();
  const external = [];
  try {
    const page = await context.newPage();
    await page.route("**/*", (route) => {
      const url = route.request().url();
      if (url.startsWith(ORIGIN + "/"))
        return route.fulfill({
          status: 200,
          contentType: "text/html; charset=utf-8",
          body: html,
        });
      try {
        external.push(new URL(url).origin);
      } catch {
        external.push("unparsable");
      }
      return route.abort();
    });
    await page.goto(ORIGIN + pathname, { waitUntil: "domcontentloaded" });
    await page.addScriptTag({ path: CORE });
    const counts = await check(page);
    assert.deepEqual(external, [], "fixture attempted an external request");
    return counts;
  } finally {
    await context.close();
  }
}

async function checkGitHubFill(page) {
  const result = await page.evaluate(() => {
    const core = globalThis.LocklarkCore;
    const inputs = [...document.querySelectorAll("input")];
    const describe = () =>
      inputs.map((el) => ({
        id: el.id,
        name: el.name,
        type: el.type,
        autocomplete: el.getAttribute("autocomplete"),
        hidden: el.hidden,
      }));
    const before = describe();
    let submits = 0,
      inputEvents = 0,
      changeEvents = 0;
    document.addEventListener("submit", (event) => {
      event.preventDefault();
      submits++;
    });
    document.addEventListener("input", () => inputEvents++);
    document.addEventListener("change", () => changeEvents++);
    const probe = core.probe();
    const filled = core.fillDocument(
      location.origin,
      "fixture-user",
      "fixture-password",
      Date.now() + 1500,
      false,
      false,
    );
    const user = document.querySelector('input[name="login"]');
    const pass = document.querySelector('input[type="password"]');
    const decoy = document.querySelector('input[name="required_field_fixture"]');
    const untouched = inputs.filter((el) => el !== user && el !== pass);
    return {
      origin: probe.origin,
      top: probe.top,
      ok: !!filled && filled.ok === true,
      step: filled && filled.step,
      submitted: filled && filled.submitted,
      usernameFilled: user.value === "fixture-user",
      passwordFilled: pass.value === "fixture-password",
      decoyHidden: decoy.hidden === true,
      decoyEmpty: decoy.value === "",
      othersIntact: untouched.every((el) => el.value === el.defaultValue),
      descriptorsIntact: JSON.stringify(before) === JSON.stringify(describe()),
      submits,
      inputEvents,
      changeEvents,
    };
  });
  assert.equal(result.origin, ORIGIN);
  assert.equal(result.top, true);
  assert.equal(result.ok, true);
  assert.equal(result.step, "combined");
  assert.equal(result.submitted, false);
  assert.equal(result.usernameFilled, true);
  assert.equal(result.passwordFilled, true);
  assert.equal(result.decoyHidden, true, "hidden decoy must stay hidden");
  assert.equal(result.decoyEmpty, true, "hidden decoy must not be filled");
  assert.equal(result.othersIntact, true, "only eligible fields may be filled");
  assert.equal(result.descriptorsIntact, true, "id/autocomplete descriptors changed");
  assert.equal(result.submits, 0, "fill must not submit without explicit autoLogin");
  assert.equal(result.inputEvents, 2);
  assert.equal(result.changeEvents, 2);
  return result;
}

async function checkGitHubCapture(page) {
  const result = await page.evaluate(() => {
    const core = globalThis.LocklarkCore;
    const inputs = [...document.querySelectorAll("input")];
    const user = document.querySelector('input[name="login"]');
    const pass = document.querySelector('input[type="password"]');
    user.value = "fixture-capture-user";
    pass.value = "fixture-capture-password";
    const values = inputs.map((el) => el.value);
    let submits = 0,
      inputEvents = 0,
      changeEvents = 0;
    document.addEventListener("submit", (event) => {
      event.preventDefault();
      submits++;
    });
    document.addEventListener("input", () => inputEvents++);
    document.addEventListener("change", () => changeEvents++);
    const probe = core.probe();
    const captured = core.fillDocument(
      location.origin,
      "",
      "",
      Date.now() + 1500,
      true,
      false,
    );
    return {
      origin: probe.origin,
      top: probe.top,
      exact:
        !!captured &&
        captured.username === "fixture-capture-user" &&
        captured.password === "fixture-capture-password" &&
        captured.isNewPassword === false &&
        captured.isPasswordChange === false,
      unchanged: inputs.every((el, index) => el.value === values[index]),
      submits,
      inputEvents,
      changeEvents,
    };
  });
  assert.equal(result.origin, ORIGIN);
  assert.equal(result.top, true);
  assert.equal(result.exact, true, "capture did not return the expected fields");
  assert.equal(result.unchanged, true, "capture must not mutate field values");
  assert.equal(result.submits, 0, "capture must not submit");
  assert.equal(result.inputEvents, 0, "capture must not emit input events");
  assert.equal(result.changeEvents, 0, "capture must not emit change events");
  return result;
}

async function checkWebAuthn(page) {
  const result = await page.evaluate(() => {
    const core = globalThis.LocklarkCore;
    const input = document.getElementById("input-email");
    const describe = () => ({
      id: input.id,
      type: input.type,
      autocomplete: input.getAttribute("autocomplete"),
    });
    const before = describe();
    let submits = 0,
      inputEvents = 0,
      changeEvents = 0;
    document.addEventListener("submit", (event) => {
      event.preventDefault();
      submits++;
    });
    document.addEventListener("input", () => inputEvents++);
    document.addEventListener("change", () => changeEvents++);
    const probe = core.probe();
    const initiallyEmpty = input.value === "";
    const filled = core.fillDocument(
      location.origin,
      "fixture-passkey-user",
      "",
      Date.now() + 1500,
      false,
      false,
    );
    const afterFill = { submits, inputEvents, changeEvents };
    const filledValue = input.value;
    const captured = core.fillDocument(
      location.origin,
      "",
      "",
      Date.now() + 1500,
      true,
      false,
    );
    return {
      origin: probe.origin,
      top: probe.top,
      initiallyEmpty,
      ok: !!filled && filled.ok === true,
      step: filled && filled.step,
      submitted: filled && filled.submitted,
      usernameFilled: filledValue === "fixture-passkey-user",
      captureRefused: captured === false,
      captureUnchanged: input.value === filledValue,
      noPasswordField:
        document.querySelectorAll('input[type="password"]').length === 0,
      descriptorsIntact: JSON.stringify(before) === JSON.stringify(describe()),
      fillSubmits: afterFill.submits,
      fillInputEvents: afterFill.inputEvents,
      fillChangeEvents: afterFill.changeEvents,
      captureSubmits: submits - afterFill.submits,
      captureInputEvents: inputEvents - afterFill.inputEvents,
      captureChangeEvents: changeEvents - afterFill.changeEvents,
    };
  });
  assert.equal(result.origin, ORIGIN);
  assert.equal(result.top, true);
  assert.equal(result.noPasswordField, true, "fixture must stay username-only");
  assert.equal(result.initiallyEmpty, true);
  assert.equal(result.ok, true);
  assert.equal(result.step, "username-only");
  assert.equal(result.submitted, false);
  assert.equal(result.usernameFilled, true, "username-only field was not filled");
  assert.equal(result.captureRefused, true, "username-only capture must be refused");
  assert.equal(result.captureUnchanged, true, "refused capture must not mutate values");
  assert.equal(result.descriptorsIntact, true, "id/autocomplete descriptors changed");
  assert.equal(result.fillSubmits, 0, "username-only fill must not submit");
  assert.equal(result.fillInputEvents, 1);
  assert.equal(result.fillChangeEvents, 1);
  assert.equal(result.captureSubmits, 0, "capture must not submit");
  assert.equal(result.captureInputEvents, 0, "capture must not emit input events");
  assert.equal(result.captureChangeEvents, 0, "capture must not emit change events");
  return result;
}

async function main() {
  const browserName = process.env.LOCKLARK_TEST_BROWSER || "chromium";
  assert(
    ["chromium", "firefox", "edge"].includes(browserName),
    "LOCKLARK_TEST_BROWSER must be chromium, firefox or edge",
  );
  const executable = process.env.LOCKLARK_TEST_BROWSER_EXECUTABLE;
  if (browserName === "edge")
    assert(
      typeof executable === "string" && executable.startsWith("/"),
      "Edge requires LOCKLARK_TEST_BROWSER_EXECUTABLE (absolute path)",
    );
  const modulePath =
    process.env.LOCKLARK_TEST_PLAYWRIGHT ||
    path.resolve(__dirname, "../web/node_modules/playwright");
  let playwright;
  try {
    playwright = require(modulePath);
  } catch {
    throw new Error("Playwright is unavailable; set LOCKLARK_TEST_PLAYWRIGHT");
  }
  const browser = await playwright[browserName === "edge" ? "chromium" : browserName].launch({
    headless: true,
    args: browserName === "chromium" ? ["--no-sandbox"] : [],
    ...(executable ? { executablePath: executable } : {}),
  });
  try {
    await scenario(browser, "/github/login", fixture("github-login.html"), checkGitHubFill);
    await scenario(browser, "/github/login", fixture("github-login.html"), checkGitHubCapture);
    await scenario(browser, "/webauthn/", fixture("webauthn-io.html"), checkWebAuthn);
  } finally {
    await browser.close();
  }
  console.log(
    "PASS " +
      browserName +
      " public-site compatibility: fixtures=2 profiles=3 probe=3 fill=2 capture=1 capture-refusal=1 external-requests=0",
  );
}

module.exports = { main, scenario, checkGitHubFill, checkGitHubCapture, checkWebAuthn };
if (require.main === module)
  main().catch(() => {
    console.error("Public-site compatibility driver failed");
    process.exitCode = 1;
  });

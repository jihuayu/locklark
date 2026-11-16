// This is an owned website/TLS fixture check, not browser save, vault revision,
// terminal lease, protected curl execution, or public HIBP acceptance.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { test } from "node:test";
import vm from "node:vm";
import { createBrowserRotationSite } from "./browser_rotation_site.mjs";
import { assertPrivateArtifacts, browserScreenshotsAllowed, captureControllerOutput,
  fixtureCanaries, registerRotationValue, ROTATION_OUTPUT_FAILURE } from "./browser_save_acceptance.mjs";

function ownedTLS(directory) {
  const file = (name) => join(directory, name);
  const openssl = (args) => {
    const result = spawnSync("openssl", args, { stdio: "ignore", timeout: 30000 });
    assert(result.status === 0, "Private fixture certificate generation failed");
  };
  openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-keyout", file("ca.key"), "-out", file("ca.pem"), "-subj", "/CN=Locklark owned fixture CA",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  openssl(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", file("site.key"),
    "-out", file("site.csr"), "-subj", "/CN=login.locklark.test"]);
  writeFileSync(file("extensions.cnf"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:login.locklark.test\n", { mode: 0o600 });
  openssl(["x509", "-req", "-in", file("site.csr"), "-CA", file("ca.pem"), "-CAkey", file("ca.key"),
    "-CAcreateserial", "-days", "1", "-out", file("site.pem"), "-extfile", file("extensions.cnf")]);
  chmodSync(file("ca.key"), 0o600);
  chmodSync(file("site.key"), 0o600);
  return { ca: readFileSync(file("ca.pem")), key: readFileSync(file("site.key")), cert: readFileSync(file("site.pem")) };
}

// Every call opens a new real TLS connection. Only this private CA is trusted;
// hostname verification and TLS authorization remain enabled.
function httpsRequest(url, ca, { method = "GET", cookie, fields, authorization, origin } = {}) {
  return new Promise((resolve, reject) => {
    const body = fields ? new URLSearchParams(fields).toString() : null;
    const headers = {};
    if (cookie) headers.Cookie = cookie;
    if (authorization) headers.Authorization = authorization;
    if (body !== null) {
      headers.Origin = origin ?? new URL(url).origin;
      headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8";
      headers["Content-Length"] = Buffer.byteLength(body);
      headers.Accept = "application/json";
    }
    const failed = () => reject(Error("Owned HTTPS request failed"));
    const req = request(url, { method, headers, ca, rejectUnauthorized: true, minVersion: "TLSv1.3",
      agent: false, family: 4, lookup: (_host, _options, callback) => callback(null, "127.0.0.1", 4) }, (response) => {
      const authorized = response.socket.authorized && response.socket.getProtocol() === "TLSv1.3";
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        length += chunk.length;
        if (length > 16384) { req.destroy(); failed(); return; }
        chunks.push(chunk);
      });
      response.once("error", failed);
      response.once("end", () => resolve({ status: response.statusCode, headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8"), authorized }));
    });
    req.once("error", failed);
    req.setTimeout(5000, () => { req.destroy(); failed(); });
    req.end(body);
  });
}

const csrf = (response) => {
  const value = /name="csrf" value="([a-f0-9]{64})"/.exec(response.body)?.[1];
  assert(typeof value === "string", "Website CSRF form field missing");
  return value;
};
const cookie = (response) => {
  const values = response.headers["set-cookie"];
  assert(values?.length === 1 && /; Path=\/; Secure; HttpOnly; SameSite=Strict$/.test(values[0]),
    "Fresh host-only secure session cookie required");
  return values[0].split(";")[0];
};

test("owned HTTPS account rotates through real forms and the same Basic verifier", async () => {
  const directory = mkdtempSync(join(tmpdir(), "locklark-owned-rotation-"));
  chmodSync(directory, 0o700);
  let site;
  try {
    const tls = ownedTLS(directory);
    const observations = [];
    site = createBrowserRotationSite({ ...tls, onSnapshot: (value) => observations.push(value) });
    const urls = await site.listen();
    const username = String.fromCodePoint(0x6d4b, 0x8bd5, 0x7528, 0x6237) + "@account._+-9";
    const oldPassword = "Owned-R0-" + randomBytes(20).toString("hex") + String.fromCodePoint(0x1f510);
    const newPassword = "Owned-R1-" + randomBytes(20).toString("hex") + String.fromCodePoint(0x1f510);
    const call = async (path, options) => {
      const response = await httpsRequest(urls.origin + path, tls.ca, options);
      assert(response.authorized, "Owned CA and hostname must authorize every real TLS request");
      return response;
    };
    const registerPage = await call("/register");
    assert.equal(registerPage.status, 200);
    assert(registerPage.headers["referrer-policy"] === "same-origin",
      "Ordinary same-origin form POST must retain its browser Origin header");
    const registrationSession = cookie(registerPage);
    for (const origin of ["null", "https://cross-origin.invalid"]) {
      const refused = await call("/register", { method: "POST", cookie: registrationSession, origin,
        fields: { csrf: csrf(registerPage), username, password: oldPassword, confirm: oldPassword } });
      assert.equal(refused.status, 403);
      assert(site.snapshot().registrations === 0 && refused.headers["set-cookie"] === undefined,
        "Opaque or cross-origin registration must not create an account or replace the session");
    }
    for (const invalidUsername of ["", "user:name", "user\nname", "user\n",
      String.fromCodePoint(0x6d4b).repeat(43), String.fromCharCode(0xd800)]) {
      const refused = await call("/register", { method: "POST", cookie: registrationSession,
        fields: { csrf: csrf(registerPage), username: invalidUsername, password: oldPassword, confirm: oldPassword } });
      assert.equal(refused.status, 400);
      assert(site.snapshot().registrations === 0 && refused.headers["set-cookie"] === undefined,
        "Invalid or oversized UTF-8 username must not create an account or replace the session");
    }
    const registered = await call("/register", { method: "POST", cookie: registrationSession,
      fields: { csrf: csrf(registerPage), username, password: oldPassword, confirm: oldPassword } });
    assert.equal(registered.status, 201);
    const registeredSession = cookie(registered);
    assert(registeredSession !== registrationSession, "Registration must establish a fresh session");

    const loginPage = await call("/login");
    assert.equal(loginPage.status, 200);
    assert(loginPage.body.includes('autocomplete="current-password"'), "Ordinary login field required");
    const anonymousSession = cookie(loginPage);
    const loggedIn = await call("/login", { method: "POST", cookie: anonymousSession,
      fields: { csrf: csrf(loginPage), username, password: oldPassword } });
    assert.equal(loggedIn.status, 303);
    const authenticatedSession = cookie(loggedIn);
    assert(authenticatedSession !== anonymousSession && authenticatedSession !== registeredSession,
      "Login must establish a fresh authenticated session");

    const changePage = await call("/change-password", { cookie: authenticatedSession });
    assert.equal(changePage.status, 200);
    assert(changePage.body.includes("<title>Locklark acceptance · Change password</title>"),
      "Website title must retain the existing X11 source-window prefix");
    assert(changePage.body.includes('action="/change-password"') &&
      changePage.body.includes('id="new-password"') && changePage.body.includes('id="confirm-password"') &&
      changePage.body.includes('fetch(form.action'), "Session-authenticated real POST change form required");
    const usernameInput = /<input id="username"[^>]*>/.exec(changePage.body)?.[0];
    assert(typeof usernameInput === "string" && usernameInput.includes('autocomplete="username"') &&
      usernameInput.includes('value="' + username + '"') && !/\b(?:readonly|disabled|hidden)\b/.test(usernameInput),
      "Change form must expose the current username for ordinary extension capture");
    const basic = (password) => "Basic " + Buffer.from(username + ":" + password).toString("base64");
    assert.equal((await call("/credential", { authorization: basic(oldPassword) })).status, 200);
    const wrongAccount = await call("/change-password", { method: "POST", cookie: authenticatedSession,
      fields: { csrf: csrf(changePage), username: "other-rotation-user", password: newPassword, confirm: newPassword } });
    assert.equal(wrongAccount.status, 403);
    assert(site.snapshot().passwordChanges === 0 && wrongAccount.headers["set-cookie"] === undefined,
      "A form username must not switch the authenticated account or rotate its session");
    assert.equal((await call("/credential", { authorization: basic(oldPassword) })).status, 200);
    const changed = await call("/change-password", { method: "POST", cookie: authenticatedSession,
      fields: { csrf: csrf(changePage), username, password: newPassword, confirm: newPassword } });
    assert.equal(changed.status, 200);
    assert(changed.body === '{"changed":true}', "Website must confirm its actual password transaction");
    assert(cookie(changed) !== authenticatedSession, "Password change must establish a fresh session");
    assert.equal((await call("/credential", { authorization: basic(oldPassword) })).status, 401);
    assert.equal((await call("/credential", { authorization: basic(newPassword) })).status, 200);

    const receipt = site.snapshot();
    assert.deepEqual(receipt, { tlsConnections: 19, requests: 19, registrations: 1, loginAccepted: 1,
      loginRejected: 0, passwordChanges: 1, changeRejected: 1, basicAccepted: 3, basicRejected: 1,
      requestRefused: 8, observerFailures: 0, countersCapped: false, accountRegistered: true, closed: false });
    assert(observations.length === 54 && observations.every(Object.isFrozen), "Read-only finite counter snapshots required");
    console.log("PASS: owned HTTPS website only; verified TLS=19 requests=19 register=1 login=1 change=1 origin refused=2 invalid-username refused=6 wrong-account refused=1 Basic accepted=3 rejected=1");
  } finally {
    if (site) {
      await site.close();
      assert(site.snapshot().closed && !site.snapshot().accountRegistered, "Owned website state must be cleared");
    }
    rmSync(directory, { recursive: true, force: true });
    assert(!existsSync(directory), "Private fixture TLS files must be removed");
  }
});

test("rotation canary reaches live output and artifact guards before forwarding", () => {
  const state = mkdtempSync(join(tmpdir(), "locklark-rotation-privacy-"));
  const originalLog = console.log, originalError = console.error;
  try {
    chmodSync(state, 0o700);
    const vault = join(state, "vault");
    mkdirSync(vault, { mode: 0o700 });
    const fixture = { Path: join(vault, "synthetic.ll") };
    const fixturePath = join(vault, "fixture.json");
    writeFileSync(fixturePath, JSON.stringify(fixture), { mode: 0o600 });
    const forwarded = [];
    console.log = (...values) => forwarded.push(values);
    console.error = (...values) => forwarded.push(values);
    const scan = captureControllerOutput({ getFixture: () => fixture });
    const value = 'Private-generated +"🔐-' + randomBytes(20).toString("hex");
    registerRotationValue(fixture, state, value);
    assert(fixtureCanaries(fixture).includes(value), "Generated value must enter the live canary set");
    assert(JSON.parse(readFileSync(fixturePath, "utf8")).RotationValue === value &&
      (statSync(fixturePath).mode & 0o777) === 0o600,
      "Observer canary must remain in the existing private fixture input");
    assert.throws(() => console.log(value), { message: "Synthetic factor or field leaked in output" });
    assert.throws(() => console.error(value), { message: "Synthetic factor or field leaked in output" });
    assert.throws(() => console.log(encodeURIComponent(value)), { message: "Synthetic factor or field leaked in output" });
    assert.throws(() => console.error(JSON.stringify(value)), { message: "Synthetic factor or field leaked in output" });
    assert(forwarded.length === 0, "Generated value must never be forwarded to controller output");
    console.log("Fixed rotation receipt");
    scan(fixture);
    const diagnostic = join(state, "rotation.log");
    writeFileSync(diagnostic, "Fixed rotation receipt", { mode: 0o600 });
    assertPrivateArtifacts(state, fixture);
    writeFileSync(diagnostic, encodeURIComponent(value), { mode: 0o600 });
    assert.throws(() => assertPrivateArtifacts(state, fixture),
      { message: "Synthetic factor or field value persisted in diagnostics" });
    assert(!browserScreenshotsAllowed("rotation:generator") && browserScreenshotsAllowed("save:positive"),
      "Rotation must forbid screenshots without changing ordinary save coverage");
  } finally {
    console.log = originalLog;
    console.error = originalError;
    rmSync(state, { recursive: true, force: true });
  }
});

test("refused private fixture input still registers the generated value for cleanup", () => {
  const state = mkdtempSync(join(tmpdir(), "locklark-rotation-refusal-"));
  try {
    chmodSync(state, 0o700);
    const fixture = { Path: join(state, "vault", "synthetic.ll") };
    const value = "Private-generated-" + randomBytes(20).toString("hex");
    assert.throws(() => registerRotationValue(fixture, state, value),
      { message: "Private rotation fixture input refused" });
    assert(fixtureCanaries(fixture).includes(value), "Input refusal must not lose the in-memory canary");
  } finally { rmSync(state, { recursive: true, force: true }); }
});

// These are controlled component producers, not real browser generator callers.
test("generation output barrier suppresses pending text until value registration succeeds", async () => {
  const state = mkdtempSync(join(tmpdir(), "locklark-rotation-barrier-"));
  const originalLog = console.log, originalError = console.error;
  try {
    chmodSync(state, 0o700);
    const vault = join(state, "vault");
    mkdirSync(vault, { mode: 0o700 });
    const fixture = { Path: join(vault, "synthetic.ll") };
    writeFileSync(join(vault, "fixture.json"), JSON.stringify(fixture), { mode: 0o600 });
    const forwarded = [];
    console.log = (...values) => forwarded.push(values);
    console.error = (...values) => forwarded.push(values);
    const scan = captureControllerOutput({ getFixture: () => fixture });
    const value = "Unknown-generated-" + randomBytes(20).toString("hex");
    let inspected = false;
    const registered = await scan.captureRotationValue(fixture, state, async () => {
      console.log(value);
      console.error({ [Symbol.for("nodejs.util.inspect.custom")]: () => { inspected = true; return value; } });
      // Direct suppression has no buffered-text limit or retained payload.
      console.error(value.repeat(10000));
      await Promise.resolve();
      assert(forwarded.length === 0 && !inspected, "Pending output must be discarded before formatting");
      return value;
    });
    assert(registered === value && fixture.RotationValue === value,
      "Barrier may reopen only after the generated value is registered");
    scan(fixture);
    assert.throws(() => console.log(value), { message: "Synthetic factor or field leaked in output" });
    assert.throws(() => console.error(encodeURIComponent(value)), { message: "Synthetic factor or field leaked in output" });
    console.log("Fixed rotation receipt");
    assert(forwarded.length === 1 && forwarded[0][0] === "Fixed rotation receipt",
      "Successful registration must restore guarded fixed output");
  } finally {
    console.log = originalLog;
    console.error = originalError;
    rmSync(state, { recursive: true, force: true });
  }
});

test("generation failure discards unknown output and reports only a fixed error", async () => {
  const originalLog = console.log, originalError = console.error;
  try {
    const fixture = {};
    const forwarded = [];
    console.log = (...values) => forwarded.push(values);
    console.error = (...values) => forwarded.push(values);
    const scan = captureControllerOutput({ getFixture: () => fixture });
    const value = "Unknown-failed-" + randomBytes(20).toString("hex");
    await assert.rejects(scan.captureRotationValue(fixture, "unused-private-state", async () => {
      console.log(value);
      console.error(new Error(value));
      throw new Error(value);
    }), (error) => error.message === ROTATION_OUTPUT_FAILURE && !error.stack.includes(value) && !("cause" in error));
    // Late output after a failed producer remains suppressed: its value may
    // never have become known to the registry or final privacy scanner.
    console.error(new Error(value));
    console.log(value);
    console.error(ROTATION_OUTPUT_FAILURE, value);
    assert(forwarded.length === 0 && fixture.RotationValue === undefined,
      "Failure must not reopen unknown-value output or retain a generated value");
    console.error(ROTATION_OUTPUT_FAILURE);
    assert(forwarded.length === 1 && forwarded[0][0] === ROTATION_OUTPUT_FAILURE,
      "A fixed failure report must remain available after suppression");
    await assert.rejects(scan.captureRotationValue(fixture, "unused-private-state", async () => value),
      { message: ROTATION_OUTPUT_FAILURE });
    scan(fixture);
  } finally { console.log = originalLog; console.error = originalError; }
});

test("static rotation integration encloses actual generator input and read in the output barrier", () => {
  const source = readFileSync(new URL("./browser_rotation_acceptance.mjs", import.meta.url), "utf8");
  const start = source.indexOf("const generated = await captureRotationValue(async () => {");
  const end = source.indexOf("    });\n    assert(generated", start);
  assert(start >= 0 && end > start, "Real generator producer must have a bounded source block");
  const producer = source.slice(start, end);
  const click = producer.indexOf('generator.click("#gen-regenerate")');
  const fill = producer.indexOf('generator.click("#gen-fill")');
  const close = producer.indexOf("await closePopups()", fill);
  const read = producer.indexOf('return page.locator("#new-password").inputValue()');
  assert(click >= 0 && fill > click && close > fill && read > close,
    "Generator click, generated fill, popup closure and actual page read must remain inside the producer");
  assert(!/\.value\s*=(?!=)/.test(source) && !source.includes(".fill(") &&
    !source.includes("runtime.sendMessage") && !source.includes("performClick"),
    "Rotation must not replace real product fill with page mutation or authorization hooks");
  assert(source.includes('page.locator("#confirm-password").press("Enter")') &&
    source.includes('response.request().method() === "POST"') &&
    source.includes("oldAuthentication.status === 401") && source.includes("newAuthentication.status === 200") &&
    source.includes("updateEvent.item_id === itemID") && source.includes("updateEvent.base_revision === r0") &&
    source.includes("await fillAndLogin(itemID, r1)"),
    "Browser POST, independent website authentication, exact native update and actual refill login must remain required");
  const candidateStart = source.indexOf("const exactCandidate = async (");
  const candidateEnd = source.indexOf("  const fillAndLogin =", candidateStart);
  const candidate = source.slice(candidateStart, candidateEnd);
  const updateStart = source.indexOf('step("update-r0:baseline-observe")');
  const updateEnd = source.indexOf('step("refill-login-r1")', updateStart);
  const update = source.slice(updateStart, updateEnd);
  const stages = (block) => [...block.matchAll(/step\("update-r0:([a-z0-9-]+)"\)/g)].map((match) => match[1]);
  assert.deepEqual(stages(candidate), ["observe-r0", "open-popup", "refresh-ready", "refresh-click", "row-ready", "manual-setting"],
    "Exact-candidate diagnostics must use only the fixed update stages");
  assert.deepEqual(stages(update), ["baseline-observe", "update-click", "native-wait", "preapproval-unchanged", "native-approve", "save-event", "revision-audit"],
    "Native-update diagnostics must use only the fixed update stages");
  const ordered = (block, tokens) => {
    let previous = -1;
    for (const token of tokens) {
      const position = block.indexOf(token, previous + 1);
      assert(position > previous, "Fixed update stages must precede their actual operation in order");
      previous = position;
    }
  };
  ordered(candidate, [
    'if (updating) step("update-r0:observe-r0")', "const row = observe()",
    'if (updating) step("update-r0:open-popup")', "const popup = await openPopup()",
    'if (updating) step("update-r0:refresh-ready")', 'await wait(async () => (await popup.disabled("#refresh")) === false',
    'if (updating) step("update-r0:refresh-click")', 'await popup.click("#refresh")',
    'if (updating) step("update-r0:row-ready")', 'await wait(async () => (await popup.disabled("#refresh")) === false &&',
    'if (updating) step("update-r0:manual-setting")', 'assert((await popup.evaluate',
  ]);
  ordered(update, [
    'step("update-r0:baseline-observe")', "const beforeUpdate = observe()", "await exactCandidate(itemID, r0, true)",
    'step("update-r0:update-click")', "await updatePopup.click(",
    'step("update-r0:native-wait")', 'input([{ wait_label: "批准更新登录" }])',
    'step("update-r0:preapproval-unchanged")', "const pending = observe()", 'pending.save_events.length === beforeUpdate.save_events.length',
    'step("update-r0:native-approve")', 'input([{ click_label: "批准更新登录" }])',
    'step("update-r0:save-event")', "await wait(() => {", 'updated.save_events.length === beforeUpdate.save_events.length + 1',
    'step("update-r0:revision-audit")', "const updateEvent =", 'updateEvent.base_revision === r0',
  ]);
  assert(source.includes("const exactCandidate = async (id, revision, updating = false) =>") &&
    (source.match(/exactCandidate\(itemID, r0, true\)/g) || []).length === 1 &&
    (source.match(/step\("update-r0:/g) || []).length === 13 &&
    !source.includes('step("update-r0")'),
    "Only the exact native update may opt into the fixed diagnostic stages");
  const failureStart = source.indexOf("\n  } catch { failed = true; }\n  finally {");
  assert(failureStart >= 0, "Rotation failure must enter cleanup without retaining the exception");
  const failure = source.slice(failureStart + 1);
  assert(failure.startsWith("  } catch { failed = true; }\n  finally {") &&
    !/\b(?:step|phase)\s*\(/.test(failure) &&
    !/\b(?:console|error|message|stack|cause)\b/.test(failure) &&
    failure.includes('throw Error("Browser rotation acceptance failed")'),
    "Failure and cleanup must preserve the last fixed stage without exposing an exception payload");
});

test("static rotation hook runs once and keeps the remaining invocation free of screenshots", () => {
  const source = readFileSync(new URL("./browser_native_acceptance.mjs", import.meta.url), "utf8");
  assert((source.match(/await acceptBrowserRotation\(/g) || []).length === 1,
    "Existing Chromium invocation must contain exactly one rotation subjourney");
  const save = source.lastIndexOf("await acceptBrowserSave(acceptanceDriver)");
  const rotation = source.indexOf("await acceptBrowserRotation(", save);
  const otp = source.indexOf("await acceptBrowserOTP(acceptanceDriver)", rotation);
  assert(save >= 0 && rotation > save && otp > rotation,
    "Rotation must reuse the current invocation between save and OTP");
  assert(source.includes("scanController.captureRotationValue(fixture, state, produce)") &&
    source.includes('process.env.LOCKLARK_BROWSER_REQUIRE_PREBUILT === "1"'),
    "Rotation must use the reviewed barrier and same-run prebuilt artifacts");
  assert((source.match(/rotationScreenshotsBlocked = false/g) || []).length === 1 &&
    source.indexOf("rotationScreenshotsBlocked = true", save) < rotation &&
    source.includes("!rotationScreenshotsBlocked && browserScreenshotsAllowed(stage)") &&
    (source.match(/screenshotsAllowed\(\)/g) || []).length === 3,
    "Rotation must latch screenshot suppression across every later failure path");
});

test("rotation ready mode rejects non-exact popup-vault overrides before startup", () => {
  const source = readFileSync(new URL("./browser_native_acceptance.mjs", import.meta.url), "utf8");
  const start = source.indexOf("if (rotationRequested) {");
  const end = source.indexOf("\n// After every route/Edge", start);
  assert(start >= 0 && end > start, "Rotation startup guard must precede launch");
  const run = (popupVault) => vm.runInNewContext(source.slice(start, end), {
    assert, isAbsolute, rotationRequested: true, browserName: "chromium", routeDetailRead: false,
    checkoutFrames: false, edgeManagerInstall: false, register: "/owned-prebuilt-register",
    process: { platform: "linux", env: { LOCKLARK_BROWSER_REQUIRE_PREBUILT: "1",
      LOCKLARK_BROWSER_FIXTURE: "/owned-prebuilt-fixture", LOCKLARK_TEST_POPUP_VAULT: popupVault } },
  });
  for (const popupVault of [undefined, "", "1"]) assert.doesNotThrow(() => run(popupVault));
  for (const popupVault of ["0", "false", "true", "2"])
    assert.throws(() => run(popupVault), { message: "Rotation popup-vault mode requires the exact opt-in" });
});

test("rotation ready proof requires the actual normal save and optional popup prelude", () => {
  const source = readFileSync(new URL("./browser_native_acceptance.mjs", import.meta.url), "utf8");
  const start = source.indexOf("assert(normalReadyProof &&");
  const end = source.indexOf(";", start) + 1;
  assert(start >= 0 && end > start, "Rotation entry must check completed runtime proofs");
  const run = (popupVault, normalReadyProof, popupVaultReadyProof) =>
    vm.runInNewContext(source.slice(start, end), { assert, normalReadyProof, popupVaultReadyProof,
      process: { env: { LOCKLARK_TEST_POPUP_VAULT: popupVault } } });
  for (const popupVault of [undefined, ""]) {
    assert.doesNotThrow(() => run(popupVault, true, false));
    assert.throws(() => run(popupVault, false, true), { message: "Rotation requires completed normal-mode proofs" });
  }
  assert.doesNotThrow(() => run("1", true, true));
  for (const [normal, popup] of [[false, false], [false, true], [true, false]])
    assert.throws(() => run("1", normal, popup), { message: "Rotation requires completed normal-mode proofs" });
  for (const popupVault of ["0", "false"])
    assert.throws(() => run(popupVault, true, true), { message: "Rotation requires completed normal-mode proofs" });
});

test("rotation ready assignments follow the complete real prelude and save returns", () => {
  const source = readFileSync(new URL("./browser_native_acceptance.mjs", import.meta.url), "utf8");
  assert((source.match(/popupVaultReadyProof = true/g) || []).length === 1 &&
    (source.match(/normalReadyProof = true/g) || []).length === 1,
    "Runtime proofs must each have a single successful assignment");
  const start = source.indexOf("if (process.env.LOCKLARK_TEST_POPUP_VAULT) {");
  const ordered = [
    'assert(didCommit, "Popup vault commits are the quick-fill pairing proof")',
    'phase("native-disconnect")', 'await popup.click("#disconnect")',
    'phase("native-reconnect")', 'click_label: "确认连接此扩展"',
    'phase("post-repair:route-reject")', 'input([{ click_label: "拒绝本次操作" }])',
    "routeWiped(observation)", "browserKey(ROUTE_IDLE_CLOSE_STALE, ROUTE_TITLE_PREFIX)",
    '"Rejected route tab was not closed"', 'phase("post-repair:route-refetched")',
    '"Refused popup not ready"', '"Refused route opened the detail view"',
    '"Refused route disclosed a synthetic fixture value"', "popupVaultReadyProof = true",
  ];
  let previous = start;
  assert(start >= 0, "Existing popup-vault prelude must remain present");
  for (const token of ordered) {
    const position = source.indexOf(token, previous);
    assert(position > previous, "Popup proof must follow every original native repair and route-wipe assertion");
    previous = position;
  }
  assert.match(source, /await acceptBrowserSave\(acceptanceDriver\);\s+normalReadyProof = true;/);
  const normal = source.indexOf("normalReadyProof = true");
  const guard = source.indexOf("assert(normalReadyProof &&", normal);
  const rotation = source.indexOf("await acceptBrowserRotation(", guard);
  assert(normal >= 0 && guard > normal && rotation > guard,
    "Rotation may start only after successful normal save and the runtime proof guard");
});

test("CI rotation wiring scopes one opt-in to the existing first Chromium invocation", () => {
  const workflow = readFileSync(new URL("../.github/workflows/check.yml", import.meta.url), "utf8");
  const job = (name) => {
    const start = workflow.indexOf("  " + name + ":\n");
    assert(start >= 0, "Existing CI job must remain present");
    const rest = workflow.slice(start);
    const next = /\n  [A-Za-z0-9_-]+:\n/.exec(rest);
    return next ? rest.slice(0, next.index) : rest;
  };
  const step = (job, name) => {
    const marker = "      - name: " + name + "\n";
    assert(job.split(marker).length === 2, "Existing CI step must remain unique");
    const rest = job.slice(job.indexOf(marker));
    const next = rest.indexOf("\n      - ");
    return next < 0 ? rest : rest.slice(0, next);
  };
  const extension = step(job("web-core"), "Test browser extension");
  assert(extension.split("\n").includes("        run: node --test browser-extension/test/*.test.js scripts/test_browser_checkout_acceptance.mjs scripts/test_browser_accessibility_acceptance.mjs scripts/test_browser_fixture_path.mjs scripts/test_browser_rotation_site.mjs"),
    "The existing cheap Node test invocation must retain every suite and append the frozen rotation file once");
  assert((workflow.match(/scripts\/test_browser_rotation_site\.mjs/g) || []).length === 1,
    "The frozen rotation test file must run once in the whole workflow");
  const chromium = step(job("web-browsers"), "Test native browser approval, popup editing, fill, save and OTP");
  const wrapper = "dbus-run-session -- xvfb-run -a -s '-screen 0 1280x900x24'";
  const commands = chromium.slice(chromium.indexOf("        run: |\n") + "        run: |\n".length)
    .split("\n").filter((line) => line.startsWith("          ") && !line.trim().startsWith("#"))
    .map((line) => line.trim()).filter((line) => line.startsWith("dbus-run-session "));
  assert.deepEqual(commands, [
    wrapper + " env LOCKLARK_TEST_BROWSER_ROTATION=1 node scripts/browser_native_acceptance.mjs",
    wrapper + " python3 scripts/browser_otp_privacy_acceptance.py chromium",
    wrapper + " env -u LOCKLARK_TEST_POPUP_VAULT LOCKLARK_TEST_ROUTE_DETAIL_READ=1 LOCKLARK_TEST_ROUTE_IDLE_TTL=1 node scripts/browser_native_acceptance.mjs",
  ], "Only the first existing invocation may gain the rotation opt-in");
  assert((workflow.match(/LOCKLARK_TEST_BROWSER_ROTATION=1/g) || []).length === 1 &&
    !/LOCKLARK_TEST_BROWSER_ROTATION:/.test(workflow),
    "Rotation opt-in must not become a step/job/global environment value or reach another invocation");
  assert((workflow.match(/node scripts\/browser_native_acceptance\.mjs/g) || []).length === 3,
    "Rotation must not add another Chromium browser invocation");
  for (const name of ["POPUP_VAULT", "PASSKEY_MANAGEMENT", "PASSKEY_CONDITIONAL", "OTHER_PROVIDER", "PASSKEY_SIGNALS"])
    assert(chromium.includes('LOCKLARK_TEST_' + name + ': "1"'), "Existing popup/attachment and Passkey coverage must remain enabled");
  assert(chromium.includes("        timeout-minutes: 15\n") &&
    !commands[0].includes("env -u"), "Rotation must preserve the native timeout and original environment");
});

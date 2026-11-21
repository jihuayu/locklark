// This is an owned website/TLS fixture check, not browser save, vault revision,
// terminal lease, protected curl execution, or public HIBP acceptance.
import assert from "node:assert/strict";
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { request } from "node:https";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { createBrowserRotationSite, ROTATION_SITE_HOST } from "./browser_rotation_site.mjs";

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
function httpsRequest(url, ca, { method = "GET", cookie, fields, authorization } = {}) {
  return new Promise((resolve, reject) => {
    const body = fields ? new URLSearchParams(fields).toString() : null;
    const headers = {};
    if (cookie) headers.Cookie = cookie;
    if (authorization) headers.Authorization = authorization;
    if (body !== null) {
      headers.Origin = new URL(url).origin;
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
    const username = "synthetic-rotation-user";
    const oldPassword = "Owned-R0-" + randomBytes(20).toString("hex");
    const newPassword = "Owned-R1-" + randomBytes(20).toString("hex");
    const call = async (path, options) => {
      const response = await httpsRequest(urls.origin + path, tls.ca, options);
      assert(response.authorized, "Owned CA and hostname must authorize every real TLS request");
      return response;
    };
    const registerPage = await call("/register");
    assert.equal(registerPage.status, 200);
    const registrationSession = cookie(registerPage);
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
    assert(changePage.body.includes('action="/change-password"') &&
      changePage.body.includes('id="new-password"') && changePage.body.includes('id="confirm-password"') &&
      changePage.body.includes('fetch(form.action'), "Session-authenticated real POST change form required");
    const basic = (password) => "Basic " + Buffer.from(username + ":" + password).toString("base64");
    assert.equal((await call("/credential", { authorization: basic(oldPassword) })).status, 200);
    const changed = await call("/change-password", { method: "POST", cookie: authenticatedSession,
      fields: { csrf: csrf(changePage), username, password: newPassword, confirm: newPassword } });
    assert.equal(changed.status, 200);
    assert(changed.body === '{"changed":true}', "Website must confirm its actual password transaction");
    assert(cookie(changed) !== authenticatedSession, "Password change must establish a fresh session");
    assert.equal((await call("/credential", { authorization: basic(oldPassword) })).status, 401);
    assert.equal((await call("/credential", { authorization: basic(newPassword) })).status, 200);

    const receipt = site.snapshot();
    assert.deepEqual(receipt, { tlsConnections: 9, requests: 9, registrations: 1, loginAccepted: 1,
      loginRejected: 0, passwordChanges: 1, changeRejected: 0, basicAccepted: 2, basicRejected: 1,
      requestRefused: 0, observerFailures: 0, countersCapped: false, accountRegistered: true, closed: false });
    assert(observations.length === 24 && observations.every(Object.isFrozen), "Read-only finite counter snapshots required");
    console.log("PASS: owned HTTPS website only; verified TLS=9 requests=9 register=1 login=1 change=1 Basic accepted=2 rejected=1");
  } finally {
    if (site) {
      await site.close();
      assert(site.snapshot().closed && !site.snapshot().accountRegistered, "Owned website state must be cleared");
    }
    rmSync(directory, { recursive: true, force: true });
    assert(!existsSync(directory), "Private fixture TLS files must be removed");
  }
});

// Explicit opt-in only. The ordinary default run above never loads Playwright
// or starts a browser; this checkpoint is separate.
const rotationBrowser = process.env.LOCKLARK_TEST_ROTATION_BROWSER === "1";
if (rotationBrowser) {
  const FLOW_PHASE = "browser-chromium-flow";
  const CLEANUP_PHASE = "browser-chromium-cleanup";
  test("real headless Chromium rotates the owned website through its ordinary forms", { timeout: 120000 }, async () => {
    let directory, site, browser;
    let flowFailed = false, cleanupFailed = false;
    try {
      directory = mkdtempSync(join(tmpdir(), "locklark-owned-browser-rotation-"));
      chmodSync(directory, 0o700);
      const tls = ownedTLS(directory);
      site = createBrowserRotationSite(tls);
      const urls = await site.listen();
      const origin = new URL(urls.origin).origin;
      assert.equal(new URL(urls.origin).hostname, ROTATION_SITE_HOST, "Browser target must be the owned .test host");

      const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
      const require = createRequire(join(root, "web/package.json"));
      const { chromium } = process.env.LOCKLARK_TEST_PLAYWRIGHT
        ? require(process.env.LOCKLARK_TEST_PLAYWRIGHT)
        : require("playwright");
      // Only the ephemeral fixture leaf SPKI is excepted; TLS verification is
      // never globally disabled and the resolver is pinned to loopback with
      // every other hostname denied.
      const spki = createHash("sha256")
        .update(new X509Certificate(tls.cert).publicKey.export({ type: "spki", format: "der" }))
        .digest("base64");
      const executablePath = process.env.LOCKLARK_TEST_BROWSER_EXECUTABLE;
      browser = await chromium.launch({
        headless: true,
        args: [
          `--host-resolver-rules=MAP ${ROTATION_SITE_HOST} 127.0.0.1, MAP * ~NOTFOUND`,
          "--ignore-certificate-errors-spki-list=" + spki,
          "--no-proxy-server",
          "--no-sandbox",
        ],
        ...(executablePath ? { executablePath } : {}),
      });
      // Disposable, non-persistent context with Service Workers blocked so
      // every request remains visible to the strict same-origin route.
      const context = await browser.newContext({ serviceWorkers: "block" });
      let externalRequests = 0;
      await context.route("**/*", async (route) => {
        let requestOrigin;
        try {
          requestOrigin = new URL(route.request().url()).origin;
        } catch {
          externalRequests++;
          await route.abort("blockedbyclient");
          return;
        }
        if (requestOrigin !== origin) {
          externalRequests++;
          await route.abort("blockedbyclient");
          return;
        }
        await route.continue();
      });
      const page = await context.newPage();
      const username = "synthetic-browser-" + randomBytes(12).toString("hex");
      const oldPassword = "Owned-R0-" + randomBytes(20).toString("hex");
      const newPassword = "Owned-R1-" + randomBytes(20).toString("hex");

      // Register R0 through the site's ordinary registration form.
      await page.goto(urls.registerURL, { waitUntil: "domcontentloaded" });
      await page.locator("#username").fill(username);
      await page.locator("#password").fill(oldPassword);
      await page.locator("#confirm-password").fill(oldPassword);
      const [registered] = await Promise.all([
        page.waitForResponse((response) =>
          response.url() === urls.registerURL && response.request().method() === "POST"),
        page.getByRole("button", { name: "Register" }).click(),
      ]);
      assert.equal(registered.status(), 201);
      await page.getByRole("heading", { name: "Account created" }).waitFor();

      const submitLogin = async (password, expectedStatus) => {
        await page.goto(urls.loginURL, { waitUntil: "domcontentloaded" });
        await page.locator("#username").fill(username);
        await page.locator("#password").fill(password);
        const [response] = await Promise.all([
          page.waitForResponse((candidate) =>
            candidate.url() === urls.loginURL && candidate.request().method() === "POST"),
          page.getByRole("button", { name: "Sign in" }).click(),
        ]);
        assert.equal(response.url(), urls.loginURL, "Login response must be the owned login endpoint");
        assert.equal(response.request().method(), "POST", "Login response must follow a real form POST");
        assert.equal(response.status(), expectedStatus, "Login status must match the exact expectation");
        if (expectedStatus === 401) {
          assert.equal(response.ok(), false, "Rejected login must not be reported as successful");
        } else {
          await page.waitForURL(urls.changeURL);
          await page.locator("#new-password").waitFor();
        }
      };

      // Log in with R0 through the real login form and follow the 303.
      await submitLogin(oldPassword, 303);

      // Type and submit R1 with the page's own button, then await the real
      // request plus the page's successful DOM state.
      await page.locator("#new-password").fill(newPassword);
      await page.locator("#confirm-password").fill(newPassword);
      const [changed] = await Promise.all([
        page.waitForResponse((response) =>
          response.url() === urls.changeURL && response.request().method() === "POST"),
        page.getByRole("button", { name: "Change password" }).click(),
      ]);
      assert.equal(changed.status(), 200);
      assert.equal((await changed.json()).changed, true);
      await page.locator('body[data-rotation-result="changed"]').waitFor();
      assert.equal(await page.locator("body").getAttribute("data-rotation-result"), "changed");

      // Same username: the old R0 must be rejected and the new R1 accepted by
      // the site's real login form; only the actual network statuses count.
      await submitLogin(oldPassword, 401);
      await submitLogin(newPassword, 303);

      // A second registration is refused, and the site still holds one account
      // with exactly one password change.
      assert.equal((await page.goto(urls.registerURL, { waitUntil: "domcontentloaded" })).status(), 409);
      const receipt = site.snapshot();
      assert.equal(receipt.registrations, 1);
      assert.equal(receipt.accountRegistered, true);
      assert.equal(receipt.passwordChanges, 1);
      assert.equal(receipt.changeRejected, 0);
      assert.equal(receipt.loginAccepted, 2);
      assert.equal(receipt.loginRejected, 1);
      assert.equal(receipt.basicAccepted, 0);
      assert.equal(receipt.basicRejected, 0);
      assert.equal(receipt.observerFailures, 0);
      assert.equal(receipt.countersCapped, false);
      assert.equal(receipt.closed, false);
      assert(receipt.tlsConnections > 0 && receipt.requests > 0);
      assert.equal(externalRequests, 0);
      console.log("PASS: real headless Chromium register=201 login=303 change=200 old=401 new=303 " +
        "registrations=1 passwordChanges=1 loginAccepted=2 loginRejected=1 externalRequests=0");
    } catch {
      flowFailed = true;
    } finally {
      // browser.close() disposes the sole disposable context. Do not let a
      // close failure skip or hide the site/TLS cleanup.
      try { if (browser) await browser.close(); } catch { cleanupFailed = true; }
      try {
        if (site) {
          await site.close();
          const closed = site.snapshot();
          assert(closed.closed && !closed.accountRegistered, "Owned website state must be cleared");
        }
      } catch {
        cleanupFailed = true;
      } finally {
        try {
          if (directory) rmSync(directory, { recursive: true, force: true });
          if (directory && existsSync(directory)) cleanupFailed = true;
        } catch {
          cleanupFailed = true;
        }
      }
    }
    const phases = [flowFailed && FLOW_PHASE, cleanupFailed && CLEANUP_PHASE].filter(Boolean);
    // Locator failures can echo synthetic fill arguments, so only fixed phases
    // are reported: no underlying exception, cause, debug data, path, or form.
    if (phases.length > 0) throw new Error(`BROWSER_ROTATION_FAILED phase=${phases.join("+")}`);
  });
}

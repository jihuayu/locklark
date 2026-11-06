// External end-to-end acceptance: actual extension action, native messaging,
// MyGo UI input, and a controlled HTTPS document. No product test bypasses.
import { createRequire } from "node:module";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "node:https";
import { createHash, X509Certificate } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import {
  acceptBrowserSave,
  captureControllerOutput,
  browserScreenshotsAllowed,
  assertPrivateText,
  assertPrivateArtifacts,
  fixtureCanaries,
  vaultObserver,
} from "./browser_save_acceptance.mjs";

import { acceptBrowserOTP, otpHTML } from "./browser_otp_acceptance.mjs";

const scanController = captureControllerOutput();
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "web/package.json"));
const { chromium } = process.env.LOCKLARK_TEST_PLAYWRIGHT
  ? require(process.env.LOCKLARK_TEST_PLAYWRIGHT)
  : require("playwright");
const go = process.env.LOCKLARK_GO || "go";
const host = process.env.LOCKLARK_BROWSER_HOST;
assert(
  host && process.env.DISPLAY,
  "A built native host and real X display are required",
);
assert(
  !process.env.LOCKLARK_TEST_FAILURE_STAGE ||
    ["after-pair", "page-arguments", "otp-page-arguments"].includes(
      process.env.LOCKLARK_TEST_FAILURE_STAGE,
    ),
  "Unsupported acceptance failure stage",
);
const state = mkdtempSync("/tmp/locklark-browser-acceptance-");
const env = { ...process.env, GOTOOLCHAIN: "go1.27.3" };
const diagnostics = mkdtempSync(join(state, "diagnostics-"));
let stage = "fixture",
  lastPopup = null,
  nativeInput = null;
let privacyValues = [];
let observedFixture = null;
function popupStatusKind(value) {
  const text = String(value || "");
  if (text.includes("已保存")) return "saved";
  if (text.includes("未找到")) return "no-candidates";
  if (text.includes("页面或活动标签")) return "context-changed";
  if (text.includes("已连接")) return "paired";
  if (text.includes("连接不可用")) return "popup-unavailable";
  if (text.includes("结果未确认")) return "unknown";
  if (text.includes("锁定")) return "locked";
  if (text.includes("未连接") || text.includes("断开")) return "disconnected";
  if (text.includes("原生") || text.includes("批准")) return "native-pending";
  if (text.includes("拒绝")) return "refused";
  return "other";
}
function phase(value) {
  stage = value;
  console.log("Native browser stage: " + value);
}
const key = join(state, "tls.key"),
  cert = join(state, "tls.crt");
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    key,
    "-out",
    cert,
    "-subj",
    "/CN=login.locklark.test",
    "-addext",
    "subjectAltName=DNS:login.locklark.test",
  ],
  { stdio: "ignore" },
);
// Trust only this ephemeral test certificate, rather than disabling TLS checks.
const spki = createHash("sha256")
  .update(
    new X509Certificate(readFileSync(cert)).publicKey.export({
      type: "spki",
      format: "der",
    }),
  )
  .digest("base64");
const html = `<!doctype html><html><title>Locklark acceptance</title><body><h1>Synthetic login</h1><form method="post"><label>User<input id="username" autocomplete="username"></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button>Submit</button></form><script>window.submits=0;document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();window.submits++;});</script></body></html>`;
const server = createServer(
  { key: readFileSync(key), cert: readFileSync(cert) },
  (req, res) => {
    res.setHeader("Content-Type", "text/html");
    res.end(
      req.url.startsWith("/otp")
        ? otpHTML.replace(
            "Locklark OTP acceptance",
            "Locklark acceptance · OTP",
          )
        : html,
    );
  },
);
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const origin = "https://login.locklark.test:" + server.address().port;
let browser;
const logs = [];
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function eventually(check, message, limit = 10000) {
  const end = Date.now() + limit;
  while (Date.now() < end) {
    if (await check()) return;
    await delay(100);
  }
  throw Error(message);
}
try {
  execFileSync(
    go,
    [
      "run",
      "./scripts/browser_acceptance_fixture",
      "-out",
      join(state, "vault"),
      "-origin",
      origin,
    ],
    { cwd: root, env, stdio: "inherit" },
  );
  const fixture = JSON.parse(readFileSync(join(state, "vault/fixture.json")));
  observedFixture = fixture;
  privacyValues = fixtureCanaries(fixture);
  const profile = join(state, "profile");
  mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
  execFileSync(
    go,
    [
      "run",
      "./cmd/locklark-browser-register",
      "--browser",
      "chrome",
      "--host",
      resolve(host),
      "--output",
      join(profile, "NativeMessagingHosts/org.locklark.browser.json"),
    ],
    { cwd: root, env, stdio: "inherit" },
  );
  execFileSync(process.execPath, ["browser-extension/build.js", "chromium"], {
    cwd: root,
  });
  const extension = join(root, "browser-extension/dist/chromium");
  browser = await chromium.launchPersistentContext(profile, {
    headless: false,
    channel: "chromium",
    viewport: { width: 1100, height: 700 },
    args: [
      "--disable-extensions-except=" + extension,
      "--load-extension=" + extension,
      "--host-resolver-rules=MAP login.locklark.test 127.0.0.1",
      "--no-proxy-server",
      "--ignore-certificate-errors-spki-list=" + spki,
      "--window-size=1200,850",
      "--remote-debugging-port=0",
    ],
  });
  browser.on("console", (msg) => logs.push(msg.text()));
  const page = browser.pages()[0] || (await browser.newPage());
  await page.goto(origin + "/login");
  const worker =
    browser.serviceWorkers()[0] ||
    (await browser.waitForEvent("serviceworker"));
  assert(
    worker.url() ===
      "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/background.js",
    "Actual fixed extension identity required",
  );
  function input(actions, native = true, inspect = false) {
    const options = typeof inspect === "object" ? inspect : { inspect };
    const request = native
      ? {
          title: "Locklark · 浏览器原生确认",
          executable: resolve(host),
          actions,
          ...options,
        }
      : { title_prefix: "Locklark acceptance", actions };
    return JSON.parse(
      execFileSync("python3", [join(root, "scripts/browser_native_x11.py")], {
        input: JSON.stringify(request),
        env,
      }).toString(),
    );
  }
  nativeInput = input;
  // Chrome action popups are real page targets but are not always surfaced by
  // Playwright Context.pages(). Attach to that popup through local test CDP.
  async function popupTargets() {
    const port = readFileSync(
      join(profile, "DevToolsActivePort"),
      "utf8",
    ).split("\n")[0];
    const targets = await (
      await fetch("http://127.0.0.1:" + port + "/json/list")
    ).json();
    return targets.filter(
      (target) =>
        target.url ===
        "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/popup.html",
    );
  }
  async function attachPopup(target) {
    const ws = new WebSocket(target.webSocketDebuggerUrl),
      calls = new Map();
    let seq = 0;
    ws.addEventListener("message", (event) => {
      const response = JSON.parse(event.data);
      if (response.method === "Runtime.consoleAPICalled")
        logs.push(JSON.stringify(response.params));
      const call = calls.get(response.id);
      if (call) {
        calls.delete(response.id);
        clearTimeout(call.timer);
        response.error
          ? call.reject(Error("Popup CDP failed"))
          : call.resolve(response.result);
      }
    });
    ws.addEventListener("close", () => {
      for (const c of calls.values()) {
        clearTimeout(c.timer);
        c.reject(Error("Popup closed"));
      }
      calls.clear();
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.close();
        reject(Error("Popup CDP connection timed out"));
      }, 3000);
      ws.addEventListener(
        "open",
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true },
      );
      ws.addEventListener(
        "error",
        () => {
          clearTimeout(timer);
          reject(Error("Popup CDP connection failed"));
        },
        { once: true },
      );
      ws.addEventListener(
        "close",
        () => {
          clearTimeout(timer);
          reject(Error("Popup CDP closed"));
        },
        { once: true },
      );
    });
    const call = (method, params = {}) =>
      new Promise((resolve, reject) => {
        if (ws.readyState !== WebSocket.OPEN) {
          reject(Error("Popup CDP closed"));
          return;
        }
        const id = ++seq,
          timer = setTimeout(() => {
            calls.delete(id);
            reject(Error("Popup CDP timed out"));
          }, 3000);
        calls.set(id, { resolve, reject, timer });
        ws.send(JSON.stringify({ id, method, params }));
      });
    await call("Runtime.enable");
    const evaluate = async (expression) => {
      const r = await call("Runtime.evaluate", {
        expression,
        returnByValue: true,
      });
      if (r.exceptionDetails) throw Error("Popup inspection failed");
      return r.result.value;
    };
    return {
      targetId: target.id,
      close: () => ws.close(),
      ready: () =>
        evaluate(
          'document.readyState === "complete" && document.visibilityState === "visible" && document.hasFocus() && document.querySelector("#status")?.textContent.length > 0',
        ),
      text: (selector) =>
        evaluate(
          "document.querySelector(" + JSON.stringify(selector) + ")?.innerText",
        ),
      count: (selector) =>
        evaluate(
          "document.querySelectorAll(" + JSON.stringify(selector) + ").length",
        ),
      disabled: (selector) =>
        evaluate(
          "document.querySelector(" + JSON.stringify(selector) + ")?.disabled",
        ),
      screenshot: async (path) => {
        const result = await call("Page.captureScreenshot", {
          format: "png",
          captureBeyondViewport: false,
        });
        writeFileSync(path, Buffer.from(result.data, "base64"), {
          mode: 0o600,
        });
      },
      click: async (selector) => {
        const rect = await evaluate(
          "(()=>{const e=document.querySelector(" +
            JSON.stringify(selector) +
            ');if(!e||e.disabled||document.visibilityState!=="visible"||!document.hasFocus())return null;const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()',
        );
        assert(rect, "Popup control must be available");
        await call("Input.dispatchMouseEvent", {
          type: "mousePressed",
          ...rect,
          button: "left",
          clickCount: 1,
        });
        await call("Input.dispatchMouseEvent", {
          type: "mouseReleased",
          ...rect,
          button: "left",
          clickCount: 1,
        });
      },
    };
  }
  async function openPopup() {
    const previous = new Set((await popupTargets()).map((target) => target.id));
    if (lastPopup) {
      previous.add(lastPopup.targetId);
      lastPopup.close();
      lastPopup = null;
    }
    await page.bringToFront();
    // Exactly one dismissal and one user action. Readiness is observed without
    // re-opening a popup or repeating a click/authorization request.
    input([{ key: "Escape" }], false);
    await eventually(
      async () =>
        !(await popupTargets()).some((target) => previous.has(target.id)),
      "Previous action popup did not close",
    );
    input([{ key: "Control_L+Shift_L+y" }], false);
    let target;
    await eventually(async () => {
      const targets = (await popupTargets()).filter(
        (target) => !previous.has(target.id),
      );
      if (targets.length > 1) throw Error("Action popup must be unique");
      target = targets[0];
      return !!target;
    }, "Action popup did not open");
    const popup = await attachPopup(target);
    lastPopup = popup;
    await eventually(
      async () => (await popup.ready()) === true,
      "Action popup is not visible and focused",
    );
    return popup;
  }
  async function blank() {
    assert(
      (await page.locator("#username").inputValue()) === "",
      "Unexpected username disclosure",
    );
    assert(
      (await page.locator("#password").inputValue()) === "",
      "Unexpected password disclosure",
    );
    assert(
      (await page.evaluate(() => window.submits)) === 0,
      "Automatic submission is forbidden",
    );
  }
  async function select(scenario) {
    phase(scenario + ":popup");
    const popup = await openPopup();
    await eventually(
      async () => (await popup.disabled("#refresh")) === false,
      "Paired popup not ready",
    );
    await popup.click("#refresh");
    await eventually(
      async () =>
        (await popup.count('#candidates [data-action="fill"]')) === 1 &&
        (await popup.disabled('#candidates [data-action="fill"]')) === false &&
        (await popup.disabled("#refresh")) === false,
      "Exact-origin candidate missing",
    );
    await popup.click('#candidates [data-action="fill"]');
    await eventually(
      async () => (await popup.text("#status"))?.includes("原生窗口核对"),
      "Native confirmation was not requested",
    );
    input([{ wait_label: "批准本次填充" }]);
    phase(scenario + ":native-confirmation");
    return popup;
  }
  phase("native-connect");
  let popup = await openPopup();
  phase("save-new:control");
  assert.equal(await popup.count("#save-new"), 1);
  await popup.click("#connect");
  phase("native-unlock");
  input([
    { click_label: "金库文件" },
    { text: fixture.Path },
    { click_label: "主密码" },
    { text: fixture.Password },
    { click_label: "Secret Key" },
    { text: fixture.Secret },
    { click_label: "解锁" },
  ]);
  phase("native-pair");
  input([{ click_label: "确认连接此扩展" }]);
  await blank();

  if (process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments") {
    await select("approved-fill");
    await blank(); // No field is released before native approval.
    if (process.env.LOCKLARK_TEST_FAILURE_STAGE === "after-pair")
      throw Error(fixtureCanaries(fixture).join("\n"));
    if (process.env.LOCKLARK_TEST_FAILURE_STAGE === "page-arguments") {
      phase("driver-arguments-failure");
      await page.evaluate(
        ([username, password]) => {
          document.querySelector("#username").value = username;
          document.querySelector("#password").value = password;
          throw Error("Controlled driver argument failure");
        },
        [fixture.SaveUsername, fixture.SaveValue],
      );
    }
    execFileSync(
      "import",
      [
        "-window",
        String(input([], true, true).window),
        join(diagnostics, "native-confirm.png"),
      ],
      { env },
    );
    phase("approved-fill:approve");
    input([{ click_label: "批准本次填充" }]);
    await eventually(
      async () =>
        (await page.locator("#password").inputValue()) === fixture.Value,
      "Approved fill did not reach the bound document",
    );
    assert(
      (await page.locator("#username").inputValue()) === fixture.Username,
      "Approved username mismatch",
    );
    assert(
      (await page.evaluate(() => window.submits)) === 0,
      "Fill submitted the form",
    );

    await page.locator("#username").fill("");
    await page.locator("#password").fill("");
    await select("rejected-fill");
    input([{ click_label: "拒绝本次填充" }]); // One actual native rejection.
    await delay(500);
    await blank();

    await select("navigated-fill");
    await page.goto(origin + "/different-document");
    await eventually(async () => {
      const control = input([], true, true).controls["批准本次填充"];
      return !control.enabled && !control.showing;
    }, "Navigated native intent remained available");
    await blank();

    await select("locked-fill");
    input([{ click_label: "立即锁定" }, { wait_label: "解锁" }]); // One actual native lock with approval pending.
    await delay(300);
    await blank();
    popup = await openPopup();
    await eventually(
      async () => await popup.disabled("#refresh"),
      "Locked host still allowed matching",
    );
    assert(
      (await popup.text("#status"))?.includes("锁定") ||
        (await popup.text("#status"))?.includes("断开"),
      "Lock status missing",
    );
  }
  const acceptanceDriver = {
    fixture,
    origin,
    phase,
    input,
    inspect: () => input([], true, true),
    observe: vaultObserver({ go, root, env, state }),
    captureNative: (kind) => {
      assert(
        browserScreenshotsAllowed(stage),
        "OTP stage forbids diagnostic screenshots",
      );
      const window = input([], true, true).window;
      assert(
        Number.isSafeInteger(window) && window > 0,
        "Strict native XID required",
      );
      execFileSync(
        "import",
        [
          "-window",
          String(window),
          join(diagnostics, "native-save-" + kind + ".png"),
        ],
        { env, stdio: "ignore" },
      );
    },
    openPopup,
    setLogin: async (username, password) => {
      await page.evaluate(
        ([username, password]) => {
          document.querySelector("#username").value = username;
          document.querySelector("#password").value = password;
        },
        [username, password],
      );
    },
    loginEquals: async (username, password) =>
      page.evaluate(
        ([username, password]) =>
          document.querySelector("#username").value === username &&
          document.querySelector("#password").value === password &&
          window.submits === 0,
        [username, password],
      ),
    navigate: (url) => page.goto(url),
    reconnect: async () => {
      let popup = await openPopup();
      await popup.click("#disconnect");
      input([], true, { wait_absent: true });
      popup = await openPopup();
      await popup.click("#connect");
      input([
        { click_label: "金库文件" },
        { text: fixture.Path },
        { click_label: "主密码" },
        { text: fixture.Password },
        { click_label: "Secret Key" },
        { text: fixture.Secret },
        { click_label: "解锁" },
      ]);
      input([{ click_label: "确认连接此扩展" }]);
    },
    root,
    state,
    env,
    pageEval: (fn, arg) => page.evaluate(fn, arg),
  };
  if (process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments")
    await acceptBrowserSave(acceptanceDriver);
  await acceptBrowserOTP(acceptanceDriver);
  assert(
    !logs.some((s) =>
      fixtureCanaries(fixture).some((value) => s.includes(value)),
    ),
    "Synthetic secret found in browser console output",
  );
  for (const line of logs) assertPrivateText(line, fixture);
  popup = await openPopup();
  await popup.click("#disconnect");
} catch {
  // Deliberately omit fixture files and exception/command bodies. The only
  // inspection text is the trusted popup's bounded status; native metadata is
  // a fixed control-name allowlist and never asks accessibility for values.
  const report = {
    stage,
    popup: { available: false },
    native: { available: false },
  };
  if (lastPopup) {
    try {
      report.popup = {
        available: true,
        status: popupStatusKind(await lastPopup.text("#status")),
        refreshDisabled: await lastPopup.disabled("#refresh"),
        candidates: await lastPopup.count("#candidates button"),
      };
    } catch {}
  }
  try {
    if (lastPopup && browserScreenshotsAllowed(stage)) {
      const text = String((await lastPopup.text("body")) || "");
      if (!privacyValues.some((value) => text.includes(value)))
        await lastPopup.screenshot(join(diagnostics, "failure-popup.png"));
    }
  } catch {}
  if (nativeInput) {
    try {
      report.native = { available: true, ...nativeInput([], true, true) };
      if (browserScreenshotsAllowed(stage)) {
        execFileSync(
          "import",
          [
            "-window",
            String(report.native.window),
            join(diagnostics, "failure-native.png"),
          ],
          { env, stdio: "ignore" },
        );
      }
    } catch {}
  }
  writeFileSync(
    join(diagnostics, "failure.json"),
    JSON.stringify(report, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.error("Native browser diagnostic: " + JSON.stringify(report));
  console.error("Synthetic diagnostic directory: " + diagnostics);
  throw Error("Native browser acceptance failed at " + stage);
} finally {
  if (browser) await browser.close();
  await new Promise((r) => server.close(r));
  if (observedFixture) {
    assertPrivateArtifacts(state, observedFixture);
    scanController(observedFixture);
  }
}
console.log(
  "PASS: real Chromium fill/save/update/OTP with native approval, cancellation, Unicode, and no synthetic secrets in console or persistent diagnostics",
);
console.log("Private synthetic artifacts: " + state);

if (observedFixture) scanController(observedFixture);

// External end-to-end acceptance: actual extension action, native messaging,
// MyGo UI input, and a controlled HTTPS document. No product test bypasses.
import { createRequire } from "node:module";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
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
  browserFixtureExecutable,
  fixtureCanaries,
  vaultObserver,
} from "./browser_save_acceptance.mjs";

import { acceptBrowserPasskey } from "./browser_passkey_acceptance.mjs";
import { acceptBrowserOTP, otpHTML } from "./browser_otp_acceptance.mjs";
import { acceptPopupVault } from "./browser_popup_vault_acceptance.mjs";
import {
  acceptSharedClipboard,
  prepareSharedEnvironment,
} from "./browser_shared_clipboard_acceptance.mjs";
import { acceptCheckoutFrames, checkoutTopHTML, checkoutCardHTML, checkoutRouteCase } from "./browser_checkout_acceptance.mjs";

const checkoutFrames = process.env.LOCKLARK_TEST_CHECKOUT_FRAMES === "1";

const scanController = captureControllerOutput();
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "web/package.json"));
const { chromium } = process.env.LOCKLARK_TEST_PLAYWRIGHT
  ? require(process.env.LOCKLARK_TEST_PLAYWRIGHT)
  : require("playwright");
const go = process.env.LOCKLARK_GO || "go";
const host = process.env.LOCKLARK_BROWSER_HOST;
const register = process.env.LOCKLARK_BROWSER_REGISTER
  ? resolve(process.env.LOCKLARK_BROWSER_REGISTER)
  : null;
const browserName = process.env.LOCKLARK_TEST_BROWSER === "edge" ? "edge" : "chromium";
const browserExecutable = process.env.LOCKLARK_TEST_BROWSER_EXECUTABLE;
if (browserName === "edge")
  assert(browserExecutable && browserExecutable.startsWith("/"), "Edge requires an explicit absolute executable path");
if (register)
  assert(existsSync(register), "LOCKLARK_BROWSER_REGISTER must name a built executable");
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
// Explicit external test mode only: the actual desktop app and the browser it
// hosts share a private HOME/TMPDIR/broker endpoint, never the real user's.
const sharedEnvironment =
  process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1"
    ? prepareSharedEnvironment(state, env)
    : null;
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
  if (text.includes("正在填充")) return "quick-filling";
  if (text.includes("个当前网站")) return "candidates-listed";
  if (text.includes("金库中有")) return "vault-listed";
  if (text.includes("Watchtower")) return "watchtower";
  if (text.includes("已填充") || text.includes("填充完成")) return "filled";
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
    checkoutFrames
      ? "subjectAltName=DNS:login.locklark.test,DNS:checkout.locklark.test,DNS:checkout.other.test"
      : "subjectAltName=DNS:login.locklark.test",
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
    if (checkoutFrames) {
      let route;
      try {
        route = checkoutRouteCase(req.url);
      } catch {
        res.statusCode = 404;
        res.end();
        return;
      }
      if (route.kind === "checkout") {
        res.end(checkoutTopHTML(server.address().port, route.options));
        return;
      }
      if (route.kind === "card") {
        res.end(checkoutCardHTML());
        return;
      }
    }
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
  // LOCKLARK_BROWSER_FIXTURE reuses one prebuilt fixture for this run, its
  // vault observers and the checkout step; otherwise the fixture is built.
  const fixtureExecutable = browserFixtureExecutable({ go, root, env, state });
  execFileSync(
    fixtureExecutable,
    [
      "-out",
      join(state, "vault"),
      "-origin",
      origin,
      ...(checkoutFrames ? ["-checkout-card"] : []),
    ],
    { cwd: root, env, stdio: "inherit" },
  );
  const fixture = JSON.parse(readFileSync(join(state, "vault/fixture.json")));
  observedFixture = fixture;
  privacyValues = fixtureCanaries(fixture);
  const profile = join(state, "profile");
  mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
  const registerArgs = [
    "--browser",
    browserName === "edge" ? "edge" : "chrome",
    "--host",
    resolve(host),
    "--output",
    join(profile, "NativeMessagingHosts/org.locklark.browser.json"),
  ];
  execFileSync(
    register || go,
    register ? registerArgs : ["run", "./cmd/locklark-browser-register", ...registerArgs],
    { cwd: root, env, stdio: "inherit" },
  );
  execFileSync(process.execPath, ["browser-extension/build.js", "chromium"], {
    cwd: root,
  });
  const extension = join(root, "browser-extension/dist/chromium");
  browser = await chromium.launchPersistentContext(profile, {
    headless: false,
    channel: browserName === "edge" ? undefined : "chromium",
    ...(browserExecutable ? { executablePath: browserExecutable } : {}),
    viewport: { width: 1100, height: 700 },
    ...(sharedEnvironment ? { env: sharedEnvironment } : {}),
    args: [
      "--no-sandbox",
      "--disable-extensions-except=" + extension,
      "--load-extension=" + extension,
      checkoutFrames
        ? "--host-resolver-rules=MAP login.locklark.test 127.0.0.1,MAP checkout.locklark.test 127.0.0.1,MAP checkout.other.test 127.0.0.1"
        : "--host-resolver-rules=MAP login.locklark.test 127.0.0.1",
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
      insertText: (text) => call("Input.insertText", { text }),
      attribute: (selector, name) => evaluate(
        "document.querySelector(" + JSON.stringify(selector) + ")?.getAttribute(" + JSON.stringify(name) + ")",
      ),
      setFile: async (selector, path) => {
        const { root } = await call("DOM.getDocument");
        const { nodeId } = await call("DOM.querySelector", { nodeId: root.nodeId, selector });
        assert(nodeId, "Attachment file control unavailable");
        await call("DOM.setFileInputFiles", { nodeId, files: [path] });
      },
      pressKey: async (key, keyCode) => {
        for (const type of ["keyDown", "keyUp"])
          await call("Input.dispatchKeyEvent", { type, key, code: key, windowsVirtualKeyCode: keyCode });
      },
      selectAll: async () => {
        for (const type of ["keyDown", "keyUp"])
          await call("Input.dispatchKeyEvent", {
            type, key: "a", code: "KeyA", modifiers: 2, windowsVirtualKeyCode: 65,
          });
      },
      targetId: target.id,
      close: () => ws.close(),
      dismiss: async () => {
        await call("Page.close").catch(() => {});
        ws.close();
      },
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
      visible: (selector) => evaluate(
        "!!document.querySelector(" + JSON.stringify(selector) + ")?.getClientRects().length",
      ),
      value: (selector) => evaluate(
        "document.querySelector(" + JSON.stringify(selector) + ")?.value ?? null",
      ),
      selectOption: async (selector, value) => {
        const options = await evaluate(
          "Array.from(document.querySelector(" + JSON.stringify(selector) + ")?.options || []).map(option => option.value)",
        );
        const index = options.indexOf(value);
        assert(index > 0, "Exact popup option unavailable");
        const id = selector.startsWith("#") ? selector.slice(1) : "";
        const labelSelector = id ? 'label[for="' + id + '"]' : selector;
        const { root } = await call("DOM.getDocument");
        const label = await call("DOM.querySelector", { nodeId: root.nodeId, selector: labelSelector });
        const { nodeId } = label.nodeId ? label :
          await call("DOM.querySelector", { nodeId: root.nodeId, selector });
        assert(nodeId, "Popup select unavailable");
        const { model } = await call("DOM.getBoxModel", { nodeId });
        const x = (model.content[0] + model.content[4]) / 2;
        const y = (model.content[1] + model.content[5]) / 2;
        for (const type of ["mousePressed", "mouseReleased"])
          await call("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
        await eventually(async () =>
          await evaluate("document.activeElement === document.querySelector(" + JSON.stringify(selector) + ")"),
        "Popup select focus missing");
        const key = async (name, code, keyCode) => {
          for (const type of ["keyDown", "keyUp"])
            await call("Input.dispatchKeyEvent", { type, key: name, code, windowsVirtualKeyCode: keyCode });
        };
        await key("Home", "Home", 36);
        for (let step = 0; step < index; step++) await key("ArrowDown", "ArrowDown", 40);
        await eventually(async () =>
          (await evaluate("document.querySelector(" + JSON.stringify(selector) + ")?.value")) === value,
        "Physical popup select did not apply the exact option");
      },
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
            ');if(!e||e.disabled||document.visibilityState!=="visible"||!document.hasFocus())return null;e.scrollIntoView({block:"center",inline:"nearest"});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,hit=document.elementFromPoint(x,y);if(!hit||(hit!==e&&!e.contains(hit)))return null;return {x,y};})()',
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
      await lastPopup.dismiss();
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
  if (process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1") {
    // Explicit external test mode: the actual desktop app is the shared
    // broker and sole clipboard owner; the extension uses its normal port.
    await acceptSharedClipboard({
      fixture,
      root,
      state,
      env: sharedEnvironment,
      openPopup,
      eventually,
      delay,
      phase,
    });
  } else {
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
  if (checkoutFrames) {
    await page.goto(origin + "/checkout");
    await acceptCheckoutFrames({ page, origin, input, fixture, openPopup, phase, eventually });
    popup = await openPopup();
    await popup.click("#disconnect");
  } else {
  if (process.env.LOCKLARK_TEST_POPUP_VAULT) {
    const downloadDirectory = join(state, "attachment-downloads");
    mkdirSync(downloadDirectory, { recursive: true });
    const fileName = "popup-attachment.bin";
    const sourcePath = join(state, fileName);
    const content = Buffer.alloc(2 << 20);
    for (let index = 0; index < content.length; index++) content[index] = index % 251;
    writeFileSync(sourcePath, content, { mode: 0o600 });
    const digest = createHash("sha256").update(content).digest("hex");
    content.fill(0);
    const downloadSession = await browser.newCDPSession(page);
    await downloadSession.send("Browser.setDownloadBehavior", {
      behavior: "allow", downloadPath: downloadDirectory,
    });
    await acceptPopupVault({
      openPopup, fixture, phase, eventually,
      observe: vaultObserver({ go, root, env, state }),
      attachment: {
        sourcePath, fileName,
        downloaded: () => {
          const path = join(downloadDirectory, fileName);
          return existsSync(path) && createHash("sha256").update(readFileSync(path)).digest("hex") === digest;
        },
      },
    });
    await downloadSession.detach();
  }
  await blank();
  popup = await openPopup();
  if (await popup.count(".site-preferences:not([open]) > summary"))
    await popup.click(".site-preferences > summary");
  await popup.click("#auto-login"); // Existing manual-mode scenarios intentionally disable auto-submit.

  if (
    !process.env.LOCKLARK_TEST_BROWSER_PARITY &&
    process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments"
  ) {
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
  if (!process.env.LOCKLARK_TEST_BROWSER_PARITY) {
    if (process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments")
      await acceptBrowserSave(acceptanceDriver);
    await acceptBrowserOTP(acceptanceDriver);
  }
  await acceptBrowserPasskey({
    page,
    browser,
    origin,
    input,
    fixture,
    openPopup,
    eventually,
    phase,
    observe: acceptanceDriver.observe,
    reconnect: acceptanceDriver.reconnect,
  });
  assert(
    !logs.some((s) =>
      fixtureCanaries(fixture).some((value) => s.includes(value)),
    ),
    "Synthetic secret found in browser console output",
  );
  for (const line of logs) assertPrivateText(line, fixture);
  popup = await openPopup();
  await popup.click("#disconnect");
  }
  }
} catch (error) {
  // Deliberately omit fixture files and exception/command bodies. The only
  // inspection text is the trusted popup's bounded status; native metadata is
  // a fixed control-name allowlist and never asks accessibility for values.
  const safeReasons = [
    "Action popup did not open",
    "Previous action popup did not close",
    "Action popup is not visible and focused",
    "AbortSignal not honored",
    "Popup CDP failed",
    "Popup CDP closed",
    "Popup CDP timed out",
    "Popup control must be available",
    "Inline control unavailable",
    "Synthetic secret found in browser console output",
    "Popup inspection failed",
    "Popup CDP connection failed",
    "Popup CDP connection timed out",
    "Action popup must be unique",
    "Shared native clipboard acceptance failed",
    "Shared clipboard mode must be requested explicitly",
    "Shared desktop host must be an absolute executable path",
    "Synthetic fixture vault path is required",
    "Synthetic fixture password is required",
    "Checkout card filter unavailable",
    "Synthetic checkout card missing from the vault",
    "Checkout card revision mismatch",
    "Checkout card category mismatch",
    "Synthetic checkout card detail did not open",
    "Checkout form picker control unavailable",
    "Checkout form picker label missing",
    "Checkout origin picker missing",
    "Checkout origin picker is incomplete",
    "Expected exactly one explicit checkout child origin",
    "Checkout popup is not connected",
    "Checkout card frame did not load",
    "Top checkout card fields must be visible",
    "Checkout card frame fields must be visible",
    "Approved checkout fill did not reach the child frame",
    "Checkout picker cancel did not close",
    "Checkout native approval must not be available",
    "Cross-site checkout forms must stay blank",
    "Cross-site checkout refusal did not finish",
    "Cross-site checkout received a value without approval",
    "Excluded checkout origin must not be auto-selected",
    "Excluded cross-site checkout wrote a value",
    "Checkout sandboxed child must be excluded from the picker",
    "Sandboxed checkout picker request did not finish",
    "Sandboxed checkout forms must stay blank",
    "Sandboxed checkout received a value without approval",
    "Checkout child document identity missing",
    "Checkout child document was not replaced",
    "Changed checkout document did not finish",
    "Changed checkout document received a value",
  ];
  const report = {
    reason: safeReasons.includes(error?.message)
      ? error.message
      : "unclassified acceptance failure",
    frames:
      typeof error?.stack === "string"
        ? error.stack.match(/browser_(?:native|checkout|passkey_management|conditional_passkey|passkey)_acceptance\.mjs:[0-9]+:[0-9]+/g)
        : [],
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
  process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1"
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} extension shared Locklark desktop native clipboard lease, private OS reads, foreign-owner TTL preservation, lock clearing and hidden-popup prepare cancellation`
    : checkoutFrames
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} checkout same-origin child approval (profile review) and picker cancellation, cross-origin approval/refusal, cross-site, opaque sandbox and changed-document rejection`
    : process.env.LOCKLARK_TEST_BROWSER_PARITY
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} quick pairing, inline fill, automatic sign-in, Passkey creation/assertion, relying-party signature verification and abort`
    : `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} fill/save/update/OTP and Passkey with native approval and private diagnostics`,
);
console.log("Private synthetic artifacts: " + state);

if (observedFixture) scanController(observedFixture);

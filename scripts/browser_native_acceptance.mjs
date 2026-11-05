// External end-to-end acceptance: actual extension action, native messaging,
// MyGo UI input, and a controlled HTTPS document. No product test bypasses.
import { createRequire } from "node:module";
import { readFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "node:https";
import { createHash, X509Certificate } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

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
const state = mkdtempSync("/tmp/locklark-browser-acceptance-");
const env = { ...process.env, GOTOOLCHAIN: "go1.27.3" };
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
  (_req, res) => {
    res.setHeader("Content-Type", "text/html");
    res.end(html);
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
  function input(actions, native = true) {
    const request = native
      ? { title: "Locklark · 浏览器原生确认", actions }
      : { title_prefix: "Locklark acceptance", actions };
    return JSON.parse(
      execFileSync("python3", [join(root, "scripts/browser_native_x11.py")], {
        input: JSON.stringify(request),
        env,
      }).toString(),
    );
  }
  // Chrome action popups are real page targets but are not always surfaced by
  // Playwright Context.pages(). Attach to that popup through local test CDP.
  async function attachPopup() {
    const port = readFileSync(
      join(profile, "DevToolsActivePort"),
      "utf8",
    ).split("\n")[0];
    const targets = await (
      await fetch("http://127.0.0.1:" + port + "/json/list")
    ).json();
    const target = targets.find(
      (t) =>
        t.url ===
        "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/popup.html",
    );
    if (!target) return null;
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
      ws.addEventListener("open", resolve, { once: true });
      ws.addEventListener("error", reject, { once: true });
    });
    const call = (method, params = {}) =>
      new Promise((resolve, reject) => {
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
      click: async (selector) => {
        const rect = await evaluate(
          "(()=>{const e=document.querySelector(" +
            JSON.stringify(selector) +
            ");if(!e||e.disabled)return null;const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};})()",
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
    await page.bringToFront();
    input([{ key: "Control_L+Shift_L+y" }], false);
    let popup;
    await eventually(
      async () => !!(popup = await attachPopup()),
      "Action popup did not open",
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
  async function select() {
    const popup = await openPopup();
    await eventually(
      async () => !(await popup.disabled("#refresh")),
      "Paired popup not ready",
    );
    await popup.click("#refresh");
    await eventually(
      async () => (await popup.count("#candidates button")) === 1,
      "Exact-origin candidate missing",
    );
    await popup.click("#candidates button");
    await eventually(
      async () => (await popup.text("#status"))?.includes("原生窗口核对"),
      "Native confirmation was not requested",
    );
    input([]);
    return popup;
  }
  let popup = await openPopup();
  await popup.click("#connect");
  await delay(800);
  input([
    { click: [240, 184] },
    { text: fixture.Path },
    { click: [240, 278] },
    { text: fixture.Password },
    { click: [240, 323] },
    { text: fixture.Secret },
    { click: [240, 370] },
  ]);
  await delay(800);
  input([{ click: [200, 260] }]); // Actual native pairing confirmation.
  await blank();

  await select();
  await blank(); // No field is released before native approval.
  execFileSync(
    "import",
    ["-window", "root", join(state, "native-confirm.png")],
    { env },
  );
  input([{ click: [200, 506] }]);
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
  await select();
  input([{ click: [200, 556] }]); // Native rejection.
  await delay(500);
  await blank();

  await select();
  await page.goto(origin + "/different-document");
  await delay(500);
  input([{ click: [200, 506] }]); // Any former button must no longer approve.
  await delay(300);
  await blank();

  await select();
  input([{ click: [935, 42] }]); // Native lock with approval pending.
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
  assert(
    !logs.some(
      (s) =>
        s.includes(fixture.Value) ||
        s.includes(fixture.Password) ||
        s.includes(fixture.Secret),
    ),
    "Synthetic secret found in browser console output",
  );
  await popup.click("#disconnect");
  console.log(
    "PASS: real Chromium action → native messaging → MyGo unlock/pair/approve → HTTPS fill; rejection, document navigation, native lock, no preapproval values, no autosubmit, no secret console output",
  );
  console.log("Synthetic acceptance artifacts: " + state);
} finally {
  if (browser) await browser.close();
  await new Promise((r) => server.close(r));
}

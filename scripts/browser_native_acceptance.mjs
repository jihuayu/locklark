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
// Explicit opt-in: a QuickFill=false action row opens one persistent route tab
// and its native per-operation approval, instead of the long default journeys.
const routeDetailRead = process.env.LOCKLARK_TEST_ROUTE_DETAIL_READ === "1";
// Route pages are the fixed extension popup document plus exactly one 64-hex
// token fragment. Action popups are that same document with no fragment.
const ROUTE_PAGE = /^chrome-extension:\/\/[a-p]{32}\/popup\.html#route=[a-f0-9]{64}$/;
const ACTION_POPUP = /^chrome-extension:\/\/[a-p]{32}\/popup\.html$/;
// The route checkpoint is the only requested journey in this mode, so every
// mode that would change what pairing, fill or checkout mean is refused before
// anything is launched.
function routeModeCompatible() {
  const off = (name) => !process.env[name];
  return (
    off("LOCKLARK_TEST_SHARED_CLIPBOARD") &&
    off("LOCKLARK_TEST_POPUP_VAULT") &&
    off("LOCKLARK_TEST_CHECKOUT_FRAMES") &&
    off("LOCKLARK_TEST_BROWSER_PARITY") &&
    off("LOCKLARK_TEST_FAILURE_STAGE") &&
    (process.env.LOCKLARK_TEST_BROWSER === undefined ||
      process.env.LOCKLARK_TEST_BROWSER === "chromium")
  );
}
const POPUP_CLOSED = ["Popup closed", "Popup CDP closed", "Popup CDP timed out"];
function popupClosed(error) {
  return POPUP_CLOSED.includes(error?.message);
}

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
if (routeDetailRead) {
  assert(routeModeCompatible(), "Route detail mode is incompatible");
  assert(browserName === "chromium", "Route detail mode requires Chromium");
}
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
  lastRouteObservation = null,
  routeAfterPopupClose = null,
  routeTargetAfterPopupClose = null,
  routeObservationHistory = [],
  nativeInput = null;
// Diagnostics only: keep at most ROUTE_HISTORY_LIMIT sanitized observations,
// appended only when one of the four fields actually changes, so a failure
// can show whether the route page ever reached locked/vault/detail first.
const ROUTE_HISTORY_LIMIT = 8;
function recordRouteObservation(observation) {
  const last = routeObservationHistory[routeObservationHistory.length - 1];
  if (
    last &&
    last.view === observation.view &&
    last.detailShown === observation.detailShown &&
    last.titleMatchesFixture === observation.titleMatchesFixture &&
    last.statusKind === observation.statusKind
  )
    return;
  routeObservationHistory = [
    ...routeObservationHistory,
    observation,
  ].slice(-ROUTE_HISTORY_LIMIT);
}
// Route lifecycle diagnostics. From the moment the exact route target is
// found, one best-effort browser-CDP websocket to that same target records
// which main-frame lifecycle events its exact target received, so a
// route-detail failure can tell "the main frame was replaced or detached" (a
// reload or navigation) apart from "the frame stayed and only the UI
// differed". Page events are accepted only when they arrive on the session id
// this observer generated (a page can never supply that session id) while its
// enable reply (its own fixed request id) ends event intake; the root-target
// session is never attached, and child sessions/OOPIFs are released at once
// and never counted. Frame, target, document and loader ids
// stay inside this closure and are never copied into the retained record, no
// raw protocol payload is retained, and every failure is swallowed. A detached
// main frame can no longer be followed, so detach is terminal.
const ROUTE_LIFECYCLE_EVENTS = [
  "frameStartedLoading",
  "frameStoppedLoading",
  "documentUpdated",
  "navigatedWithinDocument",
  "detached",
];
const ROUTE_LIFECYCLE_LIMIT = 16;
let routeLifecycleObservation = null,
  routeLifecycleSocket = null;
// Fixed allowlisted shape only: unknown events, extra keys and non-boolean
// values are dropped, so malformed input can never widen what is reported.
function sanitizeRouteLifecycle(value) {
  const counts = value?.eventCounts;
  return {
    pageOpened: value?.pageOpened === true,
    mainFrame: value?.mainFrame === true,
    loadingStarted: value?.loadingStarted === true,
    loadingStopped: value?.loadingStopped === true,
    documentReplaced: value?.documentReplaced === true,
    sameDocumentNavigation: value?.sameDocumentNavigation === true,
    mainFrameDetached: value?.mainFrameDetached === true,
    eventCounts: Object.fromEntries(
      ROUTE_LIFECYCLE_EVENTS.map((kind) => [
        kind,
        Number.isInteger(counts?.[kind]) && counts[kind] >= 0
          ? Math.min(counts[kind], ROUTE_LIFECYCLE_LIMIT)
          : 0,
      ]),
    ),
  };
}
// One fixed event kind; the retained record never exceeds ROUTE_LIFECYCLE_LIMIT
// counted events in total.
function recordRouteLifecycle(kind) {
  const current = sanitizeRouteLifecycle(routeLifecycleObservation);
  if (!ROUTE_LIFECYCLE_EVENTS.includes(kind)) return;
  const total = Object.values(current.eventCounts).reduce(
    (sum, count) => sum + count,
    0,
  );
  if (total >= ROUTE_LIFECYCLE_LIMIT) return;
  routeLifecycleObservation = sanitizeRouteLifecycle({
    ...current,
    pageOpened: true,
    mainFrame: current.mainFrame || kind === "frameStartedLoading",
    loadingStarted: current.loadingStarted || kind === "frameStartedLoading",
    loadingStopped: current.loadingStopped || kind === "frameStoppedLoading",
    documentReplaced: current.documentReplaced || kind === "documentUpdated",
    sameDocumentNavigation:
      current.sameDocumentNavigation || kind === "navigatedWithinDocument",
    mainFrameDetached: current.mainFrameDetached || kind === "detached",
    eventCounts: { ...current.eventCounts, [kind]: current.eventCounts[kind] + 1 },
  });
}
function closeRouteLifecycle() {
  try {
    routeLifecycleSocket?.close();
  } catch {}
  routeLifecycleSocket = null;
}
// Best effort: any connection, enabling or event failure leaves the record as
// it was and cannot reach any caller. Only two fixed commands go out on a
// locally generated session id, never injected page code or runtime
// messaging; only the transient session id and child session ids are read
// from replies. Once Page.enable is answered the record exists and the socket
// closes on the next turn.
function observeRouteLifecycle(target) {
  try {
    if (typeof target?.webSocketDebuggerUrl !== "string") return;
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    routeLifecycleSocket = ws;
    const session = "route-lifecycle-" + Math.random().toString(36).slice(2);
    let onTargets = false;
    const send = (id, method, params, sessionId) => {
      try {
        ws.send(JSON.stringify({ id, method, params, sessionId }));
      } catch {}
    };
    const onMessage = (event) => {
      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      if (message?.method === "Target.attachedToTarget") {
        // A child session (e.g. an OOPIF) is released at once, never counted.
        const child = message.params?.sessionId;
        if (onTargets && typeof child === "string")
          send(100, "Runtime.runIfWaitingForDebugger", {}, child);
        return;
      }
      if (message?.id === 1) {
        // The auto-attach reply: the root session is never enabled, so only
        // the dedicated observer session can yield page lifecycle events.
        onTargets = true;
        send(2, "Page.enable", {}, session);
        return;
      }
      // Command replies carry a null session id here, so the enable reply is
      // matched by its own fixed request id; page events by the session.
      if (message?.id === 2) {
        routeLifecycleObservation = {
          ...sanitizeRouteLifecycle(routeLifecycleObservation),
          pageOpened: true,
        };
        setTimeout(() => {
          try {
            if (routeLifecycleSocket === ws) routeLifecycleSocket = null;
            ws.close();
          } catch {}
        }, 0);
        return;
      }
      if (message?.sessionId !== session) return;
      const kind = String(message.method || "");
      if (!kind.startsWith("Page.")) return;
      recordRouteLifecycle(kind.slice("Page.".length));
      if (kind === "Page.frameDetached") closeRouteLifecycle();
    };
    ws.addEventListener("message", onMessage);
    ws.addEventListener("error", () => {});
    ws.addEventListener("close", () => {
      ws.removeEventListener("message", onMessage);
      if (routeLifecycleSocket === ws) routeLifecycleSocket = null;
    });
    ws.addEventListener("open", () => {
      // `root: null` returns a fresh session that is never enabled; page
      // events can therefore only arrive on the observer's own session.
      send(1, "Target.setAutoAttach", {
        autoAttach: true,
        waitForDebuggerOnStart: false,
        flatten: true,
      });
    });
  } catch {}
}
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
// Read-only observation of the attached route page for the failure report.
// Only fixed enums and booleans ever leave the page: never text, titles,
// field values, URLs, tokens, ids or hidden application state.
const ROUTE_VIEWS = ["locked", "vault", "detail", "closed", "editor"];
const ROUTE_STATUS_KINDS = ["claim-failed", "route-revoked", "other"];
const ROUTE_CLAIM_FAILED_STATUS = "无法打开此条目";
const ROUTE_REVOKED_STATUS = "条目已失效，请重新从金库打开";
function sanitizeRouteObservation(value) {
  return {
    view: ROUTE_VIEWS.includes(value?.view) ? value.view : "other",
    detailShown: value?.detailShown === true,
    titleMatchesFixture: value?.titleMatchesFixture === true,
    statusKind: ROUTE_STATUS_KINDS.includes(value?.statusKind)
      ? value.statusKind
      : "other",
  };
}
// Visible DOM only: body[data-view], the detail section, its heading and the
// status line. The fixture comparison and the status categorisation happen
// inside the page; only their fixed outcomes are returned.
function routeStateProbe(title) {
  return `(()=>{
    const view=(document.body&&document.body.dataset.view)||'';
    const detail=document.querySelector('#detail-view');
    const heading=document.querySelector('#detail-title');
    const status=document.querySelector('#status');
    const statusText=status?String(status.textContent||'').trim():'';
    return {
      view:${JSON.stringify(ROUTE_VIEWS)}.includes(view)?view:'other',
      detailShown:!!detail&&!detail.hidden,
      titleMatchesFixture:!!heading&&String(heading.textContent||'')===${JSON.stringify(title)},
      statusKind:statusText===${JSON.stringify(ROUTE_CLAIM_FAILED_STATUS)}?'claim-failed':statusText===${JSON.stringify(ROUTE_REVOKED_STATUS)}?'route-revoked':'other'
    };
  })()`;
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
    const closed = (error) => popupClosed(error) || ws.readyState !== WebSocket.OPEN;
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
      // Real evaluation in this exact popup document, used for a DOM-dispatched
      // event that is deliberately not a browser input gesture.
      evaluate,
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
      ready: async () => {
        try {
          return await evaluate(
            'document.readyState === "complete" && document.visibilityState === "visible" && document.hasFocus() && document.querySelector("#status")?.textContent.length > 0',
          );
        } catch (error) {
          if (closed(error)) return false;
          throw error;
        }
      },
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
      // Chrome closes the action popup itself after a request that needs the
      // native window, so dismissing an already-closed target is expected.
      await lastPopup.dismiss().catch(() => {});
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
  // Rendered vault rows only: identity, title and hit-test visibility. Field
  // values, revisions and item URLs are never read here.
  const VAULT_ROWS =
    "[...document.querySelectorAll('#vault-list .vault-item')]" +
    ".map(row=>({id:row.dataset.itemId||''," +
    "title:row.querySelector('.vault-item-title')?.textContent??null," +
    "visible:row.getClientRects().length>0}))";
  // The route detail surface as rendered: view, visible title, concealed
  // password control, and one boolean secret-substring check. Page text,
  // values, identity, URL and token never leave the page.
  function routeSurfaceProbe(title, password) {
    return `(()=>{
      const detail=document.querySelector('#detail-view');
      const heading=document.querySelector('#detail-title');
      const fields=document.querySelector('#detail-fields');
      const values=fields?[...fields.querySelectorAll('.field-value')]:[];
      const concealed=!!(
        fields?.querySelector('[data-field-type="password"],[data-field-type="concealed"],.concealed,[data-concealed="true"],input[type="password"]') ||
        values.some(value=>/^[\u2022\u25cf*]+$/.test(String(value.textContent||'').trim()))
      );
      return {
        view:document.body?.dataset?.view||'',
        detailShown:!!detail&&!detail.hidden,
        title:heading?heading.textContent:null,
        concealed,
        passwordRendered:document.body?String(document.body.innerText).includes(${JSON.stringify(password)}):true
      };
    })()`;
  }
  // Fixed findings only; never text, ids, revisions, URLs or tokens.
  function verifyRouteSurface(surface, title) {
    if (surface?.detailShown !== true) return "route-detail-view-missing";
    if (surface.view !== "detail") return "route-detail-view-missing";
    if (surface.title !== title) return "route-detail-title-mismatch";
    if (surface.concealed !== true) return "route-concealed-control-missing";
    if (surface.passwordRendered !== false) return "route-password-rendered";
    return "";
  }
  async function acceptRouteDetailRead(driver) {
    const {
      browser: context,
      fixture,
      phase: mark,
      eventually: wait,
      openPopup: openActionPopup,
      extensionTargets: targets,
      attachRoute: attach,
    } = driver;
    assert(
      typeof fixture.SeedID === "string" && /^[a-f0-9]{32}$/.test(fixture.SeedID),
      "Synthetic seed item identity missing",
    );
    assert(
      typeof fixture.Title === "string" && fixture.Title.length > 0,
      "Synthetic fixture title missing",
    );
    try {
    mark("route:popup");
    const action = await openActionPopup();
    // The ready control is the vault search field, not the refresh match.
    // Waiting on #refresh here would consume the wait before the ordinary
    // match step below, even though the popup already rendered vault status.
    await wait(
      async () => (await action.disabled("#search-input")) === false,
      "Paired popup not ready",
    );
    // The worker binds a route only to a source document captured by the
    // ordinary match the user starts from this popup. One physical refresh
    // click is that user action; its rendered status proves the capture.
    mark("route:match");
    await action.click("#refresh");
    await wait(
      async () =>
        String(await action.text("#status")).includes("个当前网站") &&
        (await action.disabled("#refresh")) === false,
      "Exact-origin match missing",
    );
    mark("route:vault-open");
    await action.click('#filter-tabs [data-filter="all"]');
    await wait(
      async () =>
        (await action.evaluate("document.readyState")) === "complete" &&
        (await action.count("#vault-list .vault-item")) > 0,
      "Vault rows missing",
    );
    mark("route:exact-row");
    // Exactly one rendered vault row, the fixture's seed item, its title.
    const rows = await action.evaluate(VAULT_ROWS);
    assert(
      Array.isArray(rows) &&
        rows.length === 1 &&
        rows[0].id === fixture.SeedID &&
        rows[0].title === fixture.Title &&
        rows[0].visible === true,
      "Exact synthetic vault row missing",
    );
    const rowSelector =
      '#vault-list .vault-item[data-item-id="' + fixture.SeedID + '"]';
    const before = new Set((await targets()).map((target) => target.id));
    const pagesBefore = new Set(
      context
        .pages()
        .filter((entry) => !/^chrome-extension:\/\//.test(entry.url())),
    );
    mark("route:row-click");
    // Exactly one real CDP mouse press/release through the popup wrapper.
    await action.click(rowSelector);
    mark("route:page-opened");
    let opened;
    await wait(async () => {
      const candidates = (await targets()).filter(
        (target) =>
          !before.has(target.id) &&
          ROUTE_PAGE.test(target.url) &&
          (target.type === "page" || target.type === "tab"),
      );
      if (candidates.length > 1) throw Error("Route page must be unique");
      opened = candidates[0];
      return !!opened;
    }, "Route page did not open");
    const routeTarget = opened.id;
    assert.equal(
      (await targets()).filter((target) => ROUTE_PAGE.test(target.url)).length,
      1,
      "Route page must be unique",
    );
    // Diagnostics only: from this exact target's discovery on, keep a bounded
    // main-frame lifecycle record across the popup-close waits and the route
    // attachment. It adds no wait, gate or behaviour, and any failure stays
    // swallowed; the socket is closed in this checkpoint's finally path.
    observeRouteLifecycle(opened);
    // Diagnostics only: take one best-effort visible-DOM snapshot right after
    // the exact route target is found and verified, before any popup-closed
    // wait, so a later failure can distinguish a route that was still locked
    // from one that was already closed at first sight. It uses a short-lived
    // CDP connection with no added wait or timeout, and any failure is
    // swallowed so no acceptance step can fail or skip because of it.
    try {
      const initial = await attach(opened);
      try {
        lastRouteObservation = sanitizeRouteObservation(
          await initial.evaluate(routeStateProbe(fixture.Title)),
        );
        recordRouteObservation(lastRouteObservation);
      } finally {
        try {
          await initial.close();
        } catch {}
      }
    } catch {}
    mark("route:popup-closed");
    await wait(async () => !(await action.ready()), "Action popup stayed open");
    await wait(
      async () =>
        !(await targets()).some((target) => ACTION_POPUP.test(target.url)),
      "Action popup target stayed open",
    );
    // Diagnostics only: one best-effort visible-DOM snapshot of the same exact
    // route target right after both popup-closed waits, before the pagesAfter
    // check and the route attachment, so a route-detail failure can tell
    // whether the page was still locked or already closed at that point. No
    // added wait or timeout; any failure is swallowed so no acceptance step
    // can fail or skip because of it. It is stored separately from
    // lastRouteObservation and the bounded history.
    try {
      const afterClose = await attach(opened);
      try {
        routeAfterPopupClose = sanitizeRouteObservation(
          await afterClose.evaluate(routeStateProbe(fixture.Title)),
        );
      } finally {
        try {
          await afterClose.close();
        } catch {}
      }
    } catch {}
    // Diagnostics only: the same targets() list, read once, answers whether
    // the exact captured route target still exists and still carries the route
    // URL at this checkpoint. Only these two fixed booleans are kept; any
    // failure leaves the checkpoint absent and cannot affect acceptance.
    try {
      const live = await targets();
      const route = live.find((target) => target.id === routeTarget);
      routeTargetAfterPopupClose = {
        routeTargetExists: !!route,
        routeTargetStillRoute: !!route && ROUTE_PAGE.test(route.url),
      };
    } catch {}
    // The route tab is the only new browser page: every non-extension page
    // present now must be one of the controlled-login pages seen before.
    const pagesAfter = context
      .pages()
      .filter((entry) => !/^chrome-extension:\/\//.test(entry.url()));
    assert(
      pagesAfter.length === pagesBefore.size &&
        pagesAfter.every((entry) => pagesBefore.has(entry)),
      "Unexpected page opened",
    );
    mark("route:attached");
    const route = await attach(opened);
    try {
      await wait(
        async () =>
          (await route.evaluate("document.readyState")) === "complete",
        "Route page did not load",
      );
      // The route claim starts the same native V2 item-get review the action
      // popup would have used, so the real per-operation approval appears only
      // after this tab exists. A missing window/label is retried inside the
      // bounded wait; no inspect output is retained or logged.
      mark("route:native-label");
      // Read-only visible-DOM observation refreshed on every bounded attempt,
      // so a failure can say whether this page never left startup, closed
      // after a rejected claim, or reached its detail. It never reads a
      // runtime message and retains no text, value, URL, token or hidden
      // state; it cannot make the wait pass.
      const observeRouteState = async () => {
        try {
          lastRouteObservation = sanitizeRouteObservation(
            await route.evaluate(routeStateProbe(fixture.Title)),
          );
          recordRouteObservation(lastRouteObservation);
        } catch {}
      };
      const approveLabel = async () => {
        await observeRouteState();
        try {
          const control = input([], true, true).controls?.["批准本次操作"];
          return control?.present === true && control?.showing === true;
        } catch {
          return false;
        }
      };
      await wait(approveLabel, "Native route approval label missing");
      assert.equal(
        (await targets()).filter((target) => ROUTE_PAGE.test(target.url))
          .length,
        1,
        "Route page must be unique",
      );
      mark("route:native-approve");
      // Exactly one real X11 pointer click on the native allowlisted label.
      input([{ click_label: "批准本次操作" }]);
      mark("route:approved");
      let finding = "";
      const verified = async () => {
        const live = await targets();
        const routes = live.filter((target) => ROUTE_PAGE.test(target.url));
        assert(
          routes.length === 1 && routes[0].id === routeTarget,
          "Route target was replaced",
        );
        assert(
          !live.some((target) => ACTION_POPUP.test(target.url)),
          "Action popup reopened",
        );
        finding = verifyRouteSurface(
          await route.evaluate(
            routeSurfaceProbe(fixture.Title, fixture.Value),
          ),
          fixture.Title,
        );
        return finding === "";
      };
      try {
        await wait(verified, "Route detail did not survive native approval");
      } catch (error) {
        // Only the fixed allowlisted finding id leaves this checkpoint.
        if (finding) throw Error(finding);
        throw error;
      }
      mark("route:verified");
      // The same target id is still the one route page, after approval.
      const routes = (await targets()).filter((target) =>
        ROUTE_PAGE.test(target.url),
      );
      assert.equal(routes.length, 1, "Route target was replaced");
      assert.equal(routes[0].id, routeTarget, "Route target was replaced");
      // The same console canary checks the ordinary native journeys apply
      // before this checkpoint may claim a pass. Logs are never printed.
      assert(
        !logs.some((s) =>
          fixtureCanaries(fixture).some((value) => s.includes(value)),
        ),
        "Synthetic secret found in browser console output",
      );
      for (const line of logs) assertPrivateText(line, fixture);
      console.log(
        "PASS: real popup exact row opened one persistent route tab; native approval kept the same tab's detail without revealing values",
      );
    } finally {
      try {
        await route.close();
      } catch {}
    }
    } finally {
      // Diagnostics only: the lifecycle socket never outlives this checkpoint.
      closeRouteLifecycle();
    }
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
  // The popup-vault run pairs with the real quick-fill choice; no host status
  // text is observable in the native accessibility tree, so the successful
  // popup-vault commits below are the only pairing proof needed.
  input([
    {
      click_label:
        process.env.LOCKLARK_TEST_POPUP_VAULT === "1" || checkoutFrames
          ? "连接并启用快捷填充"
          : "确认连接此扩展",
    },
  ]);
  if (routeDetailRead) {
    // The route checkpoint reuses the existing action-popup CDP wrapper and
    // the real native X11 helper. It never navigates, messages the worker or
    // injects a page hook: only the rendered popup/route UI is observed.
    async function extensionTargets() {
      const port = readFileSync(
        join(profile, "DevToolsActivePort"),
        "utf8",
      ).split("\n")[0];
      const targets = await (
        await fetch("http://127.0.0.1:" + port + "/json/list")
      ).json();
      return targets.filter((target) =>
        target.url.startsWith(
          "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/popup.html",
        ),
      );
    }
    async function attachRoute(target) {
      const route = await attachPopup(target);
      return {
        evaluate: (expression) => route.evaluate(expression),
        close: () => route.close(),
      };
    }
    await acceptRouteDetailRead({
      browser,
      input,
      fixture,
      phase,
      eventually,
      openPopup,
      extensionTargets,
      attachRoute,
    });
  } else if (checkoutFrames) {
    await page.goto(origin + "/checkout");
    const checkout = await acceptCheckoutFrames({ page, origin, input, fixture, openPopup, phase, eventually });
    // The final lock journey already invalidated/cleaned up the session; only
    // any other result still needs the redundant popup disconnect.
    if (checkout?.locked !== true) {
      popup = await openPopup();
      await popup.click("#disconnect");
    }
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
    const observe = vaultObserver({ go, root, env, state });
    const { didCommit } = await acceptPopupVault({
      openPopup, input, fixture, phase, eventually, observe,
      attachment: {
        sourcePath, fileName,
        downloaded: () => {
          const path = join(downloadDirectory, fileName);
          return existsSync(path) && createHash("sha256").update(readFileSync(path)).digest("hex") === digest;
        },
      },
    });
    await downloadSession.detach();
    // acceptPopupVault dismisses its popup in `finally`, so that target is
    // closed by the time it returns. Open a fresh, currently-open target before
    // physically clicking disconnect; the observer already proved the commits.
    assert(didCommit, "Popup vault commits are the quick-fill pairing proof");
    phase("native-disconnect");
    popup = await openPopup();
    await popup.click("#disconnect");
    input([], true, { wait_absent: true });
    phase("native-reconnect");
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
    // Native re-pair closes the popup that requested it; only openPopup returns
    // the focused, visible action popup again, so discard the stale handle.
    popup = await openPopup();
    await eventually(async () => await popup.disabled("#search-input") === false,
      "Normal-mode vault refresh did not settle");
    // In normal mode an item-get needs the native V2 review. Rejecting it
    // proves the refusal path without approving or disclosing the item.
    phase("post-repair:item-get-observe");
    const edited = observe().rows.find((item) => item.title === "Popup native contract edited");
    assert(edited, "Synthetic edited item missing after normal re-pair");
    phase("post-repair:item-get-open");
    const target = '#vault-list [data-item-id="' + edited.id + '"]';
    await popup.click('#filter-tabs [data-filter="all"]');
    await eventually(async () => await popup.count(target) === 1,
      "Edited item row absent");
    phase("post-repair:item-get-click");
    // The physical row click starts one native item-get review.
    await popup.click(target);
    phase("post-repair:item-get-refusal");
    input([{ wait_label: "批准本次操作" }]);
    const refusal = input([], true, true).controls;
    for (const label of ["批准本次操作", "拒绝本次操作"]) {
      assert(refusal[label]?.present === true && refusal[label]?.showing === true,
        "Exact native item-get control missing");
    }
    input([{ click_label: "拒绝本次操作" }]);
    phase("post-repair:item-get-refetched");
    // A fresh popup is the only trusted view after the refusal; the rejected
    // detail must never render.
    popup = await openPopup();
    await eventually(async () => await popup.disabled("#search-input") === false,
      "Refused popup not ready");
    assert.equal(await popup.count("#detail-view:not([hidden])"), 0,
      "Refused item-get opened the detail view");
    // No detail is rendered, so only the visible body text could disclose.
    const body = String(await popup.text("body"));
    for (const [name, value] of [
      ["password", fixture.Value],
      ["note", fixture.SaveValue],
      ["update", fixture.UpdateValue],
    ]) {
      assert(!body.includes(value), "Refused item-get disclosed a synthetic " + name);
    }
    phase("post-repair:item-get-refused");
    console.log("PASS: real popup native item-get refusal disclosed nothing");
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
    // Explicit quick pairing for non-destructive Passkey metadata: disconnect
    // the current session, reopen the popup, unlock and physically choose the
    // real quick-fill pairing control. Nothing is approved implicitly.
    reconnectQuickFill: async () => {
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
      input([{ click_label: "连接并启用快捷填充" }]);
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
    reconnectQuickFill: acceptanceDriver.reconnectQuickFill,
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
  // The route page contributes only its fixed view/status enums and booleans.
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
    "Native checkout review must be visible before lock",
    "Checkout forms changed before native lock",
    "Native checkout review still available after lock",
    "Native checkout review did not finish after lock",
    "Locked host still allowed matching",
    "Lock status missing",
    "Locked checkout approval received a value",
    "Route detail mode is incompatible",
    "Route detail mode requires Chromium",
    "Paired popup not ready",
    "Exact-origin match missing",
    "Vault rows missing",
    "Exact synthetic vault row missing",
    "Synthetic seed item identity missing",
    "Synthetic fixture title missing",
    "Route page did not open",
    "Route page must be unique",
    "Action popup stayed open",
    "Action popup target stayed open",
    "Unexpected page opened",
    "Route page did not load",
    "Route detail did not render",
    "Native route approval label missing",
    "Route detail did not survive native approval",
    "Route target was replaced",
    "Action popup reopened",
    "route-detail-view-missing",
    "route-detail-title-mismatch",
    "route-concealed-control-missing",
    "route-password-rendered",
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
    // Latest fixed-enum route-page observation from the bounded native-label
    // wait, plus its bounded state-transition history where consecutive
    // entries differ. Both only ever contain the four sanitized fields.
    ...(routeDetailRead
      ? {
          routePage: sanitizeRouteObservation(lastRouteObservation),
          routeHistory: routeObservationHistory.map(sanitizeRouteObservation),
          // Present only once the post-popup-close snapshot was taken, and only
          // for route-detail failures; same four sanitized fields.
          ...(routeAfterPopupClose
            ? {
                routeAfterPopupClose: sanitizeRouteObservation(
                  routeAfterPopupClose,
                ),
              }
            : {}),
          // Present only once the post-popup-close target checkpoint was read;
          // two fixed booleans, never an id, URL, fragment, token or count.
          ...(routeTargetAfterPopupClose
            ? {
                routeTargetAfterPopupClose: {
                  routeTargetExists:
                    routeTargetAfterPopupClose.routeTargetExists === true,
                  routeTargetStillRoute:
                    routeTargetAfterPopupClose.routeTargetStillRoute === true,
                },
              }
            : {}),
          // Present only once the lifecycle observer saw the route document
          // load; fixed booleans/enums and capped per-kind counts only, never
          // an id, URL, fragment, token, text, value or protocol payload.
          ...(routeLifecycleObservation
            ? {
                routeTargetLifecycle: sanitizeRouteLifecycle(
                  routeLifecycleObservation,
                ),
              }
            : {}),
        }
      : {}),
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
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} checkout same-origin child approval (profile review) and picker cancellation, cross-origin approval/refusal, cross-site, opaque sandbox, changed-document and top-navigation rejection, and lock while cross-origin card review is pending`
    : routeDetailRead
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} QuickFill=false action row opened exactly one persistent route tab, the native per-operation approval kept that same tab, and its rendered detail matched the synthetic fixture without revealing a value`
    : process.env.LOCKLARK_TEST_BROWSER_PARITY
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} quick pairing, inline fill, automatic sign-in, Passkey creation/assertion, relying-party signature verification and abort`
    : `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} fill/save/update/OTP and Passkey with native approval and private diagnostics`,
);
console.log("Private synthetic artifacts: " + state);

if (observedFixture) scanController(observedFixture);

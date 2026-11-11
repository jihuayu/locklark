// Real Linux Firefox extension/native/MyGo acceptance, using caller-owned DISPLAY.
// Run inside dbus-run-session and xvfb-run; no product hooks or extra permissions.
// Requires Python 3, OpenSSL, ImageMagick import, libnss3-tools (certutil),
// at-spi2-core/libatspi2.0-0, and geckodriver 0.36.0 from Mozilla:
// https://github.com/mozilla/geckodriver/releases/download/v0.36.0/geckodriver-v0.36.0-linux64.tar.gz
// Archive SHA-256: 0bde38707eb0a686a20c6bd50f4adcc7d60d4f73c60eb83ee9e0db8f65823e04
// Set LOCKLARK_BROWSER_HOST and LOCKLARK_BROWSER_REGISTER to built Firefox/helper
// binaries. Optional: LOCKLARK_FIREFOX (otherwise installed Playwright Firefox),
// LOCKLARK_TEST_PLAYWRIGHT, LOCKLARK_GECKODRIVER (otherwise PATH), LOCKLARK_GO,
// LOCKLARK_BROWSER_FIXTURE (prebuilt browser_acceptance_fixture; otherwise built).
// For an intentional privacy-check failure after real pairing, set the tool-only
// LOCKLARK_TEST_FAILURE_STAGE=after-pair. It must exit 1 without echoing factors.
// page-arguments exercises a real driver failure carrying synthetic parameters.
import assert from "node:assert/strict";
import { createServer } from "node:https";
import { createServer as createPortServer, createConnection } from "node:net";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { execFileSync, spawn } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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

const scanController = captureControllerOutput();
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "web/package.json"));
assert(
  process.platform === "linux",
  "This external XTest acceptance runs on Linux",
);
assert(
  process.env.DISPLAY && process.env.DBUS_SESSION_BUS_ADDRESS,
  "Run with a real DISPLAY inside dbus-run-session",
);
assert(
  process.env.LOCKLARK_BROWSER_HOST && process.env.LOCKLARK_BROWSER_REGISTER,
  "Built Firefox host and registration helper paths are required",
);
assert(
  !process.env.LOCKLARK_TEST_FAILURE_STAGE ||
    ["after-pair", "page-arguments", "otp-page-arguments"].includes(
      process.env.LOCKLARK_TEST_FAILURE_STAGE,
    ),
  "Unsupported acceptance failure stage",
);
assert(
  !process.env.LOCKLARK_TEST_FIREFOX_PASSKEY ||
    process.env.LOCKLARK_TEST_FIREFOX_PASSKEY === "1",
  "LOCKLARK_TEST_FIREFOX_PASSKEY only accepts 1",
);
assert(
  !process.env.LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY ||
    process.env.LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY === "1",
  "LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY only accepts 1",
);
assert(
  process.env.LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY !== "1" ||
    process.env.LOCKLARK_TEST_FIREFOX_PASSKEY === "1",
  "LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY requires LOCKLARK_TEST_FIREFOX_PASSKEY=1",
);
const passkeyOnly = process.env.LOCKLARK_TEST_FIREFOX_PASSKEY_ONLY === "1";
import { acceptBrowserOTP, otpHTML } from "./browser_otp_acceptance.mjs";
import {
  acceptFirefoxPasskey,
  CHROME_VIEWPORT_SOURCE,
} from "./browser_firefox_passkey_acceptance.mjs";
import {
  acceptSharedClipboard,
  prepareSharedEnvironment,
} from "./browser_shared_clipboard_acceptance.mjs";

const firefox =
  process.env.LOCKLARK_FIREFOX ||
  require(
    process.env.LOCKLARK_TEST_PLAYWRIGHT || "playwright",
  ).firefox.executablePath();
const geckodriver = process.env.LOCKLARK_GECKODRIVER || "geckodriver";
const host = resolve(process.env.LOCKLARK_BROWSER_HOST);
const register = resolve(process.env.LOCKLARK_BROWSER_REGISTER);
const state = mkdtempSync(join(tmpdir(), "locklark-firefox-native-"));
const diagnostics = mkdtempSync(join(state, "diagnostics-"));
const sharedClipboard = process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1";
const originalEnv = { ...process.env };
const env = sharedClipboard
  ? prepareSharedEnvironment(state, originalEnv)
  : originalEnv;
if (sharedClipboard && !env.GOMODCACHE) {
  // Keep the original module cache while every launched process gets the
  // private HOME/TMPDIR/broker environment.
  try {
    env.GOMODCACHE = execFileSync(
      process.env.LOCKLARK_GO || "go",
      ["env", "GOMODCACHE"],
      { env: originalEnv, encoding: "utf8" },
    ).trim();
  } catch {}
}
const nativeManifest = join(
  sharedClipboard ? env.HOME : homedir(),
  ".mozilla/native-messaging-hosts/org.locklark.browser.json",
);
try {
  lstatSync(nativeManifest);
  throw Error("Refusing to overwrite an existing Firefox native manifest");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}

const logs = [];
let stage = "prepare",
  session = "",
  base = "",
  bidi,
  pageContext;
let nativeManifestDigest = "",
  nativeManifestInode,
  nativeManifestDevice;
let driver, server;
let observedFixture = null,
  firefoxPasskey = null,
  successful = false,
  driverLogClosed = Promise.resolve(),
  driverLogFailed = false;
let rdp, consoleActor;
const rdpPending = new Map(),
  evaluations = new Map();
const debugTargets = new Map();
const bidiCalls = new Map();
let bidiSequence = 10;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const SAFE_FAILURES = [
  /^PasskeyFailure:[a-z-]+(:[^:]{0,40})?$/,
  /^Firefox passkey (creation|assertion) did not complete$/,
  /^Native acceptance [a-z -]{3,40}$/,
];
function safeFailureMessage(error) {
  const text = String(error?.message || "");
  const fixed = new Map([
    ["Paired Firefox popup not ready", "popup-not-ready"],
    ["Exact-origin Firefox candidate missing", "candidate-missing"],
    ["Firefox did not request native confirmation", "native-confirmation-missing"],
    ["Unexpected field disclosure or automatic submission", "unexpected-disclosure-or-submit"],
    ["Navigation did not revoke the native approval control", "navigation-revocation"],
    ["Popup control unavailable", "popup-control-unavailable"],
    ["Exact popup option unavailable", "popup-option-unavailable"],
    ["Popup select focus missing", "popup-select-focus-missing"],
    ["Popup select focus changed the placeholder option", "popup-select-placeholder-changed"],
    ["Physical Home did not return to the placeholder option", "popup-select-home"],
    ["Physical popup select missed an option step", "popup-select-step-missed"],
    ["Physical popup select did not apply the exact option", "popup-select-mismatch"],
  ]);
  if (fixed.has(text)) return fixed.get(text);
  for (const pattern of SAFE_FAILURES)
    if (pattern.test(text)) return text.slice(0, 120);
  return "unclassified";
}
function progress(value) {
  stage = value;
  console.log("Firefox acceptance: " + value);
}
function classifyError(error) {
  const frames =
    typeof error?.stack === "string"
      ? [
          ...new Set(
            error.stack.match(
              /browser_[a-z0-9_]*acceptance\.mjs:[0-9]+:[0-9]+/g,
            ) || [],
          ),
        ].slice(0, 12)
      : [];
  return { class: safeFailureMessage(error), frames };
}
function reportFailure(failure = { class: "unclassified", frames: [] }) {
  console.error(
    "FAIL: Firefox native acceptance at " + stage + " (AcceptanceFailure)",
  );
  console.error("Failure class: " + failure.class);
  if (failure.frames.length)
    console.error("Failure frames: " + failure.frames.join(", "));
  console.error("Private diagnostic files: " + state);
}
async function eventually(check, description, limit = 15000) {
  const end = Date.now() + limit;
  while (Date.now() < end) {
    try {
      if (await check()) return;
    } catch {}
    await pause(100);
  }
  throw Error(description);
}
function startProcess(binary, args, name) {
  const child = spawn(binary, args, {
    cwd: root,
    env,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stream = createWriteStream(join(state, name + ".log"));
  driverLogClosed = new Promise((resolve) => {
    stream.once("finish", resolve);
    stream.once("error", () => {
      driverLogFailed = true;
      resolve();
    });
  });
  child.stdout.pipe(stream, { end: false });
  child.stderr.pipe(stream, { end: false });
  child.once("close", () => stream.end());
  child.on("error", () => {});
  return child;
}
async function command(method, path, payload) {
  const response = await fetch(
    base + (path === "/session" ? path : "/session/" + session + path),
    {
      method,
      headers: { "Content-Type": "application/json" },
      body: payload === undefined ? undefined : JSON.stringify(payload),
      signal: AbortSignal.timeout(60000),
    },
  );
  const result = await response.json();
  if (!response.ok || result.value?.error)
    throw Error("WebDriver operation rejected");
  return result.value;
}
async function context(value) {
  await command("POST", "/moz/context", { context: value });
  await command("POST", "/frame", { id: null });
}
function evaluate(script, args = []) {
  return command("POST", "/execute/sync", { script, args });
}
function input(actions, native = true, options = {}) {
  const request = native
    ? {
        title: "Locklark · 浏览器原生确认",
        executable: host,
        actions,
        ...options,
      }
    : { title_prefix: "Locklark Firefox acceptance", actions, ...options };
  try {
    return JSON.parse(
      execFileSync("python3", [join(root, "scripts/browser_native_x11.py")], {
        input: JSON.stringify(request),
        env,
        timeout: 45000,
      }).toString(),
    );
  } catch (error) {
    if (native) {
      try {
        const inspection = JSON.parse(
          execFileSync(
            "python3",
            [join(root, "scripts/browser_native_x11.py")],
            {
              input: JSON.stringify({
                title: request.title,
                executable: host,
                actions: [],
                inspect: true,
              }),
              env,
              timeout: 15000,
              stdio: ["pipe", "pipe", "ignore"],
            },
          ).toString(),
        );
        const labels = [
          "金库文件",
          "主密码",
          "Secret Key",
          "解锁",
          "确认连接此扩展",
          "连接并启用快捷填充",
          "拒绝连接",
          "批准本次填充",
          "拒绝本次填充",
          "批准填充验证码",
          "拒绝填充验证码",
          "立即锁定",
          "新登录标题",
          "批准保存登录",
          "拒绝保存登录",
          "批准更新登录",
          "拒绝更新登录",
          "验证主密码",
          "验证 Secret Key",
          "批准删除 Passkey",
          "拒绝删除 Passkey",
        ];
        const controls = Object.fromEntries(
          labels.map((label) => {
            const control = inspection.controls?.[label];
            return [
              label,
              {
                present: control?.present === true,
                enabled: control?.enabled === true,
                showing: control?.showing === true,
              },
            ];
          }),
        );
        // Only public native control presence/enabled/showing is reported:
        // no field values, no process state, no exception bodies.
        console.error("Native control state: " + JSON.stringify(controls));
      } catch {
        console.error("Native control inspection unavailable");
      }
    }
    throw error;
  }
}
const elementKey = "element-6066-11e4-a52e-4f735466cecf";
async function bidiCall(method, params) {
  const id = ++bidiSequence;
  const response = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      bidiCalls.delete(id);
      reject(Error("BiDi operation timed out: " + method));
    }, 10000);
    bidiCalls.set(id, { resolve, reject, timer });
  });
  bidi.send(JSON.stringify({ id, method, params }));
  return response;
}
async function pageEvaluate(source, args = []) {
  const response = await bidiCall("script.callFunction", {
    functionDeclaration:
      "async function(){const value=await(function(){" +
      source +
      "}).apply(null,arguments);return JSON.stringify(value===undefined?null:value);}",
    target: { context: pageContext },
    arguments: args.map((value) => ({ type: "string", value })),
    awaitPromise: true,
    resultOwnership: "none",
  });
  if (response.type !== "success" || response.result?.type !== "string")
    throw Error("Controlled page BiDi inspection failed");
  return JSON.parse(response.result.value);
}
async function rdpConnect(port) {
  let incoming = Buffer.alloc(0),
    ready;
  const connected = new Promise((resolve) => {
    ready = resolve;
  });
  rdp = createConnection({ host: "127.0.0.1", port });
  rdp.on("error", () => {});
  rdp.on("data", (data) => {
    incoming = Buffer.concat([incoming, data]);
    while (true) {
      const separator = incoming.indexOf(58);
      if (separator < 0) break;
      const size = Number(incoming.subarray(0, separator).toString());
      if (incoming.length < separator + 1 + size) break;
      const message = JSON.parse(
        incoming.subarray(separator + 1, separator + 1 + size).toString(),
      );
      incoming = incoming.subarray(separator + 1 + size);
      if (message.applicationType === "browser") {
        ready();
        continue;
      }
      if (message.type === "target-available-form") {
        debugTargets.set(message.target.actor, message.target);
        continue;
      }
      if (message.type === "target-destroyed-form") {
        debugTargets.delete(message.target.actor);
        continue;
      }
      if (message.type === "evaluationResult") {
        evaluations.set(message.resultID, message);
        continue;
      }
      if (message.type === "consoleAPICall") {
        logs.push(JSON.stringify(message.message));
        continue;
      }
      const pending = rdpPending.get(message.from);
      if (pending && !message.type) {
        rdpPending.delete(message.from);
        clearTimeout(pending.timer);
        message.error
          ? pending.reject(Error("Firefox RDP operation rejected"))
          : pending.resolve(message);
      }
    }
  });
  await Promise.race([
    connected,
    pause(10000).then(() => {
      throw Error("Firefox RDP handshake timed out");
    }),
  ]);
}
async function rdpRequest(actor, type, fields = {}) {
  const response = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      rdpPending.delete(actor);
      reject(Error("Firefox RDP request timed out: " + type));
    }, 10000);
    rdpPending.set(actor, { resolve, reject, timer });
  });
  const json = JSON.stringify({ to: actor, type, ...fields });
  rdp.write(Buffer.byteLength(json) + ":" + json);
  return response;
}
async function rdpEvaluate(text) {
  const response = await rdpRequest(consoleActor, "evaluateJSAsync", { text });
  await eventually(
    () => evaluations.has(response.resultID),
    "Firefox console evaluation did not finish",
  );
  const result = evaluations.get(response.resultID);
  evaluations.delete(response.resultID);
  if (result.exception || result.exceptionMessage)
    throw Error("Firefox popup inspection failed");
  if (typeof result.result !== "string")
    throw Error("Firefox popup inspection returned no JSON");
  return JSON.parse(result.result);
}
// Two different execution contexts are involved and must stay separate:
//  * rdpEvaluate runs in this add-on's background page: WebExtension APIs and
//    the add-on's own view list exist there, but the chrome XUL popup elements
//    do not;
//  * evaluate(..., chrome) runs in the browser chrome window: XUL <browser>
//    elements and currentURI exist there, but WebExtension APIs do not.
// Both sides independently select exactly one visible popup pinned to the same
// add-on popup URL; the background realm measures the pointer target inside
// that view and the chrome realm measures the hosting panel's screen origin.
let popupExpectedURL = "";
async function popupURL() {
  // Read-only metadata read in the add-on realm; never logged or reported.
  if (!popupExpectedURL) {
    const url = await rdpEvaluate(
      'JSON.stringify(String(browser.runtime.getURL("popup.html")))',
    );
    if (!/^moz-extension:\/\/[^/]+\/popup\.html$/.test(String(url)))
      throw Error("Popup URL unavailable");
    popupExpectedURL = String(url);
  }
  return popupExpectedURL;
}
async function popupContext() {
  // Chrome realm only: WebExtension APIs are not available here.
  const expected = await popupURL();
  await context("chrome");
  return evaluate(
    'const expected=arguments[0],hosts=[...document.querySelectorAll("browser.webextension-popup-browser")].filter(b=>{try{const r=b.getBoundingClientRect();if(!(r.width>0&&r.height>0))return false;const s=getComputedStyle(b);if(s.display==="none"||s.visibility!=="visible")return false;const hidden=b.getAttribute("hidden"),collapsed=b.getAttribute("collapsed");if(hidden!==null&&hidden!=="false")return false;if(collapsed!==null&&collapsed!=="false")return false;return !!b.currentURI&&String(b.currentURI.spec)===expected}catch{return false}});if(hosts.length!==1)throw Error("Popup host not uniquely visible");const b=hosts[0],r=b.getBoundingClientRect();return {id:String(b.browsingContext.id),href:String(b.currentURI.spec),x:window.screenX+r.x,y:window.screenY+r.y};',
    [expected],
  );
}
async function popupEvaluate(source) {
  // Add-on background realm only: the chrome XUL document is not available.
  const expected = JSON.stringify(await popupURL());
  return rdpEvaluate(
    "JSON.stringify((()=>{const expected=" + expected + ";" +
      'const views=browser.extension.getViews({type:"popup"}).filter(w=>{try{return !!w&&w.closed!==true&&!!w.document&&w.document.visibilityState==="visible"&&w.document.hidden!==true&&w.innerWidth>0&&w.innerHeight>0&&String(w.location.href)===expected}catch{return false}});' +
      'if(views.length!==1)throw Error("Popup view not uniquely visible");' +
      "const popupWindow=views[0];" +
      "return (function(window,document){" +
      source +
      "})(popupWindow,popupWindow.document);})())",
  );
}
async function popupState() {
  return popupEvaluate(
    'return {status:document.querySelector("#status")?.textContent,origin:document.querySelector("#origin")?.textContent,refreshDisabled:document.querySelector("#refresh")?.disabled,candidates:document.querySelectorAll("#candidates [data-action=fill]").length};',
  );
}
async function popupClick(selector) {
  // Scrolling can resize/reposition Firefox's extension panel. Re-measure the
  // view-local pointer target and the hosted panel origin after scrolling (each
  // in its own realm) and require two stable samples with the same hosting
  // browser before the one physical XTest click.
  const control = JSON.stringify(selector);
  await popupEvaluate(
    "const e=document.querySelector(" + control +
      ');if(!e||e.disabled)throw Error("Popup control unavailable");e.scrollIntoView({block:"center",inline:"nearest"});return true;',
  );
  let popup, rect, previous;
  await eventually(async () => {
    const target = await popupEvaluate(
      "const e=document.querySelector(" + control +
        ');if(!e||e.disabled||document.visibilityState!=="visible")return null;const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,hit=document.elementFromPoint(x,y);if(r.width<=0||r.height<=0||!hit||(hit!==e&&!e.contains(hit)))return null;return {x,y};',
    );
    if (!target) { previous = null; return false; }
    const surface = await popupContext();
    const point = { x: surface.x + target.x, y: surface.y + target.y };
    const stable = previous && previous.id === surface.id &&
      Math.abs(previous.x - point.x) < 1 && Math.abs(previous.y - point.y) < 1;
    previous = { ...point, id: surface.id };
    if (!stable) return false;
    popup = surface;
    rect = target;
    return true;
  }, "Native acceptance popup target not stable", 3000);

  const pointer =
    'import ctypes as C,os,sys\nx=C.CDLL("libX11.so.6");t=C.CDLL("libXtst.so.6");p=C.c_void_p\nx.XOpenDisplay.argtypes=[C.c_char_p];x.XOpenDisplay.restype=p;x.XFlush.argtypes=[p];x.XCloseDisplay.argtypes=[p]\nt.XTestFakeMotionEvent.argtypes=[p,C.c_int,C.c_int,C.c_int,C.c_ulong];t.XTestFakeButtonEvent.argtypes=[p,C.c_uint,C.c_int,C.c_ulong]\nd=x.XOpenDisplay(os.environ["DISPLAY"].encode());assert d\nt.XTestFakeMotionEvent(d,-1,int(sys.argv[1]),int(sys.argv[2]),0);t.XTestFakeButtonEvent(d,1,1,0);t.XTestFakeButtonEvent(d,1,0,0);x.XFlush(d);x.XCloseDisplay(d)';
  execFileSync(
    "python3",
    [
      "-c",
      pointer,
      String(Math.round(popup.x + rect.x)),
      String(Math.round(popup.y + rect.y)),
    ],
    { env },
  );
}
async function popupKeyboard(actions) {
  assert(await popupEvaluate(
    'return document.hasFocus() && document.activeElement?.matches("input,textarea,select") === true;',
  ), "Native acceptance popup focus unavailable");
  return input(actions, false, { preserve_focus: true });
}
function physicalClick(x, y) {
  const pointer =
    'import ctypes as C,os,sys\nx=C.CDLL("libX11.so.6");t=C.CDLL("libXtst.so.6");p=C.c_void_p\nx.XOpenDisplay.argtypes=[C.c_char_p];x.XOpenDisplay.restype=p;x.XFlush.argtypes=[p];x.XCloseDisplay.argtypes=[p]\nt.XTestFakeMotionEvent.argtypes=[p,C.c_int,C.c_int,C.c_int,C.c_ulong];t.XTestFakeButtonEvent.argtypes=[p,C.c_uint,C.c_int,C.c_ulong]\nd=x.XOpenDisplay(os.environ["DISPLAY"].encode());assert d\nt.XTestFakeMotionEvent(d,-1,int(sys.argv[1]),int(sys.argv[2]),0);t.XTestFakeButtonEvent(d,1,1,0);t.XTestFakeButtonEvent(d,1,0,0);x.XFlush(d);x.XCloseDisplay(d)';
  execFileSync(
    "python3",
    ["-c", pointer, String(Math.round(x)), String(Math.round(y))],
    { env },
  );
}
// Read-only chrome-context inspection of the page; clicks stay physical.
async function chromeEval(source, args = []) {
  await context("chrome");
  return evaluate(source, args);
}
async function pageViewportOrigin() {
  return chromeEval(CHROME_VIEWPORT_SOURCE);
}
// BiDi locates nodes without touching the page realm; each node is measured
// through its remote reference, so closed shadow roots stay readable even for
// out-of-process tabs. Clicking still happens through physical XTest only.
async function locatePageButtons(label) {
  let nodes = [];
  try {
    const located = await bidiCall("browsingContext.locateNodes", {
      context: pageContext,
      locator: { type: "accessibility", value: { role: "button", name: label } },
      maxNodeCount: 16,
    });
    nodes = located.nodes || [];
  } catch {} // Older remote agents may not offer the accessibility locator.
  if (!nodes.length) {
    const located = await bidiCall("browsingContext.locateNodes", {
      context: pageContext,
      locator: { type: "css", value: "*" },
      maxNodeCount: 256,
      serializationOptions: { includeShadowTree: "all", maxDomDepth: 16 },
    });
    const seen = new Set();
    const visit = (value) => {
      if (!value || typeof value !== "object") return;
      if (value.sharedId && value.value?.localName === "button" && !seen.has(value.sharedId)) {
        seen.add(value.sharedId);
        nodes.push(value);
      }
      for (const child of Object.values(value)) {
        if (Array.isArray(child)) child.forEach(visit);
        else if (child && typeof child === "object") visit(child);
      }
    };
    (located.nodes || []).forEach(visit);
  }
  const buttons = [];
  for (const node of nodes.slice(0, 32)) {
    if (!node?.sharedId) continue;
    const measured = await bidiCall("script.callFunction", {
      functionDeclaration:
        'function(button){const rect=button.getBoundingClientRect();return JSON.stringify({text:(button.textContent||" ").trim(),disabled:button.disabled===true,left:rect.left,top:rect.top,width:rect.width,height:rect.height});}',
      target: { context: pageContext },
      arguments: [{ sharedId: node.sharedId }],
      awaitPromise: true,
      resultOwnership: "none",
    });
    if (measured?.type !== "success" || measured.result?.type !== "string") continue;
    buttons.push(JSON.parse(measured.result.value));
  }
  return buttons;
}
async function openPopup() {
  input([{ key: "Escape" }], false);
  await context("chrome");
  const extensions = await command("POST", "/element", {
    using: "css selector",
    value: "#unified-extensions-button",
  });
  await command("POST", "/element/" + extensions[elementKey] + "/click", {});
  const action = await command("POST", "/element", {
    using: "css selector",
    value:
      'unified-extensions-item[extension-id="browser@locklark.local"] .unified-extensions-item-action-button, #browser_locklark_local-browser-action .unified-extensions-item-action-button',
  });
  await command("POST", "/element/" + action[elementKey] + "/click", {});
  await eventually(
    async () => (await popupState()).status !== undefined,
    "Actual Firefox action popup did not open",
  );
}
async function blank() {
  assert(
    await pageEvaluate(
      'return document.querySelector("#username").value === "" && document.querySelector("#password").value === "" && window.submits === 0;',
    ),
    "Unexpected field disclosure or automatic submission",
  );
}
async function select() {
  const parent = stage;
  progress(parent + ":popup-open");
  await openPopup();
  await eventually(
    async () => (await popupState()).refreshDisabled === false,
    "Paired Firefox popup not ready",
  );
  progress(parent + ":refresh-click");
  await popupClick("#refresh");
  await eventually(async () => {
    const state = await popupState();
    return (
      state.candidates === 1 &&
      state.refreshDisabled === false &&
      (await popupEvaluate(
        'return document.querySelector("#candidates [data-action=fill]")?.disabled === false;',
      ))
    );
  }, "Exact-origin Firefox candidate missing");
  progress(parent + ":candidate-click");
  await popupClick('#candidates [data-action="fill"]');
  await eventually(
    async () => (await popupState()).status?.includes("原生窗口核对"),
    "Firefox did not request native confirmation",
  );
  progress(parent + ":native-pending");
  input([{ wait_label: "批准本次填充" }]);
}
function safeRemoveManifest() {
  if (!nativeManifestDigest) return;
  const current = lstatSync(nativeManifest);
  assert(
    current.isFile() &&
      current.ino === nativeManifestInode &&
      current.dev === nativeManifestDevice,
    "Native manifest changed externally; preserving it",
  );
  assert(
    createHash("sha256").update(readFileSync(nativeManifest)).digest("hex") ===
      nativeManifestDigest,
    "Native manifest changed externally; preserving it",
  );
  unlinkSync(nativeManifest);
  nativeManifestDigest = "";
}
let cleanupPromise;
function cleanup() {
  if (cleanupPromise) return cleanupPromise;
  cleanupPromise = (async () => {
    if (rdp) rdp.destroy();
    if (bidi) bidi.close();
    if (session)
      await Promise.race([command("DELETE", "").catch(() => {}), pause(3000)]);
    if (driver) {
      try {
        process.kill(-driver.pid, "SIGTERM");
      } catch {}
    }
    await Promise.race([driverLogClosed, pause(3000)]);
    if (driver) {
      try {
        process.kill(-driver.pid, "SIGKILL");
      } catch {}
    }
    await Promise.race([driverLogClosed, pause(3000)]);
    if (server) await new Promise((resolve) => server.close(resolve));
    try {
      safeRemoveManifest();
    } catch {
      console.error(
        "FAIL: Firefox native manifest cleanup (AcceptanceFailure)",
      );
      process.exitCode = 1;
    }
    if (observedFixture) {
      try {
        assert(!driverLogFailed, "Persistent driver logging failed");
        assertPrivateArtifacts(state, observedFixture);
        scanController(observedFixture);
      } catch {
        console.error(
          "FAIL: Firefox persistent diagnostics (AcceptanceFailure)",
        );
        process.exitCode = 1;
      }
    }
  })();
  return cleanupPromise;
}
for (const [signal, code] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
]) {
  process.once(signal, () => {
    void cleanup().finally(() => process.exit(code));
  });
}
for (const event of ["uncaughtException", "unhandledRejection"]) {
  process.once(event, (error) => {
    reportFailure(classifyError(error));
    void cleanup().finally(() => process.exit(1));
  });
}
try {
  for (const path of [firefox, host, register])
    assert(existsSync(path), "Missing required test input: " + path);
  const driverVersion = execFileSync(geckodriver, ["--version"], { env })
    .toString()
    .split("\n")[0];
  assert(
    driverVersion.startsWith("geckodriver 0.36.0 "),
    "Use the pinned and verified geckodriver 0.36.0",
  );
  execFileSync(process.execPath, ["browser-extension/build.js", "firefox"], {
    cwd: root,
  });
  const manifest = JSON.parse(
    readFileSync(join(root, "browser-extension/dist/firefox/manifest.json")),
  );
  assert(
    manifest.browser_specific_settings?.gecko?.id === "browser@locklark.local",
    "Fixed production Firefox identity required",
  );
  assert.deepEqual(
    [...manifest.permissions].sort(),
    [
      "activeTab",
      "idle",
      "nativeMessaging",
      "notifications",
      "scripting",
      "storage",
    ].sort(),
  );
  assert.deepEqual(manifest.host_permissions, ["https://*/*"]);
  assert.equal(manifest.content_scripts?.length, 2);
  const key = join(state, "tls.key"),
    certificate = join(state, "tls.crt");
  const caKey = join(state, "ca.key"),
    caCertificate = join(state, "ca.crt"),
    request = join(state, "tls.csr"),
    extensions = join(state, "tls.ext");
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
      caKey,
      "-out",
      caCertificate,
      "-subj",
      "/CN=Locklark temporary synthetic CA",
      "-addext",
      "basicConstraints=critical,CA:TRUE",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign",
    ],
    { stdio: "ignore" },
  );
  execFileSync(
    "openssl",
    [
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      request,
      "-subj",
      "/CN=login.locklark.test",
    ],
    { stdio: "ignore" },
  );
  writeFileSync(
    extensions,
    "subjectAltName=DNS:login.locklark.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
  );
  execFileSync(
    "openssl",
    [
      "x509",
      "-req",
      "-in",
      request,
      "-CA",
      caCertificate,
      "-CAkey",
      caKey,
      "-set_serial",
      "1",
      "-days",
      "1",
      "-out",
      certificate,
      "-extfile",
      extensions,
    ],
    { stdio: "ignore" },
  );
  const profile = join(state, "profile");
  mkdirSync(profile, { mode: 0o700 });
  execFileSync("certutil", ["-N", "--empty-password", "-d", "sql:" + profile], {
    stdio: "ignore",
  });
  execFileSync(
    "certutil",
    [
      "-A",
      "-n",
      "Locklark temporary synthetic certificate",
      "-t",
      "C,,",
      "-i",
      caCertificate,
      "-d",
      "sql:" + profile,
    ],
    { stdio: "ignore" },
  );
  const zipSource =
    'import base64,io,pathlib,sys,zipfile\nroot=pathlib.Path(sys.argv[1]); data=io.BytesIO()\nwith zipfile.ZipFile(data,"w",zipfile.ZIP_DEFLATED) as archive:\n for path in root.rglob("*"):\n  if path.is_file(): archive.write(path,path.relative_to(root))\nprint(base64.b64encode(data.getvalue()).decode())';
  const encodedProfile = execFileSync("python3", ["-c", zipSource, profile])
    .toString()
    .trim();
  const extensionZip = join(state, "locklark-firefox.xpi");
  execFileSync("python3", [
    "-c",
    'import pathlib,sys,zipfile\nroot=pathlib.Path(sys.argv[1])\nwith zipfile.ZipFile(sys.argv[2],"w",zipfile.ZIP_DEFLATED) as archive:\n for path in root.rglob("*"):\n  if path.is_file(): archive.write(path,path.relative_to(root))',
    join(root, "browser-extension/dist/firefox"),
    extensionZip,
  ]);
  const html =
    '<!doctype html><html><head><title>Locklark Firefox acceptance</title></head><body><h1>Synthetic login</h1><form method="post"><label>User<input id="username" autocomplete="username"></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button>Submit</button></form><script>window.submits=0;document.querySelector("form").addEventListener("submit",event=>{event.preventDefault();window.submits++;});</script></body></html>';
  server = createServer(
    { key: readFileSync(key), cert: readFileSync(certificate) },
    (request, response) => {
      response.setHeader("Content-Type", "text/html");
      response.end(
        request.url.startsWith("/otp")
          ? otpHTML.replace(
              "Locklark OTP acceptance",
              "Locklark Firefox acceptance · OTP",
            )
          : html,
      );
    },
  );
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = "https://login.locklark.test:" + server.address().port;
  progress("create private synthetic fixture");
  // LOCKLARK_BROWSER_FIXTURE reuses one prebuilt fixture instead of building.
  execFileSync(
    browserFixtureExecutable({
      go: process.env.LOCKLARK_GO || "go",
      root,
      env,
      state,
    }),
    [
      "-out",
      join(state, "vault"),
      "-origin",
      origin,
    ],
    { cwd: root, env, stdio: ["ignore", "ignore", "pipe"], timeout: 60000 },
  );
  const fixture = JSON.parse(readFileSync(join(state, "vault/fixture.json")));
  observedFixture = fixture;
  execFileSync(
    register,
    [
      "--browser",
      "firefox",
      "--host",
      resolve(host),
      "--output",
      nativeManifest,
    ],
    { env, stdio: "ignore" },
  );
  nativeManifestDigest = createHash("sha256")
    .update(readFileSync(nativeManifest))
    .digest("hex");
  const registeredManifest = lstatSync(nativeManifest);
  nativeManifestInode = registeredManifest.ino;
  nativeManifestDevice = registeredManifest.dev;
  async function availablePort() {
    const listener = createPortServer();
    await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
    const port = listener.address().port;
    await new Promise((resolve) => listener.close(resolve));
    return port;
  }
  const port = await availablePort(),
    debuggerPort = await availablePort();
  base = "http://127.0.0.1:" + port;
  driver = startProcess(
    geckodriver,
    ["--host", "127.0.0.1", "--port", String(port), "--log", "error"],
    "geckodriver",
  );
  await eventually(
    async () =>
      (await fetch(base + "/status", { signal: AbortSignal.timeout(1000) })).ok,
    "geckodriver did not start",
  );
  progress("launch real Firefox with isolated certificate trust");
  const created = await command("POST", "/session", {
    capabilities: {
      alwaysMatch: {
        browserName: "firefox",
        acceptInsecureCerts: false,
        webSocketUrl: true,
        "moz:firefoxOptions": {
          binary: firefox,
          profile: encodedProfile,
          args: [
            "-remote-allow-system-access",
            "--start-debugger-server",
            String(debuggerPort),
          ],
          prefs: {
            "network.dns.localDomains": "login.locklark.test",
            "network.trr.mode": 5,
            "network.proxy.type": 0,
            "browser.shell.checkDefaultBrowser": false,
            "browser.startup.homepage": "about:blank",
            "devtools.debugger.remote-enabled": true,
            "devtools.debugger.prompt-connection": false,
            "devtools.chrome.enabled": true,
          },
        },
      },
    },
  });
  session = created.sessionId;
  assert(
    Number.parseInt(created.capabilities.browserVersion, 10) >= 153,
    "Firefox documentIds support requires Firefox 153 or newer",
  );
  assert.equal(
    created.capabilities.acceptInsecureCerts,
    false,
    "TLS verification must remain enabled",
  );
  if (created.capabilities.webSocketUrl) {
    bidi = new WebSocket(created.capabilities.webSocketUrl);
    bidi.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.method === "log.entryAdded")
        logs.push(JSON.stringify(message.params));
      const pending = bidiCalls.get(message.id);
      if (pending) {
        bidiCalls.delete(message.id);
        clearTimeout(pending.timer);
        message.type === "error"
          ? pending.reject(Error("Firefox BiDi operation rejected"))
          : pending.resolve(message.result);
      }
    });
    await new Promise((resolve, reject) => {
      bidi.addEventListener("open", resolve, { once: true });
      bidi.addEventListener("error", reject, { once: true });
    });
    bidi.send(
      JSON.stringify({
        id: 1,
        method: "session.subscribe",
        params: { events: ["log.entryAdded"] },
      }),
    );
  }
  const installed = await command("POST", "/moz/addon/install", {
    path: extensionZip,
    temporary: true,
  });
  assert.equal(
    installed,
    "browser@locklark.local",
    "Actual fixed Firefox add-on identity required",
  );
  await rdpConnect(debuggerPort);
  const addons = await rdpRequest("root", "listAddons");
  const addon = addons.addons.find((item) => item.id === installed);
  assert(addon, "Real Firefox extension descriptor missing");
  const watcher = await rdpRequest(addon.actor, "getWatcher", {
    isServerTargetSwitchingEnabled: true,
  });
  await rdpRequest(watcher.actor, "watchTargets", { targetType: "frame" });
  await eventually(
    () =>
      [...debugTargets.values()].some((target) =>
        target.url?.includes("_generated_background_page.html"),
      ),
    "Real Firefox extension background target missing",
  );
  consoleActor = [...debugTargets.values()].find((target) =>
    target.url?.includes("_generated_background_page.html"),
  )?.consoleActor;
  assert(consoleActor, "Firefox extension console actor unavailable");
  await rdpRequest(consoleActor, "startListeners", {
    listeners: ["ConsoleAPI"],
  });
  await command("POST", "/window/rect", {
    x: 0,
    y: 0,
    width: 1200,
    height: 850,
  });
  await command("POST", "/url", { url: origin + "/login" });
  assert.equal(await command("GET", "/url"), origin + "/login");
  const tree = await bidiCall("browsingContext.getTree", {});
  pageContext = tree.contexts.find(
    (context) => context.url === origin + "/login",
  )?.context;
  assert(pageContext, "Controlled HTTPS page browsing context missing");
  await blank();
  if (sharedClipboard) {
    // The actual desktop app is the shared broker and sole clipboard owner. It
    // is spawned and unlocked through the real native UI before any action
    // popup exists, so focusing the desktop inspector cannot close the popup.
    progress("shared-clipboard");
    const wrapPopup = async () => {
      await openPopup();
      const evaluate = (selector, expression) =>
        popupEvaluate(
          "return " +
            expression.replaceAll("SELECTOR", JSON.stringify(selector)) +
            ";",
        );
      return {
        click: popupClick,
        disabled: (selector) =>
          evaluate(
            selector,
            "document.querySelector(SELECTOR)?.disabled !== false",
          ),
        count: (selector) =>
          evaluate(selector, "document.querySelectorAll(SELECTOR).length"),
        text: (selector) =>
          evaluate(
            selector,
            'document.querySelector(SELECTOR)?.textContent || ""',
          ),
        visible: (selector) =>
          evaluate(
            selector,
            "!!document.querySelector(SELECTOR)?.getClientRects().length",
          ),
        // Read-only DOM observations only: shared activation stays physical.
        attribute: (selector, name) =>
          popupEvaluate(
            "return document.querySelector(" +
              JSON.stringify(selector) +
              ")?.getAttribute(" +
              JSON.stringify(name) +
              ");",
          ),
        value: (selector) =>
          evaluate(
            selector,
            'typeof document.querySelector(SELECTOR)?.value === "string" ? document.querySelector(SELECTOR).value : null',
          ),
        dismiss: async () => {
          input([{ key: "Escape" }], false);
          await pause(250);
        },
      };
    };
    await acceptSharedClipboard({
      fixture,
      root,
      state,
      env,
      openPopup: wrapPopup,
      eventually,
      delay: pause,
      phase: progress,
    });
    assert(
      !logs.some((line) =>
        fixtureCanaries(fixture).some((value) => line.includes(value)),
      ),
      "Synthetic factor or value found in browser logs",
    );
    for (const line of logs) assertPrivateText(line, fixture);
    writeFileSync(
      join(state, "acceptance-report.json"),
      JSON.stringify(
        {
          passed: true,
          scope: "shared-clipboard",
          legacyFillSaveOtpPasskey: "not-run",
          privateAppHomeTmpdirBroker: true,
          controlledFixtureVault: true,
          nativeUnlockUi: true,
          sharedNativeIpc: true,
          normalActionPopupNativeCopy: true,
          osClipboardMatch: true,
          popupClosePreservesPaste: true,
          foreignOwnerTtlZeroRead: true,
          appLockClearsOwnedValue: true,
          laterForeignOwnerPreserved: true,
          latePrepareOwnAppStopped: true,
          pageHiddenNoCopy: true,
          browserVersion: created.capabilities.browserVersion,
          geckodriverVersion: driverVersion,
          hostSha256: createHash("sha256").update(readFileSync(host)).digest("hex"),
          certificateVerification: true,
          productionExtension: "browser@locklark.local",
          realAction: true,
        },
        null,
        2,
      ) + "\n",
    );
    successful = true;
  } else {
    progress("open actual Firefox extension action");
    await openPopup();
    progress("save-new control");
    assert(
      await popupEvaluate('return !!document.querySelector("#save-new");'),
      "Explicit save-new action is required",
    );
    progress("native-connect");
    await popupClick("#connect");
    progress("native-unlock");
    input([
      { click_label: "金库文件" },
      { text: fixture.Path },
      { click_label: "主密码" },
      { text: fixture.Password },
      { click_label: "Secret Key" },
      { text: fixture.Secret },
      { click_label: "解锁" },
    ]);
    progress("native-pair");
    input([{ click_label: "确认连接此扩展" }]);
    await blank();
    await openPopup();
    if (await popupEvaluate('return !!document.querySelector(".site-preferences:not([open]) > summary");'))
      await popupClick(".site-preferences > summary");
    await popupClick("#auto-login"); // Legacy manual-mode acceptance disables auto-submit.
    if (!passkeyOnly && process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments") {
      progress("native approval and actual Firefox document-targeted fill");
      await select();
      await blank();
      if (process.env.LOCKLARK_TEST_FAILURE_STAGE === "after-pair")
        throw Error(fixtureCanaries(fixture).join("\n"));
      if (process.env.LOCKLARK_TEST_FAILURE_STAGE === "page-arguments") {
        progress("driver-arguments-failure");
        await pageEvaluate(
          'document.querySelector("#username").value=arguments[0];document.querySelector("#password").value=arguments[1];throw Error("Controlled driver argument failure");',
          [fixture.SaveUsername, fixture.SaveValue],
        );
      }
      const nativeWindow = input([], true, { inspect: true }).window;
      assert(
        Number.isSafeInteger(nativeWindow) && nativeWindow > 0,
        "Strictly matched native X window required",
      );
      execFileSync(
        "import",
        [
          "-window",
          String(nativeWindow),
          join(diagnostics, "native-fill-confirm.png"),
        ],
        { env, stdio: "ignore" },
      );
      input([{ click_label: "批准本次填充" }]);
      await eventually(
        () =>
          pageEvaluate(
            'return document.querySelector("#username").value === arguments[0] && document.querySelector("#password").value === arguments[1] && window.submits === 0;',
            [fixture.Username, fixture.Value],
          ),
        "Approved Firefox fill did not reach the original document",
      );
      await pageEvaluate(
        'document.querySelector("#username").value="";document.querySelector("#password").value="";',
      );
      progress("native rejection refuses field release");
      await select();
      input([{ click_label: "拒绝本次填充" }]);
      await pause(500);
      await blank();
      progress("same-origin navigation rejects stale native approval");
      await select();
      await bidiCall("browsingContext.navigate", {
        context: pageContext,
        url: origin + "/different-document",
        wait: "complete",
      });
      await eventually(() => {
        const approval = input([], true, { inspect: true }).controls[
          "批准本次填充"
        ];
        return !approval.present || !approval.enabled || !approval.showing;
      }, "Navigation did not revoke the native approval control");
      await blank();
      progress("native lock revokes the pending Firefox request");
      await select();
      input([{ click_label: "立即锁定" }]);
      await pause(300);
      await blank();
      await openPopup();
      await eventually(
        async () => (await popupState()).refreshDisabled,
        "Locked native host still allowed Firefox matching",
      );
      const locked = await popupState();
      assert(
        locked.status.includes("锁定") || locked.status.includes("断开"),
        "Firefox lock status missing",
      );
    }
    const acceptanceDriver = {
      fixture,
      origin,
      phase: progress,
      input,
      inspect: () => input([], true, { inspect: true }),
      observe: vaultObserver({
        go: process.env.LOCKLARK_GO || "go",
        root,
        env,
        state,
      }),
      captureNative: (kind) => {
        assert(
          browserScreenshotsAllowed(stage),
          "OTP stage forbids diagnostic screenshots",
        );
        const window = input([], true, { inspect: true }).window;
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
      openPopup: async () => {
        await openPopup();
        return {
          click: popupClick,
          selectAll: () => popupKeyboard([{ key: "Control_L+a" }]),
          insertText: (text) => popupKeyboard([{ text }]),
          visible: (selector) => popupEvaluate(
            "return !!document.querySelector(" + JSON.stringify(selector) + ")?.getClientRects().length;",
          ),
          count: (selector) =>
            popupEvaluate(
              "return document.querySelectorAll(" +
                JSON.stringify(selector) +
                ").length;",
            ),
          text: (selector) =>
            popupEvaluate(
              "return document.querySelector(" +
                JSON.stringify(selector) +
                ')?.textContent || "";',
            ),
          disabled: (selector) =>
            popupEvaluate(
              "return document.querySelector(" +
                JSON.stringify(selector) +
                ")?.disabled !== false;",
            ),
          value: (selector) =>
            popupEvaluate(
              "return document.querySelector(" +
                JSON.stringify(selector) +
                ")?.value ?? null;",
            ),
          selectOption: async (selector, value, onPhase = () => {}) => {
            const control = JSON.stringify(selector);
            const options = await popupEvaluate(
              "return Array.from(document.querySelector(" +
                control +
                ")?.options || []).map(option => option.value);",
            );
            const index = options.indexOf(value);
            assert(index > 0, "Exact popup option unavailable");
            const id = selector.startsWith("#") ? selector.slice(1) : "";
            onPhase("select-focus");
            await popupClick(id ? 'label[for="' + id + '"]' : selector);
            await eventually(
              () =>
                popupEvaluate(
                  "return document.activeElement === document.querySelector(" +
                    control +
                    ");",
                ),
              "Popup select focus missing",
            );
            const selectedIndex = () =>
              popupEvaluate(
                "return document.querySelector(" +
                  control +
                  ")?.selectedIndex ?? null;",
              );
            assert.equal(
              await selectedIndex(),
              0,
              "Popup select focus changed the placeholder option",
            );
            onPhase("key-selection");
            // X11 keysyms are "Down", not the DOM key name "ArrowDown";
            // XStringToKeysym("ArrowDown") is NoSymbol and sends no key.
            await popupKeyboard([{ key: "Home" }]);
            assert.equal(
              await selectedIndex(),
              0,
              "Physical Home did not return to the placeholder option",
            );
            for (let step = 0; step < index; step++) {
              await popupKeyboard([{ key: "Down" }]);
              await eventually(
                async () => (await selectedIndex()) === step + 1,
                "Physical popup select missed an option step",
                5000,
              );
            }
            assert.equal(
              await popupEvaluate(
                "return document.querySelector(" +
                  control +
                  ")?.value ?? null;",
              ),
              value,
              "Physical popup select did not apply the exact option",
            );
          },
        };
      },
      setLogin: (username, password) =>
        pageEvaluate(
          'document.querySelector("#username").value=arguments[0];document.querySelector("#password").value=arguments[1];',
          [username, password],
        ),
      loginEquals: (username, password) =>
        pageEvaluate(
          'return document.querySelector("#username").value===arguments[0]&&document.querySelector("#password").value===arguments[1]&&window.submits===0;',
          [username, password],
        ),
      navigate: (url) =>
        bidiCall("browsingContext.navigate", {
          context: pageContext,
          url,
          wait: "complete",
        }),
      reconnect: async () => {
        await openPopup();
        await popupClick("#disconnect");
        input([], true, { wait_absent: true });
        await openPopup();
        await popupClick("#connect");
        progress("native-unlock");
        input([
          { click_label: "金库文件" },
          { text: fixture.Path },
          { click_label: "主密码" },
          { text: fixture.Password },
          { click_label: "Secret Key" },
          { text: fixture.Secret },
          { click_label: "解锁" },
        ]);
        progress("native-pair");
        input([{ click_label: "确认连接此扩展" }]);
      },
      // Explicit quick pairing for non-destructive Passkey metadata: disconnect
      // the current session, wait for the old native host window to disappear,
      // reopen the popup, unlock and physically choose the real quick-fill
      // pairing control. Nothing is approved implicitly.
      reconnectQuickFill: async () => {
        await openPopup();
        await popupClick("#disconnect");
        input([], true, { wait_absent: true });
        await openPopup();
        await popupClick("#connect");
        progress("native-unlock");
        input([
          { click_label: "金库文件" },
          { text: fixture.Path },
          { click_label: "主密码" },
          { text: fixture.Password },
          { click_label: "Secret Key" },
          { text: fixture.Secret },
          { click_label: "解锁" },
        ]);
        progress("native-quick-pair");
        input([{ click_label: "连接并启用快捷填充" }]);
      },
      root,
      state,
      env,
      pageEval: (fn, arg) =>
        pageEvaluate(
          "return (" + fn.toString() + ")(JSON.parse(arguments[0]));",
          [JSON.stringify(arg ?? null)],
        ),
    };
    if (!passkeyOnly) {
      if (process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments")
        await acceptBrowserSave(acceptanceDriver);
      await acceptBrowserOTP(acceptanceDriver);
    }
    async function passkeyPair() {
      await openPopup();
      await popupClick("#disconnect");
      input([], true, { wait_absent: true });
      await openPopup();
      await popupClick("#connect");
      progress("native-unlock");
      input([
        { click_label: "金库文件" },
        { text: fixture.Path },
        { click_label: "主密码" },
        { text: fixture.Password },
        { click_label: "Secret Key" },
        { text: fixture.Secret },
        { click_label: "解锁" },
      ]);
      progress("native-pair");
      input([{ click_label: "确认连接此扩展" }]);
    }
    if (process.env.LOCKLARK_TEST_FIREFOX_PASSKEY === "1") {
      progress("firefox-passkey");
      firefoxPasskey = await acceptFirefoxPasskey({
        origin,
        fixture,
        phase: progress,
        eventually,
        input,
        pageEval: acceptanceDriver.pageEval,
        chromeEval,
        clickScreen: physicalClick,
        locateButtons: locatePageButtons,
        viewportOrigin: pageViewportOrigin,
        dismissPopup: () => input([{ key: "Escape" }], false),
        reconnect: passkeyOnly ? passkeyPair : acceptanceDriver.reconnect,
        reconnectQuickFill: acceptanceDriver.reconnectQuickFill,
        openPopup: acceptanceDriver.openPopup,
        observe: acceptanceDriver.observe,
        navigate: acceptanceDriver.navigate,
        pause,
      });
    }
    assert(
      !logs.some((line) =>
        fixtureCanaries(fixture).some((value) => line.includes(value)),
      ),
      "Synthetic factor or value found in browser logs",
    );
    for (const line of logs) assertPrivateText(line, fixture);
    await openPopup();
    await popupClick("#disconnect");
    const summary = passkeyOnly
      ? {
          passed: true,
          scope: "passkey-only",
          legacyFillSaveOtp: "not-run",
          firefoxNativePasskey: firefoxPasskey,
          browserVersion: created.capabilities.browserVersion,
          geckodriverVersion: driverVersion,
          hostSha256: createHash("sha256").update(readFileSync(host)).digest("hex"),
          certificateVerification: true,
          productionExtension: "browser@locklark.local",
          realAction: true,
        }
      : {
          passed: true,
      browserVersion: created.capabilities.browserVersion,
      geckodriverVersion: driverVersion,
      hostSha256: createHash("sha256").update(readFileSync(host)).digest("hex"),
      certificateVerification: true,
      productionExtension: "browser@locklark.local",
      realAction: true,
      realNativeUnlockAndPair: true,
      approvedFill: true,
      rejection: true,
      sameOriginNavigationRefusal: true,
      nativeLock: true,
      noPreapprovalValues: true,
      noAutomaticSubmit: true,
      noSyntheticSecretsInBrowserLogs: true,
      otpNativeApprovalAndHMAC: true,
      otpRefusalNavigationLockAndOriginalWindow: true,
      saveNew: true,
      saveUpdateSameID: true,
      capturedClickTimeValues: true,
      unicodeRoundTrip: true,
      saveRejectionNavigationLock: true,
      firefoxNativePasskey: firefoxPasskey,
    };
    writeFileSync(
      join(state, "acceptance-report.json"),
      JSON.stringify(summary, null, 2) + "\n",
    );
    successful = true;
  }
} catch (error) {
  reportFailure(classifyError(error));
  process.exitCode = 1;
} finally {
  await cleanup();
}
if (successful && !process.exitCode) {
  console.log(
    sharedClipboard
      ? "PASS: real Firefox shared desktop native clipboard lease, OS reads, owner preservation, lock and hidden-popup cancellation"
      : passkeyOnly
      ? "PASS: real Firefox native Passkey-only acceptance (create/get/abort/browser-fallback) with native factor approval"
      : "PASS: real Firefox fill/save/update/OTP with native approval, cancellation, Unicode, and no synthetic secrets in console or persistent diagnostics" +
          (firefoxPasskey
            ? " · native Passkey create/get/abort/browser-fallback verified"
            : ""),
  );
  console.log("Private synthetic artifacts: " + state);
}

if (observedFixture) {
  try {
    scanController(observedFixture);
  } catch {
    console.error("FAIL: Firefox controller privacy (AcceptanceFailure)");
    process.exitCode = 1;
  }
}

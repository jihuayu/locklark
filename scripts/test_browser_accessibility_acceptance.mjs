import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  AXE_VERSION, EXTENSION_ID, MODES, SCHEMA, VIEWPORTS, assertPublicReceipt,
  auditStatus, buildReceipt, ensureNewOutput, errorCode, extensionIdFromKey,
  keyboardSummary, minimizeAxeResult, resolveAxeSource, sha256File, validateAxeVersion,
} from "./browser_accessibility_receipt.mjs";
import {
  assertActionPopupContext, focusSnapshot, lockedPopup, popupReady,
} from "./browser_accessibility_probes.mjs";
import {
  attachActionPopup, parseDevToolsPort, popupURL, selectActionPopupTarget, waitForActionPopup,
} from "./browser_accessibility_cdp_adapter.mjs";
import { parseArgs } from "./browser_accessibility_acceptance.mjs";
import { validNativeWindowResult } from "./browser_accessibility_launch.mjs";
import {
  WINDOW_MANAGER_READY, WINDOW_MANAGER_UNAVAILABLE, assertNativeWindowManager,
} from "./browser_accessibility_window_manager.mjs";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const WM_CHECK = "_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x1400003";

function xpropFixture({ root = WM_CHECK, manager = WM_CHECK, throws = false, ok = true } = {}) {
  return (args) => {
    if (throws) throw new Error("xprop unavailable");
    return { ok, stdout: args[0] === "-root" ? root : args[0] === "-id" ? manager : "" };
  };
}

function windowManagerCode(options) {
  try {
    assertNativeWindowManager(options);
    return WINDOW_MANAGER_READY;
  } catch (error) {
    return error.code;
  }
}

test("window-manager preflight accepts a real EWMH self-referencing manager", () => {
  const run = xpropFixture();
  assert.deepEqual(assertNativeWindowManager({ env: { DISPLAY: ":99" }, run }),
    { status: WINDOW_MANAGER_READY });
  assert.deepEqual(assertNativeWindowManager({ env: { DISPLAY: "localhost:10.0" }, run }),
    { status: WINDOW_MANAGER_READY });
});

test("window-manager preflight refuses missing display and non-EWMH roots", () => {
  const run = xpropFixture();
  assert.equal(windowManagerCode({ env: {}, run }), WINDOW_MANAGER_UNAVAILABLE);
  assert.equal(windowManagerCode({ env: { DISPLAY: "" }, run }), WINDOW_MANAGER_UNAVAILABLE);
  assert.equal(windowManagerCode({ env: { DISPLAY: "   " }, run }), WINDOW_MANAGER_UNAVAILABLE);
  for (const root of [
    "_NET_SUPPORTING_WM_CHECK:  not found.\n",
    "_NET_SUPPORTING_WM_CHECK(STRING): stale\n",
    "_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x0\n",
    "_NET_SUPPORTING_WM_CHECK(WINDOW): window id # not-a-window\n",
  ]) {
    assert.equal(windowManagerCode({ env: { DISPLAY: ":99" }, run: xpropFixture({ root }) }),
      WINDOW_MANAGER_UNAVAILABLE);
  }
  const mismatch = xpropFixture({
    root: "_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x1a00003",
    manager: "_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x1a00004",
  });
  assert.equal(windowManagerCode({ env: { DISPLAY: ":99" }, run: mismatch }),
    WINDOW_MANAGER_UNAVAILABLE);
});

test("window-manager probe errors use only the fixed unavailable enum", () => {
  const options = { env: { DISPLAY: ":99" } };
  assert.equal(windowManagerCode({ ...options, run: () => { throw new Error("probe"); } }),
    WINDOW_MANAGER_UNAVAILABLE);
  assert.equal(windowManagerCode({ ...options, run: () => ({ ok: false, stdout: WM_CHECK }) }),
    WINDOW_MANAGER_UNAVAILABLE);
  assert.equal(windowManagerCode({ ...options, run: () => ({ ok: true, stdout: "garbage" }) }),
    WINDOW_MANAGER_UNAVAILABLE);
  assert.equal(windowManagerCode({ ...options, run: xpropFixture({ manager: "garbage" }) }),
    WINDOW_MANAGER_UNAVAILABLE);
});

test("window-manager unavailable receipt is UNAVAILABLE with no audits", () => {
  const value = buildReceipt({
    head: HEAD, sourceSha256: SHA, failure: WINDOW_MANAGER_UNAVAILABLE,
    unavailable: true, audits: [passingAudit()],
  });
  assert.equal(value.state, "UNAVAILABLE");
  assert.deepEqual(value.audits, []);
  assert.equal(value.failure, WINDOW_MANAGER_UNAVAILABLE);
  assert.equal(value.axe.status, "available");
  assert.equal(value.summary.audits, 0);
  assert.equal(assertPublicReceipt(value), true);
});

test("committed Linux Edge accessibility receipt stays public-only", () => {
  const receipt = JSON.parse(readFileSync(
    join(ROOT, "docs/validation/browser-accessibility-linux-edge.json"), "utf8"));
  assert.equal(receipt.schema, SCHEMA);
  assert.equal(receipt.state, "PASS");
  assert.equal(receipt.summary.audits, 9);
  assert.equal(receipt.summary.violations, 0);
  assert.equal(receipt.summary.failed_audits, 0);
  assert.equal(assertPublicReceipt(receipt), true);
});

test("native shortcut acknowledgement uses the actual X11 numeric window contract", () => {
  assert.equal(validNativeWindowResult({ window: 0x200003 }), true);
  for (const window of [undefined, null, 0, -1, 1.5, "2097155", 0x100000000])
    assert.equal(validNativeWindowResult({ window }), false);
  assert.equal(validNativeWindowResult(null), false);
});

const KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GcZFP4Yh8F3N5LELUw5UYy132r9ZQOdPGMR9yzJXc5KjBRCfPZm7ao/cAEkUeTcu3Pek/aBz+GCe0ntWBXIDlt7Z7q4rW7xtnIH7h01KVBoR5yh3sgF+89QEpF3KxOYMBIzh5fvpJ5KJzzDv4S/6jhYuernWOg7F6t38cZ1mT3+yvEecWa5z+Zuw3hDX8QWNdJGNp+809SOy+SiDYsv8kQ5ETf7cDrcREgzfFHj10J8AQlhE8yG5c89INXGy5HN45j2lwSdF+CoLf2l74Wm6QHDYQJCmgIrUZ9/wyMIIZdBwd+9c2MgsWV5YmHXRkje94JpCP/r9+ge6oLW93XnSwIDAQAB";
const HEAD = "20f3f25fcc2749f0466e4f3b5cdaf0dcfad89dc9";
const SHA = "a".repeat(64);
const VIEW = { display: "block", visibility: "visible", contentVisibility: "visible" };
const POPUP_TARGET = {
  id: "7", type: "page",
  webSocketDebuggerUrl: "ws://127.0.0.1:9222/devtools/page/7",
};

class MockWebSocket {
  static OPEN = 1;
  static autoOpen = true;
  static respond = true;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.listeners = new Map();
    this.sent = [];
    MockWebSocket.instances.push(this);
    if (MockWebSocket.autoOpen) setTimeout(() => this.open(), 0);
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
  }

  removeEventListener(type, listener) {
    this.listeners.get(type)?.delete(listener);
  }

  emit(type, event = {}) {
    if (type === "open") this.readyState = MockWebSocket.OPEN;
    if (type === "close") this.readyState = 3;
    for (const listener of [...(this.listeners.get(type) || [])]) listener(event);
  }

  open() {
    if (this.readyState === 0) this.emit("open");
  }

  send(payload) {
    const message = JSON.parse(payload);
    this.sent.push(message);
    if (!MockWebSocket.respond) return;
    setTimeout(() => {
      if (this.readyState !== MockWebSocket.OPEN) return;
      this.emit("message", { data: JSON.stringify({ id: message.id, result: {} }) });
    }, 0);
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.emit("close");
  }

  static reset() {
    MockWebSocket.autoOpen = true;
    MockWebSocket.respond = true;
    MockWebSocket.instances = [];
  }
}

async function withMockWebSocket(fn) {
  const previous = globalThis.WebSocket;
  MockWebSocket.reset();
  globalThis.WebSocket = MockWebSocket;
  try { return await fn(); } finally {
    globalThis.WebSocket = previous;
    MockWebSocket.reset();
  }
}

function fakeElement({
  name = "button", tabIndex = 0, disabled = false, hidden = false, inert = false,
  attrs = {}, style = VIEW, parent = null, children = [], width = 10, height = 10,
  visible = true, textContent = "",
}) {
  const element = {
    localName: name, tabIndex, disabled, hidden, inert, parentElement: parent, children,
    style, textContent,
    getAttribute: (key) => (key === "hidden" && hidden) || (key === "inert" && inert) ? "" : attrs[key] ?? null,
    hasAttribute: (key) => (key === "hidden" && hidden) || (key === "inert" && inert) || key in attrs,
    matches: (selector) => selector === ":disabled" && disabled === true,
    getBoundingClientRect: () => ({ width, height }),
    checkVisibility: () => visible,
    closest: () => null,
    contains(candidate) {
      for (let node = candidate; node; node = node.parentElement) if (node === element) return true;
      return false;
    },
  };
  for (const child of children) child.parentElement = element;
  return element;
}

function withDocument(elements, activeElement, fn) {
  const previousDocument = globalThis.document;
  const previousStyle = globalThis.getComputedStyle;
  globalThis.document = { querySelectorAll: () => elements, activeElement };
  globalThis.getComputedStyle = (element) => element.style;
  try { return fn(); } finally {
    globalThis.document = previousDocument;
    globalThis.getComputedStyle = previousStyle;
  }
}

function contextTarget({
  views, getViews, getCurrent, current, chromeApi = null,
  visibilityState = "visible", hidden = false, href = popupURL(EXTENSION_ID),
} = {}) {
  const popupWindow = { name: "popup" };
  const api = chromeApi === null ? {
    extension: {
      getViews: getViews || ((options) =>
        options?.type === "popup" ? (views === undefined ? [popupWindow] : views) : []),
    },
    tabs: { getCurrent: getCurrent || ((callback) => callback(current)) },
  } : chromeApi;
  return {
    async evaluate(fn, arg) {
      const previous = {
        chrome: globalThis.chrome, window: globalThis.window,
        document: globalThis.document, location: globalThis.location,
      };
      globalThis.chrome = api;
      globalThis.window = popupWindow;
      globalThis.document = { visibilityState, hidden };
      globalThis.location = { href };
      try { return await fn(arg); } finally {
        globalThis.chrome = previous.chrome;
        globalThis.window = previous.window;
        globalThis.document = previous.document;
        globalThis.location = previous.location;
      }
    },
  };
}

function passingAudit(overrides = {}) {
  return {
    page: "options.html", mode: "default", viewport: "desktop",
    viewport_px: { width: 1280, height: 800 }, forced_colors: "none",
    reduced_motion: "no-preference", locked: true, overflow: false,
    violations: [], incomplete: [],
    keyboard: { total: 2, reached: 2, tab_steps: 2, status: "PASS" },
    status: "PASS", ...overrides,
  };
}

function receipt(audits = [passingAudit()], extra = {}) {
  return buildReceipt({ head: HEAD, axeSourceSha256: SHA, browserVersion: "test", audits, ...extra });
}

test("focus snapshot counts only real Tab stops, including closed-details rules", () => {
  const open = fakeElement({ name: "button" });
  const summary = fakeElement({ name: "summary" });
  const closedChild = fakeElement({ name: "input" });
  const closed = fakeElement({ name: "details", open: false, hidden: false, attrs: {}, children: [summary, closedChild] });
  closed.open = false;
  closedChild.parentElement = closed;
  const openChild = fakeElement({ name: "button" });
  const openDetails = fakeElement({ name: "details", children: [openChild] });
  openDetails.open = true;
  openChild.parentElement = openDetails;
  const hiddenButton = fakeElement({ name: "button" });
  const hiddenAncestor = fakeElement({ name: "div", hidden: true, children: [hiddenButton] });
  hiddenButton.parentElement = hiddenAncestor;
  const inertButton = fakeElement({ name: "button" });
  const inertAncestor = fakeElement({ name: "section", inert: true, children: [inertButton] });
  inertButton.parentElement = inertAncestor;
  const disabled = fakeElement({ name: "button", disabled: true });
  const cssHidden = fakeElement({ name: "button", style: { ...VIEW, contentVisibility: "hidden" } });
  const invisible = fakeElement({ name: "button", visible: false });
  const zeroSize = fakeElement({ name: "button", width: 0 });
  const notTabbable = fakeElement({ name: "div", tabIndex: -1 });
  const elements = [open, summary, closedChild, openChild, hiddenButton, inertButton,
    disabled, cssHidden, invisible, zeroSize, notTabbable];
  const snapshot = withDocument(elements, open, () => focusSnapshot("button"));
  assert.equal(snapshot.total, 3);
  assert.equal(snapshot.activeIndex, 0);
  const noActive = withDocument(elements, fakeElement({ name: "body", tabIndex: -1 }),
    () => focusSnapshot("button"));
  assert.equal(noActive.activeIndex, -1);
});

test("popup readiness distinguishes a rendered locked action popup from an uninitialized tab", async () => {
  const view = fakeElement({ name: "section", hidden: false, attrs: {} });
  const status = fakeElement({ name: "p", textContent: "已锁定" });
  const documentFixture = { readyState: "complete", querySelector: (s) => ({ "#locked-view": view, "#status": status })[s] };
  const evaluate = (fn) => { const previous = globalThis.document; globalThis.document = documentFixture;
    try { return fn(); } finally { globalThis.document = previous; } };
  const target = { evaluate };
  assert.equal(await withDocument([], null, () => popupReady(target)), true);
  assert.equal(await withDocument([], null, () => lockedPopup(target)), true);
  status.textContent = "";
  assert.equal(await withDocument([], null, () => popupReady(target)), false);
  status.textContent = "已锁定";
  view.hidden = true;
  assert.equal(await withDocument([], null, () => lockedPopup(target)), false);
});

test("action popup target metadata is only a fresh exact-URL local candidate", () => {
  assert.equal(popupURL(EXTENSION_ID), `chrome-extension://${EXTENSION_ID}/popup.html`);
  const tab = { id: "7", type: "page", url: popupURL(EXTENSION_ID),
    webSocketDebuggerUrl: "ws://127.0.0.1:9222/devtools/page/7" };
  const action = { id: "8", type: "other", url: popupURL(EXTENSION_ID),
    webSocketDebuggerUrl: "ws://127.0.0.1:9222/devtools/other/8" };
  assert.equal(selectActionPopupTarget([tab], EXTENSION_ID, []).id, "7");
  assert.equal(selectActionPopupTarget([action], EXTENSION_ID, []).id, "8");
  assert.throws(() => selectActionPopupTarget([tab, action], EXTENSION_ID, []),
    /popup-target-ambiguous/);
  assert.throws(() => selectActionPopupTarget([action], EXTENSION_ID, ["8"]), /popup-not-opened/);
  const remote = { ...tab, id: "9", webSocketDebuggerUrl: "ws://example.test/devtools/page/9" };
  assert.throws(() => selectActionPopupTarget([remote], EXTENSION_ID, []), /popup-target-not-action/);
  const worker = { ...tab, id: "10", type: "service_worker" };
  assert.throws(() => selectActionPopupTarget([worker], EXTENSION_ID, []), /popup-target-not-action/);
  assert.throws(() => selectActionPopupTarget([tab, { ...tab, id: "11" }], EXTENSION_ID, []),
    /popup-target-ambiguous/);
  const wrongURL = { ...tab, id: "12", url: popupURL("other") };
  assert.throws(() => selectActionPopupTarget([wrongURL], EXTENSION_ID, []), /popup-not-opened/);
  assert.equal(parseDevToolsPort("9222\n/devtools/browser/x"), 9222);
  assert.throws(() => parseDevToolsPort("not-a-port"), /devtools-port-timeout/);
});

test("action popup context guard requires the tabless popup view and visible fixed URL", async () => {
  const url = popupURL(EXTENSION_ID);
  assert.equal(await assertActionPopupContext(contextTarget(), url), true);
  await assert.rejects(assertActionPopupContext(contextTarget({ current: { id: 7 } }), url),
    /popup-context-not-action/);
  await assert.rejects(assertActionPopupContext(contextTarget({ current: null }), url),
    /popup-context-not-action/);
  await assert.rejects(assertActionPopupContext(contextTarget({ views: [] }), url),
    /popup-context-not-action/);
  await assert.rejects(assertActionPopupContext(contextTarget({ views: [{ name: "other" }] }), url),
    /popup-context-not-action/);
  await assert.rejects(assertActionPopupContext(contextTarget({ hidden: true }), url),
    /popup-context-not-action/);
  await assert.rejects(assertActionPopupContext(contextTarget({ visibilityState: "hidden" }), url),
    /popup-context-not-action/);
  await assert.rejects(assertActionPopupContext(contextTarget({ href: `${url}?manual=1` }), url),
    /popup-context-not-action/);
});

test("action popup context guard refuses unavailable browser platform proof", async () => {
  const url = popupURL(EXTENSION_ID);
  await assert.rejects(assertActionPopupContext(contextTarget({ chromeApi: {} }), url),
    /popup-context-unavailable/);
  await assert.rejects(assertActionPopupContext(contextTarget({
    getViews: () => { throw new Error("platform"); },
  }), url), /popup-context-unavailable/);
  await assert.rejects(assertActionPopupContext(contextTarget({ getViews: () => "not-an-array" }), url),
    /popup-context-unavailable/);
  await assert.rejects(assertActionPopupContext(contextTarget({
    getCurrent: () => { throw new Error("platform"); },
  }), url), /popup-context-unavailable/);
});

test("CDP handshake removes throwing listeners after a later popup close", async () => {
  await withMockWebSocket(async () => {
    const popup = await attachActionPopup(POPUP_TARGET, { timeoutMs: 200 });
    assert.equal(popup.targetId, "7");
    const socket = MockWebSocket.instances.at(-1);
    assert.equal(socket.listeners.get("open")?.size || 0, 0);
    assert.equal(socket.listeners.get("close").size, 1);
    assert.equal(socket.listeners.get("error").size, 1);
    socket.emit("close");
    socket.emit("error");
    assert.equal(popup.targetId, "7");
  });
});

test("post-open CDP close or error rejects pending calls without uncaught throws", async () => {
  await withMockWebSocket(async () => {
    const popup = await attachActionPopup(POPUP_TARGET, { timeoutMs: 200 });
    let socket = MockWebSocket.instances.at(-1);
    MockWebSocket.respond = false;
    const pendingClose = popup.evaluate(() => 1);
    socket.emit("close");
    await assert.rejects(pendingClose, (error) => error?.code === "cdp-closed");

    MockWebSocket.instances = [];
    MockWebSocket.respond = true;
    const second = await attachActionPopup(POPUP_TARGET, { timeoutMs: 200 });
    socket = MockWebSocket.instances.at(-1);
    MockWebSocket.respond = false;
    const pendingError = second.evaluate(() => 1);
    socket.emit("error");
    await assert.rejects(pendingError, (error) => error?.code === "cdp-closed");
  });
});

test("CDP handshake rejects pre-open error, close and timeout with a fixed code", async () => {
  await withMockWebSocket(async () => {
    MockWebSocket.autoOpen = false;
    let pending = attachActionPopup(POPUP_TARGET, { timeoutMs: 500 });
    MockWebSocket.instances.at(-1).emit("error");
    await assert.rejects(pending, (error) => error?.code === "popup-attach-failed");

    MockWebSocket.instances = [];
    pending = attachActionPopup(POPUP_TARGET, { timeoutMs: 500 });
    MockWebSocket.instances.at(-1).emit("close");
    await assert.rejects(pending, (error) => error?.code === "popup-attach-failed");

    MockWebSocket.instances = [];
    await assert.rejects(attachActionPopup(POPUP_TARGET, { timeoutMs: 15 }),
      (error) => error?.code === "popup-attach-failed");
  });
});

test("a popup that never renders fails closed instead of being skipped", async () => {
  assert.throws(() => selectActionPopupTarget([], EXTENSION_ID, []), /popup-not-opened/);
  await assert.rejects(waitForActionPopup(65000, EXTENSION_ID, [], { timeoutMs: 3000, intervalMs: 20 }),
    /devtools-list-failed/);
});

test("pinned axe version and fixed extension identity", () => {
  assert.equal(AXE_VERSION, "4.10.3");
  assert.equal(validateAxeVersion("4.10.3"), true);
  assert.equal(validateAxeVersion("4.10.2"), false);
  assert.equal(extensionIdFromKey(KEY), EXTENSION_ID);
});

test("viewport and media matrix includes desktop, narrow, forced-colors and reduced-motion", () => {
  assert.deepEqual(VIEWPORTS.map((v) => v.id), ["desktop", "narrow-200pct-equivalent"]);
  assert.deepEqual(VIEWPORTS.map((v) => v.width), [1280, 640]);
  assert.deepEqual(MODES.map((m) => m.id), ["default", "forced-colors", "reduced-motion"]);
  assert.equal(MODES[2].reducedMotion, "reduce");
});

test("axe minimization keeps only rule id, impact and node count", () => {
  const result = minimizeAxeResult({
    violations: [{
      id: "color-contrast", impact: "serious",
      nodes: [{ html: "<input id='password' value='secret'>", target: ["#password"], failureSummary: "private" }],
    }],
    incomplete: [{ id: "focus-order", impact: "moderate", nodes: [{ target: ["#x"] }] }],
  });
  assert.deepEqual(result.violations, [{ id: "color-contrast", impact: "serious", nodes: 1 }]);
  assert.deepEqual(result.incomplete, [{ id: "focus-order", impact: "moderate", nodes: 1 }]);
  assert.equal(JSON.stringify(result).includes("secret"), false);
  assert.equal(JSON.stringify(result).includes("failureSummary"), false);
});

test("keyboard summary passes only when every focusable control is reached", () => {
  assert.equal(keyboardSummary({ total: 3, reached: 3, tabSteps: 4 }).status, "PASS");
  assert.equal(keyboardSummary({ total: 3, reached: 2, tabSteps: 4 }).status, "FAIL");
  assert.equal(keyboardSummary({ total: 0, reached: 0, tabSteps: 0 }).status, "FAIL");
  assert.equal(keyboardSummary({ total: 2, reached: 2, tabSteps: -1 }).status, "FAIL");
});

test("audit status fails violations, overflow, keyboard gaps and unlocked popup", () => {
  const base = { page: "options.html", violations: [], overflow: false, keyboard: { status: "PASS" }, locked: true };
  assert.equal(auditStatus(base), "PASS");
  assert.equal(auditStatus({ ...base, violations: [{ id: "x", impact: "minor", nodes: 1 }] }), "FAIL");
  assert.equal(auditStatus({ ...base, overflow: true }), "FAIL");
  assert.equal(auditStatus({ ...base, overflow: undefined }), "FAIL");
  assert.equal(auditStatus({ ...base, keyboard: { status: "FAIL" } }), "FAIL");
  assert.equal(auditStatus({ ...base, page: "popup.html", locked: false }), "FAIL");
});

test("driver failures and unknown arguments surface only fixed error enums", () => {
  assert.throws(() => parseArgs(["--not-an-option"]), /unknown-argument/);
  assert.equal(parseArgs(["--out"]).out, "");
  assert.equal(errorCode(new Error("secret /workspace/private path")), "driver-error");
  assert.throws(() => buildReceipt({ head: HEAD, failure: "random text" }), /receipt-failure-code/);
  assert.equal(buildReceipt({ head: HEAD, failure: "popup-context-not-action" }).failure,
    "popup-context-not-action");
  assert.equal(buildReceipt({ head: HEAD, failure: "popup-context-unavailable" }).failure,
    "popup-context-unavailable");
});

test("dirty product source refuses to claim HEAD as audit evidence", () => {
  const dirty = receipt(undefined, { sourceClean: false });
  assert.equal(dirty.state, "FAIL");
  assert.equal(dirty.failure, "source-dirty");
  assert.equal(dirty.source_clean, false);
  assert.throws(() => assertPublicReceipt({ ...receipt(), state: "PASS", source_clean: false }),
    /receipt-invalid/);
  const clean = receipt();
  assert.equal(clean.state, "PASS");
  assert.equal(clean.source_clean, true);
});

test("violations produce FAIL and nonzero-style state, never PASS", () => {
  const violation = { id: "color-contrast", impact: "serious", nodes: 2 };
  const failed = receipt([passingAudit({ violations: [violation], status: "FAIL" })]);
  assert.equal(failed.state, "FAIL");
  assert.equal(failed.summary.violations, 1);
  assert.throws(() => assertPublicReceipt(receipt([passingAudit({ violations: [violation] })])));
});

test("missing axe dependency is UNAVAILABLE with no audits, not PASS", () => {
  const unavailable = buildReceipt({ head: HEAD, axeStatus: "UNAVAILABLE", failure: "axe-unavailable" });
  assert.equal(unavailable.state, "UNAVAILABLE");
  assert.deepEqual(unavailable.audits, []);
  assert.equal(unavailable.axe.status, "UNAVAILABLE");
  assert.throws(() => assertPublicReceipt({ ...unavailable, state: "PASS" }));
  const withAudit = buildReceipt({ head: HEAD, axeStatus: "UNAVAILABLE", audits: [passingAudit()] });
  assert.equal(withAudit.state, "UNAVAILABLE");
  assert.deepEqual(withAudit.audits, []);
});

test("receipt rejects forbidden node payloads, selectors and private paths", () => {
  assert.throws(() => assertPublicReceipt({ ...receipt(), target: ["#password"] }), /receipt-invalid/);
  assert.throws(() => assertPublicReceipt({ ...receipt(), note: "/workspace/private" }), /receipt-invalid/);
  assert.throws(() => assertPublicReceipt({ ...receipt(), note: "chrome-extension://secret" }), /receipt-invalid/);
  assert.throws(() => assertPublicReceipt({ ...receipt(), selector: "#password" }), /receipt-invalid/);
});

test("receipt is public-only and carries honest emulation limits", () => {
  const value = receipt();
  assert.equal(value.schema, SCHEMA);
  assert.equal(value.state, "PASS");
  assert.equal(value.axe.version, "4.10.3");
  assert.equal(value.axe.source_sha256, SHA);
  assert(value.not_claimed.some((item) => item.includes("screen reader")));
  assert(value.not_claimed.some((item) => item.includes("not real OS zoom")));
  assert(value.not_claimed.some((item) => item.includes("physical Ctrl+Shift+Y")));
  assert.equal(JSON.stringify(value).includes("/workspace/"), false);
});

test("explicit axe source must be an absolute existing file", () => {
  const directory = mkdtempSync(join(tmpdir(), "locklark-a11y-test-"));
  try {
    const source = join(directory, "axe.min.js");
    writeFileSync(source, "globalThis.axe={version:'4.10.3'};");
    assert.equal(resolveAxeSource(source, {}), source);
    assert.equal(resolveAxeSource("", { LOCKLARK_TEST_AXE_SOURCE: source }), source);
    assert.throws(() => resolveAxeSource("relative/axe.min.js", {}), /axe-source-not-absolute/);
    assert.throws(() => resolveAxeSource(join(directory, "missing.js"), {}), /axe-source-unavailable/);
    assert.equal(sha256File(source).length, 64);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("output path refuses overwrite and missing output", () => {
  const directory = mkdtempSync(join(tmpdir(), "locklark-a11y-out-"));
  try {
    assert.throws(() => ensureNewOutput(""), /output-required/);
    const output = join(directory, "receipt.json");
    assert.equal(ensureNewOutput(output), output);
    writeFileSync(output, "{}");
    assert.throws(() => ensureNewOutput(output), /output-exists/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

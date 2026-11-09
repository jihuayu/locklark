const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

const POPUP = path.join(__dirname, "../popup.js");
const ID = "b".repeat(32);
const REV = "c".repeat(64);
const TICKET = "a".repeat(64);

function element() {
  return {
    textContent: "", value: "", checked: false, disabled: false, hidden: false,
    type: "", className: "", dataset: {}, style: {}, attributes: {},
    children: [], isConnected: true, listeners: new Map(),
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener(type, callback) { this.listeners.set(type, callback); },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; },
    removeAttribute(name) { delete this.attributes[name]; },
  };
}

function fakePort() {
  const listeners = new Map();
  return {
    messages: [], disconnected: false,
    onMessage: { addListener(callback) { listeners.set("message", callback); } },
    onDisconnect: { addListener(callback) { listeners.set("disconnect", callback); } },
    postMessage(message) { this.messages.push(message); },
    emit(message) { listeners.get("message")?.(message); },
    disconnect() { this.disconnected = true; listeners.get("disconnect")?.(); },
  };
}

function fixture() {
  return {
    id: ID, revision: REV, category: "login", title: "Login",
    urls: [], tags: [], notes: "",
    fields: [
      { id: "username", label: "用户名", type: "text", value: "ada" },
      { id: "password", label: "密码", type: "concealed", value: "", concealed: true, has_value: true, revealable: true },
    ],
  };
}

// Production exposes no hooks; this instrumentation is appended only inside
// the test's evaluated copy so popup.js and its runtime behavior stay intact.
function instrumentedPopup() {
  const source = fs.readFileSync(POPUP, "utf8");
  const closing = source.lastIndexOf("})();");
  const hooks = `
  globalThis.__nativeClipboardTest = {
    copySecret,
    detailLeaseLive,
    arm(detail) {
      popupInactive = false; lastDetail = detail; document.body.dataset.view = "detail";
      lastState = { connected: true, candidates: [], vaultItems: [] };
    },
    snapshot() { return { lastState, lastDetail, generation: secretGeneration, inactive: popupInactive, busy: nativeCopyBusy }; },
  };
`;
  return source.slice(0, closing) + hooks + source.slice(closing);
}

function harness(options = {}) {
  const elements = new Map(), requests = [], clipboardWrites = [], ports = [], windowListeners = new Map(), timers = new Map();
  let nextTimer = 1;
  const body = element();
  body.dataset.vault = "1"; body.dataset.view = "vault";
  const document = {
    body, visibilityState: "visible",
    querySelector(selector) { if (!elements.has(selector)) elements.set(selector, element()); return elements.get(selector); },
    querySelectorAll() { return []; }, createElement() { return element(); },
    createTextNode(text) { return { textContent: text }; }, addEventListener() {},
  };
  const state = () => ({ connected: true, origin: "https://example.test/", candidates: [], vaultItems: [],
    generatorDefaults: { mode: "random", length: 24 }, attachmentsSupported: true, clipboardClearSeconds: 30 });
  const context = {
    LocklarkCore: core, document,
    navigator: { clipboard: { value: "", writeText(value) { clipboardWrites.push(value); this.value = value; return Promise.resolve(); } } },
    chrome: { runtime: {
      sendMessage(message) {
        return new Promise((resolve) => {
          requests.push({ message, resolve });
          setImmediate(() => message.type === "copy-field"
            ? resolve({ copiedField: { value: options.legacyValue || "Legacy-Secret-9", clearAfterSeconds: 30 } })
            : resolve(state()));
        });
      },
      connect() {
        const port = fakePort();
        ports.push(port);
        setImmediate(() => port.emit({ type: "ready", native: options.native !== false }));
        return port;
      },
    } },
    URL, Blob, Uint8Array, crypto: webcrypto,
    setTimeout(callback) { const id = nextTimer++; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); }, setInterval() { return 1; }, clearInterval() {},
    addEventListener(type, callback) {
      if (!windowListeners.has(type)) windowListeners.set(type, []);
      windowListeners.get(type).push(callback);
    },
  };
  context.globalThis = context;
  vm.runInNewContext(instrumentedPopup(), context);
  return {
    elements, requests, ports, clipboardWrites, context,
    el(selector) { return elements.get(selector); },
    async flush() { for (let i = 0; i < 6; i++) await new Promise((resolve) => setImmediate(resolve)); },
    async arm(detail) { context.__nativeClipboardTest.arm(detail); await this.flush(); },
    async hide() { for (const callback of windowListeners.get("pagehide") || []) callback(); await this.flush(); },
  };
}

function copyButton() { const button = element(); button.textContent = "复制"; return button; }

async function begin(h, detail = fixture()) {
  await h.flush();
  await h.arm(detail);
  const button = copyButton();
  const pending = h.context.__nativeClipboardTest.copySecret(detail.fields[1], detail, button);
  await h.flush();
  return { detail, button, pending, port: h.ports[0], hook: h.context.__nativeClipboardTest };
}

function prepared(port, requestID, cleanup = 0) {
  port.emit({ type: "prepared", request_id: requestID, item_id: ID, revision: REV,
    field: "password", copy_ticket: TICKET, expires_in_seconds: 15, cleanup_ttl_seconds: cleanup });
}

test("native ready leases an exact field and a confirmed commit never writes JS clipboard", async () => {
  const h = harness();
  const { button, pending, port } = await begin(h);
  const prepare = port.messages[0];
  assert.equal(prepare.type, "prepare");
  assert.deepEqual({ ...prepare, request_id: undefined }, {
    type: "prepare", request_id: undefined, item_id: ID, revision: REV, field: "password",
  });
  assert.match(prepare.request_id, /^[a-f0-9]{32}$/);
  prepared(port, prepare.request_id);
  await h.flush();
  const commit = port.messages[1];
  assert.equal(commit.type, "commit");
  assert.deepEqual({ ...commit, request_id: undefined }, {
    type: "commit", request_id: undefined, item_id: ID, revision: REV, field: "password", copy_ticket: TICKET,
  });
  port.emit({ type: "result", request_id: commit.request_id, copy_ticket: TICKET,
    state: "confirmed", copied: true, cleanup_ttl_seconds: 0 });
  await h.flush();
  await pending;
  assert.equal(button.textContent, "已复制 ✓");
  assert.equal(h.clipboardWrites.length, 0, "native path must not call navigator.writeText");
  assert.equal(h.requests.some((row) => row.message.type === "copy-field"), false, "no legacy fallback");
  assert.equal(port.messages.some((message) => message.type === "cancel"), false, "confirmed ticket persists");
  assert.equal(port.disconnected, true);
});

test("hiding before prepared disconnects without writing a JS secret", async () => {
  const h = harness();
  const { detail, pending, port, hook } = await begin(h);
  assert.equal(port.messages[0]?.type, "prepare");
  await h.hide();
  await pending;
  assert.equal(port.disconnected, true);
  assert.equal(port.messages.some((message) => message.type === "commit"), false);
  assert.equal(h.clipboardWrites.length, 0);
  assert.equal(h.requests.some((row) => row.message.type === "copy-field"), false);
  assert.equal(hook.detailLeaseLive(detail, hook.snapshot().generation), false);
  prepared(port, port.messages[0].request_id);
  await h.flush();
  assert.equal(port.messages.some((message) => message.type === "commit"), false, "late prepared cannot commit");
});

test("hiding with a queued commit cancels its ticket and disconnects before any JS write", async () => {
  const h = harness();
  const { button, pending, port } = await begin(h);
  prepared(port, port.messages[0].request_id, 30);
  await h.flush();
  const commit = port.messages[1];
  assert.equal(commit.type, "commit");
  assert.equal(commit.copy_ticket, TICKET);
  await h.hide();
  await pending;
  const cancel = port.messages.find((message) => message.type === "cancel");
  assert.ok(cancel, "queued ticket must be cancelled");
  assert.equal(cancel.copy_ticket, TICKET);
  assert.match(cancel.request_id, /^[a-f0-9]{32}$/);
  assert.equal(port.disconnected, true);
  assert.equal(h.clipboardWrites.length, 0);
  assert.equal(h.requests.some((row) => row.message.type === "copy-field"), false);
  port.emit({ type: "result", request_id: commit.request_id, copy_ticket: TICKET,
    state: "confirmed", copied: true, cleanup_ttl_seconds: 0 });
  await h.flush();
  assert.equal(button.textContent, "复制", "late result must not show copied feedback");
});

test("unknown commit results never fall back; native:false hands off to the warned manual path", async () => {
  const h = harness();
  const { pending, port } = await begin(h);
  prepared(port, port.messages[0].request_id);
  await h.flush();
  const commit = port.messages[1];
  port.emit({ type: "result", request_id: commit.request_id, copy_ticket: TICKET,
    state: "unknown", copied: false, cleanup_ttl_seconds: 0 });
  await h.flush();
  await pending;
  assert.equal(h.clipboardWrites.length, 0);
  assert.equal(h.requests.some((row) => row.message.type === "copy-field"), false, "unknown never uses legacy");
  assert.match(h.el("#toast").textContent, /未确认/);

  const legacy = harness({ native: false, legacyValue: "Legacy-Secret-9" });
  const legacyParts = await begin(legacy);
  await legacyParts.pending;
  const request = legacy.requests.find((row) => row.message.type === "copy-field");
  assert.ok(request, "native:false must use the legacy copy-field request");
  assert.deepEqual({ ...request.message, request_id: undefined }, {
    type: "copy-field", request_id: undefined, id: ID, revision: REV, field: "password",
  });
  assert.deepEqual(legacy.clipboardWrites, ["Legacy-Secret-9"]);
  assert.match(legacy.el("#toast").textContent, /浏览器无法保证自动清除/);
  assert.equal(legacyParts.port.messages.length, 0);
  assert.equal(legacyParts.port.disconnected, true);
});

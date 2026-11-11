const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

const POPUP = fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8");
const TOKEN = "a".repeat(64);
const ITEM_ID = "b".repeat(32);
const ITEM_REV = "c".repeat(64);

function element(tag = "div") {
  const node = {
    tagName: tag.toUpperCase(),
    textContent: "",
    value: "",
    checked: false,
    disabled: false,
    hidden: false,
    type: "",
    className: "",
    dataset: {},
    style: {},
    attributes: {},
    children: [],
    listeners: new Map(),
    isConnected: true,
    scrollTop: 0,
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener(type, callback) { this.listeners.set(type, callback); },
    removeEventListener() {},
    append(...children) { this.children.push(...children); },
    prepend(...children) { this.children.unshift(...children); },
    replaceChildren(...children) { this.children = children; },
    remove() { this.removed = true; },
    focus() {},
    click() { this.listeners.get("click")?.({ target: this, isTrusted: true }); },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) {
      return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null;
    },
    removeAttribute(name) { delete this.attributes[name]; },
  };
  if (tag === "button") node.type = "button";
  return node;
}

function fakePort() {
  let onMessage = null, onDisconnect = null;
  const port = {
    messages: [],
    disconnected: false,
    onMessage: { addListener(callback) { onMessage = callback; } },
    onDisconnect: { addListener(callback) { onDisconnect = callback; } },
    postMessage(message) { port.messages.push(message); },
    emit(message) { onMessage?.(message); },
    disconnect() { port.disconnected = true; onDisconnect?.(); },
  };
  return port;
}

function fixtureDetail(overrides = {}) {
  return {
    id: ITEM_ID,
    revision: ITEM_REV,
    category: "login",
    title: "Route Target",
    username: "ada",
    has_password: true,
    has_otp: true,
    urls: ["https://example.test/login"],
    tags: [],
    notes: "",
    updated_at: "",
    state: "active",
    favorite: false,
    fields: [
      { id: "username", label: "用户名", type: "text", value: "ada", concealed: false },
      {
        id: "password", label: "密码", type: "concealed", value: "",
        concealed: true, has_value: true, revealable: true,
      },
    ],
    ...overrides,
  };
}

function harness(options = {}) {
  const elements = new Map();
  const requests = [];
  const ports = [];
  const clipboardWrites = [];
  const intervals = [];
  const windowListeners = new Map();
  const documentListeners = new Map();
  let hash = options.hash || "";
  const body = element("body");
  body.dataset.vault = "1";
  body.dataset.view = "vault";
  const document = {
    body,
    visibilityState: "visible",
    activeElement: null,
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector);
    },
    querySelectorAll() { return []; },
    createElement(tag) { return element(tag); },
    createTextNode(text) { return { textContent: text }; },
    addEventListener(type, callback) {
      if (!documentListeners.has(type)) documentListeners.set(type, []);
      documentListeners.get(type).push(callback);
    },
    removeEventListener() {},
  };
  const context = {
    LocklarkCore: core,
    document,
    location: {
      get hash() { return hash; },
    },
    navigator: {
      userActivation: { isActive: true },
      clipboard: {
        writeText(value) {
          clipboardWrites.push(value);
          return Promise.resolve();
        },
      },
    },
    chrome: {
      runtime: {
        id: "fixed",
        getURL: (p) => "chrome-extension://fixed/" + p,
        sendMessage(message) {
          return new Promise((resolve, reject) => {
            requests.push({ message, resolve, reject, taken: false });
          });
        },
        connect() {
          const port = fakePort();
          ports.push(port);
          return port;
        },
        openOptionsPage() {},
      },
      tabs: { create() {} },
    },
    URL,
    Blob,
    Uint8Array,
    TextEncoder,
    crypto: webcrypto,
    setTimeout() { return 1; },
    clearTimeout() {},
    setInterval(callback) { intervals.push(callback); return intervals.length; },
    clearInterval() {},
    addEventListener(type, callback) {
      if (!windowListeners.has(type)) windowListeners.set(type, []);
      windowListeners.get(type).push(callback);
    },
    removeEventListener() {},
  };
  context.globalThis = context;
  vm.runInNewContext(POPUP, context);
  const h = {
    elements,
    requests,
    ports,
    clipboardWrites,
    intervals,
    context,
    body,
    setHash(value) { hash = value; },
    el(selector) { return elements.get(selector) || document.querySelector(selector); },
    async flush() {
      for (let i = 0; i < 8; i++) await new Promise((resolve) => setImmediate(resolve));
    },
    take(type) {
      const call = requests.find((row) => !row.taken && row.message.type === type);
      assert.ok(call, "missing request " + type + " (sent: " +
        requests.map((row) => row.message.type).join(",") + ")");
      call.taken = true;
      return call;
    },
    types: () => requests.map((row) => row.message.type),
    async resolve(type, value) {
      h.take(type).resolve(value);
      await h.flush();
    },
    click(selector) {
      const node = h.el(selector);
      assert.ok(node, "missing " + selector);
      node.listeners.get("click")?.({ target: node, isTrusted: true });
    },
    async pagehide() {
      for (const callback of windowListeners.get("pagehide") || []) callback();
      await h.flush();
    },
    async pageshow() {
      for (const callback of windowListeners.get("pageshow") || []) callback();
      await h.flush();
    },
    keydown(key) {
      const event = { key, preventDefault() {} };
      for (const callback of documentListeners.get("keydown") || []) callback(event);
    },
    detailRow(fieldId) {
      return h.el("#detail-fields").children.find(
        (row) => row.dataset?.fieldId === fieldId,
      );
    },
    detailButton(fieldId, action) {
      const row = h.detailRow(fieldId);
      assert.ok(row, "missing field row " + fieldId);
      const button = row.children.find((child) => child.dataset?.action === action);
      assert.ok(button, "missing " + action + " for " + fieldId);
      return button;
    },
  };
  return h;
}

function vaultState(overrides = {}) {
  return {
    connected: true,
    quickFill: false,
    autoLogin: true,
    offerSavePasskeys: true,
    offerUsePasskeys: true,
    offerSaveLogins: true,
    status: "ready",
    origin: "https://example.test",
    candidates: [],
    pending: false,
    saveBlocked: false,
    pendingSave: null,
    generatorDefaults: {
      mode: "random", length: 24, digits: true, symbols: true,
      wordCount: 4, separator: "hyphens", capitalize: true, pinLength: 6,
    },
    generatedHistory: [],
    neverSaveOrigins: [],
    loginOverrides: {},
    site: { origin: "https://example.test", unsecured: false },
    vaultItems: [
      {
        id: ITEM_ID, revision: ITEM_REV, category: "login", title: "Route Target",
        subtitle: "", username: "ada", urls: ["https://example.test/login"],
        tags: [], fields: [], custom_fields: [], favorite: false, state: "active",
      },
    ],
    ...overrides,
  };
}

function claimedReply(overrides = {}) {
  const detail = fixtureDetail();
  return {
    type: "route-claimed",
    token: TOKEN,
    item_id: detail.id,
    revision: detail.revision,
    expires_in_seconds: 120,
    detail,
    ...overrides,
  };
}

async function openRoutePage(reply = claimedReply()) {
  const h = harness({ hash: "#route=" + TOKEN });
  await h.flush();
  const claim = h.take("route-claim");
  assert.equal(claim.message.token, TOKEN);
  claim.resolve(reply);
  await h.flush();
  return h;
}

// ---- 1. ordinary row click asks for a route tab, never a popup read ----
test("non-QuickFill row click sends only open-route", async () => {
  const h = harness();
  await h.flush();
  await h.resolve("state", vaultState({ quickFill: false }));
  const row = h.el("#vault-list").children[0];
  assert.ok(row, "vault row missing");
  row.listeners.get("click")({ target: row, isTrusted: true });
  await h.flush();
  assert.deepEqual(h.types(), ["state", "open-route"]);
  const sent = h.take("open-route").message;
  assert.deepEqual(
    { type: sent.type, id: sent.id, revision: sent.revision, quick_fill: sent.quick_fill },
    { type: "open-route", id: ITEM_ID, revision: ITEM_REV, quick_fill: false },
  );
  assert.equal(h.types().includes("item-get"), false, "route click read the item");
});

test("QuickFill true keeps the direct detail path", async () => {
  const h = harness();
  await h.flush();
  await h.resolve("state", vaultState({ quickFill: true }));
  const row = h.el("#vault-list").children[0];
  row.listeners.get("click")({ target: row, isTrusted: true });
  await h.flush();
  assert.equal(h.types().includes("open-route"), false);
  const read = h.take("item-get");
  assert.equal(read.message.id, ITEM_ID);
  read.resolve({ detail: fixtureDetail() });
  await h.flush();
  assert.equal(h.el("#detail-title").textContent, "Route Target");
  assert.equal(h.body.dataset.view, "detail");
});

// ---- 2. route bootstrap: one claim, no ordinary traffic ----
test("route page sends exactly one claim and renders only the exact reply", async () => {
  const h = harness({ hash: "#route=" + TOKEN });
  await h.flush();
  assert.deepEqual(h.types(), ["route-claim"]);
  h.requests[0].resolve(claimedReply());
  await h.flush();
  assert.deepEqual(h.types(), ["route-claim"], "route page sent ordinary traffic");
  assert.equal(h.el("#detail-title").textContent, "Route Target");
  assert.equal(h.body.dataset.view, "detail");
  assert.deepEqual(h.intervals, [], "route page started state polling");
  await h.pageshow();
  assert.deepEqual(h.types(), ["route-claim"], "pageshow requested state");
});

test("mismatched or rejected claims never render and report close", async () => {
  const cases = [
    claimedReply({ token: "d".repeat(64) }),
    claimedReply({ item_id: "d".repeat(32) }),
    claimedReply({ revision: "e".repeat(64) }),
    { error: "refused" },
  ];
  for (const reply of cases) {
    const h = harness({ hash: "#route=" + TOKEN });
    await h.flush();
    h.requests[0].resolve(reply);
    await h.flush();
    assert.equal(h.body.dataset.view === "detail", false, "mismatched claim rendered");
    assert.equal(h.el("#detail-title").textContent, "");
    assert.deepEqual(h.types(), ["route-claim", "route-close"]);
    assert.equal(h.take("route-close").message.token, TOKEN);
  }
});

test("a malformed route fragment fails closed without ordinary behavior", async () => {
  for (const hash of ["#route=", "#route=zzzz", "#route=" + TOKEN + "0"]) {
    const h = harness({ hash });
    await h.flush();
    assert.deepEqual(h.types(), [], "malformed route sent " + h.types().join(","));
    assert.notEqual(h.body.dataset.view, "detail", "malformed route rendered detail");
    assert.equal(h.el("#detail-title").textContent, "");
  }
});

// ---- 3. field copy keeps native approval; legacy uses route-copy-field ----
test("route native field copy keeps the exact native lease selector", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.ports[0];
  assert.ok(port, "native clipboard port not opened");
  port.emit({ type: "ready", native: true });
  await h.flush();
  assert.deepEqual(
    { type: port.messages[0].type, item_id: port.messages[0].item_id,
      revision: port.messages[0].revision, field: port.messages[0].field },
    { type: "prepare", item_id: ITEM_ID, revision: ITEM_REV, field: "password" },
  );
  port.emit({
    type: "prepared", request_id: port.messages[0].request_id,
    item_id: ITEM_ID, revision: ITEM_REV, field: "password",
    copy_ticket: "f".repeat(64), expires_in_seconds: 15, cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.equal(port.messages[1].type, "commit");
  port.emit({
    type: "result", request_id: port.messages[1].request_id,
    copy_ticket: "f".repeat(64), state: "confirmed", copied: true,
    cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.equal(h.types().includes("route-copy-field"), false);
  assert.equal(h.types().includes("copy-field"), false);
  assert.deepEqual(h.clipboardWrites, [], "native path wrote the JS clipboard");
});

test("route legacy field copy uses route-copy-field only and scrubs the value", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.ports[0];
  port.emit({ type: "ready", native: false });
  await h.flush();
  const legacy = h.take("route-copy-field").message;
  assert.deepEqual(
    { type: legacy.type, token: legacy.token, item_id: legacy.item_id,
      revision: legacy.revision, field: legacy.field },
    { type: "route-copy-field", token: TOKEN, item_id: ITEM_ID,
      revision: ITEM_REV, field: "password" },
  );
  h.requests.find((row) => row.message.type === "route-copy-field").resolve({
    copiedField: {
      value: "legacy-secret", field: "password", revision: ITEM_REV,
      expires_in_seconds: 30, clearAfterSeconds: 30,
    },
  });
  await h.flush();
  assert.deepEqual(h.clipboardWrites, ["legacy-secret"]);
  assert.equal(h.types().includes("copy-field"), false);
  // A plain (non-secret) field also goes through the route's approved copy,
  // never a bare local write of the displayed value.
  const username = h.detailButton("username", "copy-field");
  username.listeners.get("click")();
  await h.flush();
  h.ports[h.ports.length - 1].emit({ type: "ready", native: false });
  await h.flush();
  const again = h.take("route-copy-field");
  assert.equal(again.message.field, "username");
  again.resolve({
    copiedField: {
      value: "ada", field: "username", revision: ITEM_REV,
      expires_in_seconds: 30, clearAfterSeconds: 30,
    },
  });
  await h.flush();
  assert.deepEqual(h.clipboardWrites, ["legacy-secret", "ada"]);
  assert.equal(h.types().includes("copy-field"), false);
  assert.equal(h.types().includes("reveal-field"), false);
});

// ---- 4. Back/Escape/pagehide close the route once ----
test("route Back, Escape and pagehide wipe and report close once", async () => {
  const h = await openRoutePage();
  h.keydown("Escape");
  await h.flush();
  assert.equal(h.body.dataset.view === "detail", false);
  assert.deepEqual(h.el("#detail-fields").children, []);
  assert.deepEqual(h.types(), ["route-claim", "route-close"]);
  assert.equal(h.take("route-close").message.token, TOKEN);
  h.click("#detail-back");
  await h.pagehide();
  assert.deepEqual(h.types(), ["route-claim", "route-close"], "close was reported twice");
});

// ---- 5. read/copy only: unsupported controls cannot act ----
test("route page hides and cannot invoke unsupported actions", async () => {
  const h = await openRoutePage();
  const controls = [
    "#detail-fill", "#detail-otp", "#detail-open-fill", "#detail-edit",
    "#detail-favorite", "#detail-archive", "#detail-trash", "#detail-history",
    "#detail-history-load", "#detail-add-site", "#attachment-upload",
    "#attachment-file", "#passkey-detail",
  ];
  for (const selector of controls) {
    assert.equal(h.el(selector).hidden, true, selector + " is visible");
  }
  // Actionable controls are also disabled, not merely hidden.
  for (const selector of [
    "#detail-fill", "#detail-otp", "#detail-open-fill", "#detail-edit",
    "#detail-favorite", "#detail-archive", "#detail-trash",
    "#detail-history-load", "#detail-add-site", "#attachment-upload",
    "#attachment-file",
  ]) {
    assert.equal(h.el(selector).disabled, true, selector + " is still enabled");
  }
  const passwordRow = h.detailRow("password");
  assert.equal(
    passwordRow.children.some((child) => child.dataset?.action === "toggle-reveal"),
    false,
    "route page offered reveal",
  );
  assert.equal(
    h.el("#detail-urls").children.some((row) =>
      row.children.some((child) => child.dataset?.action === "open-and-fill")),
    false,
    "route page offered open-and-fill",
  );
  const before = h.requests.length;
  for (const selector of controls) h.el(selector).listeners.get("click")?.({});
  await h.flush();
  assert.equal(h.requests.length, before, "an unsupported control sent a message");
  assert.equal(h.types().includes("route-close"), false);
  assert.equal(h.body.dataset.view, "detail");
});

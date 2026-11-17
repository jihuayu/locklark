const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto, randomUUID } = require("node:crypto");
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
  const lifecyclePorts = [];
  const clipboardWrites = [];
  const intervals = [];
  const windowListeners = new Map();
  const documentListeners = new Map();
  // Virtual page clock and its timer registry. A timer keeps the delay it was
  // armed with, so a test can fire exactly one still-pending timer (next()).
  const RealDate = Date;
  let clock = RealDate.now();
  let nextTimer = 1;
  let nowHook = null;
  const timers = new Map();
  class ClockDate extends RealDate {
    constructor(...args) {
      if (args.length) super(...args);
      else super(clock);
    }
    static now() {
      const value = clock;
      nowHook?.(value);
      return value;
    }
  }
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
        connect(options = {}) {
          const port = fakePort();
          port.name = options.name || "";
          if (port.name === "route-lifecycle") lifecyclePorts.push(port);
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
    // The page mints native request ids from randomUUID; the lease cancel
    // path uses one too.
    crypto: { ...webcrypto, randomUUID: () => randomUUID() },
    // The page reads the same clock this harness advances.
    Date: ClockDate,
    setTimeout(callback, ms = 0) {
      const handle = nextTimer++;
      timers.set(handle, { callback, ms });
      return handle;
    },
    clearTimeout(handle) { timers.delete(handle); },
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
    lifecyclePorts,
    nativePorts: () => ports.filter((port) => port.name !== "route-lifecycle"),
    clipboardWrites,
    intervals,
    context,
    body,
    // Timers still pending, in arm order, with the delay each was armed with.
    pendingTimers: () => [...timers].map(([handle, timer]) => ({ handle, ms: timer.ms })),
    now: () => clock,
    advanceClock(ms) { clock += ms; },
    // Lets one test move the clock between two Date.now() reads inside the
    // synchronous claim validation-to-arm handoff.
    setNowHook(callback) { nowHook = callback; },
    // Fire the oldest still-pending timer exactly as armed, without moving
    // the clock, then let its continuations settle.
    async next() {
      const first = timers.entries().next();
      assert.equal(first.done, false, "no pending page timer");
      const [handle, timer] = first.value;
      timers.delete(handle);
      timer.callback();
      await h.flush();
      return { handle, ms: timer.ms };
    },
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
    async visibility(state) {
      document.visibilityState = state;
      // Surface a listener's own failure at this call, not as a stalled flow.
      for (const callback of documentListeners.get("visibilitychange") || [])
        try {
          callback();
        } catch (error) {
          await h.flush();
          throw error;
        }
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

function claimedReply(overrides = {}, now = Date.now()) {
  const detail = fixtureDetail();
  return {
    type: "route-claimed",
    token: TOKEN,
    item_id: detail.id,
    revision: detail.revision,
    // The worker's exact original deadline, in UTC epoch milliseconds.
    expires_at_ms: now + 120000,
    detail,
    ...overrides,
  };
}

// A function reply receives the virtual instant at which the page resolves
// its claim, so tests can construct an exact absolute deadline.
async function openRoutePage(reply) {
  const h = harness({ hash: "#route=" + TOKEN });
  await h.flush();
  const lifecycle = h.lifecyclePorts[0];
  assert.ok(lifecycle, "route lifecycle port was not opened");
  lifecycle.emit({ type: "route-ready", token: TOKEN });
  await h.flush();
  const claim = h.take("route-claim");
  assert.equal(claim.message.token, TOKEN);
  claim.resolve(
    typeof reply === "function"
      ? reply(h.now())
      : reply ?? claimedReply({}, h.now()),
  );
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
  assert.deepEqual(h.types(), [], "the claim preceded the lifecycle ready");
  assert.equal(h.lifecyclePorts.length, 1, "route lifecycle port missing");
  h.lifecyclePorts[0].emit({ type: "route-ready", token: TOKEN });
  await h.flush();
  assert.deepEqual(h.types(), ["route-claim"]);
  h.requests[0].resolve(claimedReply({}, h.now()));
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
    h.lifecyclePorts[0].emit({ type: "route-ready", token: TOKEN });
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

// ---- 2a. the visible status proves the page entered its claim ----
test("route claim shows one fixed pending status until a valid reply", async () => {
  const PENDING = "正在请求桌面审批…";
  const h = harness({ hash: "#route=" + TOKEN });
  await h.flush();
  // Nothing is claimed before the lifecycle is ready, so nothing is shown.
  assert.equal(h.el("#status").textContent, "");
  h.lifecyclePorts[0].emit({ type: "route-ready", token: TOKEN });
  await h.flush();
  // The claim left this page with the fixed pending text already visible.
  assert.equal(h.requests[0].message.type, "route-claim");
  assert.equal(h.el("#status").textContent, PENDING);
  assert.equal(h.body.dataset.view, "vault");
  h.requests[0].resolve(claimedReply({}, h.now()));
  await h.flush();
  // A valid reply clears the pending text before the detail renders.
  assert.equal(h.el("#status").textContent, "");
  assert.equal(h.el("#detail-title").textContent, "Route Target");
  assert.equal(h.body.dataset.view, "detail");
});

test("a rejected route claim keeps its fixed failure status, never the pending text", async () => {
  const h = harness({ hash: "#route=" + TOKEN });
  await h.flush();
  h.lifecyclePorts[0].emit({ type: "route-ready", token: TOKEN });
  await h.flush();
  h.requests[0].resolve({ error: "refused" });
  await h.flush();
  assert.equal(h.el("#status").textContent, "无法打开此条目");
  assert.equal(h.body.dataset.view, "closed");
});

// ---- 3. field copy keeps native approval; legacy uses route-copy-field ----
test("route native field copy keeps the exact native lease selector", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.nativePorts()[0];
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
  const port = h.nativePorts()[0];
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

// ---- 2b. real route lifecycle port wipes the page on revocation ----
test("a route-revoked lifecycle message wipes detail and cancels a prepare", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const native = h.ports.find((port) => port.name !== "route-lifecycle");
  native.emit({ type: "ready", native: true });
  await h.flush();
  assert.equal(native.messages[0].type, "prepare");
  const lifecycle = h.lifecyclePorts[0];
  // The background's real revoke path sends only the token.
  lifecycle.emit({ type: "route-revoked", token: TOKEN });
  await h.flush();
  assert.equal(native.disconnected, true, "the native clipboard lease survived revocation");
  assert.equal(h.body.dataset.view === "detail", false);
  assert.deepEqual(h.el("#detail-fields").children, []);
  assert.equal(h.take("route-close").message.token, TOKEN);
  assert.equal(lifecycle.disconnected, true);
  // A late preparation can no longer commit.
  native.emit({
    type: "prepared", request_id: native.messages[0].request_id,
    item_id: ITEM_ID, revision: ITEM_REV, field: "password",
    copy_ticket: "f".repeat(64), expires_in_seconds: 15, cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.equal(native.messages.some((message) => message.type === "commit"), false);
  assert.deepEqual(h.clipboardWrites, []);
  // No ordinary reads or second claim are attempted after revocation.
  assert.deepEqual(h.types(), ["route-claim", "route-close"]);
});

test("a wrong-token or wrong-type lifecycle message is ignored", async () => {
  const h = await openRoutePage();
  const lifecycle = h.lifecyclePorts[0];
  lifecycle.emit({ type: "route-revoked", token: "d".repeat(64) });
  lifecycle.emit({ type: "route-ready", token: TOKEN });
  lifecycle.emit({ type: "something", token: TOKEN });
  await h.flush();
  assert.equal(h.body.dataset.view, "detail");
  assert.equal(h.el("#detail-title").textContent, "Route Target");
  assert.deepEqual(h.types(), ["route-claim"]);
});

test("a lifecycle port disconnect fails the route page closed", async () => {
  const h = await openRoutePage();
  const lifecycle = h.lifecyclePorts[0];
  lifecycle.disconnect();
  await h.flush();
  assert.equal(h.body.dataset.view === "detail", false);
  assert.deepEqual(h.el("#detail-fields").children, []);
  assert.equal(h.take("route-close").message.token, TOKEN);
});

test("the claim waits for a matching lifecycle ready", async () => {
  const h = harness({ hash: "#route=" + TOKEN });
  await h.flush();
  const lifecycle = h.lifecyclePorts[0];
  // A ready for another token is not this route's readiness.
  lifecycle.emit({ type: "route-ready", token: "d".repeat(64) });
  await h.flush();
  assert.deepEqual(h.types(), [], "claim sent before a matching ready");
  lifecycle.emit({ type: "route-ready", token: TOKEN });
  await h.flush();
  assert.deepEqual(h.types(), ["route-claim"]);
});

// ---- 3b. native copy survives the desktop approval focus transition ----
test("route native copy survives the page being hidden for approval", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.nativePorts()[0];
  port.emit({ type: "ready", native: true });
  await h.flush();
  assert.equal(port.messages[0].type, "prepare");
  // Desktop V2 approval brings its own window forward and hides the browser.
  await h.visibility("hidden");
  assert.equal(port.disconnected, false, "the route copy was cancelled by focus");
  assert.equal(port.messages.some((message) => message.type === "cancel"), false);
  assert.equal(h.types().includes("route-close"), false);
  port.emit({
    type: "prepared", request_id: port.messages[0].request_id,
    item_id: ITEM_ID, revision: ITEM_REV, field: "password",
    copy_ticket: "f".repeat(64), expires_in_seconds: 15, cleanup_ttl_seconds: 30,
  });
  await h.flush();
  const commit = port.messages.find((message) => message.type === "commit");
  assert.ok(commit, "commit was not sent while hidden");
  assert.deepEqual(
    { item_id: commit.item_id, revision: commit.revision,
      field: commit.field, copy_ticket: commit.copy_ticket },
    { item_id: ITEM_ID, revision: ITEM_REV, field: "password", copy_ticket: "f".repeat(64) },
  );
  port.emit({
    type: "result", request_id: commit.request_id,
    copy_ticket: "f".repeat(64), state: "confirmed", copied: true,
    cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.deepEqual(h.clipboardWrites, [], "native path wrote the JS clipboard");
  assert.equal(h.types().includes("route-copy-field"), false);
});

test("a route hidden before the click does not authorize a new copy", async () => {
  const h = await openRoutePage();
  await h.visibility("hidden");
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  assert.deepEqual(h.nativePorts(), [], "a hidden route opened a native clipboard port");
  assert.equal(h.types().includes("route-copy-field"), false);
});

test("pagehide while hidden cancels and a late prepare cannot commit", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.nativePorts()[0];
  port.emit({ type: "ready", native: true });
  await h.flush();
  await h.visibility("hidden");
  assert.equal(port.disconnected, false);
  await h.pagehide();
  assert.equal(port.disconnected, true, "pagehide kept the native port open");
  assert.deepEqual(h.el("#detail-fields").children, []);
  assert.equal(h.take("route-close").message.token, TOKEN);
  // A late preparation must never become a commit.
  port.emit({
    type: "prepared", request_id: port.messages[0].request_id,
    item_id: ITEM_ID, revision: ITEM_REV, field: "password",
    copy_ticket: "f".repeat(64), expires_in_seconds: 15, cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.equal(port.messages.some((message) => message.type === "commit"), false);
  assert.deepEqual(h.clipboardWrites, []);
});

test("Back while hidden cancels the in-flight route copy", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.nativePorts()[0];
  port.emit({ type: "ready", native: true });
  await h.flush();
  await h.visibility("hidden");
  h.click("#detail-back");
  await h.flush();
  assert.equal(port.disconnected, true, "Back kept the native port open");
  assert.equal(h.take("route-close").message.token, TOKEN);
  port.emit({
    type: "prepared", request_id: port.messages[0].request_id,
    item_id: ITEM_ID, revision: ITEM_REV, field: "password",
    copy_ticket: "f".repeat(64), expires_in_seconds: 15, cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.equal(port.messages.some((message) => message.type === "commit"), false);
  assert.deepEqual(h.clipboardWrites, []);
});

test("a revoked route cannot commit or show copy success", async () => {
  const h = await openRoutePage();
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.nativePorts()[0];
  port.emit({ type: "ready", native: true });
  await h.flush();
  await h.visibility("hidden");
  // The background revoked the route (tab switch/source change) and says so
  // on the route lifecycle port, which must cancel the native lease.
  h.lifecyclePorts[0].emit({ type: "route-revoked", token: TOKEN });
  await h.flush();
  assert.equal(port.disconnected, true);
  port.emit({
    type: "prepared", request_id: port.messages[0].request_id,
    item_id: ITEM_ID, revision: ITEM_REV, field: "password",
    copy_ticket: "f".repeat(64), expires_in_seconds: 15, cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.equal(port.messages.some((message) => message.type === "commit"), false);
  assert.deepEqual(h.clipboardWrites, []);
  assert.notEqual(button.textContent, "已复制 ✓");
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

// ---- 6. the page's own deadline derived from the claim's remainder ----
// Every timer the route page leaves pending must be the one deadline it armed
// from the claim: the page schedules nothing else.
const pageTimers = (h) => h.pendingTimers();
function assertWiped(h, label) {
  assert.notEqual(h.body.dataset.view, "detail", label + " kept the detail view");
  assert.equal(h.body.dataset.view, "closed", label + " did not close the view");
  assert.deepEqual(h.el("#detail-fields").children, [], label + " kept field rows");
  assert.equal(h.el("#detail-title").textContent, "", label + " kept the title");
}
// The page arms the claim's one absolute deadline at the instant it resolves.
// Time is always measured from that instant, never from when the harness
// started.
async function claimResolvedAt(seconds = 120) {
  const h = await openRoutePage((now) =>
    claimedReply({ expires_at_ms: now + seconds * 1000 }),
  );
  const armedAt = h.now();
  assert.equal(h.body.dataset.view, "detail");
  return {
    h,
    armedAt,
    // Move the page clock so that `seconds` have elapsed since arming.
    advanceToElapsed(seconds) {
      h.advanceClock(seconds * 1000 - (h.now() - armedAt));
    },
  };
}

test("a non-120 absolute claim deadline arms exactly that instant and wipes at it", async () => {
  const page = await claimResolvedAt(45);
  const h = page.h;
  assert.equal(h.el("#detail-title").textContent, "Route Target");
  const timers = pageTimers(h);
  assert.equal(timers.length, 1, "expected exactly the route deadline timer");
  assert.equal(timers[0].ms, 45 * 1000, "the exact original deadline was armed");
  // A repeated or later route message never re-arms or extends the deadline.
  h.lifecyclePorts[0].emit({ type: "route-ready", token: TOKEN });
  h.lifecyclePorts[0].emit({ type: "route-revoked", token: "d".repeat(64) });
  await h.flush();
  assert.deepEqual(pageTimers(h), timers, "a route message re-armed the deadline");
  // pageshow returns early for a route page, and hiding/revealing only checks
  // the deadline already armed: neither re-derives nor restarts it.
  await h.pageshow();
  await h.visibility("hidden");
  await h.visibility("visible");
  assert.deepEqual(pageTimers(h), timers, "pageshow/visibility restarted the deadline");
  assert.deepEqual(h.types(), ["route-claim"]);
  // At the original deadline the timer wipes through the ordinary revoke path.
  page.advanceToElapsed(45);
  const fired = await h.next();
  assert.equal(fired.ms, 45 * 1000);
  assertWiped(h, "an expired route");
  assert.equal(h.el("#status").textContent, "条目已失效，请重新从金库打开");
  assert.equal(h.lifecyclePorts[0].disconnected, true, "the lifecycle port stayed open");
  // Wiping reports close exactly once; later close paths are no-ops.
  await h.pagehide();
  h.keydown("Escape");
  h.click("#detail-back");
  await h.flush();
  assert.deepEqual(h.types(), ["route-claim", "route-close"], "close was reported twice");
  assert.equal(h.take("route-close").message.token, TOKEN);
  assert.deepEqual(h.pendingTimers(), [], "the route deadline survived its own wipe");
});

test("a claim 2.5s after a 120s grant stays live at 119.9s and wipes at 120s", async () => {
  // The real regression: the claim resolves 2500 ms after the grant began.
  // The old reply floored the 117.5s remainder to 117s, so the page wiped
  // about half a second before the grant's full 120s deadline. The absolute
  // deadline keeps the remaining 117500 ms exactly.
  const h = await openRoutePage((now) =>
    claimedReply({ expires_at_ms: now - 2500 + 120000 }),
  );
  assert.equal(h.body.dataset.view, "detail");
  assert.deepEqual(pageTimers(h).map((timer) => timer.ms), [117500]);
  // 119900 ms after the grant is still 100 ms before its deadline.
  h.advanceClock(117400);
  assert.equal(h.body.dataset.view, "detail", "the route wiped before its full TTL");
  assert.equal(h.el("#detail-title").textContent, "Route Target");
  assert.deepEqual(pageTimers(h).map((timer) => timer.ms), [117500]);
  // Exactly 120000 ms after the grant, the same timer wipes it.
  h.advanceClock(100);
  const fired = await h.next();
  assert.equal(fired.ms, 117500);
  assertWiped(h, "the original absolute deadline");
  assert.deepEqual(h.types(), ["route-claim", "route-close"]);
});

test("an expiry between validation and arming never renders the detail", async () => {
  const h = harness({ hash: "#route=" + TOKEN });
  await h.flush();
  h.lifecyclePorts[0].emit({ type: "route-ready", token: TOKEN });
  await h.flush();
  const reply = claimedReply({ expires_at_ms: h.now() + 100 });
  let advanced = false;
  h.setNowHook(() => {
    if (advanced) return;
    advanced = true;
    // The first Date.now() is validation's snapshot. Move the clock to the
    // deadline before the arm's own Date.now() recheck.
    h.advanceClock(100);
    h.setNowHook(null);
  });
  h.requests[0].resolve(reply);
  await h.flush();
  assert.equal(advanced, true, "the claim was not validated");
  assertWiped(h, "a deadline that passed before arming");
  assert.equal(h.el("#detail-title").textContent, "");
  assert.equal(h.el("#status").textContent, "条目已失效，请重新从金库打开");
  assert.deepEqual(pageTimers(h), [], "an expired claim armed a timer");
  assert.deepEqual(h.types(), ["route-claim", "route-close"]);
  assert.equal(h.take("route-close").message.token, TOKEN);
});

test("an early deadline timer rechecks the same absolute deadline and re-arms the remainder", async () => {
  const page = await claimResolvedAt(30);
  const h = page.h;
  assert.equal(pageTimers(h)[0].ms, 30 * 1000);
  // The callback runs with half the remainder still left: nothing is wiped
  // and the remaining 15 s of the same deadline is armed.
  page.advanceToElapsed(15);
  const early = await h.next();
  assert.equal(early.ms, 30 * 1000);
  assert.equal(h.body.dataset.view, "detail", "an early timer wiped a live route");
  assert.equal(h.el("#detail-fields").children.length > 0, true);
  assert.deepEqual(pageTimers(h).map((timer) => timer.ms), [15 * 1000]);
  assert.deepEqual(h.types(), ["route-claim"]);
  // A second early delivery (1 s left) still only re-arms 1 s.
  page.advanceToElapsed(29);
  const again = await h.next();
  assert.equal(again.ms, 15 * 1000);
  assert.equal(h.body.dataset.view, "detail");
  assert.deepEqual(pageTimers(h).map((timer) => timer.ms), [1 * 1000]);
  page.advanceToElapsed(30);
  const expiry = await h.next();
  assert.equal(expiry.ms, 1 * 1000);
  assertWiped(h, "a route past its deadline");
  assert.deepEqual(h.types(), ["route-claim", "route-close"]);
});

test("a missing, malformed, expired or oversized claim deadline never renders", async () => {
  const cases = [
    ["missing", () => claimedReply({ expires_at_ms: undefined })],
    ["legacy-seconds-only", () => claimedReply({ expires_at_ms: undefined, expires_in_seconds: 120 })],
    ["zero", (now) => claimedReply({ expires_at_ms: 0 }, now)],
    ["negative", (now) => claimedReply({ expires_at_ms: now - 5 }, now)],
    ["already-expired", (now) => claimedReply({ expires_at_ms: now - 1 }, now)],
    ["expires-now", (now) => claimedReply({ expires_at_ms: now }, now)],
    ["overlong-by-one-ms", (now) => claimedReply({ expires_at_ms: now + 120001 }, now)],
    ["overlong", (now) => claimedReply({ expires_at_ms: now + 3600000 }, now)],
    ["fractional", (now) => claimedReply({ expires_at_ms: now + 45500.5 }, now)],
    ["string", (now) => claimedReply({ expires_at_ms: String(now + 45000) }, now)],
    ["nan", () => claimedReply({ expires_at_ms: Number.NaN })],
    ["infinite", () => claimedReply({ expires_at_ms: Number.POSITIVE_INFINITY })],
    ["unsafe-integer", () => claimedReply({ expires_at_ms: Number.MAX_SAFE_INTEGER + 2 })],
  ];
  for (const [label, makeReply] of cases) {
    const h = harness({ hash: "#route=" + TOKEN });
    await h.flush();
    h.lifecyclePorts[0].emit({ type: "route-ready", token: TOKEN });
    await h.flush();
    h.requests[0].resolve(makeReply(h.now()));
    await h.flush();
    assertWiped(h, label);
    assert.equal(h.el("#detail-title").textContent, "", label + " rendered the title");
    assert.deepEqual(pageTimers(h), [], label + " armed a deadline");
    assert.deepEqual(h.types(), ["route-claim", "route-close"], label + " did not report close");
    assert.equal(h.take("route-close").message.token, TOKEN);
  }
});

test("a hidden route past its deadline wipes during an in-flight copy", async () => {
  const page = await claimResolvedAt(30);
  const h = page.h;
  const button = h.detailButton("password", "copy-field");
  button.listeners.get("click")();
  await h.flush();
  const port = h.nativePorts()[0];
  port.emit({ type: "ready", native: true });
  await h.flush();
  assert.equal(port.messages[0].type, "prepare");
  // The copy is still awaiting approval when the deadline passes and the
  // browser hides: the copy alone must not keep an expired route alive.
  page.advanceToElapsed(30);
  await h.visibility("hidden");
  assertWiped(h, "an expired hidden route");
  assert.equal(h.el("#status").textContent, "条目已失效，请重新从金库打开");
  assert.equal(port.disconnected, true, "the copy's native lease outlived the route");
  assert.deepEqual(h.take("route-close").message.token, TOKEN);
  // A late preparation can no longer commit, and no other read follows.
  port.emit({
    type: "prepared", request_id: port.messages[0].request_id,
    item_id: ITEM_ID, revision: ITEM_REV, field: "password",
    copy_ticket: "f".repeat(64), expires_in_seconds: 15, cleanup_ttl_seconds: 30,
  });
  await h.flush();
  assert.equal(port.messages.some((message) => message.type === "commit"), false);
  assert.deepEqual(h.clipboardWrites, []);
  assert.deepEqual(h.types(), ["route-claim", "route-close"]);
});

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

// Production popup.js is loaded into a DOM shim and every assertion below is
// made against real handlers (lock, generate, copy, pagehide/pageshow, vault
// search) with deferred runtime replies. No source-string assertions.
const flush = () => new Promise((resolve) => setImmediate(resolve));
async function settle(turns = 8) {
  for (let i = 0; i < turns; i++) await flush();
}

function element() {
  return {
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
    parent: null,
    classList: { add() {}, remove() {}, toggle() {} },
    listeners: new Map(),
    addEventListener(type, callback) {
      this.listeners.set(type, callback);
    },
    append(...children) {
      for (const child of children) {
        if (child && typeof child === "object") child.parent = this;
        this.children.push(child);
      }
    },
    prepend(child) {
      if (child && typeof child === "object") child.parent = this;
      this.children.unshift(child);
    },
    replaceChildren(...children) {
      this.children = [];
      this.append(...children);
    },
    querySelector() {
      return null;
    },
    remove() {
      if (!this.parent) return;
      const index = this.parent.children.indexOf(this);
      if (index >= 0) this.parent.children.splice(index, 1);
    },
    click() {},
    focus() {},
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null;
    },
    removeAttribute(name) {
      delete this.attributes[name];
    },
  };
}

const HISTORY_ENTRY = {
  id: "a".repeat(32),
  origin: "https://example.test/",
  username: "ada",
  password: "History-Secret-9",
  profile: { mode: "random", entropy_bits_floor: 80 },
};

function connectedState(overrides = {}) {
  return {
    connected: true,
    status: "ready",
    origin: "https://example.test/",
    pending: false,
    saveBlocked: false,
    pendingSave: null,
    candidates: [],
    generatedHistory: [HISTORY_ENTRY],
    generatorDefaults: { mode: "random", length: 24 },
    neverSaveOrigins: [],
    online: true,
    ...overrides,
  };
}
function disconnectedState(overrides = {}) {
  return connectedState({
    connected: false,
    status: "已锁定",
    generatedHistory: [],
    candidates: [],
    ...overrides,
  });
}

function harness() {
  const elements = new Map();
  const requests = [];
  const clipboardWrites = [];
  const lifecycles = new Map();
  let poll = null;
  const document = {
    body: { dataset: { vault: "1" } },
    visibilityState: "visible",
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector);
    },
    querySelectorAll(selector) {
      if (selector === "#filter-tabs [data-filter]")
        return [this.querySelector("#tab-passkeys")];
      return [];
    },
    createElement: element,
    createTextNode: (text) => ({ textContent: text }),
    addEventListener() {},
  };
  document.querySelector("#tab-passkeys").dataset.filter = "passkeys";
  const context = {
    LocklarkCore: core,
    document,
    navigator: {
      clipboard: {
        writeText(value) {
          clipboardWrites.push(value);
          return Promise.resolve();
        },
      },
    },
    chrome: {
      runtime: {
        sendMessage(message) {
          return new Promise((resolve, reject) => {
            requests.push({ message, resolve, reject, taken: false });
          });
        },
      },
    },
    crypto: webcrypto,
    Blob,
    URL,
    Uint8Array,
    setTimeout,
    clearTimeout,
    setInterval(callback) {
      poll = callback;
      return 0;
    },
    clearInterval: () => {},
    addEventListener(type, callback) {
      if (!lifecycles.has(type)) lifecycles.set(type, []);
      lifecycles.get(type).push(callback);
    },
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8"),
    context,
  );
  return {
    requests,
    clipboardWrites,
    el: (selector) => document.querySelector(selector),
    take(type) {
      const call = requests.find((r) => !r.taken && r.message.type === type);
      assert.ok(call, "missing " + type + " request");
      call.taken = true;
      return call;
    },
    pending(type) {
      return requests.filter((r) => !r.taken && r.message.type === type);
    },
    fire(selector, type, payload = {}) {
      const target = document.querySelector(selector);
      const listener = target.listeners.get(type);
      assert.ok(listener, "missing " + type + " listener on " + selector);
      listener({ target, ...payload });
    },
    dispatchLifecycle(type) {
      for (const callback of lifecycles.get(type) || []) callback();
    },
    poll: () => assert.ok(poll, "poll not registered") || poll(),
  };
}

// Boot: resolve the initial state request and settle.
async function boot(h, state = connectedState()) {
  h.take("state").resolve(state);
  await settle();
}

async function generateOnce(h, password = "Generated-Secret-1") {
  h.fire("#gen-regenerate", "click");
  h.take("generate").resolve({
    password,
    profile: { mode: "random", entropy_bits_floor: 77 },
  });
  await flush();
  h.take("state").resolve(connectedState());
  await settle();
}

test("lock intent clears the generated preview before the host lock reply", async () => {
  const h = harness();
  await boot(h);
  assert.equal(h.el("#gen-history").children.length, 1, "history renders");

  await generateOnce(h);
  assert.equal(h.el("#gen-preview").textContent, "Generated-Secret-1");
  assert.equal(h.el("#gen-entropy").textContent, "77 bits");
  assert.equal(h.el("#gen-copy").disabled, false);

  // Copy works before lock.
  h.el("#gen-copy").listeners.get("click")();
  await flush();
  assert.deepEqual(h.clipboardWrites, ["Generated-Secret-1"]);

  // A second generation stays deferred across the lock intent.
  h.fire("#gen-regenerate", "click");
  const deferredGenerate = h.take("generate");
  h.el("#gen-copy").disabled = false;

  h.el("#lock-btn").listeners.get("click")();
  // The lock RPC has not answered yet: everything must already be gone.
  assert.equal(h.el("#gen-copy").disabled, true, "copy disabled at lock intent");
  assert.equal(h.el("#gen-preview").textContent, "", "preview DOM cleared");
  assert.equal(h.el("#gen-entropy").textContent, "");
  assert.equal(h.el("#gen-history").children.length, 0, "history DOM cleared");

  // Clicking the (now disabled) control cannot write the cached value.
  h.el("#gen-copy").listeners.get("click")();
  await flush();
  assert.deepEqual(
    h.clipboardWrites,
    ["Generated-Secret-1"],
    "no extra clipboard write after lock intent",
  );

  // A deferred pre-lock generate reply cannot revive the cleared value.
  deferredGenerate.resolve({
    password: "Stale-Secret-2",
    profile: { mode: "random", entropy_bits_floor: 90 },
  });
  await settle();
  assert.equal(h.el("#gen-preview").textContent, "");
  assert.equal(h.el("#gen-copy").disabled, true);
  assert.equal(h.el("#gen-history").children.length, 0);

  h.take("lock").resolve(disconnectedState());
  await settle();
  assert.equal(h.el("#gen-preview").textContent, "");
  assert.equal(h.el("#gen-copy").disabled, true);
});

test("a stale connected poll cannot repopulate the wiped preview while lock is pending", async () => {
  const h = harness();
  await boot(h);
  await generateOnce(h);
  assert.equal(h.el("#gen-copy").disabled, false);

  h.el("#lock-btn").listeners.get("click")();
  assert.equal(h.el("#gen-copy").disabled, true);
  assert.equal(h.el("#gen-preview").textContent, "");

  // The interval poll lands with a pre-lock connected snapshot that still
  // carries the old password and history.
  h.poll();
  const stalePoll = h.take("state");
  stalePoll.resolve(
    connectedState({
      password: "Generated-Secret-1",
      generatedHistory: [{ ...HISTORY_ENTRY, password: "Generated-Secret-1" }],
    }),
  );
  await settle();

  assert.equal(h.el("#gen-preview").textContent, "");
  assert.equal(h.el("#gen-copy").disabled, true, "copy stays disabled");
  assert.equal(h.el("#gen-history").children.length, 0, "history stays cleared");
  assert.equal(h.el("#gen-entropy").textContent, "");
  h.el("#gen-copy").listeners.get("click")();
  await flush();
  assert.deepEqual(h.clipboardWrites, [], "nothing copied after lock intent");

  h.take("lock").resolve(disconnectedState());
  await settle();
});

test("offline generation after lock still renders and can be copied", async () => {
  const h = harness();
  await boot(h);
  await generateOnce(h);
  h.el("#lock-btn").listeners.get("click")();
  h.take("lock").resolve(disconnectedState());
  await settle();
  assert.equal(h.el("#gen-copy").disabled, true);

  // Existing feature: generate a brand new password while locked/offline.
  h.fire("#gen-regenerate", "click");
  h.take("generate").resolve({
    password: "Offline-Secret-4",
    profile: { mode: "pin", entropy_bits_floor: 20 },
  });
  await flush();
  const followUp = h.pending("state");
  if (followUp.length) followUp[0].resolve(disconnectedState());
  await settle();

  assert.equal(
    h.el("#gen-preview").textContent,
    "Offline-Secret-4",
    "offline generation is not wiped by disconnected polls",
  );
  assert.equal(h.el("#gen-copy").disabled, false);
  h.el("#gen-copy").listeners.get("click")();
  await flush();
  assert.equal(h.clipboardWrites.at(-1), "Offline-Secret-4");

  // A later disconnected poll must not erase it either.
  h.poll();
  h.take("state").resolve(disconnectedState());
  await settle();
  assert.equal(h.el("#gen-preview").textContent, "Offline-Secret-4");
  assert.equal(h.el("#gen-copy").disabled, false);
});

test("pagehide/pageshow restores a usable search box and drops the stale query", async () => {
  const h = harness();
  const first = [
    {
      id: "b".repeat(32),
      revision: "c".repeat(64),
      category: "login",
      title: "Old",
      urls: ["https://example.test/"],
      tags: [],
      favorite: false,
    },
  ];
  const second = [
    {
      id: "d".repeat(32),
      revision: "e".repeat(64),
      category: "login",
      title: "Fresh",
      urls: ["https://example.test/"],
      tags: [],
      favorite: false,
    },
  ];
  h.take("state").resolve(connectedState({ vaultItems: first }));
  await settle();
  assert.equal(h.el("#vault-list").children.length, 1);

  // A long-running query owned by the pre-hide popup.
  h.fire("#tab-passkeys", "click");
  await flush();
  const staleQuery = h.take("vault-search");
  assert.equal(h.el("#search-input").disabled, true, "query disables search");

  // A main action is still awaiting when the popup is hidden.
  h.fire("#refresh", "click");
  await flush();
  assert.equal(h.el("#refresh").disabled, true, "busy while match pending");

  h.dispatchLifecycle("pagehide");
  assert.equal(
    h.el("#search-input").disabled,
    false,
    "pagehide re-enables the search box",
  );

  h.dispatchLifecycle("pageshow");
  // The restore reply carries the cached non-empty page renderVault still
  // holds. That cache must not suppress the fresh native query.
  h.take("state").resolve(connectedState({ vaultItems: first }));
  await settle();

  // Old query stays held and exactly one fresh query now belongs to the
  // restored popup (this is the regression: the cache used to hide it).
  assert.equal(h.pending("vault-search").length, 1, "one fresh search");
  const freshQuery = h.take("vault-search");
  assert.equal(h.el("#search-input").disabled, true, "fresh query owns the box");
  assert.equal(h.el("#refresh").disabled, false, "main busy released on hide");

  // The invalidated query's finalizer must not touch the new owner.
  staleQuery.resolve({
    vaultItems: [{ ...first[0], id: "f".repeat(32), title: "Stale" }],
  });
  await settle();
  assert.equal(
    h.el("#search-input").disabled,
    true,
    "stale finalizer must not re-enable the new query's box",
  );
  assert.equal(
    h.el("#vault-list").children[0].children[0].textContent.includes("Stale"),
    false,
    "stale reply must not repopulate the list",
  );

  freshQuery.resolve({ vaultItems: second });
  await settle();
  assert.equal(h.el("#search-input").disabled, false, "new query finishes");
  assert.equal(h.el("#vault-list").children.length, 1);
  assert.equal(h.el("#vault-list").children[0].children[0].textContent.includes("Fresh"), true);
});

test("restore without cached items lets render own the single fresh search", async () => {
  const h = harness();
  h.take("state").resolve(connectedState({ vaultItems: [] }));
  await settle();

  h.dispatchLifecycle("pagehide");
  h.dispatchLifecycle("pageshow");
  h.take("state").resolve(connectedState({ vaultItems: undefined }));
  await settle();

  // renderVault() already auto-refreshed, so pageshow must not duplicate it.
  assert.equal(h.pending("vault-search").length, 1, "exactly one fresh search");
  h.take("vault-search").resolve({ vaultItems: [] });
  await settle();
  assert.equal(h.el("#search-input").disabled, false);
});

test("a trusted generate reply never revives pre-wipe generated history", async () => {
  const h = harness();
  await boot(h);
  assert.equal(h.el("#gen-history").children.length, 1);

  h.dispatchLifecycle("pagehide");
  h.dispatchLifecycle("pageshow");
  h.take("state").resolve(connectedState({ vaultItems: undefined }));
  await settle();
  if (h.pending("vault-search").length)
    h.take("vault-search").resolve({ vaultItems: [] });
  await settle();
  assert.equal(h.el("#gen-history").children.length, 0, "hide wipes history");

  // The restored popup is still connected; a fresh generate is trusted for its
  // own password only, never for background history from before the wipe.
  h.fire("#gen-regenerate", "click");
  h.take("generate").resolve({
    password: "New-Secret-5",
    profile: { mode: "random", entropy_bits_floor: 64 },
    generatedHistory: [HISTORY_ENTRY],
  });
  await flush();
  const followUp = h.pending("state");
  if (followUp.length) followUp[0].resolve(connectedState());
  await settle();

  assert.equal(h.el("#gen-preview").textContent, "New-Secret-5");
  assert.equal(h.el("#gen-copy").disabled, false);
  assert.equal(
    h.el("#gen-history").children.length,
    0,
    "old history stays absent",
  );
});

test("a deferred lock acknowledgement cannot relock a reconnected popup", async () => {
  const h = harness();
  await boot(h);

  h.el("#lock-btn").listeners.get("click")();
  const staleLock = h.take("lock");
  h.el("#lock-btn").listeners.get("click")();
  const currentLock = h.take("lock");

  // The newest lock acknowledgement owns the UI.
  currentLock.resolve(disconnectedState());
  await settle();
  assert.equal(h.el("#status").textContent, "已锁定");
  assert.equal(h.el("#connect").disabled, false);

  // Reconnect while the older acknowledgement is still outstanding.
  h.fire("#connect", "click");
  h.take("connect").resolve(connectedState({ status: "reconnected" }));
  await flush();
  h.take("state").resolve(connectedState({ status: "reconnected" }));
  await settle();
  assert.equal(h.el("#status").textContent, "reconnected");
  assert.equal(h.el("#connect").disabled, true, "connected state renders");

  const lockDisabled = h.el("#lock-btn").disabled;
  staleLock.resolve(disconnectedState({ status: "stale-lock-ack" }));
  await settle();
  assert.equal(
    h.el("#status").textContent,
    "reconnected",
    "stale lock ack must not replace the newer connected state",
  );
  assert.equal(h.el("#connect").disabled, true, "popup is not relocked");
  assert.equal(h.el("#lock-btn").disabled, lockDisabled);
});

test("an unrelated refresh during the restore state read still starts the fresh search", async () => {
  const h = harness();
  const cached = [
    {
      id: "b".repeat(32),
      revision: "c".repeat(64),
      category: "login",
      title: "Cached",
      urls: ["https://example.test/"],
      tags: [],
      favorite: false,
    },
  ];
  h.take("state").resolve(connectedState({ vaultItems: cached }));
  await settle();
  assert.equal(h.el("#vault-list").children.length, 1);

  h.dispatchLifecycle("pagehide");
  h.dispatchLifecycle("pageshow");
  const heldRestore = h.take("state");

  // An unrelated action lands first; its render marks the cached page loaded
  // without starting a read, so only the restore can unblock the search.
  h.fire("#refresh", "click");
  h.take("match");
  await flush();
  assert.equal(h.pending("vault-search").length, 0, "no read yet");

  heldRestore.resolve(connectedState({ vaultItems: cached }));
  await settle();
  assert.equal(
    h.pending("vault-search").length,
    1,
    "an unrelated action must not cancel the restore's fresh search",
  );
  const freshQuery = h.take("vault-search");
  freshQuery.resolve({ vaultItems: cached });
  await settle();
  assert.equal(h.el("#search-input").disabled, false);
});

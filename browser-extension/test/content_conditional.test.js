const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

const ORIGIN = "https://example.test";
const REQUEST_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

class Element {
  constructor(tagName) {
    this.tagName = String(tagName || "").toUpperCase();
    this.children = [];
    this.parentElement = null;
    this.attributes = {};
    this.style = { cssText: "" };
    this._text = "";
    this._listeners = {};
    this.isConnected = true;
    this._shadow = null;
    this.shadowRoot = null;
    this.className = "";
    this.id = "";
    this.name = "";
    this.placeholder = "";
    this.type = "";
    this.disabled = false;
    this.readOnly = false;
    this._value = "";
    this._rect = { left: 10, top: 10, width: 200, height: 30 };
  }
  append(...nodes) {
    for (const node of nodes) {
      if (node.parentElement)
        node.parentElement.children.splice(
          node.parentElement.children.indexOf(node),
          1,
        );
      node.parentElement = this;
      node.isConnected = this.isConnected;
      this.children.push(node);
    }
  }
  remove() {
    if (this.parentElement) {
      const index = this.parentElement.children.indexOf(this);
      if (index >= 0) this.parentElement.children.splice(index, 1);
    }
    this.parentElement = null;
    this.isConnected = false;
  }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
    if (name === "id") this.id = String(value);
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }
  hasAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name);
  }
  removeAttribute(name) {
    delete this.attributes[name];
  }
  addEventListener(type, listener) {
    (this._listeners[type] = this._listeners[type] || []).push(listener);
  }
  removeEventListener(type, listener) {
    const list = this._listeners[type];
    if (!list) return;
    const index = list.indexOf(listener);
    if (index >= 0) list.splice(index, 1);
  }
  dispatchEvent(event) {
    if (!event.target) event.target = this;
    for (const listener of [...(this._listeners[event.type] || [])])
      listener(event);
    return true;
  }
  closest(selector) {
    for (let node = this; node; node = node.parentElement)
      if (node.matches?.(selector)) return node;
    return null;
  }
  matches(selector) {
    return String(selector)
      .split(",")
      .some((part) => matchSelector(this, part.trim()));
  }
  querySelectorAll(selector) {
    const found = [];
    walk(this, (node) => {
      if (node !== this && matchSelector(node, selector)) found.push(node);
    });
    return found;
  }
  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
  get textContent() {
    return this._text + this.children.map((child) => child.textContent).join("");
  }
  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }
  getBoundingClientRect() {
    return {
      left: this._rect.left,
      top: this._rect.top,
      width: this._rect.width,
      height: this._rect.height,
      right: this._rect.left + this._rect.width,
      bottom: this._rect.top + this._rect.height,
    };
  }
  attachShadow(init) {
    const root = new Element("#shadow-root");
    root.mode = init?.mode || "open";
    root.host = this;
    this._shadow = root;
    if (root.mode === "open") this.shadowRoot = root;
    return root;
  }
}
class HTMLInputElement extends Element {
  constructor() {
    super("input");
    this.type = "text";
    this.autocomplete = "";
    this.checked = false;
  }
  get value() {
    return this._value;
  }
  set value(next) {
    this._value = String(next);
  }
}
class HTMLSelectElement extends Element {
  constructor() {
    super("select");
    this.options = [];
  }
}
class HTMLTextAreaElement extends Element {
  constructor() {
    super("textarea");
  }
}

function matchSelector(node, selector) {
  if (!selector || !node || node.tagName === "#SHADOW-ROOT") return false;
  if (selector === "*") return true;
  if (selector === ":disabled") return node.disabled === true;
  const parsed = /^([a-zA-Z][\w-]*)?(?:\[([\w-]+)(?:=["']?([^"'\]]*)["']?)?\])?$/.exec(
    selector,
  );
  if (!parsed) return false;
  const [, tag, attribute, expected] = parsed;
  if (tag && node.tagName !== tag.toUpperCase()) return false;
  if (!attribute) return true;
  const value = node.getAttribute?.(attribute);
  if (value === null || value === undefined) return false;
  if (expected === undefined) return true;
  return String(value).toLowerCase() === expected.toLowerCase();
}

function walk(node, visit) {
  for (const child of node.children || []) {
    visit(child);
    walk(child, visit);
    if (child._shadow) walk(child._shadow, visit);
  }
}

const flush = async (count = 10) => {
  for (let index = 0; index < count; index++)
    await new Promise((resolve) => setImmediate(resolve));
};

function makeHarness(options = {}) {
  const pageMessages = [];
  const sent = [];
  const windowListeners = {};
  const runtimeListeners = [];
  const timers = new Map();
  let timerSerial = 0;
  let conditionalSupported = options.supported !== false;
  const listReply = options.list || { passkeys: [], truncated: false };
  const selectReply = options.select || {
    credential: { id: "credential", rawId: "AQID" },
  };
  const deferredOpens = [];

  const documentElement = new Element("html");
  const document = {
    readyState: "complete",
    visibilityState: "visible",
    documentElement,
    baseURI: ORIGIN + "/login",
    activeElement: null,
    _listeners: {},
    createElement(tag) {
      const name = String(tag).toLowerCase();
      if (name === "input") return new HTMLInputElement();
      if (name === "select") return new HTMLSelectElement();
      if (name === "textarea") return new HTMLTextAreaElement();
      return new Element(name);
    },
    addEventListener(type, listener) {
      (document._listeners[type] = document._listeners[type] || []).push(listener);
    },
    removeEventListener(type, listener) {
      const list = document._listeners[type];
      if (!list) return;
      const index = list.indexOf(listener);
      if (index >= 0) list.splice(index, 1);
    },
    dispatchEvent(event) {
      for (const listener of [...(document._listeners[event.type] || [])])
        listener(event);
      return true;
    },
    querySelectorAll(selector) {
      const found = [];
      walk(documentElement, (node) => {
        if (matchSelector(node, selector)) found.push(node);
      });
      return found;
    },
    querySelector(selector) {
      return document.querySelectorAll(selector)[0] || null;
    },
    getElementById(id) {
      return document.querySelectorAll("[id]").find((node) => node.id === id) || null;
    },
  };
  const windowObject = {
    top: null,
    innerWidth: 1024,
    innerHeight: 768,
    addEventListener(type, listener) {
      (windowListeners[type] = windowListeners[type] || []).push(listener);
    },
    removeEventListener(type, listener) {
      const list = windowListeners[type];
      if (!list) return;
      const index = list.indexOf(listener);
      if (index >= 0) list.splice(index, 1);
    },
    postMessage(data, origin) {
      pageMessages.push({ data, origin });
      queueMicrotask(() => {
        for (const listener of [...(windowListeners.message || [])])
          listener({ source: windowObject, origin: ORIGIN, data });
      });
    },
  };
  windowObject.top = windowObject;

  const api = {
    runtime: {
      id: "fixed",
      onMessage: { addListener: (listener) => runtimeListeners.push(listener) },
      sendMessage(message) {
        sent.push(JSON.parse(JSON.stringify(message)));
        switch (message.type) {
          case "inline-state":
            return Promise.resolve({
              connected: true,
              offerSavePasskeys: true,
              offerUsePasskeys: true,
              passkeyConditionalSupported: conditionalSupported,
              neverSaveForOrigin: false,
              suppressInline: false,
              generatorDefaults: {},
            });
          case "inline-pending-save":
            return Promise.resolve({ pendingSave: null });
          case "inline-match":
            return Promise.resolve({
              connected: true,
              candidates: [],
              preferredItemId: "",
            });
          case "passkey-conditional-open":
            if (options.deferList) {
              return new Promise((resolve) => {
                deferredOpens.push({
                  resolve: (value) =>
                    resolve(
                      value === undefined
                        ? conditionalSupported
                          ? listReply
                          : { fallback: true }
                        : value,
                    ),
                });
              });
            }
            return Promise.resolve(
              conditionalSupported ? listReply : { fallback: true },
            );
          case "passkey-conditional-select":
            return Promise.resolve(selectReply);
          default:
            return Promise.resolve({});
        }
      },
    },
    storage: { local: { get: async () => ({}) } },
  };

  const context = {
    window: windowObject,
    document,
    location: {
      origin: ORIGIN,
      protocol: "https:",
      hostname: "example.test",
      href: ORIGIN + "/login",
    },
    isSecureContext: true,
    Element,
    HTMLInputElement,
    HTMLSelectElement,
    HTMLTextAreaElement,
    getComputedStyle: (node) =>
      node?._computedStyle || {
        display: "block",
        visibility: "visible",
        opacity: "1",
      },
    innerWidth: 1024,
    innerHeight: 768,
    chrome: api,
    console: {},
    URL,
    Event: class Event {
      constructor(type, init = {}) {
        this.type = type;
        this.bubbles = Boolean(init.bubbles);
      }
    },
    setTimeout: (fn, ms) => {
      const id = ++timerSerial;
      timers.set(id, { fn, ms });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
  };
  context.self = context;
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../content.js"), "utf8"),
    context,
  );

  const harness = {
    document,
    window: windowObject,
    sent,
    pageMessages,
    timers,
    input(attributes = {}) {
      const input = new HTMLInputElement();
      for (const [name, value] of Object.entries(attributes))
        input.setAttribute(name, value);
      if (attributes.autocomplete) input.autocomplete = attributes.autocomplete;
      documentElement.append(input);
      return input;
    },
    page(data) {
      for (const listener of [...(windowListeners.message || [])])
        listener({ source: windowObject, origin: ORIGIN, data });
    },
    async pageMessage(data) {
      harness.page(data);
      await flush();
    },
    focus(input, trusted = true) {
      document.activeElement = input;
      document.dispatchEvent({
        type: "focusin",
        isTrusted: trusted,
        target: input,
        composedPath: () => [input],
        bubbles: true,
      });
    },
    shadowHost(mode = "open") {
      const host = new Element("div");
      documentElement.append(host);
      const shadow = host.attachShadow({ mode });
      return { host, shadow };
    },
    shadowInput(shadow, attributes = {}) {
      const input = new HTMLInputElement();
      for (const [name, value] of Object.entries(attributes))
        input.setAttribute(name, value);
      if (attributes.autocomplete) input.autocomplete = attributes.autocomplete;
      if (attributes.type) input.type = attributes.type;
      if ("readonly" in attributes) input.readOnly = true;
      if ("disabled" in attributes) input.disabled = true;
      shadow.append(input);
      return input;
    },
    // Faithful retargeting: focus inside an open shadow root is reported as
    // the host on document.activeElement, while composedPath still carries the
    // inner input and the root. A closed root retargets the path to its host
    // and exposes no shadowRoot at all.
    focusIn(input, options = {}) {
      const host = options.host || null;
      const root = options.root || null;
      if (root) root.activeElement = input;
      document.activeElement = host || input;
      const path =
        options.path || (host ? [input, root, host].filter(Boolean) : [input]);
      document.dispatchEvent({
        type: "focusin",
        isTrusted: options.trusted !== false,
        target: host || input,
        composedPath: () => [...path],
        bubbles: true,
      });
    },
    async focusDeep(input, options = {}) {
      harness.focusIn(input, options);
      await flush();
    },
    deferredOpenCount() {
      return deferredOpens.length;
    },
    async resolveOpen(index, reply) {
      const pending = deferredOpens[index];
      if (!pending) throw new Error("no deferred conditional open at " + index);
      pending.resolve(reply);
      await flush();
    },
    async click(node, trusted = true) {
      node.dispatchEvent({ type: "click", isTrusted: trusted, target: node });
      await flush();
    },
    async hide() {
      document.visibilityState = "hidden";
      document.dispatchEvent({ type: "visibilitychange" });
      await flush();
    },
    async pagehide() {
      for (const listener of [...(windowListeners.pagehide || [])]) listener({});
      await flush();
    },
    async settle() {
      await flush();
    },
    async runtimeMessage(message, sender = { id: "fixed" }) {
      let reply;
      let handled = false;
      for (const listener of [...runtimeListeners]) {
        const result = listener(message, sender, (value) => {
          reply = value;
        });
        if (result === true) handled = true;
      }
      await flush();
      return { handled, reply };
    },
    results() {
      return pageMessages
        .map((message) => message.data)
        .filter((data) => data.source === "locklark-result-v1");
    },
    setSupported(value) {
      conditionalSupported = value;
    },
    host() {
      return (
        documentElement.children.find(
          (node) =>
            node._shadow && node._shadow.children[0]?.tagName === "STYLE",
        ) || null
      );
    },
    box() {
      const host = harness.host();
      return host ? host._shadow.children[1] || host._shadow.children[0] : null;
    },
    conditionalBox() {
      const box = harness.box();
      return box && box.getAttribute("data-locklark-conditional") === "passkey"
        ? box
        : null;
    },
    text() {
      const box = harness.box();
      return box ? box.textContent : "";
    },
    all(selector) {
      const box = harness.box();
      if (!box) return [];
      const found = [];
      walk(box, (node) => {
        if (matchSelector(node, selector)) found.push(node);
      });
      return found;
    },
    choices() {
      return harness.all("[data-locklark-passkey-choice]");
    },
    buttons() {
      return harness.all("button");
    },
    async postConditional(id = REQUEST_ID) {
      await harness.pageMessage({
        source: "locklark-request-v1",
        type: "get",
        id,
        options: JSON.stringify({
          challenge: "AAAA",
          rpId: "example.test",
          allowCredentials: [{ type: "public-key", id: "AAAA" }],
        }),
        conditional: true,
      });
    },
  };
  return harness;
}

const entry = (n) => ({
  item_id: n.toString(16).padStart(32, "0"),
  revision: n.toString(16).padStart(64, "0"),
  title: "Item " + n,
  credential_id: "credential-" + n,
  rp_id: "example.test",
  user_name: "user" + n + "@example.test",
  display_name: "User " + n,
});

test("no conditional panel appears before a qualified input is focused", async () => {
  const h = makeHarness({ list: { passkeys: [entry(1)], truncated: false } });
  const input = h.input({ autocomplete: "username webauthn", type: "text" });
  await h.postConditional();
  assert.equal(h.host(), null, "no panel is rendered on request registration");
  assert.equal(
    h.sent.some((message) => message.type === "passkey-conditional-open"),
    false,
  );
  assert.equal(
    h.sent.some((message) => message.type === "passkey-conditional-select"),
    false,
  );
  h.focus(input);
  await h.settle();
  const open = h.sent.find(
    (message) => message.type === "passkey-conditional-open",
  );
  assert.deepEqual(Object.keys(open).sort(), ["id", "options", "type"]);
  assert.equal(open.id, REQUEST_ID);
  assert.ok(h.host());
  assert.match(h.text(), /Passkey 账号/);
  const choices = h.choices();
  assert.equal(choices.length, 1);
  assert.equal(choices[0].getAttribute("data-locklark-passkey-choice"), entry(1).item_id);
  assert.equal(
    choices[0].getAttribute("data-locklark-passkey-credential"),
    entry(1).credential_id,
  );
  assert.match(choices[0].textContent, /User 1/);
  assert.match(choices[0].textContent, /user1@example\.test/);
  assert.equal(
    h.choices()[0].getAttribute("data-locklark-passkey-choice"),
    entry(1).item_id,
  );
});

test("untrusted, ignored, unqualified or hidden focus never opens the account list", async () => {
  const h = makeHarness({ list: { passkeys: [entry(1)], truncated: false } });
  const webauthn = h.input({ autocomplete: "webauthn" });
  const ignored = h.input({
    autocomplete: "webauthn",
    "data-locklark-ignore": "",
  });
  const password = h.input({ autocomplete: "current-password", type: "password" });
  const username = h.input({ autocomplete: "username" });
  await h.postConditional();
  const opens = () =>
    h.sent.filter((message) => message.type === "passkey-conditional-open").length;
  h.focus(webauthn, false);
  await h.settle();
  assert.equal(opens(), 0);
  h.focus(ignored);
  await h.settle();
  assert.equal(opens(), 0);
  h.focus(password);
  await h.settle();
  assert.equal(opens(), 0);
  h.focus(username);
  await h.settle();
  assert.equal(opens(), 0);
  await h.hide();
  h.focus(webauthn);
  await h.settle();
  assert.equal(opens(), 0);
  assert.equal(h.host(), null);
});

test("selection requires a trusted click and sends the exact selector", async () => {
  const h = makeHarness({
    list: { passkeys: [entry(2)], truncated: false },
    select: { credential: { id: "signed-credential", rawId: "AQID" } },
  });
  const input = h.input({ autocomplete: "username webauthn" });
  await h.postConditional();
  h.focus(input);
  await h.settle();
  const choice = h.choices()[0];
  assert.ok(choice);
  await h.click(choice, false);
  assert.equal(
    h.sent.some((message) => message.type === "passkey-conditional-select"),
    false,
    "programmatic clicks never start native approval",
  );
  await h.click(choice, true);
  const select = h.sent.find(
    (message) => message.type === "passkey-conditional-select",
  );
  assert.deepEqual(Object.keys(select).sort(), [
    "credential_id",
    "id",
    "item_id",
    "revision",
    "type",
  ]);
  assert.equal(select.id, REQUEST_ID);
  assert.equal(select.item_id, entry(2).item_id);
  assert.equal(select.revision, entry(2).revision);
  assert.equal(select.credential_id, entry(2).credential_id);
  const result = h.pageMessages
    .map((message) => message.data)
    .find((data) => data.source === "locklark-result-v1");
  assert.deepEqual(Object.keys(result).sort(), ["credential", "id", "source"]);
  assert.equal(result.id, REQUEST_ID);
  assert.equal(result.credential.id, "signed-credential");
  assert.equal(h.host(), null);
});

const pageResult = (h) =>
  h.pageMessages
    .map((message) => message.data)
    .find((data) => data.source === "locklark-result-v1");

test("使用其他验证器 falls back to the browser and a truncated list offers the native picker", async () => {
  const h = makeHarness({
    list: { passkeys: [entry(3)], truncated: true },
  });
  const input = h.input({ autocomplete: "username webauthn" });
  await h.postConditional();
  h.focus(input);
  await h.settle();
  const labels = h.buttons().map((node) => node.textContent);
  assert.ok(labels.includes("使用其他验证器"));
  assert.ok(labels.includes("使用系统 Passkey 选择器"));
  const native = h
    .buttons()
    .find((node) => node.getAttribute("data-locklark-passkey-native") === "true");
  await h.click(native, true);
  const select = h.sent.find(
    (message) => message.type === "passkey-conditional-select",
  );
  assert.deepEqual(Object.keys(select).sort(), ["id", "native", "type"]);
  assert.equal(select.native, true);

  const plain = makeHarness({
    list: { passkeys: [entry(4)], truncated: false },
  });
  const second = plain.input({ autocomplete: "username webauthn" });
  await plain.postConditional();
  plain.focus(second);
  await plain.settle();
  assert.equal(
    plain
      .buttons()
      .some((node) => node.textContent === "使用系统 Passkey 选择器"),
    false,
  );
  const other = plain
    .buttons()
    .find((node) => node.textContent === "使用其他验证器");
  await plain.click(other, true);
  const fallback = pageResult(plain);
  assert.equal(fallback.fallback, true);
  assert.equal(
    plain.sent.some((message) => message.type === "passkey-cancel"),
    true,
  );
});

test("only a boolean capability crosses the page bridge", async () => {
  const h = makeHarness();
  await h.pageMessage({
    source: "locklark-capability-v1",
    id: "11111111-2222-3333-4444-555555555555",
  });
  const reply = h.pageMessages
    .map((message) => message.data)
    .find((data) => data.source === "locklark-capability-v1" && data.conditional !== undefined);
  assert.deepEqual(Object.keys(reply).sort(), ["conditional", "id", "source"]);
  assert.equal(reply.conditional, true);
  assert.equal(reply.id, "11111111-2222-3333-4444-555555555555");
  const unsupported = makeHarness({ supported: false });
  await unsupported.pageMessage({
    source: "locklark-capability-v1",
    id: "11111111-2222-3333-4444-555555555556",
  });
  const denied = unsupported.pageMessages
    .map((message) => message.data)
    .find(
      (data) =>
        data.source === "locklark-capability-v1" &&
        data.id === "11111111-2222-3333-4444-555555555556",
    );
  assert.equal(denied.conditional, false);
  for (const harness of [h, unsupported])
    for (const { data } of harness.pageMessages)
      assert.equal(
        JSON.stringify(data).includes("User 1") ||
          JSON.stringify(data).includes("credential-"),
        false,
      );
});

test("unsupported settings fall back without rendering any account list", async () => {
  const h = makeHarness({ supported: false });
  const input = h.input({ autocomplete: "username webauthn" });
  await h.postConditional();
  assert.equal(h.host(), null);
  h.focus(input);
  await h.settle();
  assert.equal(h.conditionalBox(), null);
  assert.equal(h.choices().length, 0);
  assert.equal(pageResult(h).fallback, true);
});

test("pagehide, navigation abort and MAIN cancellation tear the conditional UI down", async () => {
  const h = makeHarness({ list: { passkeys: [entry(5)], truncated: false } });
  const input = h.input({ autocomplete: "username webauthn" });
  await h.postConditional();
  h.focus(input);
  await h.settle();
  assert.ok(h.conditionalBox());
  await h.hide();
  assert.equal(h.conditionalBox(), null, "page hidden removes the panel");
  await h.pagehide();
  assert.equal(
    h.sent.some((message) => message.type === "passkey-cancel"),
    true,
  );
  assert.equal(h.conditionalBox(), null);
  h.focus(input);
  await h.settle();
  assert.equal(h.conditionalBox(), null, "an aborted request never re-opens the list");
  assert.equal(
    h.sent.filter((message) => message.type === "passkey-conditional-open")
      .length,
    1,
  );

  const second = makeHarness({
    list: { passkeys: [entry(6)], truncated: false },
  });
  const field = second.input({ autocomplete: "username webauthn" });
  await second.postConditional();
  second.focus(field);
  await second.settle();
  assert.ok(second.conditionalBox());
  await second.pageMessage({
    source: "locklark-request-v1",
    type: "cancel",
    id: REQUEST_ID,
  });
  assert.equal(second.conditionalBox(), null);
  assert.equal(
    second.sent.some((message) => message.type === "passkey-cancel"),
    true,
  );
});

test("non-conditional passkey controls keep their baseline inline flow", async () => {
  const h = makeHarness();
  await h.pageMessage({
    source: "locklark-request-v1",
    type: "get",
    id: REQUEST_ID,
    options: JSON.stringify({ challenge: "AAAA", rpId: "example.test" }),
    conditional: false,
  });
  assert.ok(h.host());
  assert.match(h.text(), /使用 Passkey/);
  const labels = h.buttons().map((node) => node.textContent);
  assert.ok(labels.includes("使用 Locklark 登录"));
  assert.ok(labels.includes("使用其他验证器"));
  const primary = h
    .buttons()
    .find((node) => node.textContent === "使用 Locklark 登录");
  await h.click(primary, true);
  const request = h.sent.find((message) => message.type === "passkey");
  assert.deepEqual(Object.keys(request).sort(), [
    "id",
    "operation",
    "options",
    "type",
  ]);
  assert.equal(request.operation, "get");
  assert.equal(h.choices().length, 0);
});

const INVALIDATION_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const OTHER_ID = "aaaaaaaa-bbbb-cccc-dddd-ffffffffffff";

async function renderConditional(h, id = INVALIDATION_ID) {
  const input = h.input({ autocomplete: "username webauthn" });
  await h.postConditional(id);
  h.focus(input);
  await h.settle();
  return input;
}

test("worker invalidation clears the exact pending conditional call with NotAllowedError", async () => {
  const h = makeHarness({ list: { passkeys: [entry(7)], truncated: false } });
  await renderConditional(h);
  assert.ok(h.conditionalBox());
  const reply = await h.runtimeMessage({
    type: "locklark:conditional-passkey-cancel",
    id: INVALIDATION_ID,
  });
  assert.equal(reply.handled, true);
  assert.deepEqual(Object.keys(reply.reply), ["cancelled"]);
  assert.equal(reply.reply.cancelled, true);
  assert.equal(h.conditionalBox(), null);
  const result = h.results().at(-1);
  assert.equal(result.error, "NotAllowedError");
  assert.equal("credential" in result, false);
  assert.equal(
    JSON.stringify(result).includes("credential-7"),
    false,
    "no account metadata reaches the page",
  );
});

test("foreign, malformed or mismatched invalidation ids leave the panel intact", async () => {
  const h = makeHarness({ list: { passkeys: [entry(8)], truncated: false } });
  await renderConditional(h);
  const foreign = await h.runtimeMessage(
    { type: "locklark:conditional-passkey-cancel", id: INVALIDATION_ID },
    { id: "other-extension" },
  );
  assert.equal(foreign.handled, false);
  assert.ok(h.conditionalBox());
  const malformed = await h.runtimeMessage({
    type: "locklark:conditional-passkey-cancel",
    id: "not-a-uuid",
  });
  assert.equal(malformed.reply.cancelled, false);
  assert.ok(h.conditionalBox());
  const mismatched = await h.runtimeMessage({
    type: "locklark:conditional-passkey-cancel",
    id: OTHER_ID,
  });
  assert.equal(mismatched.reply.cancelled, false);
  assert.ok(h.conditionalBox());
  assert.equal(h.results().length, 0);
  const exact = await h.runtimeMessage({
    type: "locklark:conditional-passkey-cancel",
    id: INVALIDATION_ID,
  });
  assert.equal(exact.reply.cancelled, true);
  assert.equal(h.conditionalBox(), null);
  assert.equal(h.results().at(-1).id, INVALIDATION_ID);
});

test("a late invalidation for an old call cannot clobber the next conditional request", async () => {
  const h = makeHarness({
    list: { passkeys: [entry(9)], truncated: false },
    select: { credential: { id: "new-credential", rawId: "AQID" } },
  });
  await renderConditional(h, INVALIDATION_ID);
  await h.runtimeMessage({
    type: "locklark:conditional-passkey-cancel",
    id: INVALIDATION_ID,
  });
  assert.equal(h.conditionalBox(), null);
  await renderConditional(h, OTHER_ID);
  assert.ok(h.conditionalBox());
  const stale = await h.runtimeMessage({
    type: "locklark:conditional-passkey-cancel",
    id: INVALIDATION_ID,
  });
  assert.equal(stale.reply.cancelled, false);
  assert.ok(h.conditionalBox(), "the new call keeps its panel");
  assert.equal(
    h.results().filter((result) => result.id === OTHER_ID).length,
    0,
  );
  await h.click(h.choices()[0], true);
  const select = h.sent.find(
    (message) => message.type === "passkey-conditional-select",
  );
  assert.equal(select.id, OTHER_ID);
  const result = h.results().find((entryResult) => entryResult.id === OTHER_ID);
  assert.equal(result.credential.id, "new-credential");
});

const shadowHarness = (options = {}) => {
  const h = makeHarness({
    list: { passkeys: [entry(11)], truncated: false },
    ...options,
  });
  const { host, shadow } = h.shadowHost("open");
  const input = h.shadowInput(shadow, {
    autocomplete: "username webauthn",
    type: "text",
  });
  return { h, host, shadow, input };
};

test("a focused input inside an open shadow root renders the conditional list", async () => {
  const { h, host, shadow, input } = shadowHarness();
  const readonlyField = h.shadowInput(shadow, {
    autocomplete: "username webauthn",
    type: "text",
    readonly: "",
  });
  const hiddenField = h.shadowInput(shadow, {
    autocomplete: "username webauthn",
    type: "text",
  });
  hiddenField._computedStyle = {
    display: "none",
    visibility: "visible",
    opacity: "1",
  };
  await h.postConditional();
  assert.equal(h.host(), null);
  // readOnly and hidden shadow controls keep the baseline refusal rules.
  h.focusIn(readonlyField, { host, root: shadow });
  await h.settle();
  assert.equal(
    h.sent.some((message) => message.type === "passkey-conditional-open"),
    false,
    "a readOnly shadow field never opens the account list",
  );
  h.focusIn(hiddenField, { host, root: shadow });
  await h.settle();
  assert.equal(
    h.sent.some((message) => message.type === "passkey-conditional-open"),
    false,
    "a hidden shadow field never opens the account list",
  );
  assert.equal(h.host(), null);
  // document.activeElement is the host; only the open shadowRoot knows the
  // real focused input, exactly like a retargeted focus event.
  h.focusIn(input, { host, root: shadow });
  await h.settle();
  assert.equal(h.document.activeElement, host);
  assert.equal(shadow.activeElement, input);
  const box = h.conditionalBox();
  assert.ok(box, "retargeted shadow focus must still render the account list");
  assert.match(h.text(), /Passkey 账号/);
  const choices = h.choices();
  assert.equal(choices.length, 1);
  assert.equal(
    choices[0].getAttribute("data-locklark-passkey-choice"),
    entry(11).item_id,
  );
  assert.equal(
    choices[0].getAttribute("data-locklark-passkey-credential"),
    entry(11).credential_id,
  );
  assert.match(choices[0].textContent, /User 11/);
  const opens = h.sent.filter(
    (message) => message.type === "passkey-conditional-open",
  );
  assert.equal(opens.length, 1);
  assert.deepEqual(Object.keys(opens[0]).sort(), ["id", "options", "type"]);
  for (const { data } of h.pageMessages)
    assert.equal(
      JSON.stringify(data).includes("User 11") ||
        JSON.stringify(data).includes("credential-11"),
      false,
      "no account metadata reaches the page bridge",
    );
});

test("a request arriving while an open shadow input is focused renders immediately", async () => {
  const { h, host, shadow, input } = shadowHarness({
    list: { passkeys: [entry(12)], truncated: false },
  });
  h.focusIn(input, { host, root: shadow });
  await h.settle();
  await h.postConditional();
  assert.ok(
    h.conditionalBox(),
    "initial request focus handling must resolve the shadow input",
  );
  assert.equal(
    h.choices()[0].getAttribute("data-locklark-passkey-choice"),
    entry(12).item_id,
  );
  assert.equal(
    h.sent.filter((message) => message.type === "passkey-conditional-open")
      .length,
    1,
  );
});

test("switching shadow focus while the account list is pending refuses the stale panel", async () => {
  const h = makeHarness({ deferList: true });
  const { host, shadow } = h.shadowHost("open");
  const first = h.shadowInput(shadow, {
    autocomplete: "username webauthn",
    type: "text",
  });
  // The host stays document.activeElement; only the shadow root's active
  // element moves, so a retargeted focus switch is invisible to a shallow
  // document.activeElement comparison.
  const other = h.shadowInput(shadow, { type: "text", name: "search-query" });
  await h.postConditional();
  h.focusIn(first, { host, root: shadow });
  await h.settle();
  assert.equal(h.deferredOpenCount(), 1);
  assert.equal(h.host(), null, "no panel before the worker replies");
  h.focusIn(other, { host, root: shadow });
  await h.settle();
  assert.equal(h.document.activeElement, host);
  assert.equal(shadow.activeElement, other);
  assert.equal(
    h.deferredOpenCount(),
    1,
    "an unqualified shadow field never opens the account list",
  );
  await h.resolveOpen(0, { passkeys: [entry(13)], truncated: false });
  assert.equal(h.conditionalBox(), null, "the stale panel must not render");
  assert.equal(h.choices().length, 0);
  assert.equal(
    h.sent.some((message) => message.type === "passkey-conditional-select"),
    false,
  );
  assert.equal(
    h.sent.filter((message) => message.type === "passkey-conditional-open")
      .length,
    1,
  );
  // Returning to the qualified shadow field opens the live list normally.
  h.focusIn(first, { host, root: shadow });
  await h.settle();
  assert.equal(h.deferredOpenCount(), 2);
  await h.resolveOpen(1, { passkeys: [entry(13)], truncated: false });
  const box = h.conditionalBox();
  assert.ok(box);
  assert.equal(h.choices().length, 1);
  assert.equal(
    h.choices()[0].getAttribute("data-locklark-passkey-choice"),
    entry(13).item_id,
  );
});

test("a closed shadow root is opaque to the conditional focus walk", async () => {
  const h = makeHarness({ list: { passkeys: [entry(14)], truncated: false } });
  const { host, shadow } = h.shadowHost("closed");
  const input = h.shadowInput(shadow, {
    autocomplete: "username webauthn",
    type: "text",
  });
  assert.equal(host.shadowRoot, null, "a closed root exposes no shadowRoot");
  await h.postConditional();
  // A closed root retargets composedPath to the host and never reveals the
  // inner input.
  h.focusIn(input, { host, root: shadow, path: [host] });
  await h.settle();
  assert.equal(h.conditionalBox(), null);
  assert.equal(h.choices().length, 0);
  assert.equal(
    h.sent.some((message) => message.type === "passkey-conditional-open"),
    false,
  );
});

const sibling = (credentialSuffix, childRevision) => ({
  ...entry(21),
  credential_id: "credential-sibling-" + credentialSuffix,
  credential_revision: childRevision,
});

test("sibling credentials under one parent are distinct options and forward the exact child revision", async () => {
  const first = sibling("one", "1".repeat(64));
  const second = sibling("two", "2".repeat(64));
  const h = makeHarness({
    list: { passkeys: [first, second], truncated: false },
    select: { credential: { id: "signed-credential", rawId: "AQID" } },
  });
  const input = h.input({ autocomplete: "username webauthn" });
  await h.postConditional();
  h.focus(input);
  await h.settle();
  const choices = h.choices();
  assert.equal(choices.length, 2, "both credentials stay separate choices");
  assert.notEqual(choices[0].textContent, choices[1].textContent);
  assert.equal(
    choices[1].getAttribute("data-locklark-passkey-credential"),
    second.credential_id,
  );
  assert.equal(
    choices[1].getAttribute("data-locklark-passkey-credential-revision"),
    second.credential_revision,
  );
  assert.equal(
    choices[0].getAttribute("data-locklark-passkey-credential-revision"),
    first.credential_revision,
  );
  await h.click(choices[1], true);
  const select = h.sent.find(
    (message) => message.type === "passkey-conditional-select",
  );
  assert.deepEqual(Object.keys(select).sort(), [
    "credential_id",
    "credential_revision",
    "id",
    "item_id",
    "revision",
    "type",
  ]);
  assert.equal(select.item_id, second.item_id);
  assert.equal(select.revision, second.revision);
  assert.equal(select.credential_id, second.credential_id);
  assert.equal(select.credential_revision, second.credential_revision);
  assert.notEqual(select.credential_id, first.credential_id);
});

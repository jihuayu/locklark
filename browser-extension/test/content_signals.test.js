const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const core = require("../core.js");

const ORIGIN = "https://example.test";
const HINT_ID = "11111111-2222-3333-4444-555555555555";
const CREDENTIAL_ID = Buffer.from(new Uint8Array(32).fill(1)).toString(
  "base64url",
);
const USER_ID = Buffer.from(new Uint8Array(16).fill(2)).toString("base64url");

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

  const documentElement = new Element("html");
  const document = {
    readyState: "complete",
    visibilityState: options.visibilityState || "visible",
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
      (document._listeners[type] = document._listeners[type] || []).push(
        listener,
      );
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
      return (
        document.querySelectorAll("[id]").find((node) => node.id === id) || null
      );
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
  windowObject.top =
    options.subframe === "cross-origin"
      ? { location: { origin: "https://other.test" } }
      : options.subframe
        ? { location: { origin: ORIGIN } }
        : windowObject;

  const api = {
    runtime: {
      id: "fixed",
      onMessage: { addListener: (listener) => runtimeListeners.push(listener) },
      sendMessage(message) {
        sent.push(JSON.parse(JSON.stringify(message)));
        if (options.sendError) {
          if (options.sendError === "throw") throw Error("closed");
          return Promise.reject(Error("closed"));
        }
        switch (message.type) {
          case "inline-state":
            return Promise.resolve({
              connected: true,
              offerSavePasskeys: true,
              offerUsePasskeys: true,
              passkeyConditionalSupported: true,
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
    isSecureContext: options.insecure !== true,
    LocklarkCore: core,
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
    page(data, origin = ORIGIN, source = null) {
      for (const listener of [...(windowListeners.message || [])])
        listener({ source: source || windowObject, origin, data });
    },
    async pageMessage(data, origin, source) {
      harness.page(data, origin, source);
      await flush();
    },
    hint(extra = {}) {
      return {
        source: "locklark-signal-v1",
        id: HINT_ID,
        options: JSON.stringify({
          kind: "unknown",
          rpId: "example.test",
          credentialId: CREDENTIAL_ID,
          ...extra,
        }),
      };
    },
    hints() {
      return sent.filter((message) => message.type === "passkey-signal");
    },
    results() {
      return pageMessages
        .map((message) => message.data)
        .filter((data) => data.source === "locklark-result-v1");
    },
    signalMessages() {
      return pageMessages
        .map((message) => message.data)
        .filter((data) => data && /signal/i.test(String(data.source || "")));
    },
    async hide() {
      document.visibilityState = "hidden";
      document.dispatchEvent({ type: "visibilitychange" });
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
  };
  return harness;
}

const acceptedOptions = () =>
  JSON.stringify({
    kind: "accepted",
    rpId: "example.test",
    userId: USER_ID,
    allAcceptedCredentialIds: [CREDENTIAL_ID],
  });
const userOptions = () =>
  JSON.stringify({
    kind: "user",
    rpId: "example.test",
    userId: USER_ID,
    name: "User Name",
    displayName: "User Display",
  });

test("a well-formed same-window hint is forwarded once and never answered", async () => {
  const h = makeHarness();
  const hint = h.hint();
  await h.pageMessage(hint);
  const forwarded = h.hints();
  assert.equal(forwarded.length, 1);
  assert.deepEqual(forwarded[0], {
    type: "passkey-signal",
    options: hint.options,
  });
  assert.equal(h.results().length, 0, "no outcome is posted back to the page");
  assert.equal(h.signalMessages().length, 0, "the hint is not echoed");
});

test("all three strict dictionaries pass the isolated bounds unchanged", async () => {
  const h = makeHarness();
  await h.pageMessage(h.hint());
  await h.pageMessage({ ...h.hint(), options: acceptedOptions() });
  await h.pageMessage({ ...h.hint(), options: userOptions() });
  assert.deepEqual(
    h.hints().map((message) => JSON.parse(message.options).kind),
    ["unknown", "accepted", "user"],
  );
  assert.equal(h.hints()[1].options, acceptedOptions());
});

test("a hint from a foreign source window or origin is refused", async () => {
  const h = makeHarness();
  await h.pageMessage(h.hint(), ORIGIN, { postMessage: () => {} });
  await h.pageMessage(h.hint(), "https://evil.test");
  await h.pageMessage(h.hint(), "null");
  assert.equal(h.hints().length, 0);
});

test("a hint with extra keys, a bad id or an unknown source name is refused", async () => {
  const h = makeHarness();
  const base = h.hint();
  await h.pageMessage({ ...base, kind: "unknown" });
  await h.pageMessage({ ...base, count: 1 });
  await h.pageMessage({ ...base, origin: "https://evil.test" });
  await h.pageMessage({ ...base, credentialId: CREDENTIAL_ID });
  await h.pageMessage({ ...base, id: "not-a-uuid" });
  await h.pageMessage({ ...base, source: "locklark-signal-v2" });
  assert.equal(h.hints().length, 0);
});

test("malformed, unknown-member, unbounded and oversize documents are refused", async () => {
  const h = makeHarness();
  const base = h.hint();
  const documents = [
    "",
    "{",
    "null",
    "[]",
    JSON.stringify({ kind: "other", rpId: "example.test" }),
    JSON.stringify({ kind: "unknown", rpId: "example.test" }),
    JSON.stringify({
      kind: "unknown",
      rpId: "example.test",
      credentialId: CREDENTIAL_ID,
      extra: true,
    }),
    JSON.stringify({
      kind: "accepted",
      rpId: "example.test",
      userId: USER_ID,
      allAcceptedCredentialIds: Array.from(
        { length: 65 },
        () => CREDENTIAL_ID,
      ),
    }),
    JSON.stringify({
      kind: "user",
      rpId: "example.test",
      userId: USER_ID,
      name: "line\nbreak",
      displayName: "User",
    }),
  ];
  for (const options of documents)
    await h.pageMessage({ ...base, options });
  await h.pageMessage({ ...base, options: "x".repeat(32769) });
  await h.pageMessage({ ...base, options: undefined });
  await h.pageMessage({ ...base, options: { kind: "unknown" } });
  assert.equal(h.hints().length, 0);
});

test("a hidden document refuses the hint without forwarding anything", async () => {
  const h = makeHarness();
  await h.hide();
  await h.pageMessage(h.hint());
  assert.equal(h.hints().length, 0);
});

test("a same-origin subframe and an insecure page never forward a hint", async () => {
  const frame = makeHarness({ subframe: true });
  await frame.pageMessage(frame.hint());
  assert.equal(frame.hints().length, 0, "subframes never forward");
  const crossOrigin = makeHarness({ subframe: "cross-origin" });
  await crossOrigin.pageMessage(crossOrigin.hint());
  assert.equal(crossOrigin.hints().length, 0);
  const insecure = makeHarness({ insecure: true });
  await insecure.pageMessage(insecure.hint());
  assert.equal(insecure.hints().length, 0);
});

test("a failing runtime send is swallowed and never reaches the page", async () => {
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on("unhandledRejection", onUnhandled);
  try {
    for (const mode of ["throw", "reject"]) {
      const h = makeHarness({ sendError: mode });
      await h.pageMessage(h.hint());
      assert.equal(h.results().length, 0, mode);
      assert.equal(h.signalMessages().length, 0, mode);
      assert.equal(h.pageMessages.length, 0, mode);
    }
    await flush();
    assert.equal(unhandled.length, 0, "a refused forward stays handled");
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
});

test("a hint never occupies or cancels the conditional Passkey slot", async () => {
  const h = makeHarness();
  const requestID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  await h.pageMessage({
    source: "locklark-request-v1",
    type: "get",
    id: requestID,
    conditional: true,
    options: JSON.stringify({
      challenge: "AAAA",
      rpId: "example.test",
      allowCredentials: [{ type: "public-key", id: CREDENTIAL_ID }],
    }),
  });
  const before = h.sent.filter(
    (message) => message.type === "passkey-cancel",
  ).length;
  await h.pageMessage(h.hint());
  assert.equal(h.hints().length, 1, "the hint is still forwarded");
  assert.equal(
    h.sent.filter((message) => message.type === "passkey-cancel").length,
    before,
    "no credential flow is cancelled by a hint",
  );
  assert.equal(
    h.results().length,
    0,
    "the pending conditional call is neither finished nor failed",
  );
});

test("the isolated world never posts a signal outcome, count or metadata", async () => {
  const h = makeHarness();
  await h.pageMessage(h.hint());
  await h.pageMessage({ ...h.hint(), options: acceptedOptions() });
  assert.equal(h.hints().length, 2);
  assert.equal(
    h.pageMessages.length,
    0,
    "no acknowledgement, count, metadata or outcome is ever posted back",
  );
  assert.equal(h.results().length, 0);
});

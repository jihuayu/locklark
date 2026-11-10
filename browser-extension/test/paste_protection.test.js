const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

const ORIGIN = "https://example.test";
const SECRET = "LL1-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ".slice(0, 26);
const flush = async (count = 12) => {
  for (let index = 0; index < count; index++)
    await new Promise((resolve) => setImmediate(resolve));
};

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
    this.className = "";
    this.id = "";
    this.type = "";
    this.disabled = false;
    this.readOnly = false;
    this._rect = { left: 10, top: 10, width: 200, height: 30 };
    this.shadowRoot = null;
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
    if (name === "type") this.type = String(value);
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }
  hasAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name);
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
    for (const listener of [...(this._listeners[event.type] || [])]) {
      if (event._stopped) break;
      listener(event);
    }
    return !event.defaultPrevented;
  }
  focus() {
    const root = this.getRootNode();
    if (root) root.activeElement = this;
  }
  getRootNode() {
    let node = this;
    while (node.parentElement) node = node.parentElement;
    return node._isDocument ? node : null;
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
  attachShadow() {
    const root = new Element("#shadow-root");
    root.host = this;
    return root;
  }
}
class HTMLInputElement extends Element {
  constructor() {
    super("input");
    this.selectionStart = 0;
    this.selectionEnd = 0;
  }
  get value() {
    return this._value || "";
  }
  set value(next) {
    this._value = String(next);
    const length = this._value.length;
    this.selectionStart = length;
    this.selectionEnd = length;
  }
  setRangeText(text, start, end) {
    const value = this.value;
    this._value = value.slice(0, start) + String(text) + value.slice(end);
    const caret = start + String(text).length;
    this.selectionStart = caret;
    this.selectionEnd = caret;
  }
}
class HTMLTextAreaElement extends HTMLInputElement {}
class HTMLSelectElement extends Element {}

// Closed shadow roots are unreachable from the page, so keep a test-only handle
// on each one to assert what the panel actually rendered.
const closedRoots = new WeakMap();
const attachShadow = Element.prototype.attachShadow;
Element.prototype.attachShadow = function attachShadowForTest(init) {
  const root = attachShadow.call(this, init);
  if (init?.mode === "closed") closedRoots.set(this, root);
  return root;
};

function matchSelector(node, selector) {
  if (!selector || !node || node.tagName === "#SHADOW-ROOT") return false;
  if (selector === "*") return true;
  const parsed =
    /^([a-zA-Z][\w-]*)?(?:\[([\w-]+)(?:=["']?([^"'\]]*)["']?)?\])?$/.exec(
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
    const closed = closedRoots.get(child);
    if (closed) {
      visit(closed);
      walk(closed, visit);
    }
  }
}

function dispatch(root, event) {
  if (!event.target) event.target = root;
  for (const listener of [...(root._listeners?.[event.type] || [])]) {
    if (event._stopped) break;
    listener(event);
  }
  return !event.defaultPrevented;
}

function makeHarness(options = {}) {
  const sent = [];
  const documentListeners = {};
  const windowListeners = {};
  const inputEvents = [];

  const documentElement = new Element("html");
  const document = {
    _isDocument: true,
    readyState: "complete",
    visibilityState: "visible",
    documentElement,
    baseURI: ORIGIN + "/login",
    activeElement: null,
    _listeners: documentListeners,
    createElement(tag) {
      const name = String(tag).toLowerCase();
      if (name === "input") return new HTMLInputElement();
      if (name === "select") return new HTMLSelectElement();
      if (name === "textarea") return new HTMLTextAreaElement();
      return new Element(name);
    },
    addEventListener(type, listener) {
      (documentListeners[type] = documentListeners[type] || []).push(listener);
    },
    removeEventListener(type, listener) {
      const list = documentListeners[type];
      if (!list) return;
      const index = list.indexOf(listener);
      if (index >= 0) list.splice(index, 1);
    },
    dispatchEvent(event) {
      return dispatch(document, event);
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
  documentElement._isDocument = true;
  document.documentElement.parentElement = null;

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
    postMessage() {},
  };
  windowObject.top = windowObject;

  const api = {
    runtime: {
      id: "fixed",
      onMessage: { addListener: () => {} },
      sendMessage(message) {
        sent.push(JSON.parse(JSON.stringify(message)));
        switch (message.type) {
          case "inline-match":
            return Promise.resolve(
              options.match || {
                connected: true,
                candidates: [],
                siteLinked: false,
              },
            );
          case "inline-state":
            return Promise.resolve({
              connected: true,
              offerSavePasskeys: true,
              offerUsePasskeys: true,
              neverSaveForOrigin: false,
              suppressInline: false,
              generatorDefaults: {},
            });
          case "inline-pending-save":
            return Promise.resolve({ pendingSave: null });
          case "inline-generate":
            return Promise.resolve({
              password: "generated-password",
              profile: null,
              historyId: "",
            });
          default:
            return Promise.resolve({});
        }
      },
    },
    storage: {
      local: {
        get: async () => options.storage || {},
      },
    },
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
    HTMLTextAreaElement,
    HTMLSelectElement,
    MutationObserver: class {
      observe() {}
      disconnect() {}
    },
    navigator: {},
    getComputedStyle: () => ({
      display: "block",
      visibility: "visible",
      opacity: "1",
    }),
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
    setTimeout: (fn) => {
      fn();
      return 0;
    },
    clearTimeout: () => {},
  };
  context.self = context;
  context.globalThis = context;
  for (const file of ["core.js", "content.js"])
    vm.runInNewContext(
      fs.readFileSync(path.join(__dirname, "..", file), "utf8"),
      context,
    );

  const harness = {
    document,
    sent,
    field(attributes = {}) {
      const input = new HTMLInputElement();
      for (const [name, value] of Object.entries(attributes))
        input.setAttribute(name, value);
      if (attributes.placeholder) input.placeholder = attributes.placeholder;
      documentElement.append(input);
      return input;
    },
    focus(input, trusted = true) {
      document.activeElement = input;
      dispatch(document, {
        type: "focusin",
        isTrusted: trusted,
        target: input,
        composedPath: () => [input],
      });
    },
    async paste(input, text, trusted = true) {
      const event = {
        type: "paste",
        isTrusted: trusted,
        target: input,
        composedPath: () => [input],
        clipboardData: { getData: () => text },
        defaultPrevented: false,
        _stopped: false,
        preventDefault() {
          this.defaultPrevented = true;
        },
        stopImmediatePropagation() {
          this._stopped = true;
        },
      };
      dispatch(document, event);
      await flush();
      return event;
    },
    async click(label) {
      const node = harness
        .nodes()
        .find(
          (candidate) =>
            candidate.tagName === "BUTTON" &&
            candidate.textContent === label,
        );
      if (!node) throw new Error("missing button: " + label);
      dispatch(node, {
        type: "click",
        isTrusted: true,
        target: node,
      });
      await flush();
      return node;
    },
    nodes() {
      const found = [];
      walk(documentElement, (node) => found.push(node));
      return found;
    },
    host() {
      return (
        documentElement.children.find(
          (node) => node.tagName === "DIV" && closedRoots.has(node),
        ) || null
      );
    },
    panelText() {
      const host = harness.host();
      const root = host && closedRoots.get(host);
      return root ? root.textContent : "";
    },
    buttons() {
      return harness
        .nodes()
        .filter((node) => node.tagName === "BUTTON")
        .map((node) => node.textContent);
    },
    async trackInputs(input) {
      input.addEventListener("input", () => inputEvents.push(input.value));
      input.addEventListener("change", () => inputEvents.push(input.value));
      return inputEvents;
    },
  };
  return harness;
}

async function focusLinked(harness, input) {
  harness.focus(input);
  await flush();
}

test("an unlinked current-password paste is blocked until the user chooses", async () => {
  const h = makeHarness();
  const input = h.field({
    type: "password",
    autocomplete: "current-password",
    id: "password",
    placeholder: "Password",
  });
  await focusLinked(h, input);
  assert.match(h.panelText(), /选择账号/);
  const inputs = await h.trackInputs(input);

  const event = await h.paste(input, "hunter2");
  assert.equal(event.defaultPrevented, true);
  assert.match(h.panelText(), /粘贴保护/);
  assert.match(h.panelText(), /此网站没有已保存的登录/);
  assert.equal(input.value, "");
  assert.equal(inputs.length, 0);
  assert.equal(
    JSON.stringify(h.sent).includes("hunter2"),
    false,
    "the pasted value never reaches the worker",
  );

  await h.click("仍要粘贴");
  assert.equal(input.value, "hunter2");
  assert.deepEqual(inputs, ["hunter2", "hunter2"]);
  assert.equal(h.host(), null, "the warning closes after the decision");
});

test("a linked site leaves an ordinary password paste untouched", async () => {
  const h = makeHarness({
    match: {
      connected: true,
      candidates: [{ id: "a".repeat(32), revision: "b".repeat(64), title: "x" }],
      siteLinked: true,
    },
  });
  const input = h.field({
    type: "password",
    autocomplete: "current-password",
    id: "password",
  });
  await focusLinked(h, input);
  const event = await h.paste(input, "hunter2");
  assert.equal(event.defaultPrevented, false);
  assert.equal(h.panelText().includes("粘贴保护"), false);
});

test("an unknown site state never blocks a paste", async () => {
  const h = makeHarness();
  const input = h.field({
    type: "password",
    autocomplete: "current-password",
    id: "password",
  });
  const event = await h.paste(input, "hunter2");
  assert.equal(event.defaultPrevented, false);
  assert.equal(h.panelText().includes("粘贴保护"), false);
});

test("a locked or disconnected host stays unknown", async () => {
  const h = makeHarness({
    match: { connected: false, candidates: [], siteLinked: null },
  });
  const input = h.field({
    type: "password",
    autocomplete: "current-password",
    id: "password",
  });
  await focusLinked(h, input);
  const event = await h.paste(input, "hunter2");
  assert.equal(event.defaultPrevented, false);
});

test("a Locklark Secret Key is refused even on a linked site", async () => {
  const h = makeHarness({
    match: {
      connected: true,
      candidates: [{ id: "a".repeat(32), revision: "b".repeat(64), title: "x" }],
      siteLinked: true,
    },
  });
  const input = h.field({ id: "secret", name: "key" });
  await focusLinked(h, input);
  const event = await h.paste(input, SECRET);
  assert.equal(event.defaultPrevented, true);
  assert.match(h.panelText(), /Secret Key/);
  await h.click("取消粘贴");
  assert.equal(input.value, "");
  assert.equal(h.host(), null);
});

test("the disabled setting turns both paste guards off", async () => {
  const h = makeHarness({ storage: { pasteProtection: false } });
  const input = h.field({
    type: "password",
    autocomplete: "current-password",
    id: "password",
  });
  await focusLinked(h, input);
  const event = await h.paste(input, SECRET);
  assert.equal(event.defaultPrevented, false);
  assert.equal(h.panelText().includes("粘贴保护"), false);
});

test("signup and confirm password pastes are not treated as phishing", async () => {
  const h = makeHarness();
  const input = h.field({
    type: "password",
    autocomplete: "new-password",
    id: "new-password",
  });
  await focusLinked(h, input);
  const event = await h.paste(input, "generated-password");
  assert.equal(event.defaultPrevented, false);
});

test("untrusted paste events and non-editable targets are ignored", async () => {
  const h = makeHarness();
  const input = h.field({
    type: "password",
    autocomplete: "current-password",
    id: "password",
  });
  await focusLinked(h, input);
  assert.equal((await h.paste(input, "hunter2", false)).defaultPrevented, false);
  assert.equal(
    (await h.paste(h.document.documentElement, SECRET)).defaultPrevented,
    false,
  );
});

test("a cancelled warning leaves nothing behind in the worker or the field", async () => {
  const h = makeHarness();
  const input = h.field({
    type: "password",
    autocomplete: "current-password",
    id: "password",
  });
  await focusLinked(h, input);
  await h.paste(input, SECRET);
  await h.click("取消粘贴");
  assert.equal(input.value, "");
  assert.equal(JSON.stringify(h.sent).includes("LL1-"), false);
  assert.equal(h.host(), null);
});

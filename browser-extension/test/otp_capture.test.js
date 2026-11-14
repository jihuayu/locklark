const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

const ORIGIN = "https://example.test";
const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const OTPAUTH = "otpauth://totp/ACME%20Co:john@example.com?secret=" + SECRET;
const flush = async (count = 16) => {
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
    this._rect = { left: 10, top: 10, width: 240, height: 240 };
    this.shadowRoot = null;
    this.innerText = "";
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
    for (const listener of [...(this._listeners[event.type] || [])])
      listener(event);
    return true;
  }
  focus() {
    const root = this.getRootNode();
    if (root) root.activeElement = this;
  }
  getRootNode() {
    let node = this;
    while (node.parentElement) node = node.parentElement;
    if (node._isDocument) return node;
    return node._isShadowRoot ? node : null;
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
    root._isShadowRoot = true;
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
  }
  setRangeText(text, start, end) {
    const value = this.value;
    this._value = value.slice(0, start) + String(text) + value.slice(end);
  }
}
class HTMLTextAreaElement extends HTMLInputElement {}
class HTMLSelectElement extends Element {}

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
  if (String(selector).includes(","))
    return String(selector)
      .split(",")
      .some((part) => matchSelector(node, part.trim()));
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

function closestRoot(node) {
  let current = node;
  while (current && current.tagName !== "#SHADOW-ROOT") current = current.parentElement;
  return current || null;
}

function dispatch(root, event) {
  if (!event.target) event.target = root;
  for (const listener of [...(root._listeners?.[event.type] || [])])
    listener(event);
  return event;
}

function makeHarness(options = {}) {
  const sent = [];
  const documentListeners = {};
  const windowListeners = {};
  const timers = [];
  const mutationObservers = [];
  const detections = { count: 0 };
  const pendingDetections = [];
  const pendingCaptures = [];
  const pendingSaves = [];
  const storageListeners = [];
  const pendingStorage = [];
  let timerSerial = 0;

  const body = new Element("body");
  body.innerText = options.bodyText || "Scan this QR code with your authenticator app";
  const documentElement = new Element("html");
  documentElement.append(body);

  const document = {
    _isDocument: true,
    readyState: "complete",
    visibilityState: "visible",
    documentElement,
    body,
    title: options.title ?? "",
    baseURI: ORIGIN + (options.pathname ?? "/settings/2fa"),
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
    _listeners: windowListeners,
    dispatchEvent(event) {
      return dispatch(windowObject, event);
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
          case "inline-otp-capture":
            if (options.deferCapture)
              return new Promise((resolve) => pendingCaptures.push(resolve));
            return Promise.resolve(
              options.captureReply || {
                ok: true,
                captureId: "a".repeat(32),
                label: "ACME Co · john@example.com",
                items: [{ id: "b".repeat(32), title: "Example login" }],
              },
            );
          case "inline-pending-save":
            return Promise.resolve(
              options.pendingSave
                ? { pendingSave: options.pendingSave }
                : {},
            );
          case "inline-dismiss-save":
            return Promise.resolve({ ok: true });
          case "inline-commit-staged-save":
            return Promise.resolve(
              options.commitReply || { saved: false, status: "保存失败" },
            );
          case "inline-otp-save":
            if (options.deferSave)
              return new Promise((resolve) => pendingSaves.push(resolve));
            return Promise.resolve(
              options.saveReply || { ok: true, revision: "c".repeat(64) },
            );
          case "inline-match":
            return Promise.resolve({ connected: true, candidates: [] });
          case "inline-state":
            return Promise.resolve({ connected: true });
          default:
            return Promise.resolve({});
        }
      },
    },
    storage: {
      onChanged: {
        addListener(listener) {
          storageListeners.push(listener);
        },
      },
      local: {
        get: async () => {
          if (options.deferStorage)
            return await new Promise((resolve) => pendingStorage.push(resolve));
          return options.storage || {};
        },
      },
    },
  };

  class BarcodeDetector {
    static async getSupportedFormats() {
      return ["qr_code", "ean_13"];
    }
    constructor(init) {
      this.formats = init?.formats || [];
    }
    async detect(node) {
      detections.count++;
      if (options.deferDecode) {
        return await new Promise((resolve) => {
          pendingDetections.push({ node, resolve });
        });
      }
      if (!node || typeof node._qr !== "string") return [];
      return [{ rawValue: node._qr }];
    }
  }

  const context = {
    window: windowObject,
    document,
    location: {
      origin: ORIGIN,
      protocol: "https:",
      hostname: "example.test",
      href:
        ORIGIN +
        (options.pathname ?? "/settings/2fa") +
        (options.search ?? ""),
      pathname: options.pathname ?? "/settings/2fa",
      search: options.search ?? "",
    },
    isSecureContext: true,
    Element,
    HTMLInputElement,
    HTMLTextAreaElement,
    HTMLSelectElement,
    MutationObserver: class {
      constructor(callback) {
        this.callback = callback;
        this.target = null;
        this.config = null;
        this.disconnected = false;
        mutationObservers.push(this);
      }
      observe(target, config) {
        this.target = target;
        this.config = config;
      }
      disconnect() {
        this.disconnected = true;
      }
    },
    BarcodeDetector,
    navigator: {},
    getComputedStyle: () => ({
      display: "block",
      visibility: "visible",
      opacity: "1",
    }),
    innerWidth: 1024,
    innerHeight: 768,
    chrome: api,
    console,
    URL,
    Event: class Event {
      constructor(type, init = {}) {
        this.type = type;
        this.bubbles = Boolean(init.bubbles);
      }
    },
    setTimeout: (fn) => {
      const id = ++timerSerial;
      timers.push({ id, fn });
      return id;
    },
    clearTimeout: (id) => {
      const index = timers.findIndex((timer) => timer.id === id);
      if (index >= 0) timers.splice(index, 1);
    },
    queueMicrotask,
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
    detections: () => detections.count,
    pendingDecodes: () => pendingDetections.length,
    pendingCaptures: () => pendingCaptures.length,
    pendingSaves: () => pendingSaves.length,
    resolveCapture(reply) {
      const resolve = pendingCaptures.shift();
      if (!resolve) return false;
      resolve(
        reply || {
          ok: true,
          captureId: "a".repeat(32),
          label: "ACME Co · john@example.com",
          items: [{ id: "b".repeat(32), title: "Example login" }],
        },
      );
      return true;
    },
    resolveSave(reply) {
      const resolve = pendingSaves.shift();
      if (!resolve) return false;
      resolve(reply || { ok: true, revision: "c".repeat(64) });
      return true;
    },
    hide() {
      document.visibilityState = "hidden";
      document.dispatchEvent({ type: "visibilitychange" });
    },
    show() {
      document.visibilityState = "visible";
      document.dispatchEvent({ type: "visibilitychange" });
    },
    changeOtpSetting(value) {
      for (const listener of storageListeners)
        listener({ otpCapture: { newValue: value } }, "local");
    },
    resolveStorage(value) {
      const resolve = pendingStorage.shift();
      if (!resolve) return false;
      resolve(value || {});
      return true;
    },
    resolveDetection(index = 0) {
      const pending = pendingDetections.splice(index, 1)[0];
      if (!pending) return false;
      pending.resolve(
        typeof pending.node?._qr === "string"
          ? [{ rawValue: pending.node._qr }]
          : [],
      );
      return true;
    },
    pagehide() {
      windowObject.dispatchEvent({ type: "pagehide" });
    },
    flush: () => flush(),
    otpObserver: () =>
      mutationObservers.find(
        (observer) =>
          observer.config?.childList === true &&
          observer.config?.subtree === true &&
          observer.config?.attributes !== true,
      ),
    triggerOTPMutation() {
      for (const observer of mutationObservers) {
        if (observer.disconnected) continue;
        if (observer.config?.attributes === true) continue;
        observer.callback([], observer);
      }
    },
    image(qr, attributes = {}) {
      const node = new Element("img");
      for (const [name, value] of Object.entries(attributes))
        node.setAttribute(name, value);
      node.complete = true;
      node._qr = qr;
      documentElement.append(node);
      return node;
    },
    canvas(qr) {
      const node = new Element("canvas");
      node._qr = qr;
      documentElement.append(node);
      return node;
    },
    async runTimers() {
      // Let the async feature detection and settings load schedule work first,
      // then drain every timer (including ones scheduled by earlier timers).
      for (let round = 0; round < 20; round++) {
        await flush(4);
        if (!timers.length) return;
        const timer = timers.shift();
        timer.fn();
        await flush(4);
      }
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
      dispatch(node, { type: "click", isTrusted: true, target: node });
      await flush();
      return node;
    },
    nodes() {
      const found = [];
      walk(documentElement, (node) => found.push(node));
      return found;
    },
    panel() {
      // The toast is also a closed-root host; only the dialog section counts.
      for (const node of documentElement.children) {
        const root = closedRoots.get(node);
        if (!root) continue;
        const hasPanel = harness
          .nodes()
          .some(
            (candidate) =>
              candidate.className === "panel" &&
              closestRoot(candidate) === root,
          );
        if (hasPanel) return root;
      }
      return null;
    },
    banner() {
      for (const node of documentElement.children) {
        const root = closedRoots.get(node);
        if (!root) continue;
        const banner = harness
          .nodes()
          .find(
            (candidate) =>
              candidate.className === "banner" && closestRoot(candidate) === root,
          );
        if (banner) return { root, banner };
      }
      return null;
    },
    bannerText() {
      const found = harness.banner();
      return found ? found.banner.textContent : "";
    },
    panelText() {
      const root = harness.panel();
      return root ? root.textContent : "";
    },
  };
  return harness;
}

test("save banner focuses the title and maps Escape and Enter", async () => {
  const stage = {
    stageId: "a".repeat(32),
    mode: "new",
    origin: "https://example.test",
    title: "Example",
    username: "john",
    connected: true,
  };
  const h = makeHarness({ pendingSave: stage });
  await h.runTimers();
  const found = h.banner();
  assert.ok(found, "save banner rendered");
  const title = found.banner.querySelector("input");
  assert.equal(found.root.activeElement, title, "the title input is focused");
  dispatch(found.banner, {
    type: "keydown",
    key: "Escape",
    isTrusted: true,
    target: title,
    preventDefault() {},
  });
  await flush();
  assert.equal(h.banner(), null, "Escape dismisses without saving");
  assert.equal(
    h.sent.some((message) => message.type === "inline-dismiss-save"),
    true,
  );
  assert.equal(
    h.sent.some((message) => message.type === "inline-commit-staged-save"),
    false,
  );
});

test("Enter in the save banner commits the staged save", async () => {
  const stage = {
    stageId: "b".repeat(32),
    mode: "new",
    origin: "https://example.test",
    title: "Example",
    username: "john",
    connected: true,
  };
  const h = makeHarness({ pendingSave: stage });
  await h.runTimers();
  const found = h.banner();
  assert.ok(found);
  dispatch(found.banner, {
    type: "keydown",
    key: "Enter",
    isTrusted: true,
    target: found.banner,
    preventDefault() {},
  });
  await flush();
  const commit = h.sent.find(
    (message) => message.type === "inline-commit-staged-save",
  );
  assert.ok(commit, "commit was sent");
  assert.equal(commit.stageId, stage.stageId);
  assert.equal(commit.mode, "new");
});

test("clicking the panel anchor keeps the capture panel open", async () => {
  const h = makeHarness();
  const image = h.image(OTPAUTH);
  await h.runTimers();
  assert.ok(h.panel(), "panel rendered");
  h.document.dispatchEvent({
    type: "click",
    target: image,
    isTrusted: true,
  });
  assert.ok(h.panel(), "clicking the anchored field must not dismiss it");
});

test("clicking outside the panel dismisses it", async () => {
  const h = makeHarness();
  h.image(OTPAUTH);
  await h.runTimers();
  assert.ok(h.panel(), "panel rendered");
  h.document.dispatchEvent({
    type: "click",
    target: h.document.body,
    isTrusted: true,
  });
  assert.equal(h.panel(), null);
});

test("panel keyboard cycles actions and Escape closes it", async () => {
  const h = makeHarness();
  h.image(OTPAUTH);
  await h.runTimers();
  const root = h.panel();
  assert.ok(root, "panel rendered");
  const box = root.children.find((node) => node.className === "panel");
  const buttons = box.children.filter((node) => node.tagName === "BUTTON");
  assert.ok(buttons.length >= 2);
  const press = (key) => {
    let prevented = false;
    dispatch(box, {
      type: "keydown",
      key,
      isTrusted: true,
      target: box,
      preventDefault() {
        prevented = true;
      },
    });
    return prevented;
  };
  buttons[0].focus();
  assert.equal(press("ArrowDown"), true);
  assert.equal(root.activeElement, buttons[1]);
  press("End");
  assert.equal(root.activeElement, buttons[buttons.length - 1]);
  press("ArrowDown");
  assert.equal(root.activeElement, buttons[0]);
  press("Escape");
  assert.equal(h.panel(), null);
});

test("a setup QR code offers the matching login and saves after a click", async () => {
  const h = makeHarness();
  const image = h.image(OTPAUTH);
  await h.runTimers();
  assert.match(h.panelText(), /保存两步验证/);
  assert.match(h.panelText(), /ACME Co/);
  assert.match(h.panelText(), /Example login/);
  assert.equal(
    h.panelText().includes(SECRET),
    false,
    "the seed never reaches the page UI",
  );
  const capture = h.sent.find((message) => message.type === "inline-otp-capture");
  assert.equal(capture.otpauth, OTPAUTH);
  assert.equal(image._qr, OTPAUTH);
  await h.click("保存到 Example login");
  const save = h.sent.find((message) => message.type === "inline-otp-save");
  assert.equal(save.captureId, "a".repeat(32));
  assert.equal(save.itemId, "b".repeat(32));
  assert.equal(h.panel(), null, "the panel closes after saving");
});

test("ignoring a QR code keeps it out of a later scan prompt", async () => {
  const h = makeHarness();
  h.image(OTPAUTH);
  await h.runTimers();
  assert.match(h.panelText(), /保存两步验证/);
  await h.click("忽略");
  assert.equal(h.panel(), null);
  await h.runTimers();
  assert.equal(h.panelText(), "");
  assert.equal(
    h.sent.filter((message) => message.type === "inline-otp-capture").length,
    1,
  );
});

test("a QR code that is not a TOTP setup is ignored", async () => {
  const h = makeHarness();
  h.image("https://example.test/not-a-secret");
  h.image("otpauth://hotp/ACME:john?secret=" + SECRET);
  await h.runTimers();
  assert.equal(h.panelText(), "");
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
});

test("the otpCapture setting disables scanning", async () => {
  const h = makeHarness({ storage: { otpCapture: false } });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.panelText(), "");
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
});

test("no saved login yields no seed-bearing panel", async () => {
  const h = makeHarness({
    captureReply: { ok: false, reason: "no-item" },
  });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.panel(), null);
  assert.equal(
    h.sent.filter((message) => message.type === "inline-otp-capture").length,
    1,
  );
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-save"),
    false,
  );
});

test("a failed save leaves the panel open with a status", async () => {
  const h = makeHarness({ saveReply: { ok: false, reason: "host" } });
  h.image(OTPAUTH);
  await h.runTimers();
  await h.click("保存到 Example login");
  assert.match(h.panelText(), /保存失败/);
  assert.ok(h.panel(), "the panel stays open so the user can retry");
});

test("a page without a QR-sized candidate never reads innerText", async () => {
  const h = makeHarness({ pathname: "/dashboard" });
  let reads = 0;
  Object.defineProperty(h.document.body, "innerText", {
    configurable: true,
    get() {
      reads++;
      return "Scan this QR code with your authenticator app";
    },
  });
  await h.runTimers();
  assert.equal(reads, 0, "candidate discovery must run before page text");
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
});

test("layout-free heading and title text still recognizes a setup page", async () => {
  const h = makeHarness({ pathname: "/dashboard" });
  let reads = 0;
  Object.defineProperty(h.document.body, "innerText", {
    configurable: true,
    get() {
      reads++;
      return "";
    },
  });
  const heading = h.document.createElement("h1");
  heading.textContent = "Scan this QR code with your authenticator app";
  h.document.documentElement.append(heading);
  h.image(OTPAUTH);
  await h.runTimers();
  assert.match(h.panelText(), /保存两步验证/);
  assert.equal(reads, 0, "relevance must not force a layout flush");
});

test("body-only text is not used as a whole-page relevance signal", async () => {
  const h = makeHarness({
    pathname: "/dashboard",
    bodyText: "Scan this QR code with your authenticator app",
  });
  let reads = 0;
  Object.defineProperty(h.document.body, "innerText", {
    configurable: true,
    get() {
      reads++;
      return "";
    },
  });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.panel(), null);
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
  assert.equal(reads, 0);
});

test("the OTP MutationObserver disconnects at the scan limit", async () => {
  const h = makeHarness();
  for (let index = 0; index < 24; index++)
    h.image("https://example.test/not-a-totp/" + index);
  await h.runTimers();
  assert.ok(h.detections() > 0, "the first batch was scanned");
  assert.equal(h.otpObserver()?.disconnected, false);

  h.triggerOTPMutation();
  await h.runTimers();
  h.triggerOTPMutation();
  await h.runTimers();

  assert.equal(h.otpObserver()?.disconnected, true);
  const scanned = h.detections();
  assert.equal(scanned, 24, "each candidate is decoded at most once");
  h.triggerOTPMutation();
  await h.runTimers();
  assert.equal(h.detections(), scanned, "no decode after the scan limit");
});

test("a candidate batch crossing the scan limit never decodes past 24", async () => {
  const h = makeHarness();
  for (let index = 0; index < 23; index++)
    h.image("https://example.test/not-a-totp/" + index);
  await h.runTimers();
  h.triggerOTPMutation();
  await h.runTimers();
  h.triggerOTPMutation();
  await h.runTimers();
  assert.equal(h.detections(), 23, "the budget is partially consumed");

  for (let index = 23; index < 27; index++)
    h.image("https://example.test/not-a-totp/" + index);
  h.triggerOTPMutation();
  await h.runTimers();
  assert.equal(h.detections(), 24, "only the remaining budget is decoded");
  assert.equal(h.otpObserver()?.disconnected, true);
  h.triggerOTPMutation();
  await h.runTimers();
  assert.equal(h.detections(), 24, "the remaining batch stays undecoded");
});

test("the 24th valid candidate is offered inside the budget", async () => {
  const h = makeHarness();
  for (let index = 0; index < 23; index++)
    h.image("https://example.test/not-a-totp/" + index);
  await h.runTimers();
  h.triggerOTPMutation();
  await h.runTimers();
  h.triggerOTPMutation();
  await h.runTimers();
  assert.equal(h.detections(), 23);

  h.image(OTPAUTH);
  h.triggerOTPMutation();
  await h.runTimers();
  assert.equal(h.detections(), 24);
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    true,
    "the 24th in-budget result is still offered",
  );
  assert.equal(h.otpObserver()?.disconnected, true);
});

test("a hide or stop during a pending capture never opens the save panel", async () => {
  const h = makeHarness({ deferCapture: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.pendingCaptures(), 1);

  h.hide();
  h.pagehide();
  assert.equal(h.resolveCapture(), true);
  await h.flush();
  await h.flush();
  assert.equal(h.panel(), null);
});

test("hiding during a pending decode cancels its offer", async () => {
  const h = makeHarness({ deferDecode: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.pendingDecodes(), 1);

  h.hide();
  assert.equal(h.resolveDetection(), true);
  await h.flush();
  await h.flush();
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
  assert.equal(h.panel(), null);
});

test("a late save response cannot close or update a hidden panel", async () => {
  const h = makeHarness({ deferSave: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.ok(h.panel());
  await h.click("保存到 Example login");
  assert.equal(h.pendingSaves(), 1);

  h.hide();
  assert.equal(h.resolveSave(), true);
  await h.flush();
  await h.flush();
  assert.ok(h.panel(), "the late save response must not close the panel");
  assert.match(h.panelText(), /正在保存/);
  assert.doesNotMatch(h.panelText(), /已保存/);
});

test("runtime disable cancels a pending decode", async () => {
  const h = makeHarness({ deferDecode: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.pendingDecodes(), 1);

  h.changeOtpSetting(false);
  assert.equal(h.resolveDetection(), true);
  await h.flush();
  await h.flush();
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
});

test("runtime disable cancels a pending capture", async () => {
  const h = makeHarness({ deferCapture: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.pendingCaptures(), 1);

  h.changeOtpSetting(false);
  assert.equal(h.resolveCapture(), true);
  await h.flush();
  await h.flush();
  assert.equal(h.panel(), null);
});

test("runtime disable cancels a pending save response", async () => {
  const h = makeHarness({ deferSave: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.ok(h.panel());
  await h.click("保存到 Example login");
  assert.equal(h.pendingSaves(), 1);

  h.changeOtpSetting(false);
  assert.equal(h.resolveSave(), true);
  await h.flush();
  await h.flush();
  assert.ok(h.panel(), "the late save response must not close the panel");
  assert.match(h.panelText(), /正在保存/);
  assert.doesNotMatch(h.panelText(), /已保存/);
});

test("disable then enable rejects an old pending response", async () => {
  const h = makeHarness({ deferCapture: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.pendingCaptures(), 1);

  h.changeOtpSetting(false);
  h.changeOtpSetting(true);
  assert.equal(h.resolveCapture(), true);
  await h.flush();
  await h.flush();
  assert.equal(h.panel(), null);
});

test("hidden then visible rejects an old pending generation", async () => {
  const h = makeHarness({ deferDecode: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.pendingDecodes(), 1);

  h.hide();
  h.show();
  assert.equal(h.resolveDetection(), true);
  await h.flush();
  await h.flush();
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
});

test("a late initial settings read cannot overwrite a runtime disable", async () => {
  const h = makeHarness({ deferStorage: true });
  h.changeOtpSetting(false);
  assert.equal(h.resolveStorage({ otpCapture: true }), true);
  await h.flush();
  await h.flush();
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
  );
});

test("a stop while decode is pending never offers the late result", async () => {
  const h = makeHarness({ deferDecode: true });
  h.image(OTPAUTH);
  await h.runTimers();
  assert.equal(h.pendingDecodes(), 1);

  h.pagehide();
  assert.equal(h.otpObserver()?.disconnected, true);
  assert.equal(h.resolveDetection(), true);
  await h.flush();
  await h.flush();
  assert.equal(
    h.sent.some((message) => message.type === "inline-otp-capture"),
    false,
    "a late result after an explicit stop must not be offered",
  );
});

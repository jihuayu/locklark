const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

function element(tag, attributes = {}, children = []) {
  return {
    tagName: String(tag).toUpperCase(),
    attributes: { ...attributes },
    children,
    parentElement: null,
    isConnected: true,
    hasAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name)
        ? this.attributes[name]
        : null;
    },
    querySelectorAll(selector) {
      const want = String(selector).toUpperCase();
      const found = [];
      const walk = (node) => {
        for (const child of node.children || []) {
          if (child.tagName === want) found.push(child);
          walk(child);
        }
      };
      walk(this);
      return found;
    },
  };
}

// Runs content.js with a cross-origin top so frameAllowed() returns false right
// after the fence is installed. No runtime API or UI path is exercised.
function makeContentHarness(options = {}) {
  const observers = [];
  const documentListeners = {};
  const messages = [];
  const frames = options.frames || [];
  const root =
    options.documentElement === undefined
      ? element("html", {}, frames)
      : options.documentElement;
  const document = {
    documentElement: root,
    querySelectorAll(selector) {
      const want = String(selector).toUpperCase();
      const found = [];
      const walk = (node) => {
        for (const child of node.children || []) {
          if (child.tagName === want) found.push(child);
          walk(child);
        }
      };
      if (document.documentElement) walk(document.documentElement);
      return found;
    },
    addEventListener(type, listener) {
      (documentListeners[type] = documentListeners[type] || []).push(listener);
    },
  };
  class MutationObserver {
    constructor(callback) {
      this.callback = callback;
      observers.push(this);
    }
    observe(target, config) {
      this.target = target;
      this.config = config;
    }
  }
  const windowObject = {
    origin: options.windowOrigin ?? "https://frame.test",
    addEventListener() {},
    postMessage(data) {
      messages.push(data);
    },
  };
  if (options.topIsSelf === true) windowObject.top = windowObject;
  else {
    const top = {};
    Object.defineProperty(top, "location", {
      get() {
        throw Error("cross-origin");
      },
    });
    windowObject.top = top;
  }
  const context = {
    window: windowObject,
    document,
    location: {
      origin: options.origin ?? "https://frame.test",
      protocol: options.protocol ?? "https:",
      href: options.href ?? "https://frame.test/pay",
    },
    isSecureContext: options.isSecureContext ?? true,
    MutationObserver,
    Object,
    console: {},
  };
  context.globalThis = context;
  context.self = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../content.js"), "utf8"),
    context,
  );
  return {
    context,
    document,
    window: windowObject,
    messages,
    observerConfigs: observers.map((observer) => observer.config),
    observerTargets: observers.map((observer) => observer.target),
    documentListeners,
    snapshot() {
      const fence = context.LocklarkCheckoutFence;
      return typeof fence === "function" ? { ...fence() } : null;
    },
    emit(records) {
      for (const observer of observers)
        observer.callback(records || [], observer);
    },
    setRoot(next) {
      document.documentElement = next;
    },
    descriptor() {
      return Object.getOwnPropertyDescriptor(
        context,
        "LocklarkCheckoutFence",
      );
    },
  };
}

module.exports = { element, makeContentHarness };

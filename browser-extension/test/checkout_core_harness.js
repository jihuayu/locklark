const vm = require("node:vm");
const core = require("../core.js");

function compile(source, context) {
  return vm.runInNewContext("(" + source + ")", context);
}

// Serializes core.checkoutProbe exactly like api.scripting.executeScript does,
// so a closure reference would fail here too.
function makeProbeHarness(options = {}) {
  const origin = options.origin ?? "https://frame.test";
  const windowObject = {
    origin: options.windowOrigin ?? origin,
    top: null,
  };
  windowObject.top = options.topIsSelf === false ? {} : windowObject;
  const context = {
    location: {
      origin,
      protocol: options.protocol ?? "https:",
      href: options.href ?? "https://frame.test/pay",
    },
    window: windowObject,
    isSecureContext: options.secure ?? true,
    console: {},
  };
  if (Object.prototype.hasOwnProperty.call(options, "fence"))
    context.LocklarkCheckoutFence = options.fence;
  context.globalThis = context;
  const fn = compile(core.checkoutProbe.toString(), context);
  return { context, fn, call: () => ({ ...fn() }) };
}

class Element {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.type = this.tagName === "SELECT" ? "select-one" : "text";
    this.attributes = {};
    this.autocomplete = "";
    this.disabled = false;
    this.readOnly = false;
    this.isConnected = true;
    this.parentElement = null;
    this.options = [];
    this.events = [];
    this._value = "";
    this._style = { display: "block", visibility: "visible", opacity: "1" };
    this._rect = { width: 100, height: 20 };
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }
  hasAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name);
  }
  matches(selector) {
    return selector === ":disabled" ? this.disabled === true : false;
  }
  closest() {
    return null;
  }
  getBoundingClientRect() {
    return this._rect;
  }
  dispatchEvent(event) {
    this.events.push(event);
    if (typeof this.onEvent === "function") this.onEvent(event);
    return true;
  }
}
class HTMLInputElement extends Element {
  constructor() {
    super("input");
  }
}
class HTMLSelectElement extends Element {
  constructor() {
    super("select");
  }
}
for (const proto of [HTMLInputElement.prototype, HTMLSelectElement.prototype])
  Object.defineProperty(proto, "value", {
    configurable: true,
    get() {
      return this._value;
    },
    set(next) {
      this._value = String(next);
      if (typeof this.onSet === "function") this.onSet(next);
    },
  });

function control(tag, config = {}) {
  const name = String(tag).toUpperCase();
  const element = new (name === "SELECT" ? HTMLSelectElement : HTMLInputElement)();
  if (config.type !== undefined) element.type = config.type;
  if (config.autocomplete !== undefined) {
    element.autocomplete = config.autocomplete;
    element.attributes.autocomplete = config.autocomplete;
  }
  for (const [key, value] of Object.entries(config.attributes || {}))
    element.attributes[key] = value;
  if (config.disabled) element.disabled = true;
  if (config.readOnly) element.readOnly = true;
  if (config.hidden) element._rect = { width: 0, height: 0 };
  if (config.style) element._style = { ...config.style };
  if (config.rect) element._rect = { ...config.rect };
  if (config.options)
    element.options = config.options.map((option) => ({
      value: option.value,
      text: option.text ?? option.value,
      disabled: Boolean(option.disabled),
    }));
  if (config.value !== undefined) element._value = String(config.value);
  if (config.onSet) element.onSet = config.onSet;
  if (config.onEvent) element.onEvent = config.onEvent;
  return element;
}

// Serializes core.fillCheckoutCardDocument and runs it against a fake document.
// Default frame/window shape is a cross-origin checkout subframe.
function makeFillHarness(options = {}) {
  const clock = options.clock ?? 1_700_000_000_000;
  const elements = options.elements || [];
  const root = options.documentElement ?? { tagName: "HTML" };
  const document = {
    documentElement: root,
    querySelectorAll(selector) {
      return String(selector) === "input,select" ? elements : [];
    },
  };
  const windowObject = {
    origin: options.windowOrigin ?? options.origin ?? "https://frame.test",
    top: null,
  };
  windowObject.top =
    options.topIsSelf === true ? windowObject : { origin: "other" };
  const context = {
    document,
    location: {
      origin: options.origin ?? "https://frame.test",
      protocol: options.protocol ?? "https:",
      href: options.href ?? "https://frame.test/pay",
    },
    window: windowObject,
    isSecureContext: options.secure ?? true,
    HTMLInputElement,
    HTMLSelectElement,
    Event: class {
      constructor(type, init = {}) {
        this.type = type;
        this.bubbles = Boolean(init.bubbles);
      }
    },
    getComputedStyle: (node) =>
      (node && node._style) || {
        display: "block",
        visibility: "visible",
        opacity: "1",
      },
    Date: { now: () => clock },
    TextEncoder,
    console: {},
  };
  if (options.fence !== null)
    context.LocklarkCheckoutFence =
      options.fence ||
      (() => ({
        document_stable: options.stable !== false,
        sandbox_ever: options.sandboxEver === true,
      }));
  context.globalThis = context;
  const fn = compile(core.fillCheckoutCardDocument.toString(), context);
  return {
    context,
    document,
    elements,
    clock,
    root,
    setRoot(next) {
      document.documentElement = next;
    },
    call: (origin, fields, deadline, allowTop) => ({
      ...fn(origin, fields, deadline, allowTop),
    }),
  };
}

module.exports = { makeProbeHarness, makeFillHarness, control };

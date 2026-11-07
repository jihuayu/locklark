const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const core = require("../core.js");

const ORIGIN = "https://example.test";
const WALL = 1_700_000_000_000;

// Chrome's `scripting.executeScript` argument transport is JSON-shaped: array
// entries holding `undefined` arrive in the target world as `null`. Anything
// asserting OTP probe behaviour must therefore exercise this exact round trip.
function transport(args) {
  return JSON.parse(JSON.stringify(args));
}

class FakeElement {
  constructor(tagName, doc) {
    this.nodeType = 1;
    this.tagName = tagName;
    this.ownerDocument = doc;
    this.parentElement = null;
    this.isConnected = true;
    this.disabled = false;
    this.readOnly = false;
    this.hidden = false;
    this.attributes = {};
    this.events = [];
  }
  matches() {
    return false;
  }
  closest(selector) {
    if (selector === "form") return this.form || null;
    return null;
  }
  getRootNode() {
    return this.ownerDocument || null;
  }
  getBoundingClientRect() {
    return { width: 120, height: 24 };
  }
  getClientRects() {
    return [{}];
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }
  dispatchEvent(event) {
    this.events.push(event);
    return true;
  }
  focus() {
    this.focused = true;
  }
}
class FakeInput extends FakeElement {
  constructor(doc) {
    super("INPUT", doc);
    this.type = "text";
    this.name = "";
    this.id = "";
    this.placeholder = "";
    this.autocomplete = "";
    this.maxLength = -1;
    this._value = "";
  }
}
Object.defineProperty(FakeInput.prototype, "value", {
  get() {
    return this._value;
  },
  set(value) {
    this._value = String(value);
  },
});
class FakeEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = Boolean(init.bubbles);
    this.cancelable = Boolean(init.cancelable);
    this.data = init.data;
  }
}
class FakeInputEvent extends FakeEvent {}
class FakeKeyboardEvent extends FakeEvent {
  constructor(type, init = {}) {
    super(type, init);
    this.key = init.key;
    this.code = init.code;
  }
}

function otpBox(doc, index) {
  const input = new FakeInput(doc);
  input.name = "otp-" + index;
  input.maxLength = 1;
  input.autocomplete = "one-time-code";
  input.attributes = { autocomplete: "one-time-code", maxlength: "1" };
  return input;
}

function singleOtpInput(doc, name) {
  const input = new FakeInput(doc);
  input.name = name || "otp";
  input.autocomplete = "one-time-code";
  input.attributes = { autocomplete: "one-time-code" };
  return input;
}

function makeDocument(inputs) {
  return {
    baseURI: ORIGIN + "/page",
    querySelectorAll(selector) {
      if (selector === "input")
        return inputs.filter((input) => input.tagName === "INPUT");
      return [];
    },
    querySelector() {
      return null;
    },
    getElementById() {
      return null;
    },
  };
}

function makeForm(doc) {
  return {
    isConnected: true,
    ownerDocument: doc,
    getAttribute(name) {
      return name === "action" ? ORIGIN + "/login" : null;
    },
  };
}

// Builds an isolated-world sandbox and the probe callable that the browser
// actually injects for the args it receives.
function page(options = {}) {
  const boxes =
    options.boxes === undefined
      ? []
      : Array.from({ length: options.boxes }, (_, index) =>
          otpBox(null, index),
        );
  const singles = (options.singles || []).map((name) => singleOtpInput(null, name));
  const inputs = [...boxes, ...singles];
  const document = makeDocument(inputs);
  for (const input of inputs) input.ownerDocument = document;
  if (options.withForm) {
    const form = makeForm(document);
    for (const input of inputs) input.form = form;
  }
  const origin = options.origin ?? ORIGIN;
  const context = {
    document,
    location: {
      origin,
      protocol: options.protocol ?? "https:",
      href: origin === "null" ? "null" : origin + "/page",
    },
    getComputedStyle: () => ({
      display: "block",
      visibility: "visible",
      opacity: "1",
    }),
    Event: FakeEvent,
    InputEvent: FakeInputEvent,
    KeyboardEvent: FakeKeyboardEvent,
    URL,
    CSS: { escape: (value) => String(value) },
    Element: FakeElement,
    HTMLInputElement: FakeInput,
    Date: { now: () => options.wall ?? WALL },
    performance: {
      timeOrigin: options.timeOrigin ?? 1000,
      now: () => options.now ?? 50,
    },
    console: {},
  };
  context.window = context;
  if (options.frame) {
    const top = { location: { origin: options.topOrigin ?? origin } };
    context.top = top;
    if (options.throwTop)
      Object.defineProperty(top, "location", {
        get() {
          throw Error("cross-origin");
        },
      });
  } else {
    context.top = context;
  }
  const fn = vm.runInNewContext(
    "(" + core.otpDocument.toString() + ")",
    context,
  );
  const timing = {
    origin,
    top: !options.frame,
    timeOrigin: context.performance.timeOrigin,
    now: context.performance.now(),
    wall: options.wall ?? WALL,
  };
  // Invokes the injected function with args as the browser delivers them.
  const inject = (args) => fn(...transport(args));
  return { fn, inject, inputs, boxes, timing, context };
}

test("OTP probe args survive the scripting JSON transport as explicit nulls", () => {
  const { inject } = page({ boxes: 6, withForm: true });
  // Explicit null sentinels, as background.js now sends them.
  assert.deepEqual(
    { ...inject([ORIGIN, "probe", null, null, false]) },
    { origin: ORIGIN, top: true, timeOrigin: 1000, now: 50, wall: WALL },
  );
  // Legacy callers that rely on the transport turning undefined into null.
  assert.deepEqual(
    { ...inject([ORIGIN, "probe", undefined, undefined, false]) },
    { origin: ORIGIN, top: true, timeOrigin: 1000, now: 50, wall: WALL },
  );
  // Direct calls in a world without transport still work.
  const direct = page({ boxes: 6, withForm: true });
  assert.deepEqual(
    { ...direct.fn(ORIGIN, "probe", undefined, undefined, false) },
    { origin: ORIGIN, top: true, timeOrigin: 1000, now: 50, wall: WALL },
  );
});

test("OTP probe still refuses any non-null code or timing payload", () => {
  const cases = [
    [ORIGIN, "probe", "123456", null, false],
    [ORIGIN, "probe", 123456, null, false],
    [ORIGIN, "probe", "", null, false],
    [ORIGIN, "probe", null, {}, false],
    [ORIGIN, "probe", null, { top: true }, false],
    [ORIGIN, "probe", "123456", { now: 1 }, false],
    [
      ORIGIN,
      "probe",
      null,
      { origin: ORIGIN, top: true, timeOrigin: 1000, now: 50, wall: WALL },
      false,
    ],
    [ORIGIN, "probe", null, "timing", false],
  ];
  for (const args of cases) {
    const { inject, boxes } = page({ boxes: 6, withForm: true });
    assert.equal(inject(args), false, JSON.stringify(args));
    for (const box of boxes) assert.equal(box.value, "");
  }
});

test("OTP probe honours same-origin subframe policy after JSON transport", () => {
  const sameOrigin = page({ boxes: 6, withForm: true, frame: true });
  assert.deepEqual(
    { ...sameOrigin.inject([ORIGIN, "probe", null, null, true]) },
    {
      origin: ORIGIN,
      top: false,
      timeOrigin: 1000,
      now: 50,
      wall: WALL,
    },
  );
  // A subframe probe that does not carry allowSubframe is refused.
  assert.equal(sameOrigin.inject([ORIGIN, "probe", null, null, false]), false);

  for (const options of [
    { boxes: 6, withForm: true, frame: true, topOrigin: "https://other.test" },
    { boxes: 6, withForm: true, frame: true, throwTop: true },
    {
      boxes: 6,
      withForm: true,
      frame: true,
      origin: "null",
      topOrigin: "null",
    },
    { boxes: 6, withForm: true, origin: "null" },
  ]) {
    const crossOrigin = page(options);
    const origin = options.origin ?? ORIGIN;
    assert.equal(
      crossOrigin.inject([origin, "probe", null, null, true]),
      false,
      JSON.stringify(options),
    );
  }
});

test("OTP probe keeps refusing formless and ambiguous targets", () => {
  // Formless single OTP field: no verifiable submit target.
  const formless = page({ singles: ["otp"] });
  assert.equal(formless.inject([ORIGIN, "probe", null, null, false]), false);
  // Same field with a same-origin form is accepted.
  const formed = page({ singles: ["otp"], withForm: true });
  assert.deepEqual(
    { ...formed.inject([ORIGIN, "probe", null, null, false]) },
    { origin: ORIGIN, top: true, timeOrigin: 1000, now: 50, wall: WALL },
  );
  // Two ambiguous single OTP fields.
  const ambiguous = page({ singles: ["otp", "verification-code"], withForm: true });
  assert.equal(ambiguous.inject([ORIGIN, "probe", null, null, false]), false);
  // A same-origin form with an off-origin action is refused.
  const offOrigin = page({ boxes: 6, withForm: true });
  const form = offOrigin.inputs[0].form;
  form.getAttribute = (name) =>
    name === "action" ? "https://other.test/login" : null;
  assert.equal(offOrigin.inject([ORIGIN, "probe", null, null, false]), false);
});

test("OTP fill still validates code and timing strictly after transport", () => {
  const good = page({ boxes: 6, withForm: true });
  // Explicit nulls must never be accepted as a fill payload.
  assert.equal(good.inject([ORIGIN, "fill", null, good.timing, false]), false);
  assert.equal(good.inject([ORIGIN, "fill", "123456", null, false]), false);
  assert.equal(
    good.inject([ORIGIN, "fill", undefined, undefined, false]),
    false,
  );
  assert.equal(good.inject([ORIGIN, "fill", "12345", good.timing, false]), false);
  assert.equal(good.inject([ORIGIN, "fill", "1234567", good.timing, false]), false);
  for (const box of good.boxes) {
    assert.equal(box.value, "");
    assert.equal(box.events.length, 0);
  }
  // A valid serialized fill payload still fills box by box.
  assert.equal(
    good.inject([ORIGIN, "fill", "123456", good.timing, false]),
    true,
  );
  assert.deepEqual(
    good.boxes.map((box) => box.value),
    "123456".split(""),
  );
  // Timing from another origin or frame is refused.
  for (const timing of [
    { ...good.timing, origin: "https://other.test" },
    { ...good.timing, top: false },
    { ...good.timing, wall: WALL + 5000 },
  ]) {
    const candidate = page({ boxes: 6, withForm: true });
    assert.equal(
      candidate.inject([ORIGIN, "fill", "123456", timing, false]),
      false,
    );
    for (const box of candidate.boxes) assert.equal(box.value, "");
  }
});

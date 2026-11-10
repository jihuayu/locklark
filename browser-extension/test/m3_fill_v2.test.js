const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

const tick = () => new Promise((resolve) => setImmediate(resolve));
const settle = async (count = 10) => {
  for (let index = 0; index < count; index++) await tick();
};

class Element {
  constructor() {
    this.nodeType = 1;
    this.parentElement = null;
    this.isConnected = true;
    this.disabled = false;
    this.readOnly = false;
    this.hidden = false;
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
    return { width: 100, height: 24 };
  }
  getClientRects() {
    return [{}];
  }
  dispatchEvent(event) {
    event.target = this;
    this.events.push(event);
    return true;
  }
  focus() {
    this.focused = true;
  }
}
class HTMLInputElement extends Element {
  constructor() {
    super();
    this.tagName = "INPUT";
    this.type = "text";
    this.name = "";
    this.id = "";
    this.placeholder = "";
    this.autocomplete = "";
    this.maxLength = -1;
    this.attributes = {};
    this._value = "";
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }
}
Object.defineProperty(HTMLInputElement.prototype, "value", {
  get() {
    return this._value;
  },
  set(value) {
    this._value = String(value);
  },
});
class HTMLSelectElement extends Element {
  constructor() {
    super();
    this.tagName = "SELECT";
    this.type = "select-one";
    this.name = "";
    this.id = "";
    this.autocomplete = "";
    this.attributes = {};
    this.options = [];
    this._value = "";
  }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }
}
Object.defineProperty(HTMLSelectElement.prototype, "value", {
  get() {
    const selected = this.options.find((option) => option.selected);
    return this._value || (selected ? String(selected.value) : "");
  },
  set(value) {
    this._value = String(value);
    for (const option of this.options)
      option.selected = String(option.value) === this._value;
  },
});
class HTMLTextAreaElement extends HTMLInputElement {
  constructor() {
    super();
    this.tagName = "TEXTAREA";
  }
}
class Event {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = Boolean(init.bubbles);
    this.cancelable = Boolean(init.cancelable);
    this.data = init.data;
  }
}
class InputEvent extends Event {}
class KeyboardEvent extends Event {
  constructor(type, init = {}) {
    super(type, init);
    this.key = init.key;
    this.code = init.code;
  }
}

function matchesSelector(element, selector) {
  if (selector === "*") return true;
  return selector.split(",").some((part) => {
    const match =
      /^([a-zA-Z*]+)(?:\[([\w-]+)(?:="([^"]*)")?\])?$/.exec(part.trim());
    if (!match) return false;
    if (
      match[1] !== "*" &&
      String(element.tagName || "").toLowerCase() !== match[1].toLowerCase()
    )
      return false;
    if (match[2]) {
      const actual =
        typeof element.getAttribute === "function"
          ? element.getAttribute(match[2])
          : null;
      if (match[3] !== undefined) return actual === match[3];
      return actual !== null;
    }
    return true;
  });
}

function makeControl(tag, config = {}) {
  const Constructor =
    tag === "SELECT"
      ? HTMLSelectElement
      : tag === "TEXTAREA"
        ? HTMLTextAreaElement
        : HTMLInputElement;
  const element = new Constructor();
  element.tagName = tag;
  element.type =
    config.type ||
    (tag === "SELECT" ? "select-one" : tag === "TEXTAREA" ? undefined : "text");
  element.name = config.name || "";
  element.id = config.id || "";
  element.placeholder = config.placeholder || "";
  element.attributes = { ...(config.attributes || {}) };
  if (
    config.autocomplete &&
    !Object.hasOwn(element.attributes, "autocomplete")
  )
    element.attributes.autocomplete = config.autocomplete;
  if (config.maxLength !== undefined) element.maxLength = config.maxLength;
  if (config.disabled) element.disabled = true;
  if (config.readOnly) element.readOnly = true;
  if (config.hidden) element.hidden = true;
  if (tag === "SELECT")
    element.options = (config.options || []).map((option) => ({
      value: option.value,
      text: option.text ?? option.value,
      disabled: Boolean(option.disabled),
      defaultSelected: Boolean(option.defaultSelected),
      selected: Boolean(option.selected),
    }));
  if (config.value !== undefined) element.value = config.value;
  if (config.form) element.form = config.form;
  if (config.parentElement) element.parentElement = config.parentElement;
  return element;
}

function makeDocument(elements) {
  const document = {
    baseURI: "https://example.test/page",
    querySelectorAll(selector) {
      return elements.filter((element) =>
        matchesSelector(element, selector),
      );
    },
    querySelector(selector) {
      return this.querySelectorAll(selector)[0] || null;
    },
    getElementById(id) {
      return elements.find((element) => element.id === id) || null;
    },
  };
  for (const element of elements) element.ownerDocument = document;
  return document;
}

function makeSandbox(elements, options = {}) {
  const document = makeDocument(elements);
  const origin = options.origin ?? "https://example.test";
  const location = {
    origin,
    protocol: options.protocol ?? "https:",
    href: origin === "null" ? "null" : origin + "/page",
  };
  const context = {
    document,
    location,
    getComputedStyle: () => ({
      display: "block",
      visibility: "visible",
      opacity: "1",
    }),
    Event,
    InputEvent,
    KeyboardEvent,
    URL,
    CSS: { escape: (value) => String(value) },
    Element,
    HTMLInputElement,
    HTMLSelectElement,
    HTMLTextAreaElement,
    Date: { now: () => options.clock ?? Date.now() },
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
  // An HTTPS page is a secure context; the injected helpers require it.
  if (options.secure !== false) context.isSecureContext = true;
  return { context, document };
}

function compiledDocumentFunction(name, sandbox) {
  return vm.runInNewContext(
    "(" + core[name].toString() + ")",
    sandbox.context,
  );
}

// A minimal live card checkout page for the background's injected
// core.fillCheckoutCardDocument. The page supplies the visible controls, the
// document fence and its own clock, so the helper's real deadline, origin and
// stability checks all still apply.
const cardPage = { page: null };
Object.defineProperty(Element.prototype, "getBoundingClientRect", {
  value() {
    const page = cardPage.page;
    return page && page.controls.includes(this)
      ? { width: 240, height: 32 }
      : { width: 100, height: 24 };
  },
});
const cardEventTarget = function (page, expectedOrigin, ...rest) {
  if (!page || cardPage.page !== page) throw Error("unexpected scripting target");
  const { context } = makeSandbox([], { origin: page.origin });
  context.document.querySelectorAll = (selector) =>
    String(selector) === "input,select" ? page.controls : [];
  context.LocklarkCheckoutFence = page.fence;
  context.Event = class extends Event {
    constructor(type, init = {}) {
      super(type, init);
      this.target = null;
    }
  };
  // The page's own clock sits inside the deadline the worker passed; without a
  // passed deadline it stays on the page's base clock.
  context.Date = {
    now: () => (Number.isSafeInteger(rest[1]) ? rest[1] - 1 : page.clock),
  };
  return compiledDocumentFunction("fillCheckoutCardDocument", { context })(
    expectedOrigin,
    ...rest,
  );
};
function identitySandbox(options = {}) {
  const clock = options.clock ?? 1_700_000_000_000;
  const elements = {
    full: makeControl("INPUT", { autocomplete: "name" }),
    first: makeControl("INPUT", { autocomplete: "given-name" }),
    last: makeControl("INPUT", { autocomplete: "family-name" }),
    middle: makeControl("INPUT", { autocomplete: "additional-name" }),
    email: makeControl("INPUT", { autocomplete: "email", type: "email" }),
    phone: makeControl("INPUT", { autocomplete: "tel", type: "tel" }),
    street: makeControl("INPUT", { autocomplete: "street-address" }),
    city: makeControl("INPUT", { autocomplete: "address-level2" }),
    stateInput: makeControl("INPUT", { autocomplete: "address-level1" }),
    stateSelect: makeControl("SELECT", {
      autocomplete: "address-level1",
      options: [
        { value: "CA", text: "California" },
        { value: "NY", text: "New York" },
      ],
    }),
    postal: makeControl("INPUT", { autocomplete: "postal-code" }),
    countryInput: makeControl("INPUT", { autocomplete: "country-name" }),
    countrySelect: makeControl("SELECT", {
      autocomplete: "country",
      options: [
        { value: "US", text: "United States" },
        { value: "CN", text: "China" },
      ],
    }),
  };
  const sandbox = makeSandbox(Object.values(elements), { ...options, clock });
  const fn = compiledDocumentFunction("fillIdentityDocument", sandbox);
  return { elements, sandbox, fn, clock };
}

function cardSandbox(options = {}) {
  const clock = options.clock ?? 1_700_000_000_000;
  const months = Array.from({ length: 12 }, (_, index) => {
    const value = String(index + 1).padStart(2, "0");
    return { value, text: value };
  });
  const elements = {
    holder: makeControl("INPUT", { autocomplete: "cc-name" }),
    number: makeControl("INPUT", { autocomplete: "cc-number" }),
    expShort: makeControl("INPUT", {
      autocomplete: "cc-exp",
      maxLength: 5,
      placeholder: "MM/YY",
    }),
    expLong: makeControl("INPUT", {
      autocomplete: "cc-exp",
      maxLength: 7,
      placeholder: "MM/YYYY",
    }),
    expCompact: makeControl("INPUT", {
      autocomplete: "cc-exp",
      maxLength: 4,
      placeholder: "MMYY",
    }),
    expMonth: makeControl("SELECT", {
      autocomplete: "cc-exp-month",
      options: months,
    }),
    expYear: makeControl("SELECT", {
      autocomplete: "cc-exp-year",
      options: [
        { value: "2028", text: "2028" },
        { value: "2029", text: "2029" },
        { value: "2030", text: "2030" },
      ],
    }),
    csc: makeControl("INPUT", { autocomplete: "cc-csc" }),
  };
  const sandbox = makeSandbox(Object.values(elements), { ...options, clock });
  const compiled = compiledDocumentFunction("fillCardDocument", sandbox);
  // Card injection is only valid with the worker's explicit authorization.
  const fn = (...args) => compiled(...args, true);
  return { elements, sandbox, fn, raw: compiled, clock };
}

function otpSandbox(count, options = {}) {
  const clock = options.clock ?? 1_700_000_000_000;
  const boxes = Array.from({ length: count }, (_, index) =>
    makeControl("INPUT", {
      name: "otp-" + index,
      maxLength: 1,
      attributes: { autocomplete: "one-time-code", maxlength: "1" },
    }),
  );
  const sandbox = makeSandbox(boxes, { ...options, clock });
  const fn = compiledDocumentFunction("otpDocument", sandbox);
  const timing = {
    origin: options.origin ?? "https://example.test",
    top: options.frame ? false : true,
    timeOrigin: sandbox.context.performance.timeOrigin,
    now: sandbox.context.performance.now(),
    wall: clock,
  };
  return { boxes, sandbox, fn, timing, clock };
}

test("M3 identity classifyField covers name, contact and address fields", () => {
  const cases = [
    [{ name: "full name" }, "full_name"],
    [{ name: "first name" }, "first_name"],
    [{ name: "last name" }, "last_name"],
    [{ name: "email", type: "email" }, "email"],
    [{ name: "phone", type: "tel" }, "phone"],
    [{ name: "street address" }, "street_address"],
    [{ name: "city" }, "city"],
    [{ name: "state" }, "state"],
    [
      {
        tag: "SELECT",
        name: "state",
        options: [
          { value: "CA", text: "California" },
          { value: "NY", text: "New York" },
        ],
      },
      "state",
    ],
    [{ name: "postal code" }, "postal_code"],
    [{ name: "country" }, "country_name"],
    [
      {
        tag: "SELECT",
        name: "country",
        options: [
          { value: "US", text: "United States" },
          { value: "CN", text: "China" },
        ],
      },
      "country_code",
    ],
  ];
  for (const [config, field] of cases) {
    const control = makeControl(config.tag || "INPUT", config);
    assert.deepEqual(core.classifyField(control), {
      category: "identity",
      field,
    });
  }
  assert.equal(core.classifyField(makeControl("INPUT", { name: "username" })), null);
  assert.equal(
    core.classifyField(makeControl("INPUT", { name: "password", type: "password" })),
    null,
  );
});

test("M3 identity inspectAutofillFields returns only eligible classified controls", () => {
  const full = makeControl("INPUT", { name: "full name" });
  const email = makeControl("INPUT", { name: "email", type: "email" });
  const state = makeControl("SELECT", {
    name: "state",
    options: [
      { value: "CA", text: "California" },
      { value: "NY", text: "New York" },
    ],
  });
  const hidden = makeControl("INPUT", {
    name: "country",
    type: "hidden",
  });
  const disabled = makeControl("INPUT", { name: "city", disabled: true });
  const username = makeControl("INPUT", { name: "username" });
  const controls = [full, email, state, hidden, disabled, username];
  const root = {
    querySelectorAll(selector) {
      if (selector === "input,select,textarea" || selector === "*")
        return controls;
      return [];
    },
  };
  const found = core.inspectAutofillFields(root);
  assert.deepEqual(
    found.map((entry) => [entry.category, entry.field, entry.element]),
    [
      ["identity", "full_name", full],
      ["identity", "email", email],
      ["identity", "state", state],
    ],
  );
});

test("M3 fillIdentityDocument fills identity inputs and selects", () => {
  const { elements, fn, clock } = identitySandbox();
  const data = {
    full_name: "Ada Lovelace",
    first_name: "Ada",
    last_name: "Lovelace",
    email: "ada@example.test",
    phone: "+1 555 0100",
    street_address: "12 Analytical Way",
    city: "London",
    state: "CA",
    postal_code: "94105",
    country_code: "US",
  };
  assert.equal(
    fn("https://example.test", data, clock - 1, false),
    false,
  );
  for (const element of Object.values(elements)) assert.equal(element.value, "");

  const expiresAt = clock + 2000;
  assert.equal(fn("https://example.test", data, expiresAt, false), true);
  assert.equal(elements.full.value, "Ada Lovelace");
  assert.equal(elements.first.value, "Ada");
  assert.equal(elements.last.value, "Lovelace");
  assert.equal(elements.email.value, "ada@example.test");
  assert.equal(elements.phone.value, "+1 555 0100");
  assert.equal(elements.street.value, "12 Analytical Way");
  assert.equal(elements.city.value, "London");
  assert.equal(elements.stateInput.value, "CA");
  assert.equal(elements.stateSelect.value, "CA");
  assert.equal(elements.postal.value, "94105");
  assert.equal(elements.countryInput.value, "united states");
  assert.equal(elements.countrySelect.value, "US");
  assert.deepEqual(
    elements.email.events.map((event) => event.type),
    ["input", "change"],
  );
});

test("M3 fillIdentityDocument derives first, middle and last names", () => {
  const { elements, fn, clock } = identitySandbox();
  assert.equal(
    fn(
      "https://example.test",
      { full_name: "Grace Brewster Hopper" },
      clock + 2000,
      false,
      "identity",
    ),
    true,
  );
  assert.equal(elements.first.value, "Grace");
  assert.equal(elements.middle.value, "Brewster");
  assert.equal(elements.last.value, "Hopper");
  assert.equal(elements.full.value, "Grace Brewster Hopper");
});

test("M3 identity validResponse accepts only bounded identity maps", () => {
  const id = "a".repeat(32);
  for (const response of [
    {
      v: 1,
      id,
      type: "fill",
      category: "identity",
      identity: { full_name: "Ada Lovelace", email: "ada@example.test" },
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "identity",
      identity: { address_line1: "12 Analytical Way", country_code: "US" },
    },
    {
      v: 1,
      id,
      type: "filled-identity",
      category: "identity",
      identity: { full_name: "Ada Lovelace" },
    },
    {
      v: 1,
      id,
      type: "filled",
      category: "identity",
      identity: { phone: "+1 555 0100" },
    },
  ])
    assert.equal(core.validResponse(response), true);

  for (const response of [
    {
      v: 1,
      id,
      type: "fill",
      category: "identity",
      identity: { full_name: "Ada" },
      card: { number: "4242424242424242" },
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "identity",
      identity: { password: "not-identity" },
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "identity",
      identity: { full_name: 42 },
    },
    {
      v: 1,
      id,
      type: "filled-identity",
      category: "identity",
      identity: ["not", "a", "map"],
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "credit_card",
      identity: { full_name: "Ada" },
    },
    {
      v: 1,
      id,
      type: "filled-card",
      category: "credit_card",
      card: { number: "4242424242424242" },
      identity: { full_name: "Ada" },
    },
  ])
    assert.equal(core.validResponse(response), false);
});

test("M3 card classifyField covers cardholder, number, expiry and security", () => {
  const cases = [
    [{ autocomplete: "cc-name" }, "cardholder_name"],
    [{ name: "cardholder name" }, "cardholder_name"],
    [{ autocomplete: "cc-number" }, "number"],
    [{ name: "card number" }, "number"],
    [{ autocomplete: "cc-exp" }, "exp"],
    [{ name: "expiry date" }, "exp"],
    [
      { tag: "SELECT", name: "exp month" },
      "exp_month",
    ],
    [
      { tag: "SELECT", name: "exp year" },
      "exp_year",
    ],
    [{ autocomplete: "cc-csc" }, "cvv"],
    [{ name: "cvv" }, "cvv"],
  ];
  for (const [config, field] of cases) {
    const control = makeControl(config.tag || "INPUT", config);
    assert.deepEqual(core.classifyField(control), {
      category: "credit_card",
      field,
    });
  }
});

test("M3 fillCardDocument fills number, expiry variants, selects and csc", () => {
  const { elements, fn, clock } = cardSandbox();
  const data = {
    cardholder_name: "Ada Lovelace",
    number: "4242 4242-4242 4242",
    exp_month: "12",
    exp_year: "2029",
    cvv: "123",
  };
  assert.equal(
    fn("https://example.test", data, clock + 2000, false, "credit_card"),
    true,
  );
  assert.equal(elements.holder.value, "Ada Lovelace");
  assert.equal(elements.number.value, "4242424242424242");
  assert.equal(elements.expShort.value, "12/29");
  assert.equal(elements.expLong.value, "12/2029");
  assert.equal(elements.expCompact.value, "1229");
  assert.equal(elements.expMonth.value, "12");
  assert.equal(elements.expYear.value, "2029");
  assert.equal(elements.csc.value, "123");
  for (const name of ["expShort", "expLong", "expCompact"])
    assert.deepEqual(
      elements[name].events.map((event) => event.type),
      ["input", "change"],
    );

  const derived = cardSandbox();
  assert.equal(
    derived.fn(
      "https://example.test",
      {
        cardholder_name: "Grace Hopper",
        number: "4111 1111 1111 1111",
        exp: "11/2030",
        cvv: "987",
      },
      derived.clock + 2000,
      false,
      "credit_card",
    ),
    true,
  );
  assert.equal(derived.elements.holder.value, "Grace Hopper");
  assert.equal(derived.elements.expLong.value, "11/2030");
  assert.equal(derived.elements.expMonth.value, "11");
  assert.equal(derived.elements.expYear.value, "2030");
});

test("M3 fillCardDocument refuses credit-card data without explicit authorization", () => {
  const { elements, raw, clock } = cardSandbox();
  assert.equal(
    raw(
      "https://example.test",
      { number: "4242 4242 4242 4242" },
      clock + 2000,
      false,
      "credit_card",
    ),
    false,
  );
  assert.equal(elements.number.value, "");
  assert.equal(elements.number.events.length, 0);
});

test("M3 card validResponse accepts only bounded card maps", () => {
  const id = "a".repeat(32);
  for (const response of [
    {
      v: 1,
      id,
      type: "fill",
      category: "credit_card",
      card: { cardholder_name: "Ada Lovelace", number: "4242424242424242" },
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "credit_card",
      card: { exp_month: "12", exp_year: "2029", cvv: "123" },
    },
    {
      v: 1,
      id,
      type: "filled-card",
      category: "credit_card",
      card: { number: "4242424242424242" },
    },
  ])
    assert.equal(core.validResponse(response), true);

  for (const response of [
    {
      v: 1,
      id,
      type: "fill",
      category: "credit_card",
      card: { number: "4242424242424242" },
      identity: { full_name: "Ada" },
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "credit_card",
      card: { full_name: "not-card" },
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "credit_card",
      card: { cvv: 123 },
    },
    {
      v: 1,
      id,
      type: "fill",
      category: "identity",
      card: { number: "4242424242424242" },
    },
    {
      v: 1,
      id,
      type: "filled-identity",
      category: "identity",
      identity: { full_name: "Ada" },
      card: { number: "4242424242424242" },
    },
  ])
    assert.equal(core.validResponse(response), false);
});

function fakeRoot(matches, all) {
  return {
    querySelectorAll(selector) {
      if (selector === "*") return all;
      return matches[selector] || [];
    },
  };
}

test("M3 queryAllDeep traverses nested open shadow roots only", () => {
  const top = makeControl("INPUT", { name: "full name" });
  const middle = makeControl("INPUT", { name: "email", type: "email" });
  const deep = makeControl("INPUT", { name: "city" });
  const closed = makeControl("INPUT", { name: "phone" });
  const deepHost = {
    shadowRoot: { ...fakeRoot({ input: [deep] }, []), mode: "open" },
  };
  const middleRoot = fakeRoot({ input: [middle] }, [deepHost, middle]);
  const middleHost = { shadowRoot: { ...middleRoot, mode: "open" } };
  const closedHost = {
    shadowRoot: { ...fakeRoot({ input: [closed] }, []), mode: "closed" },
  };
  const root = fakeRoot({ input: [top] }, [middleHost, closedHost, top]);

  assert.deepEqual(core.queryAllDeep(root, "input"), [top, middle, deep]);
  assert.deepEqual(core.queryAllDeep(root, "input", 1), [top, middle]);
  assert.deepEqual(core.queryAllDeep(root, "input", 0), [top]);
});

test("M3 split OTP distributes six and eight digits box by box", () => {
  for (const [count, code] of [
    [6, "123456"],
    [8, "12345678"],
  ]) {
    const { boxes, fn, timing } = otpSandbox(count);
    assert.deepEqual({ ...fn("https://example.test", "probe") }, {
      origin: "https://example.test",
      top: true,
      timeOrigin: 1000,
      now: 50,
      wall: timing.wall,
    });
    assert.equal(
      fn("https://example.test", "fill", code, timing, false),
      true,
    );
    assert.deepEqual(
      boxes.map((box) => box.value),
      code.split(""),
    );
    for (const [index, box] of boxes.entries()) {
      assert.deepEqual(
        box.events.map((event) => event.type),
        ["keydown", "beforeinput", "input", "change", "keyup"],
      );
      assert.equal(box.events[0].key, code[index]);
      assert.equal(box.events[1].data, code[index]);
      assert.equal(box.events[2].data, code[index]);
      assert.equal(box.events[4].key, code[index]);
    }
  }
});

test("M3 split OTP rejects mismatched box counts and invalid codes", () => {
  for (const [count, code] of [
    [5, "123456"],
    [6, "12345678"],
    [7, "1234567"],
    [6, "12345a"],
  ]) {
    const { boxes, fn, timing } = otpSandbox(count);
    assert.equal(
      fn("https://example.test", "fill", code, timing, false),
      false,
    );
    for (const box of boxes) {
      assert.equal(box.value, "");
      assert.equal(box.events.length, 0);
    }
  }
});

function frameIdentitySandbox(options = {}) {
  const clock = options.clock ?? 1_700_000_000_000;
  const elements = {
    full: makeControl("INPUT", { autocomplete: "name" }),
    email: makeControl("INPUT", { autocomplete: "email", type: "email" }),
  };
  const sandbox = makeSandbox(Object.values(elements), {
    ...options,
    clock,
  });
  return {
    elements,
    fn: compiledDocumentFunction("fillIdentityDocument", sandbox),
    clock,
  };
}

test("M3 identity fill permits only same-origin subframes", () => {
  const data = { full_name: "Ada Lovelace", email: "ada@example.test" };
  const sameOrigin = frameIdentitySandbox({ frame: true });
  assert.equal(
    sameOrigin.fn(
      "https://example.test",
      data,
      sameOrigin.clock + 2000,
      true,
    ),
    true,
  );
  assert.equal(sameOrigin.elements.full.value, "Ada Lovelace");

  for (const options of [
    { frame: true, deny: true },
    { frame: true, topOrigin: "https://other.test" },
    { frame: true, throwTop: true },
    {
      frame: true,
      origin: "null",
      topOrigin: "null",
      protocol: "https:",
    },
  ]) {
    const testCase = frameIdentitySandbox(options);
    assert.equal(
      testCase.fn(
        options.origin || "https://example.test",
        data,
        testCase.clock + 2000,
        !options.deny,
      ),
      false,
    );
    assert.equal(testCase.elements.full.value, "");
    assert.equal(testCase.elements.email.value, "");
  }

  const topLevel = frameIdentitySandbox();
  assert.equal(
    topLevel.fn("https://example.test", data, topLevel.clock + 2000, false),
    true,
  );
});

test("M3 OTP fill permits only same-origin subframes", () => {
  const sameOrigin = otpSandbox(6, { frame: true });
  assert.equal(
    sameOrigin.fn(
      "https://example.test",
      "fill",
      "123456",
      sameOrigin.timing,
      true,
    ),
    true,
  );
  for (const options of [
    { frame: true, deny: true },
    { frame: true, topOrigin: "https://other.test" },
    {
      frame: true,
      origin: "null",
      topOrigin: "null",
      protocol: "https:",
    },
  ]) {
    const testCase = otpSandbox(6, options);
    assert.equal(
      testCase.fn(
        options.origin || "https://example.test",
        "fill",
        "123456",
        testCase.timing,
        !options.deny,
      ),
      false,
    );
    assert.deepEqual(
      testCase.boxes.map((box) => box.value),
      Array(6).fill(""),
    );
  }
});

function harness(options = {}) {
  const listeners = {};
  const sent = [];
  const injected = [];
  const injectedArgs = [];
  const messageListeners = [];
  const timers = new Map();
  let tabURL = options.tabURL || "https://example.test/login";
  let doc = options.doc || "doc-1";
  let frameOrigin = options.frameOrigin || core.originFromURL(tabURL);
  let frameDoc = options.frameDoc || "frame-doc-1";
  let frameDocId = 1;
  let clock = options.clock || 1_700_000_000_000;
  let performanceNow = 0;
  let nextFillResult = {
    ok: true,
    step: "combined",
    submitted: false,
  };
  let tabId = 1;
  let windowId = 1;
  let portMessage;
  let portDisconnect;
  const itemId = "b".repeat(32);
  const itemRevision = "c".repeat(64);

  const port = {
    onMessage: { addListener: (listener) => (portMessage = listener) },
    onDisconnect: {
      addListener: (listener) => (portDisconnect = listener),
    },
    disconnect: () => portDisconnect?.(),
    postMessage: (request) => {
      sent.push(request);
      if (request.type === "hello")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "paired",
            capability: "a".repeat(32),
          }),
        );
      if (request.type === "match")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "candidates",
            candidates: [
              {
                id: itemId,
                revision: itemRevision,
                state: "active",
                title: "Fixture",
                ...(request.category ? { category: request.category } : {}),
              },
            ],
          }),
        );
      if (request.type === "match-profiles")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "profiles",
            profiles: [
              {
                id: itemId,
                revision: itemRevision,
                category: request.profile_kind,
                title: "Fixture",
              },
            ],
          }),
        );
      if (request.type === "fill-profile")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "profile-fill",
            profile_fill: {
              item_id: itemId,
              revision: itemRevision,
              category: "credit_card",
              fields: {
                "cc-name": "Fixture Holder",
                "cc-number": "4242424242424242",
                "cc-exp-month": "12",
                "cc-exp-year": "2030",
                "cc-csc": "123",
              },
            },
          }),
        );
      // The native vault list the popup reads before a menu action, as the real
      // popup does; it answers with the same card item and revision.
      if (request.type === "vault-search")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "items",
            items: [
              {
                id: itemId,
                revision: itemRevision,
                title: "Fixture",
                category: "credit_card",
                urls: [core.originFromURL(tabURL) + "/login"],
              },
            ],
          }),
        );
      if (request.type === "otp")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "otp-ready",
            nonce: "d".repeat(64),
          }),
        );
      if (request.type === "otp-ack")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: request.id,
            type: "otp-fill",
            code: "123456",
          }),
        );
      if (request.type === "cancel-otp")
        queueMicrotask(() =>
          portMessage({ v: 1, id: request.id, type: "cancelled" }),
        );
    },
  };

  const api = {
    storage: {
      local: {
        get: async () => ({}),
        set: async () => {},
      },
    },
    runtime: {
      id: "fixed",
      getURL: (value) => "chrome-extension://fixed/" + value,
      connectNative: () => port,
      onMessage: {
        addListener: (listener) => messageListeners.push(listener),
      },
    },
    tabs: {
      query: async () => [{ id: tabId, url: tabURL, windowId }],
      onActivated: { addListener: (listener) => (listeners.active = listener) },
      onUpdated: { addListener: (listener) => (listeners.updated = listener) },
      onRemoved: { addListener: (listener) => (listeners.removed = listener) },
    },
    contextMenus: {
      create() {},
      removeAll() {},
      onClicked: { addListener: (listener) => (listeners.menu = listener) },
    },
    windows: {
      WINDOW_ID_NONE: -1,
      onFocusChanged: {
        addListener: (listener) => (listeners.focus = listener),
      },
    },
    scripting: {
      executeScript: async (request) => {
        // Mirror Chrome: frameIds and documentIds are mutually exclusive.
        if (request.target.frameIds && request.target.documentIds)
          throw Error("Cannot specify both 'frameIds' and 'documentIds'.");
        const frameId = request.target.documentIds
          ? request.target.documentIds[0] === frameDoc
            ? frameDocId
            : 0
          : (request.target.frameIds?.[0] ?? 0);
        const documentId = frameId ? frameDoc : doc;
        if (request.func === core.probe) {
          const origin = frameId
            ? frameOrigin
            : core.originFromURL(tabURL);
          return [
            {
              frameId,
              documentId,
              result: frameId ? { top: false, origin } : { top: true, origin },
            },
          ];
        }
        if (request.func === core.fillDocument) {
          injected.push(request);
          if (request.args[4] === true)
            return [
              {
                frameId,
                documentId,
                result: { username: "", password: "" },
              },
            ];
          return [{ frameId, documentId, result: nextFillResult }];
        }
        // A context-menu card fill is executed on the live page; return exactly
        // what that page reported, as Chrome does.
        if (request.func === core.fillCheckoutCardDocument) {
          injected.push(request);
          injectedArgs.push({
            func: request.func,
            args: [...request.args],
            fields: { ...(request.args[1] || {}) },
          });
          const result = cardEventTarget(cardPage.page, ...request.args);
          return [{ frameId, documentId, result }];
        }
        if (
          request.func === core.fillIdentityDocument ||
          request.func === core.fillCardDocument
        ) {
          injected.push(request);
          injectedArgs.push({
            func: request.func,
            args: [...request.args],
            data: { ...(request.args[1] || {}) },
          });
          return [{ frameId, documentId, result: true }];
        }
        if (request.func === core.otpDocument) {
          injected.push(request);
          if (request.args[1] === "probe")
            return [
              {
                frameId,
                documentId,
                result: {
                  origin: frameId
                    ? frameOrigin
                    : core.originFromURL(tabURL),
                  top: frameId === 0,
                  timeOrigin: 1000,
                  now: performanceNow,
                  wall: clock,
                },
              },
            ];
          injectedArgs.push({
            func: "otpDocument",
            args: [...request.args],
          });
          return [{ frameId, documentId, result: true }];
        }
        return [{ frameId, documentId, result: true }];
      },
    },
  };

  const context = {
    chrome: api,
    LocklarkCore: core,
    crypto: webcrypto,
    setTimeout: (fn, milliseconds) => {
      const handle = setTimeout(fn, milliseconds);
      timers.set(handle, { fn, milliseconds });
      return handle;
    },
    clearTimeout: (handle) => {
      timers.delete(handle);
      clearTimeout(handle);
    },
    console: {},
    importScripts: () => {},
    URL,
    Uint8Array,
    TextEncoder,
    Date: { now: () => clock },
    performance: { now: () => performanceNow },
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../background.js"), "utf8"),
    context,
  );

  const popupSender = {
    id: "fixed",
    url: "chrome-extension://fixed/popup.html",
  };
  const h = {
    sent,
    injected,
    injectedArgs,
    listeners,
    itemId,
    itemRevision,
    send: (message, sender = popupSender) =>
      new Promise((resolve) => {
        let handled = false;
        for (const listener of messageListeners)
          if (listener(message, sender, resolve) === true) handled = true;
        if (!handled) resolve(undefined);
      }),
    deliver: (message) => portMessage(message),
    setFillResult: (value) => (nextFillResult = value),
    advanceClock: (milliseconds) => (clock += milliseconds),
    now: () => clock,
    setTab: (url, nextDoc) => {
      tabURL = url;
      if (nextDoc) doc = nextDoc;
    },
    // Chrome passes the clicked tab object as the second listener argument.
    clickMenu: (menuItemId, tab = {}) =>
      listeners.menu?.(
        { menuItemId },
        { id: tabId, windowId, url: tabURL, ...tab },
      ),
    // The external checkout page the user is looking at, if any.
    cardPage: (page) => (cardPage.page = page || null),
    setFrame: (origin, nextDoc) => {
      frameOrigin = origin;
      if (nextDoc) frameDoc = nextDoc;
    },
    navigate: (url, nextDoc) => {
      tabURL = url;
      if (nextDoc) doc = nextDoc;
      listeners.updated(tabId, { url });
    },
    contentSender: (
      frame = 0,
      documentId = frame ? frameDoc : doc,
      url = core.originFromURL(tabURL) + "/login",
    ) => {
      if (frame && documentId === frameDoc) frameDocId = frame;
      return {
        id: "fixed",
        url,
        documentId,
        frameId: frame,
        tab: { id: tabId, windowId, url: tabURL },
      };
    },
    state: () => h.send({ type: "state" }),
  };
  return h;
}

async function connect(h) {
  await h.send({ type: "connect" });
  await settle(2);
}
async function ready(h) {
  await connect(h);
  await h.send({ type: "match" });
  await settle(2);
}
async function fillLogin(h, result) {
  h.setFillResult(result);
  const before = h.sent.filter((request) => request.type === "fill").length;
  await h.send({
    type: "fill",
    id: h.itemId,
    revision: h.itemRevision,
  });
  for (let index = 0; index < 30; index++) {
    await tick();
    if (h.sent.filter((request) => request.type === "fill").length > before)
      break;
  }
  const request = h.sent.filter((entry) => entry.type === "fill").at(-1);
  assert.ok(request, "native fill request missing");
  h.deliver({
    v: 1,
    id: request.id,
    type: "fill",
    username: "fixture-user",
    password: "fixture-password",
  });
  await settle(10);
  return request;
}
async function fillStructured(h, category, payload) {
  const before = h.sent.filter((request) => request.type === "fill").length;
  await h.send({
    type: "fill",
    id: h.itemId,
    revision: h.itemRevision,
    category,
    ...(category === "credit_card" ? { userGesture: cardGesture(h) } : {}),
  });
  for (let index = 0; index < 30; index++) {
    await tick();
    if (h.sent.filter((request) => request.type === "fill").length > before)
      break;
  }
  const request = h.sent.filter((entry) => entry.type === "fill").at(-1);
  assert.ok(request, "native structured fill request missing");
  h.deliver({
    v: 1,
    id: request.id,
    type: "fill",
    category,
    [category === "identity" ? "identity" : "card"]: payload,
  });
  await settle(15);
  return request;
}

test("M3 multi-step login continues username, password and OTP across navigation", async () => {
  const h = harness();
  try {
    await ready(h);
    await fillLogin(h, {
      ok: true,
      step: "username-only",
      submitted: false,
    });
    await h.send({ type: "match" });
    await settle(2);
    let state = await h.state();
    assert.equal(state.step, "username");
    assert.equal(state.preferredItemId, h.itemId);

    h.navigate("https://example.test/welcome", "doc-2");
    await settle(2);
    await h.send({ type: "match" });
    await settle(2);
    state = await h.state();
    assert.equal(state.step, "username");
    assert.equal(state.origin, "https://example.test");

    await fillLogin(h, {
      ok: true,
      step: "password-only",
      submitted: false,
    });
    h.navigate("https://auth.example.test/login", "doc-3");
    await settle(2);
    await h.send({ type: "match" });
    await settle(2);
    state = await h.state();
    assert.equal(state.step, "password");
    assert.equal(state.preferredItemId, h.itemId);
    assert.equal(state.origin, "https://auth.example.test");

    await h.send({
      type: "otp",
      id: h.itemId,
      revision: h.itemRevision,
    });
    await settle(30);
    const otp = h.injectedArgs.find(
      (entry) => entry.func === "otpDocument" && entry.args[1] === "fill",
    );
    assert.ok(otp, "OTP fill was not injected");
    assert.equal(otp.args[2], "123456");
    assert.equal(h.injected.some((entry) => entry.func === core.otpDocument), true);

    await h.send({ type: "match" });
    await settle(2);
    state = await h.state();
    assert.equal(state.step, "");
    assert.equal(state.preferredItemId, "");
  } finally {
    await h.send({ type: "disconnect" });
    await settle(2);
  }
});

test("M3 multi-step login is cleared by cross-site navigation, TTL and vault lock", async (t) => {
  async function seeded() {
    const h = harness();
    await ready(h);
    await fillLogin(h, {
      ok: true,
      step: "username-only",
      submitted: false,
    });
    await h.send({ type: "match" });
    await settle(2);
    assert.equal((await h.state()).step, "username");
    return h;
  }

  await t.test("cross-site navigation", async () => {
    const h = await seeded();
    try {
      h.navigate("https://other.test/login", "doc-2");
      await settle(2);
      await h.send({ type: "match" });
      await settle(2);
      const state = await h.state();
      assert.equal(state.step, "");
      assert.equal(state.preferredItemId, "");
      assert.equal(state.origin, "https://other.test");
    } finally {
      await h.send({ type: "disconnect" });
      await settle(2);
    }
  });

  await t.test("TTL expiry", async () => {
    const h = await seeded();
    try {
      h.advanceClock(120001);
      const state = await h.state();
      assert.equal(state.step, "");
      assert.equal(state.preferredItemId, "");
    } finally {
      await h.send({ type: "disconnect" });
      await settle(2);
    }
  });

  await t.test("vault lock", async () => {
    const h = await seeded();
    try {
      h.deliver({ v: 1, type: "locked" });
      await settle(4);
      await ready(h);
      const state = await h.state();
      assert.equal(state.step, "");
      assert.equal(state.preferredItemId, "");
    } finally {
      await h.send({ type: "disconnect" });
      await settle(2);
    }
  });
});

test("M3 background identity and card fills are category-bound and zeroed", async (t) => {
  const cases = [
    [
      "identity",
      "fillIdentityDocument",
      {
        full_name: "Ada Lovelace",
        email: "ada@example.test",
        address_line1: "12 Analytical Way",
      },
    ],
    [
      "credit_card",
      "fillCardDocument",
      {
        cardholder_name: "Ada Lovelace",
        number: "4242424242424242",
        exp_month: "12",
        exp_year: "2029",
        cvv: "123",
      },
    ],
  ];
  for (const [category, functionName, data] of cases) {
    await t.test(category, async () => {
      const h = harness();
      try {
        await ready(h);
        await h.send({ type: "match", category });
        await settle(2);
        const payload = { ...data };
        const request = await fillStructured(h, category, payload);
        assert.equal(request.category, category);
        assert.equal(request.origin, "https://example.test");
        assert.equal(
          Object.values(payload).every((value) => value === ""),
          true,
          "structured response map retained secrets",
        );
        const injection = h.injected.find(
          (entry) => entry.func === core[functionName],
        );
        assert.ok(injection, "structured fill was not injected");
        assert.equal(injection.target.frameIds, undefined);
        assert.equal(injection.target.documentIds[0], "doc-1");
        assert.equal(injection.args[3], false);
        assert.equal(injection.args[4], category);
        const recorded = h.injectedArgs.find(
          (entry) => entry.func === core[functionName],
        );
        assert.deepEqual(recorded.data, data);
        assert.equal(
          h.injected.some((entry) => entry.func === core.fillDocument),
          false,
        );
      } finally {
        await h.send({ type: "disconnect" });
        await settle(2);
      }
    });
  }
});

// The popup, inline menu and context menu mint exactly this shape inside a
// trusted click: a nonce and its mint time, never a tab/frame/document claim.
let gestureSerial = 0;
function cardGesture(h, overrides = {}) {
  return {
    v: 2,
    scope: "credit_card",
    at: h.now(),
    nonce: (++gestureSerial).toString(16).padStart(32, "0"),
    ...overrides,
  };
}

// The live top-document checkout page the user is looking at.
function checkoutPage(origin = "https://example.test") {
  return {
    origin,
    clock: 1_700_000_000_000,
    fence: () => ({ document_stable: true, sandbox_ever: false }),
    controls: [
      makeControl("INPUT", { autocomplete: "cc-name" }),
      makeControl("INPUT", { autocomplete: "cc-number" }),
      makeControl("SELECT", {
        autocomplete: "cc-exp-month",
        options: [
          { value: "01", text: "01" },
          { value: "12", text: "12" },
        ],
      }),
      makeControl("INPUT", { autocomplete: "cc-csc" }),
    ],
  };
}

test("inline and context-menu card fills use the same proof shape", async () => {
  const h = harness({ frameOrigin: "https://example.test" });
  try {
    await connect(h);
    const sender = h.contentSender(2);
    const matched = await h.send(
      { type: "inline-match", category: "credit_card" },
      sender,
    );
    await settle(4);
    assert.deepEqual(
      [...matched.candidates].map((entry) => entry.category),
      ["credit_card"],
    );
    const fills = () => h.sent.filter((entry) => entry.type === "fill").length;
    // Content inline-fill makes a native `fill`. The worker awaits the native
    // roundtrip, so deliver the reply while the request is still in flight.
    const inline = async (userGesture, from = sender) => {
      const before = fills();
      const pending = h.send(
        {
          type: "inline-fill",
          id: h.itemId,
          revision: h.itemRevision,
          category: "credit_card",
          ...(userGesture ? { userGesture } : {}),
        },
        from,
      );
      let request = null;
      for (let index = 0; index < 30; index++) {
        await tick();
        if (fills() > before) {
          request = h.sent.filter((entry) => entry.type === "fill").at(-1);
          break;
        }
      }
      if (request) {
        assert.equal("userGesture" in request, false);
        h.deliver({
          v: 1,
          id: request.id,
          type: "fill",
          category: "credit_card",
          card: { number: "4242424242424242" },
        });
      }
      await pending;
      await settle(15);
      return fills() > before;
    };
    // No proof, a stale proof and a proof carrying a tab, frame or document
    // claim are refused for this same-origin subframe.
    assert.equal(await inline(undefined), false);
    assert.equal(await inline(cardGesture(h, { at: h.now() - 10_001 })), false);
    assert.equal(
      await inline(cardGesture(h, { frameId: 2, documentId: "frame-doc-0" })),
      false,
    );
    // A proof inside its ten-second window is accepted once for the
    // browser-verified sender frame/document; the same nonce replayed from the
    // same unchanged sender reaches native only once. The page-side menu mints
    // the proof milliseconds before delivery, so mint it now.
    h.advanceClock(9_000);
    const proof = cardGesture(h);
    assert.equal(await inline(proof), true, "the fresh proof is honored");
    assert.equal(fills(), 1);
    assert.equal(await inline({ ...proof }), false, "nonce replay refused");
    assert.equal(fills(), 1);
    // A page-side proof cannot fill the card without a live match context.
    h.navigate("https://example.test/login", "doc-3");
    await settle(2);

    // Context menu: the popup first reads the native vault list, exactly as
    // the real popup does, so the worker holds the item the menu entry names.
    const page = checkoutPage();
    h.cardPage(page);
    const listed = await h.send({
      type: "vault-search",
      query: "",
      category: "credit_card",
    });
    assert.deepEqual(
      [...listed.vaultItems].map((item) => [item.id, item.revision]),
      [[h.itemId, h.itemRevision]],
    );
    await settle(2);
    const cardInjection = () =>
      h.injectedArgs.filter(
        (entry) => entry.func === core.fillCheckoutCardDocument,
      );
    // An entry that does not match the live vault item is refused and never
    // reaches native.
    h.clickMenu(`fill-card:${h.itemId}:${"d".repeat(64)}`);
    await settle(10);
    assert.equal(
      h.sent.filter((entry) => entry.type === "match-profiles").length,
      0,
    );
    // The worker's own click mints the proof, binds it to the browser-reported
    // tab and goes through match-profiles + fill-profile, not `fill`.
    h.clickMenu(`fill-card:${h.itemId}:${h.itemRevision}`);
    for (let index = 0; index < 40; index++) {
      await tick();
      if (h.sent.some((entry) => entry.type === "fill-profile")) break;
    }
    assert.equal(fills(), 1, "the menu click sends no login/card fill request");
    const matches = h.sent.filter((entry) => entry.type === "match-profiles");
    assert.equal(matches.length, 1, "the menu asked native to match profiles");
    assert.equal(matches[0].tab_id, 1);
    assert.equal(matches[0].profile_kind, "credit_card");
    assert.equal(JSON.stringify(matches[0]).includes(proof.nonce), false);
    const profiles = h.sent.filter((entry) => entry.type === "fill-profile");
    assert.equal(profiles.length, 1, "native fill-profile is requested once");
    assert.equal(profiles[0].item_id, h.itemId);
    assert.equal(profiles[0].revision, h.itemRevision);
    assert.equal("userGesture" in profiles[0], false);
    for (let index = 0; index < 40; index++) {
      await tick();
      if (cardInjection().length) break;
    }
    assert.equal(cardInjection().length, 1, "the approved card is injected once");
    const injection = cardInjection()[0];
    assert.equal(injection.args[0], page.origin);
    assert.equal(injection.args[3], true, "the menu targets the top document");
    assert.equal(injection.args[4], true);
    assert.deepEqual(injection.fields, {
      "cc-name": "Fixture Holder",
      "cc-number": "4242424242424242",
      "cc-exp-month": "12",
      "cc-exp-year": "2030",
      "cc-csc": "123",
    });
    // The real injected helper ran on the page and wrote each field once.
    assert.deepEqual(
      page.controls.map((control) => control.value),
      ["Fixture Holder", "4242424242424242", "12", "123"],
    );
    for (const control of page.controls)
      assert.deepEqual(
        control.events.map((event) => event.type),
        ["input", "change"],
      );
    let state = await h.state();
    assert.equal(
      state.status,
      "已请求填充所选银行卡；未自动提交；请核实网站结果",
    );
    assert.equal(
      JSON.stringify({ ...state, status: "" }).includes("4242424242424242"),
      false,
      "card fields never return to the popup",
    );
    // A second menu click is a separate trusted click: it mints a fresh proof,
    // is honored once more, and never retries or doubles the first injection.
    h.clickMenu(`fill-card:${h.itemId}:${h.itemRevision}`);
    for (let index = 0; index < 40; index++) {
      await tick();
      if (h.sent.filter((entry) => entry.type === "fill-profile").length > 1)
        break;
    }
    assert.equal(
      h.sent.filter((entry) => entry.type === "fill-profile").length,
      2,
    );
    for (let index = 0; index < 40; index++) {
      await tick();
      if (cardInjection().length > 1) break;
    }
    assert.equal(cardInjection().length, 2);
    for (const control of page.controls)
      assert.deepEqual(
        control.events.map((event) => event.type),
        ["input", "change", "input", "change"],
        "each click writes every field exactly once",
      );
    await settle(15);
    state = await h.state();
    assert.equal(state.pending, false);
    assert.equal(fills(), 1);
    // A click whose reported tab is not the active captured tab/documents
    // sends no native profile request.
    const menuRequests = () => ({
      matches: h.sent.filter((entry) => entry.type === "match-profiles").length,
      profiles: h.sent.filter((entry) => entry.type === "fill-profile").length,
    });
    const settled = menuRequests();
    h.clickMenu(`fill-card:${h.itemId}:${h.itemRevision}`, {
      id: 99,
      windowId: 8,
    });
    await settle(15);
    assert.deepEqual(
      menuRequests(),
      settled,
      "a click for another tab sends no native profile request",
    );
    assert.equal(cardInjection().length, 2);
    state = await h.state();
    assert.equal(state.pending, false);
  } finally {
    h.cardPage(null);
    await h.send({ type: "disconnect" });
    await settle(2);
  }
});

test("M3 same-origin iframe fill carries frameId and allowSubframe; cross-origin is refused", async () => {
  const h = harness({ frameOrigin: "https://example.test" });
  try {
    await connect(h);
    const sender = h.contentSender(2);
    const matched = await h.send(
      { type: "inline-match", category: "identity" },
      sender,
    );
    await settle(4);
    assert.equal(matched.candidates.length, 1);
    assert.equal(matched.candidates[0].category, "identity");

    const filling = h.send(
      {
        type: "inline-fill-identity",
        id: h.itemId,
        revision: h.itemRevision,
      },
      sender,
    );
    for (let index = 0; index < 30; index++) {
      await tick();
      if (h.sent.some((request) => request.type === "fill")) break;
    }
    const request = h.sent.find((entry) => entry.type === "fill");
    assert.ok(request, "framed native fill request missing");
    assert.equal(request.origin, "https://example.test");
    assert.equal(request.category, "identity");
    h.deliver({
      v: 1,
      id: request.id,
      type: "fill",
      category: "identity",
      identity: { full_name: "Ada Lovelace" },
    });
    await filling;
    await settle(20);
    const injection = h.injected.find(
      (entry) => entry.func === core.fillIdentityDocument,
    );
    assert.ok(injection, "framed identity fill was not injected");
    assert.equal(injection.target.frameIds, undefined);
    assert.equal(injection.target.documentIds[0], "frame-doc-1");
    assert.equal(injection.args[3], true);
    assert.equal(injection.args[4], "identity");

    const matches = h.sent.filter((entry) => entry.type === "match").length;
    const denied = await h.send(
      { type: "inline-match", category: "identity" },
      h.contentSender(2, "frame-doc-1", "https://other.test/login"),
    );
    assert.equal(denied, undefined);
    await settle(2);
    assert.equal(
      h.sent.filter((entry) => entry.type === "match").length,
      matches,
    );
    const opaque = await h.send(
      { type: "inline-match", category: "identity" },
      h.contentSender(2, "frame-doc-1", "null"),
    );
    assert.equal(opaque, undefined);
  } finally {
    await h.send({ type: "disconnect" });
    await settle(2);
  }
});

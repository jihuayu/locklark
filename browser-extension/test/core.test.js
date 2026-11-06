const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const core = require("../core.js");
test("strict HTTPS origin profile", () => {
  assert.equal(
    core.originFromURL("https://Example.test:443/login?x=1#anchor"),
    "https://example.test",
  );
  for (const url of [
    "http://example.test",
    "https://127.0.0.1",
    "https://xn--a.test",
    "https://example.test.",
    "https://a.local",
    "https://user:pw@example.test",
    "https://example.test:0443",
    "https://example.test\\evil",
  ])
    assert.throws(() => core.originFromURL(url));
});
test("exact extension popup sender only", () => {
  const runtime = { id: "id", getURL: (p) => "chrome-extension://id/" + p };
  assert.equal(
    core.validSender(
      { id: "id", url: "chrome-extension://id/popup.html" },
      runtime,
    ),
    true,
  );
  for (const sender of [
    { id: "id", url: "https://example.test" },
    { id: "other", url: "chrome-extension://id/popup.html" },
    { id: "id", url: "chrome-extension://id/popup.html?x=1" },
    { id: "id", url: "chrome-extension://id/popup.html", tab: { id: 1 } },
  ])
    assert.equal(core.validSender(sender, runtime), false);
});
test("document and active tab identity", () => {
  const a = { tabId: 1, documentId: "doc-1", origin: "https://example.test" };
  assert.equal(core.sameContext(a, { ...a }), true);
  for (const b of [
    { ...a, tabId: 2 },
    { ...a, documentId: "doc-2" },
    { ...a, origin: "https://similar-example.test" },
    null,
  ])
    assert.equal(core.sameContext(a, b), false);
});
test("native response DTO is bounded and rejects unknown fields", () => {
  assert.equal(core.validResponse({ v: 1, type: "locked" }), true);
  for (const r of [
    { v: 2, type: "locked" },
    { v: 1, type: "locked", password: "secret" },
    { v: 1, type: "unpaired", error: "arbitrary" },
    {
      v: 1,
      type: "fill",
      id: "a".repeat(32),
      username: "u",
      password: "p",
      field: "otp",
    },
    {
      v: 1,
      type: "candidates",
      id: "a".repeat(32),
      candidates: new Array(101).fill({}),
    },
  ])
    assert.equal(core.validResponse(r), false);
});
test("expired or unbounded injection approval is refused before DOM access", () => {
  assert.equal(
    core.fillDocument(
      "https://example.test",
      "fixture-user",
      "fixture-password",
      Date.now() - 1,
    ),
    false,
  );
  assert.equal(
    core.fillDocument(
      "https://example.test",
      "fixture-user",
      "fixture-password",
      Date.now() + 60000,
    ),
    false,
  );
});
test("OTP response DTO isolates its challenge and ASCII code", () => {
  const id = "a".repeat(32);
  assert.equal(
    core.validResponse({ v: 1, id, type: "otp-ready", nonce: "b".repeat(64) }),
    true,
  );
  for (const code of ["012345", "01234567"])
    assert.equal(
      core.validResponse({ v: 1, id, type: "otp-fill", code }),
      true,
    );
  for (const response of [
    { v: 1, id, type: "otp-ready", nonce: "b".repeat(63) },
    { v: 1, id, type: "otp-ready", nonce: "b".repeat(64), code: "012345" },
    ...["12345", "1234567", "123456789", "１２３４５６", 123456].map(
      (code) => ({ v: 1, id, type: "otp-fill", code }),
    ),
    { v: 1, id, type: "otp-fill", code: "012345", password: "forbidden" },
    { v: 1, id, type: "fill", username: "", password: "", code: "012345" },
    { v: 1, id, type: "cancelled", code: "012345" },
  ])
    assert.equal(core.validResponse(response), false);
});
test("static OTP injection is exported and fails closed outside its document", () => {
  assert.equal(typeof core.otpDocument, "function");
  assert.equal(core.otpDocument("https://example.test", "probe"), false);
});

function fillSandbox(spec) {
  const calls = { events: [], submits: [] };
  function Element() {}
  function HTMLInputElement() {}
  HTMLInputElement.prototype = Object.create(Element.prototype);
  function HTMLButtonElement() {}
  HTMLButtonElement.prototype = Object.create(Element.prototype);
  function HTMLFormElement() {}
  HTMLFormElement.prototype.requestSubmit = function (button) {
    calls.submits.push(button);
  };
  Object.defineProperty(HTMLInputElement.prototype, "value", {
    get() {
      return this._value;
    },
    set(value) {
      this._value = value;
    },
  });
  function Event(type, init) {
    this.type = type;
    this.bubbles = Boolean(init && init.bubbles);
  }
  function visible(el) {
    el.isConnected = true;
    el.disabled = false;
    el.readOnly = false;
    el.matches = () => false;
    el.closest = () => null;
    el.parentElement = null;
    el.getBoundingClientRect = () => ({ width: 100, height: 20 });
    el.getClientRects = () => [{}];
    return el;
  }
  function makeInput(options) {
    const el = visible(new HTMLInputElement());
    el.type = options.type || "text";
    el.autocomplete = options.autocomplete || "";
    el.name = options.name || "";
    el.id = options.id || "";
    el._value = "";
    const attributes = options.attributes || {};
    el.getAttribute = (name) =>
      Object.prototype.hasOwnProperty.call(attributes, name)
        ? attributes[name]
        : null;
    el.dispatchEvent = (event) => {
      calls.events.push({ target: el, type: event.type, bubbles: event.bubbles });
      return true;
    };
    return el;
  }
  const form = new HTMLFormElement();
  form.ownerDocument = null;
  form.method = "post";
  form.isConnected = true;
  form.getAttribute = (name) =>
    name === "action" ? "https://example.test/login" : null;
  const user = makeInput(spec.user);
  const pass = spec.pass ? makeInput(spec.pass) : null;
  const button = visible(new HTMLButtonElement());
  button.type = "submit";
  button.textContent = "Sign in";
  button.value = "";
  button.getAttribute = () => null;
  const inputs = [user, pass].filter(Boolean);
  for (const input of inputs) input.form = form;
  form.elements = [...inputs, button];
  const document = {
    baseURI: "https://example.test/login",
    querySelectorAll(selector) {
      if (selector === "input") return inputs;
      if (selector === "button[formaction],input[formaction]") return [];
      return [];
    },
  };
  form.ownerDocument = document;
  const sandbox = {
    document,
    location: { origin: "https://example.test", href: "https://example.test/login" },
    getComputedStyle: () => ({
      display: "block",
      visibility: "visible",
      opacity: "1",
    }),
    Event,
    URL,
    TextEncoder,
    Element,
    HTMLInputElement,
    HTMLButtonElement,
    HTMLFormElement,
    Date: { now: () => spec.clock },
  };
  sandbox.window = sandbox;
  sandbox.top = sandbox;
  const fillDocument = vm.runInNewContext(
    "(" + core.fillDocument.toString() + ")",
    sandbox,
  );
  return { fillDocument, calls, user, pass, button };
}

test("serialized fillDocument uses autocomplete HTML attribute when IDL property is empty (Firefox)", () => {
  const first = fillSandbox({
    clock: Date.now() + 4000,
    user: { type: "text", name: "user", attributes: { autocomplete: "username" } },
    pass: {
      type: "password",
      name: "password",
      attributes: { autocomplete: "current-password" },
    },
  });
  assert.equal(
    first.fillDocument(
      "https://example.test",
      "alice",
      "secret",
      Date.now() + 5000,
      false,
      true,
    ),
    true,
  );
  assert.equal(first.user.value, "alice");
  assert.equal(first.pass.value, "secret");
  for (const field of [first.user, first.pass])
    assert.deepEqual(
      first.calls.events
        .filter((event) => event.target === field)
        .map((event) => event.type),
      ["input", "change"],
    );
  assert.equal(first.calls.submits.length, 1);
  assert.equal(first.calls.submits[0], first.button);

  const second = fillSandbox({
    clock: Date.now() + 4000,
    user: { type: "text", name: "user", attributes: { autocomplete: "username" } },
    pass: {
      type: "password",
      name: "password",
      attributes: { autocomplete: "new-password" },
    },
  });
  assert.equal(
    second.fillDocument(
      "https://example.test",
      "alice",
      "secret",
      Date.now() + 5000,
      false,
      true,
    ),
    false,
  );
  assert.equal(second.user.value, "");
  assert.equal(second.pass.value, "");
  assert.equal(second.calls.events.length, 0);
  assert.equal(second.calls.submits.length, 0);

  const third = fillSandbox({
    clock: Date.now() + 4000,
    user: {
      type: "text",
      name: "",
      id: "",
      attributes: { autocomplete: "username" },
    },
    pass: null,
  });
  assert.equal(
    third.fillDocument(
      "https://example.test",
      "alice",
      "secret",
      Date.now() + 5000,
      false,
      false,
    ),
    true,
  );
  assert.equal(third.user.value, "alice");
  assert.deepEqual(
    third.calls.events
      .filter((event) => event.target === third.user)
      .map((event) => event.type),
    ["input", "change"],
  );
  assert.equal(third.calls.submits.length, 0);
});

function credentialSandbox(spec) {
  const calls = { events: [] };
  function Element() {}
  function HTMLInputElement() {}
  HTMLInputElement.prototype = Object.create(Element.prototype);
  function HTMLButtonElement() {}
  HTMLButtonElement.prototype = Object.create(Element.prototype);
  function HTMLFormElement() {}
  HTMLFormElement.prototype.requestSubmit = () => {};
  Object.defineProperty(HTMLInputElement.prototype, "value", {
    get() {
      return this._value;
    },
    set(value) {
      this._value = value;
    },
  });
  function Event(type, init) {
    this.type = type;
    this.bubbles = Boolean(init && init.bubbles);
  }
  function visible(el) {
    el.isConnected = true;
    el.disabled = false;
    el.readOnly = false;
    el.matches = () => false;
    el.closest = () => null;
    el.parentElement = null;
    el.getBoundingClientRect = () => ({ width: 100, height: 20 });
    el.getClientRects = () => [{}];
    return el;
  }
  function makeInput(options = {}) {
    const el = visible(new HTMLInputElement());
    el.type = options.type || "text";
    el.autocomplete = options.autocomplete || "";
    el.name = options.name || "";
    el.id = options.id || "";
    el.placeholder = options.placeholder || "";
    el._value = options.value || "";
    const attributes = options.attributes || {};
    el.getAttribute = (name) =>
      Object.prototype.hasOwnProperty.call(attributes, name)
        ? attributes[name]
        : null;
    el.dispatchEvent = (event) => {
      calls.events.push({ target: el, type: event.type });
      return true;
    };
    return el;
  }
  const location = {
    origin: "https://example.test",
    href: "https://example.test/form",
  };
  const form = new HTMLFormElement();
  form.ownerDocument = null;
  form.method = "post";
  form.isConnected = true;
  form.getAttribute = (name) =>
    name === "action" ? spec.action || "https://example.test/form" : null;
  const user = spec.user ? makeInput(spec.user) : null;
  const passwords = (spec.passwords || []).map(makeInput);
  const inputs = [user, ...passwords].filter(Boolean);
  for (const input of inputs) input.form = form;
  form.elements = [...inputs];
  const document = {
    baseURI: location.href,
    activeElement: spec.active || passwords[0] || user || null,
    querySelectorAll(selector) {
      if (selector === "input") return inputs;
      if (selector === 'input[type="password"]') return passwords;
      return [];
    },
  };
  form.ownerDocument = document;
  const sandbox = {
    document,
    location,
    getComputedStyle: () => ({
      display: "block",
      visibility: "visible",
      opacity: "1",
    }),
    Event,
    URL,
    TextEncoder,
    Element,
    HTMLInputElement,
    HTMLButtonElement,
    HTMLFormElement,
    Date: { now: () => spec.clock ?? Date.now() },
  };
  sandbox.window = sandbox;
  sandbox.top = sandbox;
  return {
    fillDocument: vm.runInNewContext(
      "(" + core.fillDocument.toString() + ")",
      sandbox,
    ),
    fillGeneratedPassword: vm.runInNewContext(
      "(" + core.fillGeneratedPassword.toString() + ")",
      sandbox,
    ),
    calls,
    form,
    user,
    passwords,
  };
}

function loginSpec(overrides = {}) {
  return {
    action: "https://example.test/login",
    user: { type: "text", autocomplete: "username", value: "alice" },
    passwords: [
      {
        type: "password",
        name: "password",
        autocomplete: "current-password",
        value: "current-password",
      },
    ],
    ...overrides,
  };
}
function signupSpec(overrides = {}) {
  return {
    action: "https://example.test/signup",
    user: { type: "text", autocomplete: "username", value: "alice" },
    passwords: [
      {
        type: "password",
        name: "new-password",
        autocomplete: "new-password",
        value: "new-password",
      },
      {
        type: "password",
        name: "confirm-password",
        autocomplete: "new-password",
        value: "new-password",
      },
    ],
    ...overrides,
  };
}
function changeSpec(count) {
  const passwords = [
    {
      type: "password",
      name: "current-password",
      autocomplete: "current-password",
      value: "old-password",
    },
    {
      type: "password",
      name: "new-password",
      autocomplete: "new-password",
      value: "new-password",
    },
  ];
  if (count === 3)
    passwords.push({
      type: "password",
      name: "confirm-password",
      autocomplete: "new-password",
      value: "new-password",
    });
  return {
    action: "https://example.test/change-password",
    user: { type: "email", value: "alice@example.test" },
    passwords,
  };
}

test("generatePassword random mode clamps bounds, includes classes and rejects unknown options", () => {
  const generated = core.generatePassword({ mode: "random", length: 24 });
  assert.equal(generated.profile.mode, "random");
  assert.equal(generated.profile.length, 24);
  assert.equal(generated.password.length, 24);
  assert.match(generated.password, /[A-Z]/);
  assert.match(generated.password, /[a-z]/);
  assert.match(generated.password, /[0-9]/);
  assert.match(generated.password, /[!@#$%^&*()\-_=+[\]{}|;:,.<>?]/);
  assert.equal(
    generated.profile.entropy_bits_floor,
    Math.floor(24 * Math.log2(generated.profile.alphabet_size)),
  );
  assert.ok(generated.profile.entropy_bits_floor >= 128);

  const noExtras = core.generatePassword({
    mode: "random",
    length: 8,
    digits: false,
    symbols: false,
  });
  assert.equal(noExtras.password.length, 8);
  assert.match(noExtras.password, /^[A-Za-z]+$/);
  assert.equal(noExtras.profile.alphabet_size, 52);

  const digitsOnly = core.generatePassword({
    mode: "random",
    length: 16,
    digits: true,
    symbols: false,
  });
  assert.match(digitsOnly.password, /[0-9]/);
  assert.doesNotMatch(digitsOnly.password, /[!@#$%^&*()\-_=+[\]{}|;:,.<>?]/);

  assert.equal(core.generatePassword({ length: 1 }).password.length, 8);
  assert.equal(core.generatePassword({ length: 999 }).password.length, 256);
  assert.equal(core.generatePassword({ length: 1.5 }).password.length, 24);
  for (const invalid of [
    [],
    "random",
    null,
    { length: 24, unknown: true },
    { mode: "random", random: Math.random },
  ])
    assert.throws(() => core.generatePassword(invalid), /refused/);
  const originalRandom = Math.random;
  Math.random = () => {
    throw Error("Math.random must not be used");
  };
  try {
    assert.equal(core.generatePassword({ length: 32 }).password.length, 32);
  } finally {
    Math.random = originalRandom;
  }
  assert.equal(core.generatePassword.toString().includes("Math.random"), false);
});
test("generatePassword memorable separators, capitalization, digits and bounds", () => {
  const plain = core.generatePassword({ mode: "memorable" });
  assert.equal(plain.profile.mode, "memorable");
  assert.equal(plain.profile.length, 4);
  const words = plain.password.split("-");
  assert.equal(words.length, 4);
  assert.ok(words.every((word) => /^[A-Z][a-z]+$/.test(word)));
  assert.equal(
    plain.profile.entropy_bits_floor,
    Math.floor(4 * Math.log2(plain.profile.alphabet_size)),
  );

  const separators = {
    hyphens: "-",
    spaces: " ",
    periods: ".",
    commas: ",",
    underscores: "_",
  };
  for (const [separator, delimiter] of Object.entries(separators)) {
    const result = core.generatePassword({
      mode: "memorable",
      length: 3,
      separator,
      capitalize: false,
    });
    const words = result.password.split(delimiter);
    assert.equal(words.length, 3, separator);
    assert.ok(words.every((word) => /^[a-z]+$/.test(word)), separator);
  }
  for (const separator of ["numbers", "numbers-and-symbols"]) {
    const result = core.generatePassword({
      mode: "memorable",
      length: 5,
      separator,
      capitalize: false,
    });
    assert.match(result.password, /^[a-z]+[0-9!@#$%^&*()\-_=+[\]{}|;:,.<>?][a-z]+/);
  }
  const withDigits = core.generatePassword({
    mode: "memorable",
    length: 4,
    separator: "hyphens",
    digits: true,
  });
  assert.ok(withDigits.password.split("-").some((word) => /\d{2}$/.test(word)));
  assert.equal(core.generatePassword({ mode: "memorable", length: 1 }).profile.length, 3);
  assert.equal(core.generatePassword({ mode: "memorable", length: 99 }).profile.length, 10);
});
test("generatePassword pin mode bounds and alphabet", () => {
  const pin = core.generatePassword({ mode: "pin" });
  assert.equal(pin.profile.mode, "pin");
  assert.equal(pin.password.length, 6);
  assert.match(pin.password, /^[0-9]{6}$/);
  assert.equal(pin.profile.alphabet_size, 10);
  assert.equal(
    pin.profile.entropy_bits_floor,
    Math.floor(6 * Math.log2(10)),
  );
  assert.equal(core.generatePassword({ mode: "pin", length: 1 }).password.length, 4);
  assert.equal(core.generatePassword({ mode: "pin", length: 99 }).password.length, 12);
  assert.match(core.generatePassword({ mode: "pin", length: 12 }).password, /^[0-9]{12}$/);
});
test("fillDocument capture supports login, signup and change-password forms", () => {
  const login = credentialSandbox(loginSpec());
  assert.deepEqual(
    {
      ...login.fillDocument(
        "https://example.test",
        "",
        "",
        Date.now() + 1000,
        true,
      ),
    },
    {
      username: "alice",
      password: "current-password",
      isNewPassword: false,
      isPasswordChange: false,
    },
  );
  const signup = credentialSandbox(signupSpec());
  assert.deepEqual(
    {
      ...signup.fillDocument(
        "https://example.test",
        "",
        "",
        Date.now() + 1000,
        true,
      ),
    },
    {
      username: "alice",
      password: "new-password",
      isNewPassword: true,
      isPasswordChange: false,
    },
  );
  for (const count of [2, 3]) {
    const change = credentialSandbox(changeSpec(count));
    assert.deepEqual(
      {
        ...change.fillDocument(
          "https://example.test",
          "",
          "",
          Date.now() + 1000,
          true,
        ),
      },
      {
        username: "alice@example.test",
        password: "new-password",
        isNewPassword: true,
        isPasswordChange: true,
      },
      "change " + count,
    );
  }
});
test("fillDocument capture refuses mismatched confirmations and cross-origin actions", () => {
  const two = credentialSandbox(signupSpec());
  two.passwords[1]._value = "different";
  assert.equal(
    two.fillDocument("https://example.test", "", "", Date.now() + 1000, true),
    false,
  );
  const three = credentialSandbox(changeSpec(3));
  three.passwords[2]._value = "different";
  assert.equal(
    three.fillDocument("https://example.test", "", "", Date.now() + 1000, true),
    false,
  );
  const cross = credentialSandbox(
    signupSpec({ action: "https://evil.example/signup" }),
  );
  assert.equal(
    cross.fillDocument("https://example.test", "", "", Date.now() + 1000, true),
    false,
  );
  assert.equal(
    cross.fillDocument(
      "https://other.example",
      "",
      "",
      Date.now() + 1000,
      true,
      false,
    ),
    false,
  );
});
test("fillGeneratedPassword fills new and confirm fields but never the current password", () => {
  const signup = credentialSandbox(signupSpec());
  const signupResult = signup.fillGeneratedPassword(
    "https://example.test",
    "Generated-Pass-1",
    Date.now() + 1000,
  );
  assert.deepEqual({ ...signupResult }, {
    ok: true,
    filledCount: 2,
    username: "alice",
    isPasswordChange: false,
  });
  assert.equal(signup.passwords[0].value, "Generated-Pass-1");
  assert.equal(signup.passwords[1].value, "Generated-Pass-1");
  assert.deepEqual(
    signup.calls.events
      .filter((event) => event.target === signup.passwords[0])
      .map((event) => event.type),
    ["input", "change"],
  );
  assert.deepEqual(
    signup.calls.events
      .filter((event) => event.target === signup.passwords[1])
      .map((event) => event.type),
    ["input", "change"],
  );

  for (const count of [2, 3]) {
    const change = credentialSandbox(changeSpec(count));
    const result = change.fillGeneratedPassword(
      "https://example.test",
      "Generated-Pass-2",
      Date.now() + 1000,
    );
    assert.equal(result.ok, true);
    assert.equal(result.isPasswordChange, true);
    assert.equal(result.filledCount, count === 3 ? 2 : 1);
    assert.equal(change.passwords[0].value, "old-password");
    assert.equal(change.passwords[1].value, "Generated-Pass-2");
    if (count === 3) assert.equal(change.passwords[2].value, "Generated-Pass-2");
    assert.equal(
      change.calls.events.some((event) => event.target === change.passwords[0]),
      false,
    );
  }

  const login = credentialSandbox(loginSpec());
  assert.equal(
    login.fillGeneratedPassword(
      "https://example.test",
      "Generated-Pass-3",
      Date.now() + 1000,
    ),
    false,
  );
  assert.equal(login.passwords[0].value, "current-password");
  assert.equal(login.calls.events.length, 0);

  const expired = credentialSandbox(signupSpec());
  assert.equal(
    expired.fillGeneratedPassword(
      "https://example.test",
      "Generated-Pass-4",
      Date.now() - 1,
    ),
    false,
  );
  assert.equal(
    expired.fillGeneratedPassword(
      "https://other.example",
      "Generated-Pass-4",
      Date.now() + 1000,
    ),
    false,
  );
  assert.equal(expired.passwords[0].value, "new-password");
  const crossAction = credentialSandbox(
    signupSpec({ action: "https://evil.example/signup" }),
  );
  assert.equal(
    crossAction.fillGeneratedPassword(
      "https://example.test",
      "Generated-Pass-5",
      Date.now() + 1000,
    ),
    false,
  );
  assert.equal(crossAction.passwords[0].value, "new-password");
});

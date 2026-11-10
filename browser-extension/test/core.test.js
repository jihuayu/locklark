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
  const firstResult = first.fillDocument(
    "https://example.test",
    "alice",
    "secret",
    Date.now() + 5000,
    false,
    true,
  );
  assert.equal(firstResult.ok, true);
  assert.equal(firstResult.step, "combined");
  assert.equal(firstResult.submitted, true);
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
  const thirdResult = third.fillDocument(
    "https://example.test",
    "alice",
    "secret",
    Date.now() + 5000,
    false,
    false,
  );
  assert.equal(thirdResult.ok, true);
  assert.equal(thirdResult.step, "username-only");
  assert.equal(thirdResult.submitted, false);
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
function watchtowerFinding(overrides = {}) {
  return {
    id: "a".repeat(32),
    revision: "b".repeat(64),
    title: "Example",
    origin: "https://example.test",
    flags: ["weak", "reused"],
    strength_score: 32,
    strength_category: "weak",
    reuse_count: 2,
    breach_count: 0,
    ...overrides,
  };
}
function watchtowerReport(overrides = {}) {
  return {
    profile: "watchtower-v2",
    hibp_checked: false,
    overall_score: 78,
    checked: 12,
    skipped: 1,
    counts: {
      vulnerable: 0,
      reused: 2,
      weak: 1,
      unsecured_http: 1,
      totp_not_stored: 4,
      expiring: 0,
      passkey_not_stored: 4,
    },
    site: { origin: "https://example.test", unsecured_http: false },
    site_findings: [watchtowerFinding()],
    findings: [watchtowerFinding({ flags: ["weak"] })],
    ...overrides,
  };
}
test("watchtower report DTO accepts the native shape and rejects unknown or unbounded data", () => {
  assert.equal(core.validWatchtower(watchtowerReport()), true);
  const omittedOptional = watchtowerReport({
    hibp_checked: true,
    hibp_error: "unavailable",
    counts: {
      vulnerable: 0,
      reused: 0,
      weak: 0,
      unsecured_http: 0,
      totp_not_stored: 0,
      expiring: 0,
    },
    site: { unsecured_http: false },
    site_findings: [],
    findings: [],
  });
  delete omittedOptional.skipped;
  assert.equal(
    core.validWatchtower(omittedOptional),
    true,
    "six counts and omitted optional fields stay valid",
  );
  const bad = [
    watchtowerReport({ unknown: true }),
    watchtowerReport({ profile: "watchtower-v1" }),
    watchtowerReport({ hibp_checked: "false" }),
    watchtowerReport({ hibp_error: "network" }),
    watchtowerReport({ overall_score: 101 }),
    watchtowerReport({ overall_score: -1 }),
    watchtowerReport({ overall_score: 42.5 }),
    watchtowerReport({ checked: -1 }),
    watchtowerReport({ skipped: 1.5 }),
    watchtowerReport({ counts: { ...watchtowerReport().counts, bogus: 1 } }),
    watchtowerReport({
      counts: { ...watchtowerReport().counts, vulnerable: -1 },
    }),
    watchtowerReport({
      counts: { ...watchtowerReport().counts, reused: "2" },
    }),
    watchtowerReport({ site: { origin: "http://example.test", unsecured_http: false } }),
    watchtowerReport({ site: { origin: "https://example.test/path", unsecured_http: false } }),
    watchtowerReport({ site: { origin: "https://example.test", unsecured_http: "no" } }),
    watchtowerReport({ site: { origin: "https://example.test", unsecured_http: false, extra: 1 } }),
    watchtowerReport({ site_findings: "none" }),
    watchtowerReport({ findings: {} }),
    watchtowerReport({
      findings: [{ ...watchtowerFinding(), extra: true }],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ flags: ["not-a-flag"] })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ flags: ["weak", "weak"] })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ strength_score: 101 })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ strength_category: "strong" })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ strength_category: "Weak" })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ title: "x".repeat(1025) })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ id: "A".repeat(32) })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ revision: "b".repeat(63) })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ reuse_count: -1 })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ breach_count: 1.5 })],
    }),
    watchtowerReport({
      findings: [watchtowerFinding({ origin: "https://example.test/" })],
    }),
  ];
  bad.forEach((report, index) =>
    assert.equal(core.validWatchtower(report), false, "bad report " + index),
  );
});
test("watchtower native response is accepted only with a validated report", () => {
  const id = "c".repeat(32);
  assert.equal(
    core.validResponse({
      v: 1,
      id,
      type: "watchtower",
      watchtower: watchtowerReport(),
    }),
    true,
  );
  for (const response of [
    { v: 1, id, type: "watchtower" },
    { v: 1, id, type: "watchtower", watchtower: null },
    {
      v: 1,
      id,
      type: "watchtower",
      watchtower: watchtowerReport({ password: "secret" }),
    },
    {
      v: 1,
      id,
      type: "watchtower",
      watchtower: watchtowerReport(),
      extra: true,
    },
  ])
    assert.equal(core.validResponse(response), false);
});
test("candidate DTO keeps the historical shape and bounds optional health fields", () => {
  const id = "1".repeat(32),
    revision = "2".repeat(64);
  const historical = {
    id,
    revision,
    title: "GitHub",
    state: "active",
  };
  assert.equal(core.validCandidate(historical), true);
  assert.equal(
    core.validResponse({
      v: 1,
      id: "c".repeat(32),
      type: "candidates",
      candidates: [historical],
    }),
    true,
  );
  const healthy = {
    ...historical,
    watchtower_flags: ["weak", "reused"],
    strength_score: 32,
    strength_category: "weak",
    reuse_count: 2,
    breach_count: 0,
  };
  assert.equal(core.validCandidate(healthy), true);
  assert.equal(
    core.validResponse({
      v: 1,
      id: "c".repeat(32),
      type: "candidates",
      candidates: [healthy],
    }),
    true,
  );
  for (const row of [
    { ...healthy, watchtower_flags: ["not-a-flag"] },
    { ...healthy, watchtower_flags: "weak" },
    { ...healthy, watchtower_flags: ["weak", "weak"] },
    { ...healthy, strength_score: 101 },
    { ...healthy, strength_score: "32" },
    { ...healthy, strength_category: "STRONG" },
    { ...healthy, reuse_count: -1 },
    { ...healthy, breach_count: 1.5 },
    { ...healthy, password: "secret" },
    { ...healthy, title: "x".repeat(1025) },
    { ...healthy, id: "A".repeat(32) },
    { ...healthy, state: "archived" },
  ])
    assert.equal(core.validCandidate(row), false);
  assert.equal(
    core.validResponse({
      v: 1,
      id: "c".repeat(32),
      type: "candidates",
      candidates: [healthy, { ...healthy, password: "secret" }],
    }),
    false,
  );
});
test("watchtower flag helper filters unknown and duplicate values in stable order", () => {
  assert.deepEqual(
    core.watchtowerFlagsForRow({
      watchtower_flags: ["vulnerable", "bogus", "weak", "vulnerable"],
    }),
    ["weak", "vulnerable"],
  );
  assert.deepEqual(core.watchtowerFlagsForRow({}), []);
  assert.deepEqual(core.watchtowerFlagsForRow(null), []);
  assert.equal(core.validWebOrigin("https://example.test"), true);
  assert.equal(core.validWebOrigin("http://example.test:8080"), true);
  assert.equal(core.validWebOrigin("https://example.test/path"), false);
  assert.equal(core.validWebOrigin("https://user@example.test"), false);
  assert.equal(core.validHTTPSOrigin("https://example.test"), true);
  assert.equal(core.validHTTPSOrigin("http://example.test"), false);
  assert.deepEqual(core.siteFromURL("https://example.test/login"), {
    origin: "https://example.test",
    unsecured: false,
  });
  assert.deepEqual(core.siteFromURL("http://example.test/login"), {
    origin: "http://example.test",
    unsecured: true,
  });
  assert.deepEqual(core.siteFromURL("http://localhost:3000/login"), {
    origin: "http://localhost:3000",
    unsecured: false,
  });
  assert.deepEqual(core.siteFromURL("http://127.0.0.1/login"), {
    origin: "http://127.0.0.1",
    unsecured: false,
  });
  assert.equal(core.siteFromURL("chrome://settings"), null);
});

test("paste protection recognises only complete Locklark Secret Key material", () => {
  const key = "LL1-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ".slice(0, 26);
  const seed = "LLR2-" + "A".repeat(52);
  assert.equal(key.length, 30);
  assert.equal(core.looksLikeLocklarkSecret(key), true);
  assert.equal(core.looksLikeLocklarkSecret("  " + key + "\n"), true);
  assert.equal(core.looksLikeLocklarkSecret(seed), true);
  assert.equal(core.looksLikeLocklarkSecret(seed + "-" + "B".repeat(52)), true);
  assert.equal(core.looksLikeLocklarkSecret(key.toLowerCase()), false);
  assert.equal(core.looksLikeLocklarkSecret("LL1-" + "A".repeat(25)), false);
  assert.equal(core.looksLikeLocklarkSecret("LL1-" + "1".repeat(26)), false);
  assert.equal(core.looksLikeLocklarkSecret(key + " trailer"), false);
  assert.equal(core.looksLikeLocklarkSecret(""), false);
  assert.equal(core.looksLikeLocklarkSecret(null), false);
});

test("paste protection warns only on known state and never blocks by default", () => {
  const key = "LL1-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ".slice(0, 26);
  assert.equal(
    core.pasteWarning({ text: key, isPasswordField: false, siteLinked: true }),
    "secret-key",
  );
  assert.equal(
    core.pasteWarning({ text: "hunter2", isPasswordField: true, siteLinked: false }),
    "phishing",
  );
  assert.equal(
    core.pasteWarning({ text: "hunter2", isPasswordField: true, siteLinked: true }),
    "",
  );
  assert.equal(
    core.pasteWarning({ text: "hunter2", isPasswordField: true, siteLinked: null }),
    "",
  );
  assert.equal(
    core.pasteWarning({ text: "hunter2", isPasswordField: false, siteLinked: false }),
    "",
  );
  assert.equal(
    core.pasteWarning({
      text: "hunter2",
      isPasswordField: true,
      siteLinked: false,
      enabled: false,
    }),
    "",
  );
  assert.equal(
    core.pasteWarning({ text: "   ", isPasswordField: true, siteLinked: false }),
    "",
  );
  assert.equal(core.pasteWarning(null), "");
});

test("paste protection is on by default and normalises a stored boolean", () => {
  assert.equal(core.DEFAULT_SETTINGS.pasteProtection, true);
  assert.equal(core.normalizeSettings({}).pasteProtection, true);
  assert.equal(core.normalizeSettings({ pasteProtection: false }).pasteProtection, false);
  assert.equal(core.normalizeSettings({ pasteProtection: "off" }).pasteProtection, true);
});

test("two-factor setup URLs are parsed strictly and never expose the seed", () => {
  const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const parsed = core.parseOTPAuthTOTP(
    "otpauth://totp/ACME%20Co:john@example.com?secret=" +
      secret +
      "&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
  );
  assert.deepEqual(parsed, {
    issuer: "ACME Co",
    account: "john@example.com",
    label: "ACME Co · john@example.com",
    digits: 8,
    period: 60,
    algorithm: "SHA256",
  });
  assert.equal("secret" in parsed, false);
  assert.deepEqual(core.parseOTPAuthTOTP("otpauth://totp/ACME:john?secret=" + secret), {
    issuer: "ACME",
    account: "john",
    label: "ACME · john",
    digits: 6,
    period: 30,
    algorithm: "SHA1",
  });
  // Lowercase Base32 is accepted by the native parser and stored upper-cased.
  assert.equal(
    core.parseOTPAuthTOTP("otpauth://totp/x?secret=" + secret.toLowerCase()).label,
    "x",
  );
  // An issuer parameter alone is valid; only a conflicting label issuer is not.
  assert.equal(
    core.parseOTPAuthTOTP("otpauth://totp/x?secret=" + secret + "&issuer=Other")
      .label,
    "Other · x",
  );
  // Padded Base32 that decodes to fewer than 16 bytes is refused.
  assert.equal(
    core.parseOTPAuthTOTP("otpauth://totp/x?secret=MZXW6YTBOI======"),
    null,
  );
});

test("two-factor setup parsing refuses HOTP, unknown fields and bad bounds", () => {
  const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const base = "otpauth://totp/x?secret=" + secret;
  for (const value of [
    "otpauth://hotp/x?secret=" + secret,
    base + "&digits=7",
    base + "&digits=06",
    base + "&period=0",
    base + "&period=3601",
    base + "&algorithm=MD5",
    base + "&foo=bar",
    "otpauth://totp/ACME:john?secret=" + secret + "&issuer=Other",
    "otpauth://totp/ACME:a:b?secret=" + secret,
    "otpauth://totp/x?secret=" + secret + "#fragment",
    "otpauth://totp/x?secret=" + secret + "&secret=" + secret,
    "otpauth://totp/x?secret=" + secret + ";a=b",
    "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/x?secret=" + "A".repeat(105),
    "otpauth://totp/x?secret=" + "1".repeat(32),
    "otpauth://totp/x?secret=",
    "otpauth://totp/x?secret=" + secret + "&issuer=bad/issuer",
    "otpauth://totp/x?secret=" + secret + " ",
    42,
    null,
  ])
    assert.equal(core.parseOTPAuthTOTP(value), null, String(value));
});

test("idle auto-lock and notifications stay bounded and opt-in", () => {
  for (const value of [0, 1, 5, 15, 30, 60])
    assert.equal(
      core.normalizeSettings({ idleLockMinutes: value }).idleLockMinutes,
      value,
    );
  for (const value of [-1, 2, 7, 1.5, "5", null, undefined])
    assert.equal(
      core.normalizeSettings({ idleLockMinutes: value }).idleLockMinutes,
      0,
    );
  assert.equal(core.normalizeSettings({}).notifications, false);
  assert.equal(core.normalizeSettings({ notifications: true }).notifications, true);
  assert.equal(
    core.normalizeSettings({ notifications: "true" }).notifications,
    false,
  );
});

test("identity provider recognition is display-only and cannot be spoofed", () => {
  assert.equal(core.identityProviderFor("https://accounts.google.com/o/oauth2"), "Google");
  assert.equal(core.identityProviderFor("https://login.microsoftonline.com/common"), "Microsoft");
  assert.equal(core.identityProviderFor("https://appleid.apple.com/auth"), "Apple");
  assert.equal(core.identityProviderFor("https://github.com/login"), "GitHub");
  assert.equal(core.identityProviderFor("https://example.okta.com/login"), "Okta");
  for (const host of [
    "https://accounts.google.com.evil.test/",
    "https://evil-accounts.google.com.test/",
    "https://accounts.google.com@evil.test/",
    "https://notgoogle.com/",
    "not a url",
  ])
    assert.equal(core.identityProviderFor(host), "", host);
});

test("native status frames are bounded and unknown keys are refused", () => {
  const frame = {
    v: 1,
    id: "a".repeat(32),
    type: "status",
    desktop_connected: true,
    unlocked: false,
    vault_locked: true,
    paired: false,
    capabilities: ["shared-session-v1"],
  };
  assert.equal(core.validResponse(frame), true);
  assert.equal(core.validResponse({ ...frame, unexpected: 1 }), false);
  assert.equal(core.validResponse({ ...frame, v: 2 }), false);
});

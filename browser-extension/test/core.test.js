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

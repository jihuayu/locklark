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

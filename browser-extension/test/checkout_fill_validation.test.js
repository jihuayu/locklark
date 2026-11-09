const test = require("node:test");
const assert = require("node:assert/strict");
const { makeFillHarness, control } = require("./checkout_core_harness.js");

const ORIGIN = "https://frame.test";
const DEADLINE = (harness) => harness.clock + 1000;
const refuse = { filled: false, count: 0 };
const field = (config = {}) =>
  control("input", { autocomplete: "cc-number", ...config });

test("origin, secure context, opaque window and deadline guards refuse first", () => {
  const number = field();
  const cases = [
    ["https://other.test", {}],
    [ORIGIN, { secure: false }],
    [ORIGIN, { windowOrigin: "null" }],
    ["null", { origin: "null", protocol: "about:", href: "about:blank" }],
    ["http://frame.test", { origin: "http://frame.test", protocol: "http:" }],
    [ORIGIN, { href: "about:srcdoc" }],
  ];
  for (const [expected, options] of cases) {
    const harness = makeFillHarness({ elements: [number], ...options });
    assert.deepEqual(
      harness.call(expected, { "cc-number": "4242" }, DEADLINE(harness), false),
      refuse,
    );
  }
  const harness = makeFillHarness({ elements: [number] });
  for (const deadline of [harness.clock - 1, harness.clock, harness.clock + 1501, "x"]) {
    assert.deepEqual(
      harness.call(ORIGIN, { "cc-number": "4242" }, deadline, false),
      refuse,
    );
  }
  assert.equal(number._value, "");
  assert.equal(number.events.length, 0);
});

test("topness must match allowTop exactly", () => {
  const frameField = field();
  const frame = makeFillHarness({ elements: [frameField] });
  assert.deepEqual(
    frame.call(ORIGIN, { "cc-number": "4242" }, DEADLINE(frame), false),
    { filled: true, count: 1 },
  );
  frameField._value = "";
  assert.deepEqual(
    frame.call(ORIGIN, { "cc-number": "4242" }, DEADLINE(frame), true),
    refuse,
  );

  const topField = field();
  const top = makeFillHarness({ elements: [topField], topIsSelf: true });
  assert.deepEqual(
    top.call(ORIGIN, { "cc-number": "4242" }, DEADLINE(top), false),
    refuse,
  );
  assert.deepEqual(
    top.call(ORIGIN, { "cc-number": "4242" }, DEADLINE(top), true),
    { filled: true, count: 1 },
  );
});

test("missing, unstable or ever-sandboxed fence refuses injection", () => {
  for (const options of [{ fence: null }, { stable: false }, { sandboxEver: true }, { fence: 42 }]) {
    const number = field();
    const harness = makeFillHarness({ elements: [number], ...options });
    assert.deepEqual(
      harness.call(ORIGIN, { "cc-number": "4242" }, DEADLINE(harness), false),
      refuse,
    );
    assert.equal(number._value, "");
  }
});

test("field map is bounded to the exact native card whitelist", () => {
  const malformed = [
    null,
    [],
    "x",
    { pin: "1234" },
    { password: "secret" },
    { ssn: "123" },
    { "cc-number": 42 },
    { "cc-number": "" },
    { "cc-number": "a".repeat(16385) },
  ];
  for (const fields of malformed) {
    const number = field();
    const harness = makeFillHarness({ elements: [number] });
    assert.deepEqual(
      harness.call(ORIGIN, fields, DEADLINE(harness), false),
      refuse,
    );
    assert.equal(number._value, "");
  }
  const allowed = [
    "cc-name",
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-exp-year-short",
    "cc-csc",
    "cc-type",
  ];
  const oversized = {};
  for (const key of allowed) oversized[key] = "a".repeat(5000);
  const harness = makeFillHarness({ elements: [field()] });
  assert.deepEqual(
    harness.call(ORIGIN, oversized, DEADLINE(harness), false),
    refuse,
  );
});

test("ambiguous, hidden, disabled, readonly and empty matches refuse", () => {
  const fields = { "cc-number": "4242" };
  const duplicate = [
    field(),
    field(),
  ];
  for (const elements of [
    duplicate,
    [field({ hidden: true })],
    [field({ type: "hidden" })],
    [field({ disabled: true })],
    [field({ readOnly: true })],
    [],
    [control("select", { autocomplete: "cc-exp-month", options: [{ value: "01" }] })],
  ]) {
    const harness = makeFillHarness({ elements });
    const result = harness.call(ORIGIN, fields, DEADLINE(harness), false);
    assert.deepEqual(result, refuse);
    for (const element of elements) {
      assert.equal(element._value, "");
      assert.equal(element.events.length, 0);
    }
  }
});

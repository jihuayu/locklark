const test = require("node:test");
const assert = require("node:assert/strict");
const { makeFillHarness, control } = require("./checkout_core_harness.js");

const ORIGIN = "https://frame.test";
const DEADLINE = (harness) => harness.clock + 1000;

test("fills unique visible card controls with normal input/change events", () => {
  const name = control("input", { autocomplete: "cc-name" });
  const number = control("input", { autocomplete: "cc-number" });
  const month = control("select", {
    autocomplete: "cc-exp-month",
    options: [{ value: "01" }, { value: "12" }],
  });
  const csc = control("input", { autocomplete: "cc-csc" });
  const unrelated = control("input", { autocomplete: "email" });
  const harness = makeFillHarness({ elements: [name, number, month, csc, unrelated] });
  const messages = [];
  const clipboard = [];
  harness.context.window.postMessage = (data) => messages.push(data);
  harness.context.navigator = { clipboard: { writeText: (v) => clipboard.push(v) } };
  harness.context.form = {
    submitted: false,
    submit() {
      this.submitted = true;
    },
  };
  const result = harness.call(
    ORIGIN,
    {
      "cc-name": "Ada Lovelace",
      "cc-number": "4242 4242 4242 4242",
      "cc-exp-month": "12",
      "cc-csc": "123",
    },
    DEADLINE(harness),
    false,
  );
  assert.deepEqual(result, { filled: true, count: 4 });
  assert.deepEqual(Object.keys(result).sort(), ["count", "filled"]);
  assert.equal(result.count > 0, true);
  assert.equal(name._value, "Ada Lovelace");
  assert.equal(number._value, "4242 4242 4242 4242");
  assert.equal(month._value, "12");
  assert.equal(csc._value, "123");
  assert.equal(unrelated._value, "");
  for (const element of [name, number, month, csc])
    assert.deepEqual(element.events.map((event) => event.type), ["input", "change"]);
  assert.equal(unrelated.events.length, 0);
  assert.equal(harness.context.form.submitted, false);
  assert.equal(clipboard.length, 0);
  assert.equal(messages.length, 0);
  assert.equal(JSON.stringify(result).includes("4242"), false);
});

test("native setter that mutates the DOM yields unknown, not a second write", () => {
  const number = control("input", { autocomplete: "cc-number" });
  const csc = control("input", { autocomplete: "cc-csc" });
  const replacement = control("input", { autocomplete: "cc-csc" });
  const harness = makeFillHarness({ elements: [number, csc] });
  number.onSet = () => {
    csc.isConnected = false;
    harness.elements.push(replacement);
  };
  const result = harness.call(
    ORIGIN,
    { "cc-number": "4242", "cc-csc": "123" },
    DEADLINE(harness),
    false,
  );
  assert.deepEqual(result, { filled: false, count: 1, unknown: true });
  assert.equal(number._value, "4242");
  assert.equal(csc._value, "");
  assert.equal(csc.events.length, 0);
  assert.equal(replacement._value, "");
  assert.equal(replacement.events.length, 0);
});

test("document root replacement after a partial write yields unknown", () => {
  const number = control("input", { autocomplete: "cc-number" });
  const csc = control("input", { autocomplete: "cc-csc" });
  const harness = makeFillHarness({ elements: [number, csc] });
  number.onSet = () => harness.setRoot({ tagName: "HTML" });
  const result = harness.call(
    ORIGIN,
    { "cc-number": "4242", "cc-csc": "123" },
    DEADLINE(harness),
    false,
  );
  assert.deepEqual(result, { filled: false, count: 1, unknown: true });
  assert.equal(csc._value, "");
  assert.equal(csc.events.length, 0);
});

test("a page event handler that removes the next node yields unknown", () => {
  const number = control("input", { autocomplete: "cc-number" });
  const csc = control("input", { autocomplete: "cc-csc" });
  const harness = makeFillHarness({ elements: [number, csc] });
  number.onEvent = (event) => {
    if (event.type === "input") csc.isConnected = false;
  };
  const result = harness.call(
    ORIGIN,
    { "cc-number": "4242", "cc-csc": "123" },
    DEADLINE(harness),
    false,
  );
  assert.deepEqual(result, { filled: false, count: 1, unknown: true });
  assert.equal(csc._value, "");
});

test("a select without a matching option is not filled", () => {
  const month = control("select", {
    autocomplete: "cc-exp-month",
    options: [{ value: "01" }, { value: "02" }],
  });
  const harness = makeFillHarness({ elements: [month] });
  assert.deepEqual(
    harness.call(ORIGIN, { "cc-exp-month": "12" }, DEADLINE(harness), false),
    { filled: false, count: 0 },
  );
  assert.equal(month._value, "");
  assert.equal(month.events.length, 0);
});

test("month select is written through the native SELECT setter via option mapping", () => {
  const name = control("input", { autocomplete: "cc-name" });
  const month = control("select", {
    autocomplete: "cc-exp-month",
    options: [
      { value: "01", text: "January" },
      { value: "12", text: "December" },
    ],
  });
  const writes = [];
  month.onSet = (next) => writes.push(String(next));
  const harness = makeFillHarness({ elements: [name, month] });
  const result = harness.call(
    ORIGIN,
    {
      "cc-name": "Ada Lovelace",
      "cc-exp-month": "12",
      // No control matches this optional field, so it is skipped, not refused.
      "cc-exp-year": "2030",
    },
    DEADLINE(harness),
    false,
  );
  assert.deepEqual(result, { filled: true, count: 2 });
  assert.equal(month.constructor.name, "HTMLSelectElement");
  assert.equal(month.tagName, "SELECT");
  assert.deepEqual(writes, ["12"]);
  assert.equal(month._value, "12");
  assert.equal(name._value, "Ada Lovelace");
  assert.deepEqual(month.events.map((event) => event.type), ["input", "change"]);
});

test("an unmatched select refuses the whole fill with zero writes and events", () => {
  const number = control("input", { autocomplete: "cc-number" });
  const month = control("select", {
    autocomplete: "cc-exp-month",
    options: [
      { value: "01", text: "January" },
      { value: "02", text: "February" },
    ],
  });
  const harness = makeFillHarness({ elements: [number, month] });
  for (const requested of ["12", "December"]) {
    const result = harness.call(
      ORIGIN,
      { "cc-number": "4242 4242 4242 4242", "cc-exp-month": requested },
      DEADLINE(harness),
      false,
    );
    assert.deepEqual(result, { filled: false, count: 0 });
    assert.equal(number._value, "");
    assert.equal(month._value, "");
    assert.equal(number.events.length, 0);
    assert.equal(month.events.length, 0);
  }
});

test("refuses a card fill without explicit user authorization", () => {
  const number = control("input", { autocomplete: "cc-number" });
  const csc = control("input", { autocomplete: "cc-csc" });
  const harness = makeFillHarness({ elements: [number, csc] });
  const result = harness.call(
    ORIGIN,
    { "cc-number": "4242", "cc-csc": "123" },
    DEADLINE(harness),
    false,
    false,
  );
  assert.deepEqual(result, { filled: false, count: 0 });
  assert.equal(number._value, "");
  assert.equal(csc._value, "");
  assert.equal(number.events.length, 0);
  assert.equal(csc.events.length, 0);
});

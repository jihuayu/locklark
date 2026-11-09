const test = require("node:test");
const assert = require("node:assert/strict");
const { makeProbeHarness } = require("./checkout_core_harness.js");

const STABLE = () => ({ document_stable: true, sandbox_ever: false });
const PUBLIC_KEYS = [
  "document_stable",
  "fence_present",
  "origin",
  "sandbox_ever",
  "secure",
  "top",
];

test("checkoutProbe reports only the public HTTPS/fence snapshot", () => {
  const harness = makeProbeHarness({
    origin: "https://pay.shop.test",
    fence: STABLE,
  });
  const result = harness.call();
  assert.deepEqual(Object.keys(result).sort(), PUBLIC_KEYS);
  assert.deepEqual(result, {
    origin: "https://pay.shop.test",
    top: true,
    secure: true,
    fence_present: true,
    document_stable: true,
    sandbox_ever: false,
  });
  assert.equal(
    makeProbeHarness({ topIsSelf: false, fence: STABLE }).call().top,
    false,
  );
  assert.equal(
    makeProbeHarness({
      fence: () => ({ document_stable: true, sandbox_ever: true }),
    }).call().sandbox_ever,
    true,
  );
});

test("opaque, insecure and about/srcdoc documents are refused", () => {
  for (const options of [
    { origin: "null", protocol: "https:", href: "https://frame.test/pay" },
    { origin: "null", protocol: "about:", href: "about:blank" },
    {
      origin: "https://frame.test",
      protocol: "about:",
      href: "about:srcdoc",
    },
    { windowOrigin: "null" },
    { origin: "http://frame.test", protocol: "http:", href: "http://x.test" },
  ]) {
    const result = makeProbeHarness({ ...options, fence: STABLE }).call();
    assert.equal(result.origin, "");
    assert.equal(result.secure, false);
  }
});

test("a missing or unknown fence is unsupported and never initialized", () => {
  const missing = makeProbeHarness();
  const missingResult = missing.call();
  assert.deepEqual(missingResult, {
    origin: "https://frame.test",
    top: true,
    secure: true,
    fence_present: false,
    document_stable: false,
    sandbox_ever: true,
  });
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      missing.context,
      "LocklarkCheckoutFence",
    ),
    false,
  );

  const unknown = makeProbeHarness({ fence: 42 });
  assert.equal(unknown.call().fence_present, false);
  assert.equal(unknown.call().document_stable, false);
});

test("probe output ignores unrelated page-shaped values", () => {
  const harness = makeProbeHarness({
    origin: "https://pay.shop.test",
    fence: STABLE,
  });
  harness.context.pageOrigin = "https://evil.test";
  harness.context.document = { origin: "https://evil.test", secure: true };
  const result = harness.call();
  assert.equal(result.origin, "https://pay.shop.test");
  assert.equal(result.secure, true);
  assert.deepEqual(Object.keys(result).sort(), PUBLIC_KEYS);
});

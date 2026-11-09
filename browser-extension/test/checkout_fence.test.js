const test = require("node:test");
const assert = require("node:assert/strict");
const { element, makeContentHarness } = require("./checkout_content_harness.js");

test("fence installs before the frameAllowed early return as a frozen global", () => {
  const harness = makeContentHarness();
  const fence = harness.context.LocklarkCheckoutFence;
  assert.equal(typeof fence, "function");
  const descriptor = harness.descriptor();
  assert.equal(descriptor.writable, false);
  assert.equal(descriptor.configurable, false);
  assert.equal(descriptor.enumerable, false);
  assert.equal(Object.isFrozen(fence), true);
  const snapshot = harness.snapshot();
  assert.deepEqual(Object.keys(snapshot).sort(), [
    "document_stable",
    "sandbox_ever",
  ]);
  assert.deepEqual(snapshot, { document_stable: true, sandbox_ever: false });
  assert.equal(Object.isFrozen(fence()), true);
  // The cross-origin early return still happened: only the fence observer and
  // the DOMContentLoaded latch exist, no autofill UI wiring or page messages.
  assert.equal(harness.observerConfigs.length, 1);
  assert.equal(harness.observerTargets[0], harness.document);
  // The observer record was created inside the content.js VM realm, so compare
  // the public plain-JSON shape instead of prototype-sensitive deep equality.
  assert.deepEqual(JSON.parse(JSON.stringify(harness.observerConfigs[0])), {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["sandbox"],
    attributeOldValue: true,
  });
  assert.equal(harness.documentListeners.focusin, undefined);
  assert.equal(harness.messages.length, 0);
});

test("initial scan latches an already-present sandboxed iframe", () => {
  const harness = makeContentHarness({
    frames: [element("iframe", { sandbox: "" })],
  });
  assert.equal(harness.snapshot().sandbox_ever, true);
});

test("added subtree, removed frame and attribute-oldValue all latch sandbox", () => {
  const added = makeContentHarness();
  const wrapper = element("div", {}, [element("iframe", { sandbox: "" })]);
  added.emit([{ type: "childList", addedNodes: [wrapper], removedNodes: [] }]);
  assert.equal(added.snapshot().sandbox_ever, true);

  const removed = makeContentHarness();
  removed.emit([
    {
      type: "childList",
      addedNodes: [],
      removedNodes: [element("iframe", { sandbox: "allow-scripts" })],
    },
  ]);
  assert.equal(removed.snapshot().sandbox_ever, true);

  // The attribute was removed again before delivery, so only oldValue remains.
  const raced = makeContentHarness();
  raced.emit([
    {
      type: "attributes",
      attributeName: "sandbox",
      attributeOldValue: "allow-scripts",
      oldValue: "allow-scripts",
      target: element("iframe"),
    },
  ]);
  assert.equal(raced.snapshot().sandbox_ever, true);
});

test("root replacement is permanent, including a late first latch", () => {
  const harness = makeContentHarness();
  const original = harness.document.documentElement;
  harness.setRoot(element("html"));
  harness.emit([{ type: "childList", addedNodes: [], removedNodes: [] }]);
  assert.equal(harness.snapshot().document_stable, false);
  harness.setRoot(original);
  assert.equal(harness.snapshot().document_stable, false);

  const late = makeContentHarness({ documentElement: null });
  assert.equal(late.snapshot().document_stable, false);
  const first = element("html");
  late.setRoot(first);
  late.emit([{ type: "childList", addedNodes: [first], removedNodes: [] }]);
  assert.equal(late.snapshot().document_stable, true);
  late.setRoot(element("html"));
  assert.equal(late.snapshot().document_stable, false);
});

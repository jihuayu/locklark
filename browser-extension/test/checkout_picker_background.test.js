const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

const tick = () => new Promise((resolve) => setImmediate(resolve));
async function settle(rounds = 14) {
  for (let i = 0; i < rounds; i++) await tick();
}

const CARD_ID = "b".repeat(32);
const CARD_REV = "c".repeat(64);
const TOP_ORIGIN = "https://shop.test";
const TOP_DOC = "top-doc-1";
const FRAME_DOC = "sub-doc-1";
const FRAME_ORIGIN = "https://shop.test";
const CARD_NUMBER = "4242424242424242";

const RealDate = Date;
let CLOCK = 1_700_000_000_000;
class ClockDate extends RealDate {
  constructor(...args) {
    if (args.length) super(...args);
    else super(CLOCK);
  }
  static now() {
    return CLOCK;
  }
}

// One public frame/document snapshot as core.checkoutProbe reports it after the
// browser injected into that frame.
function frame(frameId, documentId, origin, top) {
  return {
    frameId,
    documentId,
    result: {
      document_stable: true,
      fence_present: true,
      origin,
      sandbox_ever: false,
      secure: true,
      top,
    },
  };
}

function cardItem() {
  return {
    id: CARD_ID,
    revision: CARD_REV,
    title: "Visa",
    category: "credit_card",
    urls: [TOP_ORIGIN + "/checkout"],
    credit_card: {
      type: "Visa",
      cardholder_name: "Ada",
      expiry_date: "12/30",
      masked_number: "•••• 4242",
      has_cvv: true,
    },
  };
}

function harness(options = {}) {
  let frames = options.frames
    ? options.frames.map((entry) => entry)
    : [
        frame(0, TOP_DOC, TOP_ORIGIN, true),
        frame(3, FRAME_DOC, FRAME_ORIGIN, false),
      ];
  let tabUrl = options.tabUrl || TOP_ORIGIN + "/checkout";
  const timers = new Set();
  const messageListeners = [];
  const sent = [];
  const probes = [];
  const injections = [];
  let portMessage, portDisconnect;

  const reply = (request, message) =>
    queueMicrotask(() => portMessage({ v: 1, id: request.id, ...message }));

  const port = {
    onMessage: { addListener: (fn) => (portMessage = fn) },
    onDisconnect: { addListener: (fn) => (portDisconnect = fn) },
    disconnect: () => portDisconnect?.(),
    postMessage: (request) => {
      sent.push(request);
      if (request.type === "hello")
        reply(request, {
          type: "paired",
          capability: "a".repeat(32),
          capabilities: ["checkout-frames-v1"],
        });
      else if (request.type === "item-get")
        reply(request, { type: "item-detail", item: cardItem() });
      else if (request.type === "match-profiles") {
        if (options.matchRefusal) reply(request, { type: "error", error: "refused" });
        else
          reply(request, {
            type: "profiles",
            profiles: [
              {
                id: CARD_ID,
                revision: CARD_REV,
                category: "credit_card",
                title: "Visa",
              },
            ],
          });
      } else if (request.type === "fill-profile") {
        // Native policy is the only authority on the cross-site proposal.
        if (options.fillRefusal) reply(request, { type: "error", error: "refused" });
        else
          reply(request, {
            type: "profile-fill",
            profile_fill: {
              item_id: CARD_ID,
              revision: CARD_REV,
              category: "credit_card",
              fields: { card_number: CARD_NUMBER, cvv: "123" },
            },
          });
      } else if (request.type === "cancel") reply(request, { type: "cancelled" });
    },
  };

  const api = {
    storage: {
      onChanged: { addListener() {} },
      local: {
        get: async () => ({}),
        set: async () => {},
      },
    },
    runtime: {
      id: "fixed",
      getURL: (p) => "chrome-extension://fixed/" + p,
      connectNative: () => port,
      onMessage: { addListener: (fn) => messageListeners.push(fn) },
    },
    tabs: {
      query: async () => [{ id: 1, url: tabUrl, windowId: 1 }],
      sendMessage: async () => {},
      onActivated: { addListener() {} },
      onUpdated: { addListener() {} },
      onRemoved: { addListener() {} },
    },
    windows: { WINDOW_ID_NONE: -1, onFocusChanged: { addListener() {} } },
    scripting: {
      executeScript: async (scriptOptions) => {
        const target = scriptOptions.target || {};
        if (scriptOptions.func === core.checkoutProbe) {
          probes.push({ target });
          return frames.map((entry) => ({
            frameId: entry.frameId,
            documentId: entry.documentId,
            result: { ...entry.result },
          }));
        }
        if (scriptOptions.func === core.fillCheckoutCardDocument) {
          // chrome.scripting.executeScript JSON-serializes `args` when it is
          // dispatched, so the injected frame never observes later mutation.
          // Snapshot here for the same reason: the background scrubs its own
          // copy of the native card fields as soon as the call settles.
          injections.push({
            ...scriptOptions,
            args: scriptOptions.args.map((arg) =>
              arg && typeof arg === "object"
                ? JSON.parse(JSON.stringify(arg))
                : arg,
            ),
          });
          const documentId = (target.documentIds || [])[0];
          const match = frames.find((entry) => entry.documentId === documentId);
          if (!match) throw Error("Cannot access contents of the document.");
          if (options.mismatchedResult)
            return [
              {
                frameId: 0,
                documentId: TOP_DOC,
                result: { count: 1, filled: true },
              },
            ];
          return [
            {
              frameId: match.frameId,
              documentId: match.documentId,
              result: { count: 1, filled: true },
            },
          ];
        }
        throw Error("unexpected scripting target");
      },
    },
  };

  const context = {
    chrome: api,
    LocklarkCore: core,
    crypto: webcrypto,
    Date: ClockDate,
    setTimeout: (fn, ms) => {
      const handle = setTimeout(fn, ms);
      handle.unref?.();
      timers.add(handle);
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
    performance: { now: () => 0 },
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../background.js"), "utf8"),
    context,
  );

  const sender = { id: "fixed", url: "chrome-extension://fixed/popup.html" };
  return {
    sent,
    probes,
    injections,
    setFrames: (next) => {
      frames = next;
    },
    setTabUrl: (value) => {
      tabUrl = value;
    },
    send: (message, from = sender) =>
      new Promise((resolve) => {
        let handled = false;
        for (const listener of messageListeners)
          if (listener(message, from, resolve) === true) handled = true;
        if (!handled) resolve(undefined);
      }),
  };
}

async function connect(h) {
  await h.send({ type: "connect" });
  await settle(4);
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, true, "native pairing must succeed");
}

const gesture = () => ({ v: 1, scope: "credit_card", at: CLOCK });

async function openPicker(h) {
  const state = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: gesture(),
  });
  assert.ok(state && state.checkoutPicker, "picker view expected");
  return state.checkoutPicker;
}

// Values created inside the vm context are a different realm, so public
// shapes are compared by value.
const keys = (value) => JSON.stringify(Object.keys(value).sort());
const json = (value) => JSON.stringify(value);

const choiceFor = (picker, top) =>
  picker.candidates.find((entry) => entry.top === top).choice;

const select = (h, picker, choice) =>
  h.send({
    type: "checkout-select",
    nonce: picker.nonce,
    choice,
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: gesture(),
  });

test("picker exposes only public same-site origins and opaque keys", async () => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);

  assert.equal(keys(picker), '["candidates","expiresAt","nonce","topOrigin"]');
  assert.equal(picker.topOrigin, TOP_ORIGIN);
  assert.match(picker.nonce, /^[a-f0-9]{32}$/);
  assert.equal(picker.candidates.length, 2);
  for (const entry of picker.candidates) {
    assert.equal(keys(entry), '["choice","frameId","origin","top"]');
    assert.match(entry.choice, /^[a-f0-9]{32}$/);
    assert.equal(entry.origin, TOP_ORIGIN);
  }
  assert.equal(json([...picker.candidates].map((entry) => entry.top)), "[true,false]");
  const choices = [...picker.candidates].map((entry) => entry.choice);
  assert.equal(new Set(choices).size, 2, "choice keys must be unguessable/unlinked");
  assert.equal(
    JSON.stringify(picker).includes(TOP_DOC) ||
      JSON.stringify(picker).includes(FRAME_DOC),
    false,
    "document ids never leave the background",
  );
  // Enumerating frames filled nothing and asked the native host nothing.
  assert.equal(h.injections.length, 0);
  assert.equal(h.sent.filter((r) => r.type === "fill-profile").length, 0);
  assert.equal(h.sent.filter((r) => r.type === "match-profiles").length, 0);
});

test("only the popup sender with the exact message shape may pick", async () => {
  const h = harness();
  await connect(h);

  // A content script or page cannot enumerate checkout frames.
  const pageSender = {
    id: "fixed",
    url: "https://shop.test/checkout",
    tab: { id: 1 },
  };
  assert.equal(
    await h.send(
      { type: "checkout-frames", id: CARD_ID, revision: CARD_REV },
      pageSender,
    ),
    undefined,
  );
  // Extra claims such as a caller-supplied origin are refused, not trusted.
  const extra = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    origin: "https://evil.test",
  });
  assert.equal(extra.checkoutPicker, undefined);
  assert.match(extra.status, /拒绝/);
  const badID = await h.send({
    type: "checkout-frames",
    id: "not-a-key",
    revision: CARD_REV,
  });
  assert.equal(badID.checkoutPicker, undefined);
  assert.equal(h.probes.length, 0, "no frame enumeration on a refused message");
});

test("a frame or document replaced before the choice is refused", async () => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);
  const probesBefore = h.probes.length;
  assert.ok(probesBefore >= 1);

  // The chosen subframe navigated: same frame id, new document.
  h.setFrames([
    frame(0, TOP_DOC, TOP_ORIGIN, true),
    frame(3, "sub-doc-2", FRAME_ORIGIN, false),
  ]);
  const state = await select(h, picker, choiceFor(picker, false));
  // Consumption is synchronous: the accepted ack only means this exact opaque
  // choice was consumed, never that native approved the changed page.
  assert.equal(state.checkoutStarted, true, "the choice itself was accepted");
  // Wait bounded for the background's own final refusal after revalidation.
  let final = null;
  for (let i = 0; i < 40; i++) {
    final = await h.send({ type: "state" });
    if (final.pending === false && /未完成|拒绝|已变化/.test(final.status)) break;
    await settle(2);
  }
  assert.ok(final && final.pending === false, "the intent must settle");
  assert.match(final.status, /未完成|拒绝|已变化/);
  assert.equal(h.injections.length, 0, "no card field may reach a changed page");
  assert.equal(h.sent.filter((r) => r.type === "fill-profile").length, 0);
  assert.equal(h.sent.filter((r) => r.type === "match-profiles").length, 0);
  assert.ok(h.probes.length > probesBefore, "the changed page was re-probed");

  // The consumed picker cannot be replayed.
  const again = await select(h, picker, choiceFor(picker, false));
  assert.equal(again.checkoutStarted, undefined);
  assert.match(again.status, /拒绝/);
  assert.equal(h.injections.length, 0);
});

test("an expired picker nonce is refused", async () => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);

  CLOCK += 30_001;
  const state = await select(h, picker, choiceFor(picker, true));
  await settle();
  assert.equal(state.checkoutStarted, undefined);
  assert.match(state.status, /拒绝/);
  assert.equal(h.injections.length, 0);
  assert.equal(h.sent.filter((r) => r.type === "fill-profile").length, 0);
  CLOCK = 1_700_000_000_000;
});

test("native PSL policy is the authority on a cross-site frame", async () => {
  const h = harness({
    frames: [
      frame(0, TOP_DOC, TOP_ORIGIN, true),
      frame(5, "sub-doc-x", "https://pay.other.test", false),
    ],
    fillRefusal: true,
  });
  await connect(h);
  const picker = await openPicker(h);
  assert.equal(
    json([...picker.candidates].map((entry) => entry.origin)),
    json([TOP_ORIGIN, "https://pay.other.test"]),
  );

  const state = await select(h, picker, choiceFor(picker, false));
  await settle();
  assert.equal(state.checkoutStarted, true, "the choice itself was accepted");
  // The background only *proposes* the cross-site target and lets native
  // decide; a refusal releases nothing.
  const match = h.sent.find((r) => r.type === "match-profiles");
  assert.equal(
    json(match.checkout),
    json({ top_origin: TOP_ORIGIN, top_document_id: TOP_DOC, frame_id: 5 }),
  );
  const fill = h.sent.find((r) => r.type === "fill-profile");
  assert.equal(json(fill.checkout), json(match.checkout));
  assert.equal(h.injections.length, 0, "refused approval injects nothing");
  assert.equal(h.sent.filter((r) => r.type === "fill-profile").length, 1);
  const final = await h.send({ type: "state" });
  assert.match(final.status, /未完成|拒绝/);
});

test("an approved same-site choice injects the exact document once", async () => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);
  const state = await select(h, picker, choiceFor(picker, false));
  await settle();

  assert.equal(state.checkoutStarted, true);
  assert.equal(h.injections.length, 1, "no broadcast, retry or fallback injection");
  const injection = h.injections[0];
  assert.equal(injection.func, core.fillCheckoutCardDocument);
  assert.equal(keys(injection.target), '["documentIds","tabId"]');
  assert.equal(json(injection.target.documentIds), json([FRAME_DOC]));
  assert.equal(injection.target.allFrames, undefined);
  assert.equal(injection.target.frameIds, undefined);
  assert.equal(injection.args[0], FRAME_ORIGIN);
  assert.equal(injection.args[1].card_number, CARD_NUMBER);
  assert.equal(injection.args[3], false, "subframe injection is not the top document");

  // Public frame metadata was recaptured before the metadata request and again
  // after native approval, always as a bounded all-frame probe.
  assert.ok(h.probes.length >= 3);
  for (const probe of h.probes) {
    assert.equal(probe.target.allFrames, true);
    assert.equal(probe.target.documentIds, undefined);
  }
  // Same-site target: no cross-site proposal is sent to native.
  const match = h.sent.find((r) => r.type === "match-profiles");
  assert.equal(match.checkout, undefined);

  const final = await h.send({ type: "state" });
  assert.match(final.status, /已请求填充结账表单/);
  assert.equal(
    JSON.stringify({ ...final, status: "" }).includes(CARD_NUMBER),
    false,
    "card fields never return to the popup",
  );
});

test("a response from another frame or document is not trusted or retried", async () => {
  const h = harness({ mismatchedResult: true });
  await connect(h);
  const picker = await openPicker(h);
  await select(h, picker, choiceFor(picker, false));
  await settle();

  assert.equal(h.injections.length, 1, "the exact result is required, no retry");
  const final = await h.send({ type: "state" });
  assert.match(final.status, /登录填充结果未确认/);
});

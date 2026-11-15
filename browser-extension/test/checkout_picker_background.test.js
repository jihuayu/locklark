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
test.afterEach(() => { CLOCK = 1_700_000_000_000; });
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
  let tabId = 1, windowId = 1;
  const timers = new Set();
  const messageListeners = [];
  const sent = [];
  const probes = [];
  const injections = [];
  const deliveries = [], badgeWrites = [];
  const hooks = { onCheckoutProbe: null, finishFill: null };
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
      else if (request.type === "match" && options.loginCandidate)
        reply(request, { type: "candidates", candidates: [{
          id: CARD_ID, revision: CARD_REV, title: "Login", state: "active", category: "login",
        }] });
      else if (request.type === "fill" && options.loginCandidate)
        hooks.finishFill = () => reply(request, { type: "error", error: "refused" });
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
    action: {
      setBadgeText: (value) => badgeWrites.push(value),
      setBadgeBackgroundColor: (value) => badgeWrites.push(value),
      setTitle: (value) => badgeWrites.push(value),
    },
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
      query: async () => [{ id: tabId, url: tabUrl, windowId }],
      sendMessage: async () => {},
      onActivated: { addListener() {} },
      onUpdated: { addListener() {} },
      onRemoved: { addListener() {} },
    },
    windows: { WINDOW_ID_NONE: -1, onFocusChanged: { addListener() {} } },
    scripting: {
      executeScript: async (scriptOptions) => {
        const target = scriptOptions.target || {};
        if (scriptOptions.func === core.probe) {
          const frameId = (target.frameIds || [])[0] ?? 0;
          const match = frames.find((entry) => entry.frameId === frameId);
          if (!match) throw Error("No frame with id " + frameId);
          const origin = frameId
            ? match.result.origin
            : core.originFromURL(tabUrl);
          return [
            {
              frameId,
              documentId: match.documentId,
              result: { top: frameId === 0, origin },
            },
          ];
        }
        if (scriptOptions.func === core.checkoutProbe) {
          probes.push({ target });
          await hooks.onCheckoutProbe?.();
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
    deliveries,
    badgeWrites,
    finishFill: () => hooks.finishFill?.(),
    setTab: (nextTab, nextWindow = windowId) => { tabId = nextTab; windowId = nextWindow; },
    setFrames: (next) => {
      frames = next;
    },
    setTabUrl: (value) => {
      tabUrl = value;
    },
    onCheckoutProbe: (fn) => {
      hooks.onCheckoutProbe = fn;
    },
    send: (message, from = sender) =>
      new Promise((resolve) => {
        const delivery = { type: message?.type, handlers: 0, replies: [] };
        deliveries.push(delivery);
        const respond = (value) => { delivery.replies.push(value); resolve(value); };
        // Invoke every listener, just as runtime messaging does. A second
        // listener must not compete with the dedicated read-only responder.
        for (const listener of messageListeners)
          if (listener(message, from, respond) === true) delivery.handlers++;
        if (!delivery.handlers) resolve(undefined);
      }),
  };
}

async function connect(h) {
  await h.send({ type: "connect" });
  await settle(4);
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, true, "native pairing must succeed");
}

// The popup mints exactly this shape inside a trusted click: a nonce and its
// mint time, with no tab, frame or document claim. The worker binds the nonce
// to what the browser reports and consumes it once, within its TTL.
let gestureSerial = 0;
const freshNonce = () =>
  (++gestureSerial).toString(16).padStart(32, "f");
const gesture = (overrides = {}) => ({
  v: 2,
  scope: "credit_card",
  at: CLOCK,
  nonce: freshNonce(),
  ...overrides,
});

async function openPicker(h, userGesture = gesture()) {
  const state = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture,
  });
  assert.ok(state && state.checkoutPicker, "picker view expected: " + state?.status);
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
  });

const checkPicker = (h, picker, overrides = {}, sender) => h.send({
  type: "checkout-picker-current", nonce: picker.nonce,
  id: CARD_ID, revision: CARD_REV, ...overrides,
}, sender);

async function assertCheck(h, picker, valid, overrides = {}) {
  const before = h.sent.length, badges = h.badgeWrites.length;
  const status = (await h.send({ type: "state" })).status;
  const reply = await checkPicker(h, picker, overrides);
  await settle();
  assert.equal(json(reply), json({ type: "checkout-picker-current", valid }));
  const delivery = h.deliveries.filter((entry) => entry.type === "checkout-picker-current").at(-1);
  assert.equal(delivery.handlers, 1);
  assert.equal(delivery.replies.length, 1);
  assert.equal(h.sent.length, before, "verification sends no native requests");
  assert.equal(h.badgeWrites.length, badges, "verification changes no badge");
  assert.equal((await h.send({ type: "state" })).status, status);
  assert.equal(h.injections.length, 0);
}

test("read-only picker checks keep the original nonce, choice and deadline", async () => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);
  const expiry = picker.expiresAt;
  CLOCK += 4000;
  await assertCheck(h, picker, true);
  CLOCK += 4000;
  await assertCheck(h, picker, true);
  assert.equal(picker.expiresAt, expiry);
  const selected = await select(h, picker, choiceFor(picker, false));
  await settle();
  assert.equal(selected.checkoutStarted, true);
  assert.equal(h.sent.filter((request) => request.type === "fill-profile").length, 1);
  const replay = await select(h, picker, choiceFor(picker, false));
  assert.equal(replay.checkoutStarted, undefined);
  assert.equal(h.sent.filter((request) => request.type === "fill-profile").length, 1);
});

test("read-only checks never renew the original picker TTL", async () => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);
  CLOCK = picker.expiresAt - 4000;
  await assertCheck(h, picker, true);
  CLOCK = picker.expiresAt - 1;
  await assertCheck(h, picker, true);
  CLOCK = picker.expiresAt;
  await assertCheck(h, picker, false);
});

test("read-only checks reject malformed identity without consuming a live picker", async (t) => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);
  const requests = [
    { nonce: "invalid" }, { nonce: "d".repeat(32) },
    { id: "e".repeat(32) }, { revision: "f".repeat(64) },
    { extra: true }, { nonce: null }, { revision: {} },
  ];
  for (const [index, request] of requests.entries()) {
    await t.test("identity shape " + index, () => assertCheck(h, picker, false, request));
  }
  await assertCheck(h, picker, true);
});

test("only the exact popup sender can query the current picker", async () => {
  const h = harness();
  await connect(h);
  const picker = await openPicker(h);
  const before = h.sent.length;
  for (const sender of [
    { id: "other", url: "chrome-extension://fixed/popup.html" },
    { id: "fixed", url: "chrome-extension://fixed/options.html" },
    { id: "fixed", url: "chrome-extension://fixed/popup.html#route=x", tab: { id: 1 } },
    { id: "fixed", url: "https://shop.test/checkout", tab: { id: 1 } },
  ]) {
    assert.equal(await checkPicker(h, picker, {}, sender), undefined);
    const delivery = h.deliveries.at(-1);
    assert.equal(delivery.handlers, 0);
    assert.equal(delivery.replies.length, 0);
  }
  assert.equal(h.sent.length, before);
  await assertCheck(h, picker, true);
});

test("read-only checks compare the full active tab and frame document signature", async (t) => {
  const changes = [
    ["same-origin top replacement", (h) => h.setFrames([
      frame(0, "top-doc-2", TOP_ORIGIN, true), frame(3, FRAME_DOC, FRAME_ORIGIN, false),
    ])],
    ["same-origin child replacement", (h) => h.setFrames([
      frame(0, TOP_DOC, TOP_ORIGIN, true), frame(3, "sub-doc-2", FRAME_ORIGIN, false),
    ])],
    ["child origin changed", (h) => h.setFrames([
      frame(0, TOP_DOC, TOP_ORIGIN, true), frame(3, FRAME_DOC, "https://other.test", false),
    ])],
    ["top origin changed", (h) => h.setTabUrl("https://other.test/checkout")],
    ["active tab changed", (h) => h.setTab(2)],
    ["active window changed", (h) => h.setTab(1, 2)],
    ["missing frame", (h) => h.setFrames([frame(0, TOP_DOC, TOP_ORIGIN, true)])],
    ["invalid probe", (h) => h.setFrames([{
      ...frame(0, TOP_DOC, TOP_ORIGIN, true), result: { secure: false },
    }])],
  ];
  for (const [name, change] of changes) {
    await t.test(name, async () => {
      const h = harness();
      await connect(h);
      const picker = await openPicker(h);
      change(h);
      await assertCheck(h, picker, false);
    });
  }
});

test("read-only checks recheck picker ownership, lock and TTL after their probe await", async (t) => {
  for (const change of ["top", "child", "lock", "disconnect", "replacement picker", "expiry"]) {
    await t.test(change, async () => {
      const h = harness();
      await connect(h);
      const picker = await openPicker(h);
      let release;
      h.onCheckoutProbe(() => new Promise((resolve) => { release = resolve; }));
      const checking = checkPicker(h, picker);
      await settle();
      assert.equal(typeof release, "function");
      h.onCheckoutProbe(null);
      let replacement;
      if (change === "top") h.setFrames([
        frame(0, "top-doc-2", TOP_ORIGIN, true), frame(3, FRAME_DOC, FRAME_ORIGIN, false),
      ]);
      else if (change === "child") h.setFrames([
        frame(0, TOP_DOC, TOP_ORIGIN, true), frame(3, "sub-doc-2", FRAME_ORIGIN, false),
      ]);
      else if (change === "lock" || change === "disconnect") await h.send({ type: change });
      else if (change === "replacement picker") replacement = await openPicker(h);
      else CLOCK = picker.expiresAt;
      const before = h.sent.length, badges = h.badgeWrites.length;
      release();
      assert.equal((await checking).valid, false);
      await settle();
      const delivery = h.deliveries.filter((entry) => entry.type === "checkout-picker-current").at(-1);
      assert.equal(delivery.handlers, 1);
      assert.equal(delivery.replies.length, 1);
      assert.equal(h.sent.length, before);
      assert.equal(h.badgeWrites.length, badges);
      assert.equal(h.injections.length, 0);
      if (replacement) await assertCheck(h, replacement, true);
    });
  }
});

test("read-only checks refuse another pending native action before and after their probe await", async (t) => {
  for (const boundary of ["before query", "during probe"]) {
    await t.test(boundary, async () => {
      const h = harness({ loginCandidate: true });
      await connect(h);
      await h.send({ type: "match" });
      const picker = await openPicker(h);
      let checking, release;
      if (boundary === "during probe") {
        h.onCheckoutProbe(() => new Promise((resolve) => { release = resolve; }));
        checking = checkPicker(h, picker);
        await settle();
        h.onCheckoutProbe(null);
      }
      await h.send({ type: "fill", id: CARD_ID, revision: CARD_REV });
      await settle();
      assert.equal((await h.send({ type: "state" })).pending, true);
      const before = h.sent.length;
      if (checking) {
        release();
        assert.equal((await checking).valid, false);
      } else await assertCheck(h, picker, false);
      await settle();
      assert.equal(h.sent.length, before);
      assert.equal(h.injections.length, 0);
      h.finishFill();
      await settle();
    });
  }
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

test("a page replaced mid-enumeration yields no choice set", async () => {
  const h = harness();
  await connect(h);
  const gestureBefore = gesture();
  // The click's page is replaced while the bounded probe is running.
  h.onCheckoutProbe(() => {
    h.onCheckoutProbe(null);
    h.setFrames([
      frame(0, "top-doc-2", TOP_ORIGIN, true),
      frame(3, "sub-doc-9", FRAME_ORIGIN, false),
    ]);
  });
  const state = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: gestureBefore,
  });
  assert.equal(state.checkoutPicker, undefined);
  assert.equal(h.sent.filter((r) => r.type === "match-profiles").length, 0);
  assert.equal(h.injections.length, 0);
  // The nonce was spent by the click, so it cannot retry the new document.
  const again = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: gestureBefore,
  });
  assert.equal(again.checkoutPicker, undefined);
});

test("the popup's tab/document claims are not part of the proof", async () => {
  const h = harness();
  await connect(h);
  const state = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: gesture({ tabId: 1, frameId: 0, documentId: "forged-document" }),
  });
  assert.equal(
    state.checkoutPicker,
    undefined,
    "an extra claim is a different shape and is refused",
  );
  // A real nonce still binds to the browser-observed tab/document even if the
  // popup never names one.
  const picker = await openPicker(h);
  assert.equal(picker.topOrigin, TOP_ORIGIN);
});

test("a nonce is consumed once and expires within ten seconds", async () => {
  const h = harness();
  await connect(h);
  const used = gesture();
  await openPicker(h, used);
  const replay = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: { ...used },
  });
  assert.equal(replay.checkoutPicker, undefined, "a nonce is never reusable");

  // A nonce minted by a click more than ten seconds ago is stale.
  const late = gesture();
  CLOCK += 10_001;
  const stale = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: late,
  });
  assert.equal(stale.checkoutPicker, undefined);
  // Inside the window (minted now) the fresh nonce is still good.
  const ok = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: gesture(),
  });
  assert.ok(ok.checkoutPicker);
  CLOCK = 1_700_000_000_000;
});

test("a full nonce registry fails closed instead of evicting live nonces", async () => {
  const h = harness();
  await connect(h);
  const first = gesture();
  await openPicker(h, first);
  for (let index = 1; index < 64; index++) await openPicker(h);
  const refused = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: gesture(),
  });
  assert.equal(refused.checkoutPicker, undefined);
  // An earlier nonce is still consumed: the cap never made a replay valid.
  const replay = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
    userGesture: { ...first },
  });
  assert.equal(replay.checkoutPicker, undefined);
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

// Same-site HTTPS sibling origins: the browser-observed identity, not the
// popup, binds the opaque choice to the exact frame/document/origin.
const SIBLING_TOP_ORIGIN = "https://shop.example.test";
const SIBLING_FRAME_ORIGIN = "https://pay.example.test";
const SIBLING_TOP_DOC = "shop-top-doc";
const SIBLING_FRAME_DOC = "pay-frame-doc";
const SIBLING_FRAME_SPARE_DOC = "pay-frame-spare-doc";
const siblingHarness = (options = {}) =>
  harness({
    ...options,
    tabUrl: SIBLING_TOP_ORIGIN + "/checkout",
    frames: options.frames || [
      frame(0, SIBLING_TOP_DOC, SIBLING_TOP_ORIGIN, true),
      frame(7, SIBLING_FRAME_DOC, SIBLING_FRAME_ORIGIN, false),
      frame(8, SIBLING_FRAME_SPARE_DOC, SIBLING_FRAME_ORIGIN, false),
    ],
  });

test("a same-site sibling checkout child fills only its captured document", async () => {
  const h = siblingHarness();
  await connect(h);
  // A minted nonce alone is not a gesture: without one no picker exists.
  const ungestured = await h.send({
    type: "checkout-frames",
    id: CARD_ID,
    revision: CARD_REV,
  });
  assert.equal(ungestured.checkoutPicker, undefined);
  assert.equal(h.probes.length, 0, "no enumeration without a fresh gesture");

  const picker = await openPicker(h);
  assert.equal(picker.topOrigin, SIBLING_TOP_ORIGIN);
  assert.equal(keys(picker), '["candidates","expiresAt","nonce","topOrigin"]');
  assert.equal(
    json([...picker.candidates].map((entry) => entry.top)),
    json([true, false, false]),
  );
  const publicJSON = JSON.stringify(picker);
  for (const documentId of [
    SIBLING_TOP_DOC,
    SIBLING_FRAME_DOC,
    SIBLING_FRAME_SPARE_DOC,
  ])
    assert.equal(publicJSON.includes(documentId), false, "document ids stay private");

  const child = picker.candidates.find(
    (entry) => entry.top === false && entry.origin === SIBLING_FRAME_ORIGIN,
  );
  // Choosing the sibling child never exposes the other same-origin child.
  assert.equal(keys(child), '["choice","frameId","origin","top"]');
  assert.equal(h.sent.filter((r) => r.type === "match-profiles").length, 0);

  const state = await select(h, picker, child.choice);
  assert.equal(state.checkoutStarted, true);
  await settle();

  const match = h.sent.find((r) => r.type === "match-profiles");
  assert.ok(match, "native profile request expected");
  assert.equal(match.origin, SIBLING_FRAME_ORIGIN, "ordinary child origin");
  assert.equal(match.document_id, SIBLING_FRAME_DOC, "ordinary child document");
  assert.equal(match.profile_kind, "credit_card");
  assert.equal(
    json(match.checkout),
    json({
      top_origin: SIBLING_TOP_ORIGIN,
      top_document_id: SIBLING_TOP_DOC,
      frame_id: 7,
    }),
  );

  const fill = h.sent.find((r) => r.type === "fill-profile");
  assert.ok(fill, "native fill request expected");
  assert.equal(fill.origin, SIBLING_FRAME_ORIGIN);
  assert.equal(fill.document_id, SIBLING_FRAME_DOC);
  assert.equal(fill.item_id, CARD_ID);
  assert.equal(fill.revision, CARD_REV);
  assert.equal(json(fill.checkout), json(match.checkout));
  assert.equal(
    JSON.stringify(fill.checkout).includes(SIBLING_FRAME_DOC),
    false,
    "the child document id is not smuggled through the checkout object",
  );

  assert.equal(h.injections.length, 1);
  const injection = h.injections[0];
  assert.equal(injection.func, core.fillCheckoutCardDocument);
  assert.equal(keys(injection.target), '["documentIds","tabId"]');
  assert.equal(json(injection.target.documentIds), json([SIBLING_FRAME_DOC]));
  assert.equal(injection.target.allFrames, undefined);
  assert.equal(injection.target.frameIds, undefined);
  assert.equal(injection.args[0], SIBLING_FRAME_ORIGIN);
  assert.equal(injection.args[3], false);

  const final = await h.send({ type: "state" });
  assert.match(final.status, /已请求填充结账表单/);
});

test("a sibling child replaced after capture fails closed by document and origin", async () => {
  // The picked frame id is reused by a fresh document of the sibling origin;
  // the other same-origin child keeps its own identity throughout.
  for (const replacement of [
    { documentId: "pay-frame-doc-2", origin: SIBLING_FRAME_ORIGIN },
    { documentId: SIBLING_FRAME_DOC, origin: SIBLING_TOP_ORIGIN },
  ]) {
    const h = siblingHarness();
    await connect(h);
    const picker = await openPicker(h);
    const child = picker.candidates.find(
      (entry) => entry.frameId === 7 && entry.origin === SIBLING_FRAME_ORIGIN,
    );
    h.setFrames([
      frame(0, SIBLING_TOP_DOC, SIBLING_TOP_ORIGIN, true),
      frame(7, replacement.documentId, replacement.origin, false),
      frame(8, SIBLING_FRAME_SPARE_DOC, SIBLING_FRAME_ORIGIN, false),
    ]);
    const state = await select(h, picker, child.choice);
    assert.equal(state.checkoutStarted, true, "the choice itself was accepted");
    let final = null;
    for (let i = 0; i < 40; i++) {
      final = await h.send({ type: "state" });
      if (final.pending === false && /未完成|拒绝|已变化/.test(final.status)) break;
      await settle(2);
    }
    assert.ok(final && final.pending === false, "the intent must settle");
    assert.match(final.status, /未完成|拒绝|已变化/);
    // Nothing native and nothing injected reaches the replaced sibling page.
    assert.equal(h.sent.filter((r) => r.type === "match-profiles").length, 0);
    assert.equal(h.sent.filter((r) => r.type === "fill-profile").length, 0);
    assert.equal(h.injections.length, 0);
  }
});


const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");

const tick = () => new Promise((resolve) => setImmediate(resolve));
async function flush(rounds = 8) {
  for (let i = 0; i < rounds; i++) await tick();
}

const ID = "a".repeat(32);
const REV = "b".repeat(64);
const NONCE = "c".repeat(32);
const CHOICE_TOP = "1".repeat(32);
const CHOICE_FRAME = "2".repeat(32);
const TOP_ORIGIN = "https://shop.test";
const FRAME_ORIGIN = "https://pay.shop.test";

function element() {
  return {
    textContent: "",
    value: "",
    disabled: false,
    hidden: false,
    checked: false,
    className: "",
    type: "",
    dataset: {},
    style: {},
    attributes: {},
    children: [],
    listeners: new Map(),
    addEventListener(type, callback) {
      this.listeners.set(type, callback);
    },
    replaceChildren(...children) {
      this.children = children;
    },
    append(...children) {
      this.children.push(...children);
    },
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null;
    },
    removeAttribute(name) {
      delete this.attributes[name];
    },
  };
}

function cardDetail() {
  return {
    id: ID,
    revision: REV,
    category: "credit_card",
    title: "Visa",
    urls: [TOP_ORIGIN + "/"],
    tags: [],
    notes: "",
    fields: [
      {
        id: "cc-number",
        label: "卡号",
        type: "concealed",
        value: "•••• 4242",
        concealed: true,
        has_value: true,
        revealable: true,
      },
    ],
    credit_card: { type: "Visa", masked_number: "•••• 4242", has_cvv: true },
  };
}

function candidateRow() {
  return {
    id: ID,
    revision: REV,
    category: "credit_card",
    title: "Visa",
    urls: [TOP_ORIGIN + "/"],
    tags: [],
    favorite: false,
  };
}

function loginDetail() {
  return {
    id: ID,
    revision: REV,
    category: "login",
    title: "Shop account",
    username: "buyer",
    urls: [TOP_ORIGIN + "/"],
    tags: [],
    notes: "",
    fields: [
      {
        id: "password",
        label: "密码",
        type: "concealed",
        value: "••••••••",
        concealed: true,
        has_value: true,
        revealable: true,
      },
    ],
  };
}

function connectedState(overrides = {}) {
  return {
    connected: true,
    status: "ready",
    origin: TOP_ORIGIN,
    pending: false,
    saveBlocked: false,
    // The page's candidates are LOGIN/URL matches. A card that only the native
    // metadata read returned is never listed here, which is exactly the parent
    // checkout state: no row for the reviewed card exists.
    candidates: [],
    vaultItems: [candidateRow()],
    generatedHistory: [],
    generatorDefaults: { mode: "random", length: 24 },
    neverSaveOrigins: [],
    checkoutFramesSupported: true,
    ...overrides,
  };
}

function pickerView(overrides = {}) {
  return {
    nonce: NONCE,
    topOrigin: TOP_ORIGIN,
    expiresAt: Date.now() + 25000,
    candidates: [
      { choice: CHOICE_TOP, origin: TOP_ORIGIN, frameId: 0, top: true },
      { choice: CHOICE_FRAME, origin: FRAME_ORIGIN, frameId: 3, top: false },
    ],
    ...overrides,
  };
}

function harness() {
  const elements = new Map();
  const requests = [];
  const clipboardWrites = [];
  const documentListeners = new Map();
  let poll = null;
  let pagehide = null;
  const document = {
    body: { dataset: { vault: "1", view: "vault" } },
    visibilityState: "visible",
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector);
    },
    querySelectorAll(selector) {
      if (selector === "#filter-tabs [data-filter]")
        return [this.querySelector("#tab-passkeys")];
      return [];
    },
    createElement: element,
    createTextNode: (text) => ({ textContent: text }),
    addEventListener(type, callback) {
      const listeners = documentListeners.get(type) || [];
      listeners.push(callback);
      documentListeners.set(type, listeners);
    },
    dispatch(type, event = {}) {
      for (const callback of documentListeners.get(type) || [])
        callback({ type, target: this, isTrusted: true, ...event });
    },
  };
  document.querySelector("#tab-passkeys").dataset.filter = "passkeys";
  const context = {
    LocklarkCore: core,
    document,
    navigator: { clipboard: { writeText: async (value) => clipboardWrites.push(value) } },
    chrome: {
      runtime: {
        sendMessage(message) {
          return new Promise((resolve, reject) =>
            requests.push({ message, resolve, reject, taken: false }),
          );
        },
      },
    },
    crypto: webcrypto,
    Blob,
    URL,
    Uint8Array,
    TextEncoder,
    // Product timers must not keep the test process alive.
    setTimeout: (fn, ms) => {
      const handle = setTimeout(fn, ms);
      handle.unref?.();
      return handle;
    },
    clearTimeout,
    setInterval(callback) {
      poll = callback;
      return 0;
    },
    clearInterval: () => {},
    addEventListener(type, callback) {
      if (type === "pagehide") pagehide = callback;
    },
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8"),
    context,
  );
  const h = {
    context,
    requests,
    clipboardWrites,
    el: (selector) => document.querySelector(selector),
    poll: () => poll?.(),
    pagehide: () => pagehide?.(),
    // A real popup hide both changes visibilityState and fires the document
    // visibilitychange event every registered listener observes.
    hide: () => {
      document.visibilityState = "hidden";
      document.dispatch("visibilitychange");
    },
    take(type) {
      const call = requests.find((r) => !r.taken && r.message.type === type);
      assert.ok(call, "missing " + type + " request");
      call.taken = true;
      return call;
    },
    pending(type) {
      return requests.filter((r) => !r.taken && r.message.type === type);
    },
    sent(type) {
      return requests.filter((r) => r.message.type === type);
    },
    click(selector, event = { isTrusted: true }) {
      const target = typeof selector === "string" ? this.el(selector) : selector;
      const listener = target.listeners.get("click");
      assert.ok(listener, "missing click listener for " + selector);
      listener({ target, ...event });
    },
  };
  return h;
}

// Opens the credit-card detail of the current-site candidate.
async function openCard(h, overrides = {}, detail = cardDetail()) {
  h.take("state").resolve(connectedState(overrides));
  await flush();
  h.el("#vault-list").children[0].listeners.get("click")();
  const read = h.take("item-get");
  read.resolve({ detail, connected: true });
  await flush();
  return detail;
}

// Starts the picker and adopts the background's public view.
async function openPicker(h, view = pickerView()) {
  h.click("#detail-fill");
  const request = h.take("checkout-frames");
  assert.deepEqual(
    Object.keys(request.message).sort(),
    ["id", "revision", "type", "userGesture"],
    "checkout-frames carries only the reviewed card identity and gesture proof",
  );
  assert.equal(request.message.id, ID);
  assert.equal(request.message.revision, REV);
  request.resolve(connectedState({ checkoutPicker: view }));
  await flush();
  return view;
}

test("card action asks the background only after a trusted gesture", async () => {
  const h = harness();
  await openCard(h);
  assert.equal(h.el("#detail-fill").textContent, "选择结账表单并填充");

  // A synthetic click must never enumerate the page's frames.
  h.click("#detail-fill", { isTrusted: false });
  await flush();
  assert.equal(h.pending("checkout-frames").length, 0);
  assert.equal(h.sent("checkout-frames").length, 0);
  assert.equal(h.el("#checkout-picker").hidden !== false, true);

  h.click("#detail-fill");
  assert.equal(h.pending("checkout-frames").length, 1);
});

test("picker renders public origins and opaque keys without selecting one", async () => {
  const h = harness();
  await openCard(h);
  const view = await openPicker(h);

  const panel = h.el("#checkout-picker");
  assert.equal(panel.hidden, false);
  assert.equal(h.el("#checkout-current-page").textContent, "当前页面来源：" + TOP_ORIGIN);

  const choices = h.el("#checkout-choices").children;
  assert.equal(choices.length, 2);
  assert.deepEqual(
    choices.map((button) => button.dataset.choice),
    [CHOICE_TOP, CHOICE_FRAME],
  );
  // Only the public origin text is displayed; the document/frame ids the
  // background holds are never rendered or treated as authority.
  assert.equal(choices[0].textContent, TOP_ORIGIN + "（当前页面）");
  assert.equal(choices[1].textContent, FRAME_ORIGIN + "（页面中的表单框架）");
  for (const button of choices) {
    assert.equal(button.dataset.origin, undefined);
    assert.equal(button.dataset.frameId, undefined);
    assert.equal(button.textContent.includes("top-doc-1"), false);
    assert.equal(button.disabled, false);
  }
  // Explicit choice only: opening the list never asks to fill anything.
  assert.equal(h.sent("checkout-select").length, 0);
  assert.equal(
    h.el("#checkout-status").textContent.includes("不会自动选择"),
    true,
  );
  assert.ok(view.candidates.length === 2);
});

test("a trusted choice sends back only the opaque nonce and key", async () => {
  const h = harness();
  await openCard(h);
  await openPicker(h);

  const choice = h.el("#checkout-choices").children[1];
  // Untrusted activation of a choice is ignored.
  choice.listeners.get("click")({ target: choice, isTrusted: false });
  await flush();
  assert.equal(h.sent("checkout-select").length, 0);

  choice.listeners.get("click")({ target: choice, isTrusted: true });
  const select = h.take("checkout-select");
  assert.deepEqual(
    Object.keys(select.message).sort(),
    // The one-time card gesture was consumed when the list was requested;
    // selecting an opaque key never mints a second authorization.
    ["choice", "id", "nonce", "revision", "type"],
  );
  assert.equal(select.message.nonce, NONCE);
  assert.equal(select.message.choice, CHOICE_FRAME);
  assert.equal(select.message.id, ID);
  assert.equal(select.message.revision, REV);
  assert.equal("userGesture" in select.message, false);
  // No origin, frame id or document id is presented as an authority claim.
  assert.equal("origin" in select.message, false);
  assert.equal("frameId" in select.message, false);
  assert.equal("documentId" in select.message, false);
  assert.equal(JSON.stringify(select.message).includes(FRAME_ORIGIN), false);

  select.resolve(
    connectedState({
      checkoutStarted: true,
      status: "正在核对所选结账表单页面",
    }),
  );
  await flush();
  // checkoutStarted: true only acknowledges consumption. The popup must say the
  // page is being checked, not that native approval already exists.
  assert.equal(
    h.el("#checkout-status").textContent,
    "已提交所选表单，正在核对所选页面",
  );
  assert.equal(h.el("#status").textContent.includes("原生窗口"), false);
  // The background already consumed the choice, so hiding must not cancel the
  // legitimate native approval in flight.
  assert.equal(h.sent("checkout-cancel").length, 0);
  h.hide();
  await flush();
  h.pagehide();
  await flush();
  assert.equal(
    h.sent("checkout-cancel").length,
    0,
    "a used picker is never cancelled from the popup",
  );
});

test("cancelling drops the unused picker and closes the panel", async () => {
  const h = harness();
  await openCard(h);
  await openPicker(h);
  assert.equal(h.el("#checkout-picker").hidden, false);

  h.click("#checkout-cancel");
  await flush();
  const cancel = h.take("checkout-cancel");
  assert.deepEqual(Object.keys(cancel.message).sort(), ["nonce", "type"]);
  assert.equal(cancel.message.nonce, NONCE);
  assert.equal(h.el("#checkout-picker").hidden, true);
  assert.equal(h.el("#checkout-choices").children.length, 0);
});

test("hiding the popup drops an unused picker", async () => {
  const h = harness();
  await openCard(h);
  await openPicker(h);

  h.pagehide();
  await flush();
  const cancel = h.take("checkout-cancel");
  assert.deepEqual(Object.keys(cancel.message).sort(), ["nonce", "type"]);
  assert.equal(cancel.message.nonce, NONCE);
  assert.equal(h.el("#checkout-picker").hidden, true);
  assert.equal(h.el("#checkout-choices").children.length, 0);
});

test("visibilitychange cancels exactly the unused picker once", async () => {
  const h = harness();
  await openCard(h);
  await openPicker(h);

  h.hide();
  await flush();
  const cancels = h.sent("checkout-cancel");
  assert.equal(cancels.length, 1, "exactly one cancellation");
  assert.deepEqual(Object.keys(cancels[0].message).sort(), ["nonce", "type"]);
  assert.equal(cancels[0].message.nonce, NONCE, "its own picker nonce only");
  assert.equal(h.el("#checkout-picker").hidden, true);
  assert.equal(h.el("#checkout-choices").children.length, 0);
  assert.equal(h.sent("checkout-select").length, 0);

  // The picker is already gone: a second hide must not cancel anything else.
  h.hide();
  await flush();
  assert.equal(h.sent("checkout-cancel").length, 1);
});

test("a locally expired list closes without cancelling the background", async () => {
  const h = harness();
  await openCard(h);
  await openPicker(h, pickerView({ expiresAt: Date.now() + 40 }));
  assert.equal(h.el("#checkout-picker").hidden, false);

  await new Promise((resolve) => setTimeout(resolve, 120));
  await flush();
  assert.equal(h.el("#checkout-picker").hidden, true);
  assert.equal(h.el("#checkout-choices").children.length, 0);
  // The background owns the same TTL; expiry is not a user cancel.
  assert.equal(h.sent("checkout-cancel").length, 0);
  assert.equal(h.sent("checkout-select").length, 0);
});

test("an unusable frame list is refused instead of rendered", async () => {
  const h = harness();
  await openCard(h);
  h.click("#detail-fill");
  const request = h.take("checkout-frames");
  request.resolve(
    connectedState({
      checkoutPicker: pickerView({
        candidates: [
          { choice: CHOICE_TOP, origin: TOP_ORIGIN, frameId: 0, top: true },
          { choice: CHOICE_FRAME, origin: "http://pay.shop.test", frameId: 3, top: false },
        ],
      }),
    }),
  );
  await flush();
  assert.equal(h.el("#checkout-picker").hidden, true);
  assert.equal(h.el("#checkout-choices").children.length, 0);
  assert.equal(h.sent("checkout-select").length, 0);
});

// Regression: the parent checkout paints a reviewed card whose 32-hex id /
// 64-hex revision came from the native metadata read, while the page's
// candidate list only holds LOGIN/URL matches. The metadata action must be
// enabled from that public metadata alone.
test("a connected card outside the page candidates still enables the picker", async () => {
  const h = harness();
  const state = connectedState();
  assert.deepEqual(
    state.candidates.filter((row) => row.id === ID),
    [],
    "the regression state must not list the card as a page candidate",
  );
  h.take("state").resolve(state);
  await flush();
  h.el("#vault-list").children[0].listeners.get("click")();
  h.take("item-get").resolve({ detail: cardDetail(), connected: true });
  await flush();

  const fill = h.el("#detail-fill");
  assert.equal(fill.disabled, false, "a canonical card enables the picker action");
  assert.equal(fill.textContent, "选择结账表单并填充");
  assert.equal(fill.dataset.checkout, "1");
  // Enabling is inert: no frame is enumerated and no field is read.
  assert.equal(h.sent("checkout-frames").length, 0);
  assert.equal(h.sent("fill").length, 0);

  // Only a real user gesture starts metadata frame enumeration.
  fill.listeners.get("click")({ target: fill, isTrusted: true });
  const request = h.take("checkout-frames");
  assert.deepEqual(
    Object.keys(request.message).sort(),
    ["id", "revision", "type", "userGesture"],
    "the picker start carries only the reviewed card identity and gesture proof",
  );
  assert.equal(request.message.id, ID);
  assert.equal(request.message.revision, REV);
});

// The relaxed gate is card-checkout only: an ordinary fill still needs its own
// exact page candidate.
test("a normal login without a matching candidate stays disabled", async () => {
  const h = harness();
  await openCard(h, {}, loginDetail());

  const fill = h.el("#detail-fill");
  assert.equal(fill.disabled, true, "no exact candidate, no ordinary fill");
  assert.equal(fill.textContent, "填充到此页面");
  assert.equal(fill.dataset.checkout, "");
  // Even a forced activation never takes the checkout path.
  fill.listeners.get("click")({ target: fill, isTrusted: true });
  await flush();
  assert.equal(h.sent("checkout-frames").length, 0);
  assert.equal(h.pending("fill").length, 1, "it would only ask for a normal fill");
});

// The relaxed gate is host-support gated too: no native frame enumeration means
// no special path and no enabled button.
test("an unsupported host never enables the card picker path", async () => {
  const h = harness();
  await openCard(h, { checkoutFramesSupported: false });

  const fill = h.el("#detail-fill");
  assert.equal(fill.disabled, true, "unsupported host and no candidate stays disabled");
  assert.equal(fill.textContent, "填充到此页面");
  assert.equal(fill.dataset.checkout, "");
  fill.listeners.get("click")({ target: fill, isTrusted: true });
  await flush();
  assert.equal(h.sent("checkout-frames").length, 0);
  h.take("fill");
});

// A card identity that is not the canonical 32/64 hex pair gets no action.
test("a card without a canonical identity gets no metadata action", async () => {
  const h = harness();
  await openCard(h, {}, { ...cardDetail(), revision: "short" });

  const fill = h.el("#detail-fill");
  assert.equal(fill.disabled, true);
  assert.equal(fill.textContent, "填充到此页面");
  assert.equal(fill.dataset.checkout, "");
  assert.equal(h.sent("checkout-frames").length, 0);
});

test("a card only offers frame choice when the host reports support", async () => {
  const h = harness();
  await openCard(h, { checkoutFramesSupported: false });
  assert.equal(h.el("#detail-fill").textContent, "填充到此页面");
  h.click("#detail-fill");
  await flush();
  assert.equal(h.sent("checkout-frames").length, 0);
  h.take("fill");
});


function detailFillDiagnosticLog(h) {
  return h.context.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC_LOG__;
}

function assertDiagnosticShape(records, expectedPhases) {
  const plain = Array.from(records, (record) => ({ ...record }));
  assert.deepEqual(
    plain.map((record) => record.phase),
    expectedPhases,
  );
  for (const [index, record] of plain.entries()) {
    assert.deepEqual(
      Object.keys(record).sort(),
      index === 0
        ? ["isTrusted", "phase", "userActivation"]
        : ["phase"],
    );
    if (index === 0) {
      assert.equal(typeof record.isTrusted, "boolean");
      assert.equal(typeof record.userActivation, "boolean");
    }
  }
}

test("detail-fill diagnostics are disabled by default and do not branch", async () => {
  const h = harness();
  await openCard(h);
  assert.equal(detailFillDiagnosticLog(h), undefined);
  h.click("#detail-fill");
  assert.equal(detailFillDiagnosticLog(h), undefined);
  assert.equal(h.pending("checkout-frames").length, 1);
  h.take("checkout-frames").resolve(null);
  await flush();
});

test("detail-fill diagnostics record entry, early guard and refused gesture", async () => {
  const early = harness();
  early.context.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC__ = true;
  early.click("#detail-fill");
  assertDiagnosticShape(detailFillDiagnosticLog(early), [
    "handler-entry",
    "early-guard",
  ]);

  const refused = harness();
  await openCard(refused);
  refused.context.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC__ = true;
  refused.click("#detail-fill", { isTrusted: false });
  const records = detailFillDiagnosticLog(refused);
  assertDiagnosticShape(records, ["handler-entry", "gesture-refused"]);
  assert.equal(records[0].isTrusted, false);
  assert.equal(records[0].userActivation, false);
  assert.equal(refused.pending("checkout-frames").length, 0);
});

test("detail-fill diagnostics record reply and adopt phases", async () => {
  const nullReply = harness();
  await openCard(nullReply);
  nullReply.context.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC__ = true;
  nullReply.click("#detail-fill");
  assertDiagnosticShape(detailFillDiagnosticLog(nullReply), [
    "handler-entry",
    "request-sent",
  ]);
  nullReply.take("checkout-frames").resolve(null);
  await flush();
  assertDiagnosticShape(detailFillDiagnosticLog(nullReply), [
    "handler-entry",
    "request-sent",
    "reply-null",
    "adopt-refused",
  ]);

  const refusedAdopt = harness();
  await openCard(refusedAdopt);
  refusedAdopt.context.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC__ = true;
  refusedAdopt.click("#detail-fill");
  refusedAdopt
    .take("checkout-frames")
    .resolve(connectedState({ checkoutPicker: pickerView({ candidates: [] }) }));
  await flush();
  assertDiagnosticShape(detailFillDiagnosticLog(refusedAdopt), [
    "handler-entry",
    "request-sent",
    "reply-present",
    "adopt-refused",
  ]);

  const adopted = harness();
  await openCard(adopted);
  adopted.context.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC__ = true;
  adopted.click("#detail-fill");
  adopted
    .take("checkout-frames")
    .resolve(connectedState({ checkoutPicker: pickerView() }));
  await flush();
  const records = detailFillDiagnosticLog(adopted);
  assertDiagnosticShape(records, [
    "handler-entry",
    "request-sent",
    "reply-present",
    "adopted",
  ]);
  assert.equal(records[0].isTrusted, true);
  assert.equal(records[0].userActivation, false);
  assert.deepEqual(
    Array.from(records, (record) => Object.keys(record).sort()),
    [
      ["isTrusted", "phase", "userActivation"],
      ["phase"],
      ["phase"],
      ["phase"],
    ],
  );
});

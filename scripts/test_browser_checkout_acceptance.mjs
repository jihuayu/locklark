// Pure fixture and driver-order tests for the checkout acceptance module.
// These run without a browser, native host or private vault fixture.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import {
  checkoutTopHTML,
  checkoutCardHTML,
  checkoutFrameOrigin,
  checkoutSameOrigin,
  checkoutRouteCase,
  chooseChildOrigin,
  openCheckoutPicker,
  assertProgrammaticClickRefused,
  acceptCheckoutFrames,
  runLockDuringReviewJourney,
  runCrossSiteJourney,
  CHECKOUT_LOCKED,
} from "./browser_checkout_acceptance.mjs";

const TOP_ORIGIN = "https://login.locklark.test:8443";
const CARD_ORIGIN = TOP_ORIGIN;
const DEFAULT_CARD_ORIGIN = "https://checkout.locklark.test:8443";
const OTHER_ORIGIN = "https://checkout.other.test:8443";
const TOP_LABEL = TOP_ORIGIN + "（当前页面）";
const FRAME_SUFFIX = "（页面中的表单框架）";

function countMatches(text, pattern) {
  return (text.match(pattern) || []).length;
}

// A present, fully visible and blank form for both the top and child page.
function blankFormState() {
  const state = {
    formPresent: true,
    values: {},
    visible: {},
    tags: {},
    submits: 0,
  };
  for (const key of ["name", "number", "month", "year", "csc", "pin"]) {
    state.values[key] = "";
    state.visible[key] = true;
    state.tags[key] = key === "month" || key === "year" ? "SELECT" : "INPUT";
  }
  return state;
}

test("default checkout fixture keeps the original host and no sandbox", () => {
  const html = checkoutTopHTML(8443);
  assert.match(html, /src="https:\/\/checkout\.locklark\.test:8443\/card"/);
  assert.equal(countMatches(html, /sandbox=/g), 0);
  assert.match(html, /id="checkout-card-frame"/);
  assert.match(html, /id="top-card-pin"/);
  assert.match(checkoutCardHTML(), /id="card-pin"/);
});

test("cross-site and sandbox variants are allowlisted exactly", () => {
  const cross = checkoutTopHTML(8443, { host: "checkout.other.test" });
  assert.match(cross, /src="https:\/\/checkout\.other\.test:8443\/card"/);
  assert.doesNotMatch(cross, /checkout\.locklark\.test/);
  assert.equal(countMatches(cross, /sandbox=/g), 0);

  const sandbox = checkoutTopHTML(8443, { sandbox: true });
  assert.match(sandbox, /src="https:\/\/checkout\.locklark\.test:8443\/card"/);
  assert.equal(countMatches(sandbox, /sandbox="allow-scripts"/g), 1);
  assert.doesNotMatch(sandbox, /allow-same-origin/);

  const combined = checkoutTopHTML(8443, {
    host: "checkout.other.test",
    sandbox: true,
  });
  assert.match(combined, /src="https:\/\/checkout\.other\.test:8443\/card"/);
  assert.equal(countMatches(combined, /sandbox="allow-scripts"/g), 1);
  assert.doesNotMatch(combined, /allow-same-origin/);
});

test("variant options and ephemeral ports are strictly bounded", () => {
  for (const bad of ["evil.test", "", "checkout.locklark.test.evil"])
    assert.throws(
      () => checkoutTopHTML(8443, { host: bad }),
      /Unsupported checkout card host/,
    );
  assert.throws(
    () => checkoutTopHTML(8443, { src: "https://evil.test/card" }),
    /Unsupported checkout top variant option/,
  );
  assert.throws(
    () => checkoutTopHTML(8443, { sandbox: "allow-scripts" }),
    /Checkout sandbox variant must be boolean/,
  );
  for (const port of [0, "0", "abc", 70000, "", null])
    assert.throws(
      () => checkoutTopHTML(port),
      /Ephemeral checkout HTTPS port required/,
    );
  assert.throws(
    () => checkoutFrameOrigin("http://login.locklark.test:8443"),
    /Checkout top origin must be an ephemeral HTTPS origin/,
  );
  assert.equal(
    checkoutFrameOrigin(TOP_ORIGIN, { host: "checkout.other.test" }),
    OTHER_ORIGIN,
  );
});

test("same-origin variant embeds the exact top origin and port", () => {
  const html = checkoutTopHTML(8443, { host: "login.locklark.test" });
  assert.match(html, /src="https:\/\/login\.locklark\.test:8443\/card"/);
  assert.equal(
    countMatches(html, /https:\/\/login\.locklark\.test:8443/g),
    1,
    "only the embedded child may reference the top origin",
  );
  assert.doesNotMatch(html, /checkout\.(locklark|other)\.test/);
  assert.equal(countMatches(html, /sandbox=/g), 0);
  assert.throws(
    () => checkoutTopHTML(8443, { host: "login.locklark.test", sandbox: true }),
    /Same-origin checkout variant cannot be sandboxed/,
  );
  // The child is still the shared card document with its own PIN selector.
  assert.match(checkoutCardHTML(), /id="checkout-card-frame-form"/);
  assert.match(checkoutCardHTML(), /id="card-pin" name="card-pin"/);
});

test("same-origin frame origin must equal the exact allowlisted top origin", () => {
  assert.equal(checkoutSameOrigin(TOP_ORIGIN), TOP_ORIGIN);
  assert.equal(
    checkoutFrameOrigin(TOP_ORIGIN, { host: "login.locklark.test" }),
    TOP_ORIGIN,
  );
  for (const bad of [
    "https://login.locklark.test",
    "https://login.locklark.test:8443/checkout",
    "https://login.locklark.test:8443/",
    "http://login.locklark.test:8443",
    "https://checkout.locklark.test:8443",
    "https://evil.test:8443",
    "https://login.locklark.test.evil:8443",
  ])
    assert.throws(
      () => checkoutSameOrigin(bad),
      /Unsupported checkout card host|ephemeral HTTPS origin|exact top origin/,
    );
  assert.throws(() => checkoutSameOrigin(""), /ephemeral HTTPS origin/);
});

test("fixture routing accepts only the known checkout query cases", () => {
  assert.deepEqual(checkoutRouteCase("/checkout"), {
    kind: "checkout",
    options: {},
  });
  for (const suffix of ["?case=deny", "?case=stale"])
    assert.deepEqual(checkoutRouteCase("/checkout" + suffix), {
      kind: "checkout",
      options: {},
    });
  assert.deepEqual(checkoutRouteCase("/checkout?variant=cross-site"), {
    kind: "checkout",
    options: { host: "checkout.other.test" },
  });
  assert.deepEqual(checkoutRouteCase("/checkout?variant=sandbox"), {
    kind: "checkout",
    options: { sandbox: true },
  });
  assert.deepEqual(checkoutRouteCase("/checkout?variant=same-origin"), {
    kind: "checkout",
    options: { host: "login.locklark.test" },
  });
  // The fresh-page picker cancellation journey rides the allowed default
  // route (`/checkout?case=deny`); an invented "picker-cancel" variant is
  // still refused.
  // The route variant genuinely renders the same-origin child; a route that
  // returned an option the HTML ignored would silently test the wrong page.
  const route = checkoutRouteCase("/checkout?variant=same-origin");
  assert.match(
    checkoutTopHTML(8443, route.options),
    /src="https:\/\/login\.locklark\.test:8443\/card"/,
  );
  assert.match(
    checkoutTopHTML(8443, checkoutRouteCase("/checkout").options),
    /src="https:\/\/checkout\.locklark\.test:8443\/card"/,
  );
  assert.deepEqual(checkoutRouteCase("/card"), { kind: "card" });
  assert.deepEqual(checkoutRouteCase("/card?changed"), { kind: "card" });
  assert.deepEqual(checkoutRouteCase("/login"), { kind: "other" });
  for (const bad of [
    "/checkout?variant=hidden",
    "/checkout?variant=cross-site&variant=sandbox",
    "/checkout?variant=same-origin&variant=sandbox",
    "/checkout?case=approve",
    "/checkout?case=same-origin",
    "/checkout?variant=sandbox&case=deny",
    "/checkout?variant=picker-cancel&extra=1",
    "/checkout?variant=same-origin&extra=1",
    "/card?other",
    "/checkout?variant=cross-site&extra=1",
  ])
    assert.throws(() => checkoutRouteCase(bad), /checkout/i);
});

// `options.status` is the popup's bounded public status line read after the
// trusted fill click. `options.noPicker` models a popup that never shows the
// picker after that one click, while the cancel control still "exists" in the
// markup so a harness that skips the picker wait would press it.
function pickerPopup(labels, options = {}) {
  const state = { open: options.noPicker !== true };
  const count = (selector) =>
    selector.includes('button[data-action="checkout-select"]')
      ? state.open
        ? labels.length
        : 0
      : selector === "#checkout-cancel"
        ? 1
        : 0;
  return {
    clicked: [],
    canceled: 0,
    async click(selector) {
      this.clicked.push(selector);
      if (selector === "#checkout-cancel") {
        this.canceled++;
        if (options.refuseCancel !== true) state.open = false;
      }
    },
    async visible(selector) {
      if (selector === "#checkout-picker") return state.open;
      return count(selector) === 1;
    },
    async disabled(selector) {
      return selector === "#checkout-cancel" && options.cancelDisabled === true;
    },
    async text(selector) {
      if (selector === "#checkout-current-page")
        return "当前页面来源：" + TOP_ORIGIN;
      if (selector === "#checkout-status")
        return "请选择一个结账表单来源；不会自动选择，也不会自动提交";
      if (selector === "#status")
        return options.status === undefined ? "已连接" : options.status;
      const match = selector.match(/:nth-child\((\d+)\)$/);
      if (match) return labels[Number(match[1]) - 1];
      return "";
    },
    async count(selector) {
      return count(selector);
    },
  };
}

// The real driver throws its message when the predicate never becomes true;
// the stub does exactly one attempt so module failures stay observable.
// A fulfilled `false` keeps the exact message a real missing picker would
// report here; a bare `assert.equal(result, true)` would compare a Promise.
const eventually = async (check, message) => {
  const result = await check();
  assert.equal(result, true, message);
};

test("physical choice uses the exact public origin label, not an ordinal", async () => {
  const popup = pickerPopup([
    TOP_LABEL,
    CARD_ORIGIN + FRAME_SUFFIX,
    OTHER_ORIGIN + FRAME_SUFFIX,
  ]);
  assert.deepEqual(
    await chooseChildOrigin(popup, TOP_ORIGIN, OTHER_ORIGIN, eventually),
    { selected: true },
  );
  assert.deepEqual(popup.clicked, [
    "#detail-fill",
    '#checkout-choices button[data-action="checkout-select"]:nth-child(3)',
  ]);

  // Platform frame ordering is not part of the contract: the same exact
  // origin must still be selected when it moves to a different position.
  const reordered = pickerPopup([
    TOP_LABEL,
    OTHER_ORIGIN + FRAME_SUFFIX,
    CARD_ORIGIN + FRAME_SUFFIX,
  ]);
  assert.deepEqual(
    await chooseChildOrigin(reordered, TOP_ORIGIN, OTHER_ORIGIN, eventually),
    { selected: true },
  );
  assert.deepEqual(reordered.clicked, [
    "#detail-fill",
    '#checkout-choices button[data-action="checkout-select"]:nth-child(2)',
  ]);
});

test("same-origin child is chosen while the top origin is never chosen", async () => {
  // The same-origin variant lists the top origin twice: as "（当前页面）" and
  // as the embedded card frame. Only the exact frame label may be selected.
  const popup = pickerPopup([TOP_LABEL, TOP_ORIGIN + FRAME_SUFFIX]);
  assert.deepEqual(
    await chooseChildOrigin(popup, TOP_ORIGIN, TOP_ORIGIN, eventually),
    { selected: true },
  );
  assert.deepEqual(popup.clicked, [
    "#detail-fill",
    '#checkout-choices button[data-action="checkout-select"]:nth-child(2)',
  ]);
  assert.ok(!popup.clicked.includes("#checkout-cancel"));

  // Two same-origin frame candidates are ambiguous even though the exact top
  // origin is being chosen: the first duplicate is never picked, and the
  // refusal happens before a cancel control is even pressed.
  const sameOriginAmbiguous = pickerPopup([
    TOP_LABEL,
    TOP_ORIGIN + FRAME_SUFFIX,
    TOP_ORIGIN + FRAME_SUFFIX,
  ]);
  await assert.rejects(
    () =>
      chooseChildOrigin(
        sameOriginAmbiguous,
        TOP_ORIGIN,
        TOP_ORIGIN,
        eventually,
      ),
    /Expected exactly one explicit checkout child origin/,
  );
  assert.deepEqual(sameOriginAmbiguous.clicked, ["#detail-fill"]);

  // A duplicated label on any other origin stays ambiguous and is refused
  // before a cancel control is even pressed.
  const ambiguous = pickerPopup([
    TOP_LABEL,
    CARD_ORIGIN + FRAME_SUFFIX,
    CARD_ORIGIN + FRAME_SUFFIX,
  ]);
  await assert.rejects(
    () => chooseChildOrigin(ambiguous, TOP_ORIGIN, CARD_ORIGIN, eventually),
    /Expected exactly one explicit checkout child origin/,
  );
  assert.deepEqual(ambiguous.clicked, ["#detail-fill"]);
});

test("missing or duplicate public origins are never guessed or forced", async () => {
  // A missing origin is reported without a click; the journey that proves
  // exclusion cancels through the picker's own control.
  const missing = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX]);
  assert.deepEqual(
    await chooseChildOrigin(missing, TOP_ORIGIN, OTHER_ORIGIN, eventually),
    { selected: false },
  );
  assert.deepEqual(missing.clicked, ["#detail-fill"]);

  const duplicate = pickerPopup([
    TOP_LABEL,
    OTHER_ORIGIN + FRAME_SUFFIX,
    OTHER_ORIGIN + FRAME_SUFFIX,
  ]);
  await assert.rejects(
    () => chooseChildOrigin(duplicate, TOP_ORIGIN, OTHER_ORIGIN, eventually),
    /Expected exactly one explicit checkout child origin/,
  );
  assert.deepEqual(duplicate.clicked, ["#detail-fill"]);
});

test("the picker is requested by exactly one trusted fill click", async () => {
  const popup = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX]);
  await openCheckoutPicker(popup, eventually);
  assert.deepEqual(popup.clicked, ["#detail-fill"]);

  // The cancel path reuses the same request: no second request opens a
  // different picker before the user cancels the first one.
  const cancel = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX]);
  await chooseChildOrigin(cancel, TOP_ORIGIN, CARD_ORIGIN, eventually, {
    cancel: true,
  });
  assert.deepEqual(cancel.clicked, ["#detail-fill", "#checkout-cancel"]);
});

test("a picker that never appears is never reported as cancelled", async () => {
  // A fixed public status is carried on the same bounded reason so the red
  // stage stays diagnosable, while an unrecognised status is never echoed.
  for (const [line, shown] of [
    ["请选择要填充的结账表单来源；不会自动选择", "不会自动选择"],
    ["当前原生宿主或浏览器不支持选择结账表单", "不支持选择结账表单"],
    ["无法列出当前页面的结账表单", "无法列出当前页面的结账表单"],
    ["本次请求被拒绝", "other (unrecognised public status)"],
    [undefined, "other (unrecognised public status)"],
    ["", "unavailable"],
  ]) {
    await assert.rejects(
      () =>
        chooseChildOrigin(
          pickerPopup([TOP_LABEL], { status: line, noPicker: true }),
          TOP_ORIGIN,
          CARD_ORIGIN,
          eventually,
          { cancel: true },
        ),
      new RegExp(
        "^Error: Checkout origin picker missing: popup status " +
          shown.replace(/[()]/g, "\\$&") +
          "$",
      ),
    );
  }

  // The unreadable popup status must not hide the bounded reason either.
  const unreadable = pickerPopup([TOP_LABEL], { noPicker: true });
  unreadable.text = async (selector) => {
    if (selector === "#status") throw Error("Popup inspection failed");
    return "";
  };
  await assert.rejects(
    () => openCheckoutPicker(unreadable, eventually),
    /^Error: Checkout origin picker missing: popup status unavailable$/,
  );
  // No cancel control may be pressed when the picker never appeared.
  assert.deepEqual(unreadable.clicked, ["#detail-fill"]);
});

test("picker cancellation presses only the real cancel control", async () => {
  const popup = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX]);
  assert.deepEqual(
    await chooseChildOrigin(popup, TOP_ORIGIN, CARD_ORIGIN, eventually, {
      cancel: true,
    }),
    { selected: false },
  );
  assert.deepEqual(popup.clicked, ["#detail-fill", "#checkout-cancel"]);
  assert.ok(
    popup.clicked.every(
      (selector) => !selector.includes('data-action="checkout-select"'),
    ),
  );

  // No candidate at all (e.g. a refused page): cancel is still the only
  // action that may close the picker.
  const excluded = pickerPopup([TOP_LABEL]);
  assert.deepEqual(
    await chooseChildOrigin(excluded, TOP_ORIGIN, OTHER_ORIGIN, eventually, {
      cancel: true,
    }),
    { selected: false },
  );
  assert.deepEqual(excluded.clicked, ["#detail-fill", "#checkout-cancel"]);

  // A picker that does not close fails instead of reporting a cancel.
  const stuck = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX], {
    refuseCancel: true,
  });
  await assert.rejects(
    () =>
      chooseChildOrigin(stuck, TOP_ORIGIN, CARD_ORIGIN, eventually, {
        cancel: true,
      }),
    /Checkout picker cancel did not close/,
  );

  const disabled = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX], {
    cancelDisabled: true,
  });
  await assert.rejects(
    () =>
      chooseChildOrigin(disabled, TOP_ORIGIN, CARD_ORIGIN, eventually, {
        cancel: true,
      }),
    /Checkout picker cancel control unavailable/,
  );
  assert.deepEqual(disabled.clicked, ["#detail-fill"]);
});

// Models the real popup for the programmatic-click refusal. `evaluate` runs
// the bounded expression in the popup and records it; `click` models only the
// physical Input.dispatch path. A DOM click is received as untrusted and
// refused. Only a received `false` counts as that proof; a missing receipt is
// a failure, never a silent pass.
function programmaticPopup() {
  const state = {
    pickerOpen: false,
    status: "已连接",
    trusted: null,
    evaluated: [],
    clicked: [],
  };
  return {
    state,
    async evaluate(expression) {
      state.evaluated.push(expression);
      state.trusted = false;
      return false;
    },
    async click(selector) {
      state.clicked.push(selector);
      state.pickerOpen = true;
    },
    async visible(selector) {
      if (selector === "#checkout-picker") return state.pickerOpen;
      return selector === "#checkout-cancel";
    },
    async disabled() {
      return false;
    },
    async text(selector) {
      return selector === "#status" ? state.status : "";
    },
    async count() {
      // Candidate markup belongs to the picker panel and is rendered only
      // while that panel is open.
      return state.pickerOpen ? 1 : 0;
    },
  };
}

test("programmatic fill click must be received untrusted and refused", async () => {
  const popup = programmaticPopup();
  await assertProgrammaticClickRefused(popup, eventually);
  // Exactly one DOM click, evaluated in the popup and not through the physical
  // input path; the physical "#detail-fill" click is left to the caller.
  assert.equal(popup.state.evaluated.length, 1);
  assert.match(popup.state.evaluated[0], /#detail-fill/);
  assert.match(popup.state.evaluated[0], /\.click\(\)/);
  assert.match(popup.state.evaluated[0], /isTrusted/);
  assert.deepEqual(popup.state.clicked, []);
  assert.equal(popup.state.trusted, false);
  assert.equal(popup.state.pickerOpen, false);
  assert.equal(popup.state.status, "已连接");
});

test("a popup that acts on a programmatic click is never reported as refusing it", async () => {
  // A DOM click that is somehow received as trusted yields no evidence of
  // refusal, and no physical click is made on its behalf.
  const trusted = programmaticPopup();
  trusted.evaluate = async (expression) => {
    trusted.state.evaluated.push(expression);
    trusted.state.trusted = true;
    return true;
  };
  await assert.rejects(
    () => assertProgrammaticClickRefused(trusted, eventually),
    /Programmatic checkout fill click must be received as untrusted/,
  );
  assert.deepEqual(trusted.state.clicked, []);

  // A DOM click that is refused yet still shows the picker is an exposure
  // even though the received click was untrusted.
  const accepted = programmaticPopup();
  accepted.evaluate = async (expression) => {
    accepted.state.evaluated.push(expression);
    accepted.state.trusted = false;
    accepted.state.pickerOpen = true;
    return false;
  };
  await assert.rejects(
    () => assertProgrammaticClickRefused(accepted, eventually),
    /Programmatic checkout fill click opened the picker/,
  );
  assert.deepEqual(accepted.state.clicked, []);

  // A popup that reports the click as untrusted yet still renders a candidate
  // is caught by the panel check as well, even if the panel is hidden.
  const shown = programmaticPopup();
  shown.visible = async (selector) => selector !== "#detail-fill";
  shown.count = async () => 1;
  await assert.rejects(
    () => assertProgrammaticClickRefused(shown, eventually),
    /Checkout picker must be absent before the programmatic click/,
  );

  // A refused click that still moves a bounded public status line is a
  // failure: the unchanged status is the proof no frame listing started.
  const noisy = programmaticPopup();
  noisy.evaluate = async (expression) => {
    noisy.state.evaluated.push(expression);
    noisy.state.status =
      "请选择一个结账表单来源；不会自动选择，也不会自动提交";
    return false;
  };
  await assert.rejects(
    () => assertProgrammaticClickRefused(noisy, eventually),
    /Programmatic checkout fill click changed the popup status/,
  );
});

test("a picker already open cannot be proven refused programmatically", async () => {
  const popup = programmaticPopup();
  popup.state.pickerOpen = true;
  await assert.rejects(
    () => assertProgrammaticClickRefused(popup, eventually),
    /Checkout picker must be absent before the programmatic click/,
  );
  assert.equal(popup.state.evaluated.length, 0);
});

test("the real popup adapter exposes CDP evaluation", () => {
  // The picker-cancel journey dispatches a DOM `.click()` through the popup's
  // own CDP Runtime. Dropping that adapter must fail here instead of silently
  // skipping the real-browser proof. The journey sends no physical Escape:
  // closing the action popup would disconnect the same CDP target.
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /^\s*evaluate,$/m);
  assert.doesNotMatch(source, /pressEscape/);
});

test("native absence probes preserve popup focus across the journey", () => {
  // Default callers ask for the plain inspect request, which raises and
  // focuses the native window. Every popup-stage probe must instead use the
  // X11 helper's documented `preserve_focus` + `title_prefix` form: focusing
  // the native window closes the Chromium action popup that is still to be
  // clicked, which is exactly the "Popup control must be available" failure.
  const source = readFileSync(
    new URL("./browser_checkout_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(source, /assertNoNative(Approval|ProfileReview)\(input\)/);
  // Every native absence probe the picker-cancel journey makes uses the
  // focus-preserving form while its popup stays open.
  const journey = source.slice(
    source.indexOf("async function runPickerCancelJourney"),
    source.indexOf("export async function acceptCheckoutFrames"),
  );
  assert.equal(
    countMatches(journey, /assertNoNative(?:Approval|ProfileReview)\(input, POPUP_OPEN\)/g),
    countMatches(journey, /assertNoNative(?:Approval|ProfileReview)\(/g),
  );
  assert.ok(countMatches(journey, /assertNoNative(?:Approval|ProfileReview)\(/g) >= 6);
  assert.match(
    source,
    /title_prefix: NATIVE_TITLE_PREFIX,\n\s+preserve_focus: true,\n\s+inspect: true,/,
  );
  assert.match(source, /const NATIVE_TITLE_PREFIX = "Locklark";/);
  // The journey never sends a physical Escape to its popup: closing the action
  // popup would leave the held CDP object disconnected.
  assert.doesNotMatch(journey, /pressEscape|checkout-picker-cancel:withdraw/);
});

test("native absence probes fail closed on an unavailable snapshot", async () => {
  // A failed native probe observed no native UI, so it must fail the journey
  // instead of reading as "both native decisions absent". The default journey
  // probes its first popup before reading any card detail or picker state, so
  // the popup is a bare object: any progress past the probe fails on a missing
  // popup method, never inside the probe.
  const fixture = {
    CardID: "0".repeat(32),
    CardRevision: "a".repeat(64),
    CardTitle: "Synthetic checkout card",
    CardNumber: "4111111111111111",
    CardHolder: "Synthetic Holder",
    CardVerification: "123",
    CardExpiry: "2030-01",
    CardPIN: "1234",
  };
  const visibleFormState = blankFormState;
  const probes = [];
  const driver = (probe) => ({
    page: {
      url: () => TOP_ORIGIN + "/checkout",
      goto: async () => assert.fail("journey navigated past the probe"),
      frames: () => [
        {
          url: () => DEFAULT_CARD_ORIGIN + "/card",
          evaluate: async () => visibleFormState(),
        },
      ],
      evaluate: async () => visibleFormState(),
    },
    origin: TOP_ORIGIN,
    fixture,
    input: (_actions, _native, options) => {
      probes.push(options);
      return probe();
    },
    openPopup: async () => ({}),
    phase: () => {},
    eventually: async (check, message) => {
      if (!(await check())) throw Error(message);
    },
  });

  // A thrown probe error propagates unchanged: it is never swallowed into a
  // null snapshot and then read as "both controls absent".
  const failed = Error(
    "Native acceptance input failed [native-window-unavailable]",
  );
  await assert.rejects(
    () =>
      acceptCheckoutFrames(
        driver(() => {
          throw failed;
        }),
      ),
    (error) => {
      assert.deepEqual(probes, [
        {
          title_prefix: "Locklark",
          preserve_focus: true,
          inspect: true,
        },
      ]);
      return error === failed;
    },
  );

  // A probe that succeeds without a control object is an unavailable
  // snapshot and fails closed instead of marking both controls absent.
  const unavailable = ["x", null, {}, [], { controls: null }, { controls: [] }];
  for (const result of unavailable) {
    await assert.rejects(
      () => acceptCheckoutFrames(driver(() => result)),
      { message: "Native control snapshot unavailable" },
    );
  }
});

// Source of one journey, bounded by the next journey's leading comment block.
// The boundary is searched from this journey's own end, so it can never match
// the declaration it is looking for.
function journeySource(name) {
  const source = readFileSync(
    new URL("./browser_checkout_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.match(name, /^async function \w+$/, "journey name");
  const start = source.indexOf(name);
  assert.ok(start >= 0, name + " missing");
  const tail = source.slice(start + name.length);
  // Each journey ends right before the next journey's leading comment.
  const ends = [
    "\n// `sandbox=\"allow-scripts\"`",
    "\n// The valid child was selected and its native approval was visible.",
    "\n// The fixed public statuses that only a finished native review can set.",
    "\n// The valid child was explicitly chosen and its real cross-origin native",
    "\n// The same-origin variant embeds its child on the exact top origin",
    "\n// A fresh same-site cross-origin checkout page",
    "\n// The last journey, because it locks the session.",
  ]
    .map((marker) => tail.indexOf(marker))
    .filter((index) => index > 0);
  assert.ok(ends.length > 0, "Journey source end not found");
  return source.slice(start, start + name.length + Math.min(...ends));
}

test("navigating the top tab never acts on the stale native approval", () => {
  const journey = journeySource("async function runDenyNavigationJourney");
  // The stale review is only observed: no native action of any kind is sent
  // while it is visible, before, during or after the top navigation. The one
  // native request is the explicit selection wait that surfaces the review.
  assert.doesNotMatch(journey, /click_label|key:/);
  assert.equal(countMatches(journey, /wait_label/g), 1);
  assert.match(
    journey,
    /input\(\[\{ wait_label: CHECKOUT_APPROVE_LABEL \}\]\)/,
  );
  // Only the top tab navigates, to a fresh default-route document; the child
  // frame is of that new document and is never navigated by this journey.
  assert.equal(countMatches(journey, /page\.goto\(/g), 2);
  assert.match(journey, /page\.goto\(topOrigin \+ "\/checkout\?case=deny"\)/);
  assert.doesNotMatch(journey, /frame\.goto|goto\(frameOrigin/);
  // The popup-preserving probe only guards the reopened, live popup.
  const reopen = journey.indexOf("const reopened = await openPopup();");
  assert.ok(reopen > 0);
  assert.doesNotMatch(journey.slice(0, reopen), /POPUP_OPEN/);
  assert.match(
    journey.slice(reopen),
    /assertNoNativeApproval\(input, POPUP_OPEN\)/,
  );
});

test("fixed PASS summary names the top-navigation and pending-review lock", () => {
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /checkout same-origin child approval \(profile review\) and picker cancellation, cross-origin approval\/refusal, cross-site, opaque sandbox, changed-document and top-navigation rejection, and lock while cross-origin card review is pending`/,
  );
});

test("a stale approval that stays available fails instead of being read as absent", () => {
  // The bounded wait proves the review finished before the popup is reopened:
  // any still-available approve or refuse control fails the check with a
  // public control-name reason, and the popup open comes only after the wait.
  const journey = journeySource("async function runDenyNavigationJourney");
  const wait = journey.indexOf(
    "Native checkout review did not finish after top navigation",
  );
  const reopen = journey.indexOf("const reopened = await openPopup();");
  assert.ok(wait > 0 && reopen > wait);
  assert.match(
    journey.slice(0, reopen),
    /available\.length === 0,\s*"Native checkout review still available after top navigation: "/,
  );
  // Both decisions are part of the requirement, each from a default probe.
  assert.equal(
    countMatches(journey.slice(0, reopen), /nativeControls\(input\)/g),
    2,
  );
  assert.doesNotMatch(journey.slice(0, reopen), /POPUP_OPEN/);
});

test("checkout choice options are strictly bounded", async () => {
  const popup = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX]);
  await assert.rejects(
    () => chooseChildOrigin(popup, TOP_ORIGIN, CARD_ORIGIN, eventually, null),
    /Checkout choice options must be an object/,
  );
  await assert.rejects(
    () =>
      chooseChildOrigin(popup, TOP_ORIGIN, CARD_ORIGIN, eventually, {
        force: true,
      }),
    /Unsupported checkout choice option/,
  );
  await assert.rejects(
    () =>
      chooseChildOrigin(popup, TOP_ORIGIN, CARD_ORIGIN, eventually, {
        cancel: "yes",
      }),
    /Checkout cancel must be boolean/,
  );
  assert.deepEqual(popup.clicked, []);
});

test("lock during a pending cross-origin review is ordered, clicked physically and never decided", async () => {
  const fixture = {
    CardID: "0".repeat(32),
    CardRevision: "a".repeat(64),
    CardTitle: "Synthetic checkout card",
    CardNumber: "4111111111111111",
    CardHolder: "Synthetic Holder",
    CardVerification: "123",
    CardExpiry: "2030-01",
    CardPIN: "1234",
  };
  const cardRow = '#vault-list [data-item-id="' + fixture.CardID + '"]';
  let locked = false;
  const log = [];
  const page = {
    url: () => (locked ? TOP_ORIGIN + "/" : TOP_ORIGIN + "/checkout"),
    goto: async (url) => log.push(["goto", url]),
    // The lock journey derives its child from the top origin: the default
    // same-site card frame on the server's own HTTPS port.
    frames: () => [
      {
        url: () => DEFAULT_CARD_ORIGIN + "/card",
        evaluate: async () => blankFormState(),
      },
    ],
    // The page-side form reader needs a DOM; returning a blank top form keeps
    // the ordering test focused on native actions and popup clicks.
    evaluate: async () => blankFormState(),
  };
  const reviewControls = () => {
    const controls = {};
    for (const label of [
      "批准本次跨源银行卡填充",
      "拒绝本次跨源银行卡填充",
      "立即锁定",
    ])
      controls[label] = { present: true, enabled: !locked, showing: !locked };
    controls["解锁"] = { present: locked, enabled: locked, showing: locked };
    return controls;
  };
  const input = (actions, native, inspect) => {
    const options = typeof inspect === "object" ? inspect : { inspect };
    // Native label actions and the inspected probe both target the native
    // window; only the harness key/pointer helper may pass a false flag.
    assert.equal(actions.length > 0 || options.inspect === true, true);
    assert.equal(options.preserve_focus, undefined);
    log.push(["native", actions, options]);
    for (const action of actions) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(action, "click_label") ||
          Object.prototype.hasOwnProperty.call(action, "wait_label") ||
          Object.keys(action).length === 0,
        "only native label actions or read-only probes",
      );
      if (action.click_label === "立即锁定") locked = true;
      assert.notEqual(action.click_label, "批准本次跨源银行卡填充");
      assert.notEqual(action.click_label, "拒绝本次跨源银行卡填充");
      assert.notEqual(action.click_label, "解锁");
    }
    return actions.length === 0 ? { controls: reviewControls() } : {};
  };
  const labels = [TOP_LABEL, DEFAULT_CARD_ORIGIN + FRAME_SUFFIX];
  // The popup is the reviewed picker popup: every listed row is a candidate
  // and its cancel row is present.
  const popup = {
    clicked: [],
    async disabled(selector) {
      if (selector === "#refresh") return locked;
      return false;
    },
    async count(selector) {
      if (selector === '#filter-tabs [data-filter="credit_card"]') return 1;
      if (selector === cardRow) return 1;
      // Like the real adapter, an unmatched row reports 0 instead of null.
      if (selector.startsWith('#checkout-choices button[data-action="checkout-select"]'))
        return labels.length;
      if (selector === "#checkout-cancel") return 1;
      return 0;
    },
    async click(selector) {
      this.clicked.push(selector);
      assert.equal(locked, false, "locked popup must not be clicked");
      log.push(["popup", selector]);
    },
    async attribute(selector, name) {
      if (name === "data-item-revision") return fixture.CardRevision;
      if (name === "data-category") return "credit_card";
      if (name === "data-checkout") return "1";
      return null;
    },
    async text(selector) {
      if (selector === "#detail-title") return fixture.CardTitle;
      if (selector === "#detail-fill") return "选择结账表单并填充";
      if (selector === "#status")
        return locked ? "原生金库已锁定，请重新连接并配对" : "已连接";
      if (selector === "#checkout-current-page")
        return "当前页面来源：" + TOP_ORIGIN;
      if (selector === "#checkout-status") return "不会自动选择";
      const match = selector.match(/:nth-child\((\d+)\)$/);
      if (match) return labels[Number(match[1]) - 1];
      return "";
    },
    // The fill control is a visible detail action, not a picker candidate.
    async visible(selector) {
      if (selector === "#checkout-picker") return true;
      return selector === "#checkout-cancel" || selector === "#detail-fill";
    },
  };
  const phases = [];
  const opens = [];
  const driver = {
    page,
    input,
    phase: (value) => phases.push(value),
    openPopup: async () => {
      opens.push(phases.length);
      return popup;
    },
    eventually: async (check, message) => {
      if (!(await check())) throw Error(message);
    },
  };
  await runLockDuringReviewJourney(driver, fixture, TOP_ORIGIN);

  // Fresh exact /checkout first; popup opened and picker used afterwards.
  assert.deepEqual(log[0], ["goto", TOP_ORIGIN + "/checkout"]);
  assert.deepEqual(phases, [
    "checkout-lock-review:navigation",
    "checkout-lock-review:native-review",
    "checkout-lock-review:lock",
    "checkout-lock-review:status",
  ]);
  // The initial popup opens before any native review, the reopened one only
  // after the lock.
  assert.deepEqual(opens, [1, 4]);
  // The exact child origin is chosen, never the top origin. The helper's
  // result object itself is asserted by the picker-cancel test below, whose
  // opening check is the helper's own `visible("#checkout-picker")` read.
  assert.ok(
    log.some(
      ([kind, value]) =>
        kind === "popup" &&
        value === '#checkout-choices button[data-action="checkout-select"]:nth-child(2)',
    ),
  );
  // Native grammar: review wait, read-only review probes, then exactly one
  // physical lock followed by the unlock-screen wait. Nothing else is clicked,
  // and the native window is never focused again while a popup is pending.
  const nativeCalls = log.filter(([kind]) => kind === "native");
  assert.deepEqual(
    nativeCalls.map(([, actions]) => actions),
    [
      [{ wait_label: "批准本次跨源银行卡填充" }],
      [],
      [],
      [{ click_label: "立即锁定" }, { wait_label: "解锁" }],
      [],
    ],
  );
  const lock = nativeCalls[3][1];
  assert.deepEqual(lock, [
    { click_label: "立即锁定" },
    { wait_label: "解锁" },
  ]);
});


test("acceptCheckoutFrames returns an explicit locked result only after the lock journey", () => {
  const source = readFileSync(
    new URL("./browser_checkout_acceptance.mjs", import.meta.url),
    "utf8",
  );
  const accept = source.slice(source.indexOf("export async function acceptCheckoutFrames"));
  const lock = accept.indexOf("await runLockDuringReviewJourney(driver, card, topOrigin);");
  const result = accept.indexOf("return CHECKOUT_LOCKED;");
  assert.ok(lock > 0 && result > lock);
  for (const name of [
    "runDefaultJourneys",
    "runCrossSiteJourney",
    "runSandboxJourney",
    "runStaleDocumentJourney",
    "runDenyNavigationJourney",
    "runSameOriginJourney",
    "runPickerCancelJourney",
  ])
    assert.ok(accept.indexOf("await " + name + "(") < lock, name);
  assert.deepEqual(CHECKOUT_LOCKED, { locked: true });
  // The harness skips its final popup disconnect only for that result.
  const harness = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    harness,
    /const checkout = await acceptCheckoutFrames\([\s\S]*?if \(checkout\?\.locked !== true\) \{[\s\S]*?popup\.click\("#disconnect"\)/,
  );
});

test("the cross-site branch reads the boolean and never the result object", () => {
  // `chooseChildOrigin` always resolves to an object; only `selected` carries
  // the outcome. Source contract of the journey that drives the real helper.
  const journey = journeySource("async function runCrossSiteJourney");
  // Exactly one branch decision, and it compares the boolean field.
  assert.match(journey, /if \(choice\.selected === false\) \{/);
  assert.equal(countMatches(journey, /\bif \(/g), 1);
  // A returned object, a missing result or a non-boolean is refused instead of
  // being read as a selection.
  assert.match(
    journey,
    /typeof choice\.selected === "boolean",\s*"Checkout cross-site choice must report a boolean selection"/,
  );
  // Object truthiness in any form would claim a native review for an
  // excluded child. None of these may appear as a branch or value test.
  for (const pattern of [
    /\bif \(!choice\)/,
    /\bif \(!selected\)/,
    /\bif \(choice\)/,
    /\bif \(selected\)/,
    /\?\.selected\b/,
    /\bchoice\.selected\s*(?:\|\||&&|\?\?)/,
    /Boolean\(\s*choice/,
    /!!\s*choice/,
    /\bnot\s+selected\b/,
  ])
    assert.doesNotMatch(journey, pattern);
  assert.equal(countMatches(journey, /\.selected\b/g), 2);

  // Each branch claims only its own marker; the common refusal is emitted once
  // after the branch that ran passed every assertion.
  const excluded = journey.indexOf('phase("checkout-cross-site:excluded");');
  const review = journey.indexOf('phase("checkout-cross-site:native-review");');
  const refused = journey.indexOf('phase("checkout-cross-site:refused");');
  assert.ok(excluded > 0 && review > excluded);
  assert.ok(refused > review);
  for (const marker of [
    "navigation",
    "picker",
    "excluded",
    "native-review",
    "refused",
  ])
    assert.equal(
      countMatches(
        journey,
        new RegExp(`checkout-cross-site:${marker}"`, "g"),
      ),
      1,
      marker,
    );
  // The branch bodies close before the common stage and neither exits early,
  // so a branch that passed can never skip the common refusal proof.
  const close = journey.indexOf("  }\n  // Both outcomes must prove");
  assert.ok(close > review && close < refused);
  for (const line of journey.slice(excluded, close + 1).split("\n"))
    assert.ok(
      !/^ {2,4}return\b/.test(line),
      "a cross-site branch must not exit before the common refusal stage",
    );

  // Both outcomes keep the privacy proofs: no native approval and no value.
  const branch = journey.slice(excluded, close + 1);
  assert.match(branch, /Excluded checkout origin must not be auto-selected/);
  assert.match(branch, /await popup\.click\("#checkout-cancel"\)/);
  assert.match(branch, /"Cross-site checkout refusal did not finish"/);
  assert.match(branch, /"Excluded cross-site checkout wrote a value"/);
  assert.match(branch, /"Cross-site checkout received a value without approval"/);
  assert.ok(countMatches(branch, /assertNoNativeApproval\(input, POPUP_OPEN\)/g) >= 2);
  assert.ok(countMatches(branch, /assertBothBlank\(/g) >= 2);
  assert.doesNotMatch(journey, /input\(\[/);
});

// Executes the real cross-site journey through its driver interface. `page`,
// `input` and `openPopup` are the existing stubs above; only the cross-site
// outcomes the browser chooses between are modelled here.
function crossSiteDriver(options = {}) {
  const fixture = {
    CardID: "0".repeat(32),
    CardRevision: "a".repeat(64),
    CardTitle: "Synthetic checkout card",
    CardNumber: "4111111111111111",
    CardHolder: "Synthetic Holder",
    CardVerification: "123",
    CardExpiry: "2030-01",
    CardPIN: "1234",
  };
  const cardRow = '#vault-list [data-item-id="' + fixture.CardID + '"]';
  const state = {
    // A listed cross-site child means the helper selects it (selected:true)
    // and the native host must refuse it (native-review branch); an omitted
    // one means the picker excludes it (selected:false, excluded branch).
    listed: options.listed === true,
    pickerOpen: false,
    // The top form reads blank for the first `topFilledAfterReads` reads and
    // carries a value afterwards. The journey reads the top form before its
    // first blank check and, for the excluded branch, again for the branch's
    // own check, so a value can appear exactly between that branch check and
    // the shared one.
    topFilledAfterReads: options.topFilledAfterReads ?? Infinity,
    topReads: 0,
    // The excluded branch waits for the picker panel to close after cancel.
    // The journey's check reads the panel itself, so the stub models that
    // panel, not the adapter's per-origin `visible` (which never reports it).
    cancelCloses: options.cancelCloses !== false,
    popupStatus: options.popupStatus || "已连接",
    phases: [],
    log: [],
    controls: {},
  };
  const filledTopForm = () => {
    const value = blankFormState();
    value.values.number = fixture.CardNumber;
    return value;
  };
  const labels = state.listed
    ? [TOP_LABEL, OTHER_ORIGIN + FRAME_SUFFIX]
    : [TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX];
  const page = {
    url: () => TOP_ORIGIN + "/checkout?variant=cross-site",
    goto: async (url) => state.log.push(["goto", url]),
    frames: () => [
      {
        url: () => OTHER_ORIGIN + "/card",
        evaluate: async () => blankFormState(),
      },
    ],
    evaluate: async () => {
      state.topReads += 1;
      return state.topReads > state.topFilledAfterReads
        ? filledTopForm()
        : blankFormState();
    },
  };
  // Read-only native probe, like `assertNoNativeApproval` expects: no native
  // action is ever sent by this journey.
  const input = (actions, native, inspect) => {
    const probe = typeof inspect === "object" ? inspect : { inspect };
    assert.deepEqual(actions, [], "the cross-site journey sends no native action");
    assert.equal(native, true);
    assert.equal(probe.preserve_focus, true);
    state.log.push(["native", state.phases.length]);
    return { controls: state.controls };
  };
  const text = async (selector) => {
    if (selector === "#checkout-current-page")
      return "当前页面来源：" + TOP_ORIGIN;
    if (selector === "#checkout-status")
      return "请选择一个结账表单来源；不会自动选择，也不会自动提交";
    if (selector === "#status") return state.popupStatus;
    if (selector === "#detail-title") return fixture.CardTitle;
    if (selector === "#detail-fill") return "选择结账表单并填充";
    const match = selector.match(/:nth-child\((\d+)\)$/);
    if (match) return labels[Number(match[1]) - 1];
    return "";
  };
  const count = async (selector) => {
    if (selector === '#filter-tabs [data-filter="credit_card"]') return 1;
    if (selector === cardRow) return 1;
    if (selector.startsWith('#checkout-choices button[data-action="checkout-select"]'))
      return state.pickerOpen ? labels.length : 0;
    if (selector === "#checkout-cancel") return 1;
    return 0;
  };
  const visible = async (selector) => {
    if (selector === "#checkout-picker") return state.pickerOpen;
    return selector === "#checkout-cancel";
  };
  const popup = {
    async disabled() {
      return false;
    },
    async count(selector) {
      return count(selector);
    },
    async visible(selector) {
      return visible(selector);
    },
    async text(selector) {
      return text(selector);
    },
    async attribute(selector, name) {
      // The card detail's picker control is marked as checkout-capable.
      if (selector === "#detail-fill") return name === "data-checkout" ? "1" : null;
      if (selector !== cardRow) return null;
      if (name === "data-item-revision") return fixture.CardRevision;
      if (name === "data-category") return "credit_card";
      return null;
    },
    async click(selector) {
      state.log.push(["popup", selector]);
      if (selector === "#detail-fill") state.pickerOpen = true;
      if (selector === "#checkout-cancel" && state.cancelCloses)
        state.pickerOpen = false;
      if (
        selector.includes('data-action="checkout-select"') &&
        selector.endsWith(":nth-child(2)")
      )
        // The native host refuses the cross-site proposal, and the popup then
        // reports one of its fixed terminal statuses.
        state.popupStatus = "原生宿主机已拒绝：跨站来源不允许自动填充";
    },
  };
  const driver = {
    page,
    input,
    openPopup: async () => popup,
    phase: (value) => state.phases.push(value),
    eventually: async (check, message) => {
      if (!(await check())) throw Error(message);
    },
  };
  return { driver, fixture, state, popup };
}

test("cross-site journey records the excluded branch marker and refuses last", async () => {
  const { driver, fixture, state, popup } = crossSiteDriver({ listed: false });
  await runCrossSiteJourney(driver, fixture, TOP_ORIGIN);
  assert.deepEqual(state.phases, [
    "checkout-cross-site:navigation",
    "checkout-cross-site:picker",
    "checkout-cross-site:excluded",
    "checkout-cross-site:refused",
  ]);
  // The excluded child was absent from the listing: the card detail was
  // opened, then only its own cancel control was pressed, never a candidate.
  assert.deepEqual(
    state.log
      .filter(([kind]) => kind === "popup")
      .map(([, selector]) => selector)
      .filter((selector) => selector === "#detail-fill" ||
        selector === "#checkout-cancel" ||
        selector.includes('data-action="checkout-select"')),
    ["#detail-fill", "#checkout-cancel"],
  );
  // The top form stayed blank throughout; the native stub received probes
  // only and this journey never sent a native action.
  assert.ok(
    state.log
      .filter(([kind]) => kind === "popup")
      .every(([, selector]) => !selector.includes("data-action=\"checkout-select\"")),
  );
});

test("cross-site journey records the native-review branch marker and refuses last", async () => {
  const { driver, fixture, state } = crossSiteDriver({ listed: true });
  await runCrossSiteJourney(driver, fixture, TOP_ORIGIN);
  assert.deepEqual(state.phases, [
    "checkout-cross-site:navigation",
    "checkout-cross-site:picker",
    "checkout-cross-site:native-review",
    "checkout-cross-site:refused",
  ]);
  // The listed child was selected physically; then no value and no approval
  // were written.
  assert.ok(
    state.log.some(
      ([kind, selector]) =>
        kind === "popup" &&
        selector ===
          '#checkout-choices button[data-action="checkout-select"]:nth-child(2)',
    ),
  );
});

test("cross-site markers are mutually exclusive and only the branch that ran appears", async () => {
  const branches = {
    excluded: { listed: false, own: "checkout-cross-site:excluded" },
    "native-review": { listed: true, own: "checkout-cross-site:native-review" },
  };
  const markers = Object.values(branches).map((branch) => branch.own);
  for (const [name, branch] of Object.entries(branches)) {
    const { driver, fixture, state } = crossSiteDriver({ listed: branch.listed });
    await runCrossSiteJourney(driver, fixture, TOP_ORIGIN);
    const observed = state.phases.filter((phase) => markers.includes(phase));
    assert.deepEqual(observed, [branch.own], name);
    assert.equal(state.phases.at(-1), "checkout-cross-site:refused", name);
  }
});

test("a shared privacy failure never emits the refused completion", async () => {
  // The excluded journey reads the top form twice during navigation (control
  // check, then blank check) and once more for its own branch blank check. A
  // value appearing after the third read leaves the branch assertion passing
  // and its marker emitted, so only the shared check catches it. The
  // completion marker follows that check.
  const { driver, fixture, state } = crossSiteDriver({
    listed: false,
    topFilledAfterReads: 3,
  });
  await assert.rejects(
    () => runCrossSiteJourney(driver, fixture, TOP_ORIGIN),
    /Cross-site checkout received a value without approval/,
  );
  assert.deepEqual(state.phases, [
    "checkout-cross-site:navigation",
    "checkout-cross-site:picker",
    "checkout-cross-site:excluded",
  ]);
  // A branch marker without the common completion is partial evidence that
  // the parser must still reject.
  assert.ok(!state.phases.includes("checkout-cross-site:refused"));
  assert.equal(state.topReads, 4);
});

test("a failed native proof never emits the refused completion", async () => {
  // An unavailable native snapshot fails closed. The listed branch first
  // reaches it in the shared check, the excluded branch in its own check, and
  // neither run may print the completion marker after that failure.
  for (const listed of [false, true]) {
    const { driver, fixture, state } = crossSiteDriver({ listed });
    state.controls = null;
    await assert.rejects(
      () => runCrossSiteJourney(driver, fixture, TOP_ORIGIN),
      /Native control snapshot unavailable/,
    );
    assert.ok(!state.phases.includes("checkout-cross-site:refused"));
    // The branch itself had already finished, so dropping the completion is
    // what keeps this run from passing as a complete cross-site proof.
    assert.equal(state.phases.at(-1), listed
      ? "checkout-cross-site:native-review"
      : "checkout-cross-site:excluded");
  }
});

test("both helper outcomes are asserted through the actual result object", () => {
  // The helper always resolves to an object, so `selected` is the only signal
  // that distinguishes a chosen child from an excluded one. Existing helper
  // callers assert that field for both outcomes rather than re-encoding the
  // browser cases here.
  const testSource = readFileSync(
    new URL("./test_browser_checkout_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.ok(
    countMatches(testSource, /\{ selected: true \},/g) >= 3,
    "selected:true result must be asserted at its call sites",
  );
  assert.ok(
    countMatches(testSource, /\{ selected: false \},/g) >= 3,
    "selected:false result must be asserted at its call sites",
  );
  // The result is a plain object with the boolean field, never a bare boolean.
  for (const branch of ["true", "false"])
    assert.doesNotMatch(
      testSource,
      new RegExp(`chooseChildOrigin\\([^)]*\\)\\s*,\\s*${branch}\\)`),
    );
});

test("route lifecycle sanitizer keeps only fixed booleans and capped counts", () => {
  // The QuickFill=false route smoke reports routeTargetLifecycle only on a
  // route-detail failure. It must stay a fixed allowlisted shape: no url,
  // token, frame/loader/document id, text, value or raw protocol payload.
  // Only the pure lifecycle helpers are compiled, in an empty context; the
  // harness itself is never imported (it launches a browser when run).
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  const start = source.indexOf("const ROUTE_LIFECYCLE_EVENTS = [");
  const stop = source.indexOf("\nlet privacyValues", start);
  assert.ok(start >= 0 && stop > start, "lifecycle helpers must stay top-level");
  const context = vm.createContext({});
  vm.runInContext(source.slice(start, stop), context);
  const sanitized = JSON.parse(
    vm.runInContext(
      "JSON.stringify(sanitizeRouteLifecycle({" +
        'enabled: true, mainFrame: "yes", navigated: 1, mainFrameDetached: true,' +
        'url: "chrome-extension://abcd/popup.html#route=SECRET",' +
        'frameId: "FRAME", loaderId: "LOADER", documentId: "DOC", text: "SECRET",' +
        "eventCounts: { frameNavigated: 999, frameStoppedLoading: -1, injected: 2 }," +
        "raw: { method: \"Page.frameNavigated\" }" +
        "}))",
      context,
    ),
  );
  assert.deepEqual(sanitized, {
    enabled: true,
    mainFrame: false,
    loadingStarted: false,
    loadingStopped: false,
    navigated: false,
    navigationRequested: false,
    sameDocumentNavigation: false,
    mainFrameDetached: true,
    eventCounts: {
      frameStartedLoading: 0,
      frameStoppedLoading: 0,
      frameNavigated: 16,
      frameRequestedNavigation: 0,
      navigatedWithinDocument: 0,
      frameDetached: 0,
    },
  });
});

test("route label inspect preserves focus and the approval click stays physical", () => {
  // The native-label wait only reads the route page's approval state. It must
  // use the helper's focus-preserving form (partial title, no raise/focus), or
  // the idle native window can cover the route page before any approval
  // exists. The later approval stays one ordinary physical click.
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /inspect: true,\n\s+title_prefix: "Locklark · 浏览器原生确认",\n\s+preserve_focus: true,/,
  );
  assert.match(source, /input\(\[\], true, ROUTE_LABEL_INSPECT\)\.controls\?\.\["批准本次操作"\]/);
  // The raising/focusing positional form never appears in the route
  // checkpoint; it remains only for the unconditional-fill journeys.
  assert.ok(countMatches(source, /input\(\[\], true, true\)/g) > 0);
  const checkpoint = source.slice(
    source.indexOf("async function acceptRouteDetailRead"),
    source.indexOf("async function blank()"),
  );
  assert.doesNotMatch(checkpoint, /input\(\[\], true, true\)/);
  assert.equal(
    countMatches(checkpoint, /input\(\[\], true, ROUTE_LABEL_INSPECT\)/g),
    1,
  );
  assert.equal(
    countMatches(
      source,
      /^\s*input\(\[\{ click_label: "批准本次操作" \}\]\);$/gm,
    ),
    1,
  );
});

test("route probe maps the fixed claim-pending status to native-pending", () => {
  // The visible route status is the only proof that the page entered its
  // claim before pagehide. Exactly the fixed text maps to a fixed enum, and
  // no status text or other DOM content leaves the page.
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  // Anchored at the real declaration: `ROUTE_VIEWS` also appears inside the
  // probe's own template text.
  const start = source.search(/^const ROUTE_VIEWS = /m);
  const stop = source.indexOf("\nfunction phase(", start);
  assert.ok(start >= 0 && stop > start, "route probe must stay top-level");
  const context = vm.createContext({});
  vm.runInContext(
    source.slice(start, stop) + "\nthis.probe = routeStateProbe;",
    context,
  );
  const kindFor = (statusText) => {
    context.document = {
      body: { dataset: { view: "closed" } },
      querySelector(selector) {
        if (selector === "#status") return { textContent: statusText };
        if (selector === "#detail-view") return { hidden: true };
        return null;
      },
    };
    // The probe returns the page-side expression string; evaluate it against
    // the fake document exactly as the harness sends it to Runtime.evaluate.
    const expression = vm.runInContext("probe('fixture')", context);
    const probed = vm.runInContext(
      "JSON.stringify(eval(" + JSON.stringify(expression) + "))",
      context,
    );
    const value = JSON.parse(probed);
    assert.deepEqual(Object.keys(value).sort(), [
      "detailShown",
      "statusKind",
      "titleMatchesFixture",
      "view",
    ]);
    assert.ok(!probed.includes(statusText) || statusText === "");
    return value.statusKind;
  };
  assert.equal(kindFor("正在请求桌面审批…"), "native-pending");
  assert.equal(kindFor("正在请求桌面审批"), "other");
  assert.equal(kindFor("正在请求桌面审批… "), "native-pending");
  assert.equal(kindFor("无法打开此条目"), "claim-failed");
  assert.equal(kindFor("条目已失效，请重新从金库打开"), "route-revoked");
  assert.equal(kindFor(""), "other");
});

test("route status trace keeps every #status write batched in one callback", () => {
  // popup.js writes #status.textContent, so the observer sees childList records
  // whose target is #status and whose addedNodes are its text nodes. Separate
  // writes batched into one callback must each classify from their own record,
  // in order. Only the live #status subtree is read, the cap holds, and stop
  // disconnects.
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  const start = source.search(/^const ROUTE_VIEWS = /m);
  const stop = source.indexOf("\nfunction phase(", start);
  assert.ok(start >= 0 && stop > start, "route trace helpers must stay top-level");
  const code = source.slice(start, stop);
  assert.match(code, /^const ROUTE_STATUS_TRACE_LIMIT = 8;$/m);

  const textNode = (data) => ({ nodeType: 3, data, parentNode: null });
  class FakeElement {
    constructor(tag, selector = "") {
      this.tag = tag;
      this.selector = selector;
      this.childNodes = [];
      this.hidden = true;
      this.contains = (node) => node === this;
      this.matches = (selectors) =>
        selectors.split(",").some((part) => part.trim() === this.selector);
    }
    // Same contract as the DOM: assigning textContent replaces all children
    // with one text node (written once; popup.js never writes twice per task).
    get textContent() {
      return this.childNodes.map((node) => node.data ?? "").join("");
    }
    set textContent(value) {
      this.childNodes = [];
      const text = String(value ?? "");
      if (text) {
        const node = textNode(text);
        node.parentNode = this;
        this.childNodes.push(node);
      }
    }
  }
  const deliveries = [];
  const observers = [];
  class FakeObserver {
    constructor(callback) {
      this.callback = callback;
      this.disconnected = false;
      observers.push(this);
    }
    observe(target) {
      this.target = target;
    }
    disconnect() {
      this.disconnected = true;
    }
    takeRecords() {
      return deliveries.splice(0);
    }
  }
  const document = {
    body: new FakeElement("body"),
    nodes: {},
    querySelector(selector) {
      return this.nodes[selector] ?? null;
    },
  };
  document.body.dataset = { view: "vault" };
  document.nodes["#detail-view"] = new FakeElement("section", "#detail-view");
  document.nodes["#detail-title"] = new FakeElement("h2", "#detail-title");
  const status = new FakeElement("p", "#status");
  const addStatus = () => {
    document.nodes["#status"] = status;
    status.contains = (node) =>
      node === status || (node?.parentNode === status && node !== status);
  };
  const context = vm.createContext({
    MutationObserver: FakeObserver,
    document,
    Element: FakeElement,
  });
  vm.runInContext(code + "\nthis.probe = routeStatusTraceProbe;this.clean = sanitizeRouteStatusTrace;", context);
  // A second, independent installation (same fake document shape) for checks
  // whose result must not depend on earlier writes.
  const newContext = () => {
    const nodes = { ...document.nodes, "#status": status };
    const isolatedDocument = {
      body: document.body,
      nodes,
      querySelector(selector) {
        return nodes[selector] ?? null;
      },
    };
    const isolated = vm.createContext({
      MutationObserver: FakeObserver,
      document: isolatedDocument,
      Element: FakeElement,
    });
    vm.runInContext(
      code + "\nthis.probe = routeStatusTraceProbe;",
      isolated,
    );
    vm.runInContext(
      "eval(" + JSON.stringify(vm.runInContext("probe('FIXTURE')", isolated)) + ")",
      isolated,
    );
    return {
      document: isolatedDocument,
      statuses: () =>
        JSON.parse(vm.runInContext("__locklarkRouteStatusTraceRead()", isolated))
          .filter((entry) => entry.channel === "status")
          .map((entry) => entry.value),
      batch: (records) => {
        deliveries.push(...records);
        observers.at(-1).callback(observers.at(-1).takeRecords());
      },
    };
  };
  vm.runInContext(
    "eval(" + JSON.stringify(vm.runInContext("probe('FIXTURE')", context)) + ")",
    context,
  );
  assert.equal(observers.length, 1);
  // The main installation's observer (isolated contexts add their own).
  const mainObserver = observers[0];
  const trace = () => JSON.parse(vm.runInContext("__locklarkRouteStatusTraceRead()", context));
  const statuses = () =>
    trace().filter((entry) => entry.channel === "status").map((entry) => entry.value);
  const batch = (records) => {
    deliveries.push(...records);
    observers.at(-1).callback(observers.at(-1).takeRecords());
  };
  // What assigning `textContent` produces as one MutationRecord.
  const write = (value, element = status) => {
    const removed = element.childNodes;
    element.textContent = value;
    return {
      type: "childList",
      target: element,
      addedNodes: element.childNodes.slice(),
      removedNodes: removed,
    };
  };

  // Unrelated page text never appends a status event.
  const before = trace();
  const heading = textNode("普通标题文本");
  document.nodes["#detail-title"].textContent = "普通标题文本";
  document.nodes["#detail-title"].contains = (node) => node === heading || node.parentNode === document.nodes["#detail-title"];
  batch([
    { type: "characterData", target: heading },
    { type: "childList", addedNodes: [heading], target: document.body },
  ]);
  assert.deepEqual(trace(), before);

  // #status inserted after installation with the pending literal is captured.
  addStatus();
  const pendingNode = textNode("正在请求桌面审批…");
  pendingNode.parentNode = status;
  status.childNodes = [pendingNode];
  batch([{ type: "childList", target: document.body, addedNodes: [status], removedNodes: [] }]);
  assert.deepEqual(statuses().at(-1), "native-pending");

  // The real case: pending then revoked, then cleared, all in one callback.
  // Each record carries its own text node, so every transition survives even
  // though only the last write remains current in the DOM.
  const pending = write("正在请求桌面审批…");
  const revoked = write("条目已失效，请重新从金库打开");
  const cleared = write("");
  batch([pending, revoked, cleared]);
  const tail = statuses().slice(-3);
  assert.deepEqual(tail, ["native-pending", "route-revoked", "empty"]);

  // The same batched shape for pending then the closed text.
  const pendingAgain = write("正在请求桌面审批…");
  batch([pendingAgain, write("已关闭此条目")]);
  assert.deepEqual(statuses().slice(-2), ["native-pending", "closed"]);

  // Only a status-owned characterData record classifies, and unknown status
  // text becomes only the fixed "other" enum. A fresh context keeps this
  // independent of the text left by the writes above.
  const isolated = newContext();
  const isolatedStatus = isolated.document.nodes["#status"];
  const foreign = textNode("无法打开此条目");
  const mark = isolated.statuses().length;
  isolated.batch([{ type: "characterData", target: foreign }]);
  assert.equal(isolated.statuses().length, mark);
  const owned = textNode("无法打开此条目");
  owned.parentNode = isolatedStatus;
  isolatedStatus.childNodes = [owned];
  isolated.batch([{ type: "characterData", target: owned }]);
  assert.deepEqual(isolated.statuses().at(-1), "claim-failed");
  isolatedStatus.textContent = "SECRET-STATUS-TEXT";
  isolated.batch([
    {
      type: "childList",
      target: isolatedStatus,
      addedNodes: isolatedStatus.childNodes.slice(),
      removedNodes: [owned],
    },
  ]);
  assert.deepEqual(isolated.statuses().at(-1), "other");

  // The cap holds and nothing arbitrary or raw leaves the page.
  for (let index = 0; index < 30; index++)
    batch([write(index % 2 ? "无法打开此条目" : "正在请求桌面审批…")]);
  assert.equal(trace().length, 8);
  const serialized = JSON.stringify(trace());
  assert.doesNotMatch(serialized, /SECRET|普通|FIXTURE|正在请求|无法打开|已关闭|已失效|http|#route=/);
  for (const entry of trace()) {
    assert.deepEqual(Object.keys(entry).sort(), ["channel", "value"]);
    assert.ok(entry.value === true || entry.value === false || entry.value.length <= 16);
  }

  // Cleanup disconnects the observer and removes both hooks.
  assert.equal(vm.runInContext("__locklarkRouteStatusTraceStop()", context), true);
  assert.equal(mainObserver.disconnected, true);
  assert.equal(
    vm.runInContext(
      "typeof globalThis.__locklarkRouteStatusTraceRead + typeof globalThis.__locklarkRouteStatusTraceStop",
      context,
    ),
    "undefinedundefined",
  );
});

test("route per-field copy uses physical input, exact native labels and the private pipe", () => {
  // The route journey's field-copy proof must click the rendered Copy control
  // with real CDP mouse input, accept only the fixed approval labels, approve
  // physically, show the fixed feedback and compare the OS clipboard through
  // the private-pipe reader. Only booleans leave; expected bytes never do.
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  const ROUTE_REVIEW_LITERAL = '"批准本次操作"';
  const helper = (name) => {
    const from = source.indexOf(name);
    assert.ok(from > 0, "missing " + name);
    const body = source.slice(from);
    const end = body.indexOf("\n  }\n", body.indexOf("async function"));
    const next = source.indexOf("\n  async function ", from + name.length);
    const stop = source.indexOf("\n  }\n", next);
    return source.slice(from, next > 0 && stop > next ? stop : end);
  };
  assert.match(source, /^const ROUTE_COPY_FIELD_SELECTOR =\n  '\[data-field-id="password"\] \[data-action="copy-field"\]';$/m);
  assert.match(source, /^const ROUTE_COPY_REVIEW_LABEL = "批准本次操作";$/m);
  assert.match(source, /^const ROUTE_COPY_DISCLOSURE_LABEL = "批准本次字段披露";$/m);
  const checkpoint = helper("async function acceptRouteDetailRead");
  // One physical click on the exact Copy control through the wrapper.
  assert.equal(
    countMatches(checkpoint, /await route\.click\(ROUTE_COPY_FIELD_SELECTOR\);/g),
    1,
  );
  assert.doesNotMatch(checkpoint, /\.evaluate\([^)]*click\(\)|dispatchEvent/);
  // Only the fixed labels are ever clicked, each through the native helper.
  assert.match(
    checkpoint,
    /input\(\[\{ click_label: ROUTE_COPY_REVIEW_LABEL \}\]\);/,
  );
  assert.match(
    checkpoint,
    /input\(\[\{ click_label: ROUTE_COPY_DISCLOSURE_LABEL \}\]\);/,
  );
  // Every native label click in the checkpoint is one of the two fixed
  // approval labels (the earlier route review plus the field disclosure).
  for (const match of checkpoint.matchAll(/click_label: ([^\s}]+)/g))
    assert.ok(
      [ROUTE_REVIEW_LITERAL, "ROUTE_COPY_REVIEW_LABEL", "ROUTE_COPY_DISCLOSURE_LABEL"].includes(
        match[1],
      ),
      "unexpected native click label " + match[1],
    );
  // Focus-preserving inspect only for the approval waits.
  assert.match(
    checkpoint,
    /inspect: true,\n\s+title_prefix: "Locklark · 浏览器原生确认",\n\s+preserve_focus: true,/,
  );
  assert.doesNotMatch(checkpoint, /input\(\[\], true, true\)/);
  // The disclosure is always required, even after a legacy review.
  assert.match(checkpoint, /Native field disclosure did not appear/);
  assert.match(checkpoint, /Native field disclosure did not follow its review/);
  // Fixed UI feedback, never a page-computed success.
  // All three fixed success variants: both native-lease lines and the
  // legacy manual-copy line. Pending/refusal/unknown text is absent.
  assert.match(
    source,
    /^const ROUTE_COPY_FEEDBACK = \[\n  "已启用自动清理",\n  "自动清理已关闭",\n  "已复制；浏览器无法保证自动清除，请按需手动清理",\n\];$/m,
  );
  const feedbackList = source.slice(
    source.indexOf("const ROUTE_COPY_FEEDBACK = ["),
    source.indexOf("];", source.indexOf("const ROUTE_COPY_FEEDBACK = [")) + 2,
  );
  for (const text of ["已启用自动清理", "自动清理已关闭", "已复制；浏览器无法保证自动清除，请按需手动清理"])
    assert.ok(feedbackList.includes(text), "missing success feedback " + text);
  assert.equal(countMatches(feedbackList, /已复制；/g), 1);
  for (const failure of ["复制失败", "复制结果未确认", "复制已取消或被拒绝"])
    assert.ok(!feedbackList.includes(failure), "failure text accepted: " + failure);
  // The legacy line is the real popup success feedback after writeText,
  // not an invented string: it appears in writeClipboard -> copiedFeedback.
  const popupSource = readFileSync(
    new URL("../browser-extension/popup.js", import.meta.url),
    "utf8",
  );
  const writeFrom = popupSource.indexOf("async function writeClipboard(value, button) {");
  assert.ok(writeFrom > 0, "missing writeClipboard");
  const writeBody = popupSource.slice(
    writeFrom,
    popupSource.indexOf("\n  }\n", writeFrom),
  );
  assert.match(
    writeBody,
    /await globalThis\.navigator\.clipboard\.writeText\(value\);\n    \} catch \{\n      toast\("复制失败"\);\n      return;\n    \}\n    copiedFeedback\(button, "已复制；浏览器无法保证自动清除，请按需手动清理"\);/,
  );
  // Success is only ever the feedback text; the clipboard match below
  // stays mandatory.
  assert.match(checkpoint, /ROUTE_COPY_FEEDBACK\.some/);
  // Private-pipe comparison; no success without a matching clipboard.
  assert.match(checkpoint, /new PrivateClipboard\(\{ root, state, env \}\)/);
  assert.match(checkpoint, /clipboardReader\.start\(\)/);
  assert.match(checkpoint, /clipboardReader\.matches\(fixture\.Value\)/);
  assert.match(checkpoint, /OS clipboard did not receive the approved field/);
  assert.match(checkpoint, /clipboardReader\.stop\(\)/);
  // The expected bytes are never passed to input/native helpers or printed.
  assert.doesNotMatch(checkpoint, /input\([^)]*fixture\.Value/);
  assert.doesNotMatch(checkpoint, /console\.(log|error)\([^)]*fixture\.Value/);
  assert.doesNotMatch(checkpoint, /click_label: [^"]*Value/);
  // Concealment is asserted again right before the copy, as booleans only.
  assert.match(checkpoint, /routePasswordRowProbe\(fixture\.Value\)/);
  assert.match(checkpoint, /rowBefore\?\.masked, true/);
  assert.match(checkpoint, /rowBefore\?\.leaked, false/);
  // The checkpoint drives the real adapter: attachRoute must forward the
  // existing popup mouse wrapper, not just evaluate/close, and that wrapper is
  // the reviewed CDP input path (no DOM event dispatch anywhere).
  const adapterFrom = source.indexOf("async function attachRoute(target) {");
  assert.ok(adapterFrom > 0, "missing attachRoute adapter");
  const adapter = source.slice(
    adapterFrom,
    source.indexOf("\n    }\n", adapterFrom) + "\n    }\n".length,
  );
  assert.match(adapter, /const route = await attachPopup\(target\);/);
  assert.match(adapter, /click: \(selector\) => route\.click\(selector\),/);
  // count/text forward the existing popup readers; the copy proof waits on
  // the rendered row count and the fixed toast text through them.
  assert.match(adapter, /count: \(selector\) => route\.count\(selector\),/);
  assert.match(adapter, /text: \(selector\) => route\.text\(selector\),/);
  assert.match(adapter, /evaluate: \(expression\) => route\.evaluate\(expression\),/);
  assert.match(adapter, /bringToFront: \(\) => route\.bringToFront\(\),/);
  assert.match(adapter, /close: \(\) => route\.close\(\),/);
  assert.doesNotMatch(adapter, /dispatchEvent|\.evaluate\([^)]*click/);
  // Closed world: the adapter exposes exactly these five methods and the
  // checkpoint only calls those, so a missing forward cannot slip through.
  const exposed = [...adapter.matchAll(/^\s{8}([a-zA-Z]+): /gm)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(exposed, [
    "bringToFront",
    "click",
    "close",
    "count",
    "evaluate",
    "text",
  ]);
  const called = new Set(
    [...checkpoint.matchAll(/\broute\.([a-zA-Z]+)\(/g)].map((match) => match[1]),
  );
  assert.deepEqual([...called].sort(), exposed);
  // The forwarded bringToFront is exactly one CDP Page.bringToFront call.
  assert.equal(
    countMatches(source, /bringToFront: \(\) => call\("Page\.bringToFront"\),/g),
    1,
  );
  // The forwarded method is the real mouse wrapper: visibility and hit-test
  // first, then one CDP mousePressed/mouseReleased pair.
  const popupFrom = source.indexOf("async function attachPopup(target) {");
  assert.ok(popupFrom > 0, "missing attachPopup wrapper");
  const popup = source.slice(popupFrom, source.indexOf("\n  }\n", popupFrom));
  const clickFrom = popup.indexOf("click: async (selector) => {");
  assert.ok(clickFrom > 0, "attachPopup has no click method");
  const wrapper = popup.slice(clickFrom, popup.indexOf("\n      },", clickFrom));
  assert.match(wrapper, /document\.visibilityState!=="visible"/);
  assert.match(wrapper, /document\.elementFromPoint/);
  assert.match(wrapper, /type: "mousePressed"/);
  assert.match(wrapper, /type: "mouseReleased"/);
  assert.doesNotMatch(wrapper, /dispatchEvent/);
  // Focus is restored and proven (visible and focused) immediately before the
  // one physical click, never by a DOM or synthesized bypass.
  const focusStage = checkpoint.indexOf('mark("route:copy-focus")');
  const bringCall = checkpoint.indexOf("await route.bringToFront();");
  const focusProof = checkpoint.indexOf(
    'document.visibilityState === "visible" && document.hasFocus() === true',
  );
  const clickCall = checkpoint.indexOf(
    "await route.click(ROUTE_COPY_FIELD_SELECTOR);",
  );
  assert.ok(focusStage > 0 && bringCall > focusStage, "focus stage/order");
  assert.ok(focusProof > bringCall, "focus proof must follow bringToFront");
  assert.ok(clickCall > focusProof, "click must follow the focus proof");
  assert.match(
    checkpoint.slice(bringCall, clickCall),
    /Route page did not return to the foreground/,
  );
  assert.doesNotMatch(checkpoint, /document\.hasFocus =|\.focus\(\)/);
  // The route journey calls that forwarded method, not a local substitute.
  assert.match(
    checkpoint,
    /await route\.click\(ROUTE_COPY_FIELD_SELECTOR\);/,
  );
  // The private-pipe reader is the shared one, exported without behavior change.
  const shared = readFileSync(
    new URL("./browser_shared_clipboard_acceptance.mjs", import.meta.url),
    "utf8",
  );
  assert.match(shared, /^export class PrivateClipboard \{$/m);
  assert.match(
    source,
    /import \{\n  acceptSharedClipboard,\n  prepareSharedEnvironment,\n  PrivateClipboard,\n\} from "\.\/browser_shared_clipboard_acceptance\.mjs";/,
  );
  // Bounded stages exist for click, approval and clipboard comparison.
  for (const stage of [
    "route:copy-field",
    "route:field-approval",
    "route:field-approve",
    "route:clipboard",
  ])
    assert.ok(source.includes('mark("' + stage + '")'), stage);
});

// The route-revocation section of the harness, from its fixed constants to the
// browser block. It contains no import-time side effects, so it can be
// evaluated like the route probes in an empty context.
function routeRevocationHelpers(source) {
  const start = source.indexOf("// Route revocation checkpoint (after the field-copy proof).");
  const stop = source.indexOf("\nfunction phase(", start);
  assert.ok(start > 0 && stop > start, "revocation helpers must stay top-level");
  // The fixed route status literals and the Copy selector come first.
  const literals = source.indexOf("const ROUTE_VIEWS = [");
  assert.ok(literals > 0 && literals < start, "fixed literals must stay top-level");
  const literalsEnd = source.indexOf("\n// The concealed password row's own Copy control.", literals);
  assert.ok(literalsEnd > literals, "status literals must stay top-level");
  // The browser key title prefixes are fixed constants next to the route page
  // patterns.
  const selector = source.indexOf("const ROUTE_COPY_FIELD_SELECTOR =");
  assert.ok(selector > literalsEnd, "Copy selector must stay top-level");
  const prefixes = source.indexOf("const SOURCE_TITLE_PREFIX =");
  assert.ok(prefixes > 0 && prefixes < literals, "title prefixes must stay top-level");
  return {
    start,
    stop,
    code:
      source.slice(prefixes, source.indexOf("\n", source.indexOf("const ROUTE_TITLE_PREFIX =", prefixes))) +
      "\n" +
      source.slice(literals, literalsEnd) +
      "\n" +
      source.slice(selector, source.indexOf("\n", source.indexOf("';", selector))) +
      "\n" +
      source.slice(start, stop),
  };
}

function routeRevocationCheckpoint(source) {
  const start = source.indexOf("    // Route revocation checkpoint: the same tab and target");
  const stop = source.indexOf("\n  async function blank()", start);
  assert.ok(start > 0 && stop > start, "revocation checkpoint must stay in the route journey");
  return source.slice(start, stop);
}

// One context with the real revocation helpers and their JSON-able values.
function routeRevocationContext(source) {
  const context = vm.createContext({});
  vm.runInContext(
    routeRevocationHelpers(source).code +
      "\nthis.probes={ROUTE_SWITCH_PROBE,routeRevokedProbe,routeWiped,ROUTE_NATIVE_ABSENT_LIMIT,ROUTE_NATIVE_TITLE,ROUTE_SWITCH_SOURCE,ROUTE_RETURN,ROUTE_RELOAD,SOURCE_TITLE_PREFIX,ROUTE_TITLE_PREFIX};",
    context,
  );
  return context;
}

// The real page expression of one probe, run against a minimal fake DOM inside
// the same helper context (so `routeWiped` is the real one).
async function routeProbeResult(context, expression, document) {
  const probe = vm.createContext({
    document,
    MutationObserver: class {
      observe() {}
      disconnect() {}
    },
    setTimeout,
    clearTimeout,
    Promise,
  });
  return JSON.parse(
    await vm.runInContext("(async()=>JSON.stringify(await (" + expression + ")))()", probe),
  );
}

function routeElement(extra = {}) {
  return { hidden: true, childElementCount: 0, textContent: "", ...extra };
}

function routeFakePage({
  visible = true,
  view = "closed",
  detailHidden = true,
  title = "",
  copy = false,
  bodyText = "",
  status = "条目已失效，请重新从金库打开",
} = {}) {
  const detail = routeElement({ hidden: detailHidden });
  return {
    body: { dataset: { view }, innerText: bodyText },
    visibilityState: visible ? "visible" : "hidden",
    querySelector(selector) {
      if (selector === "#detail-view") return detail;
      if (selector === "#detail-title") return routeElement({ textContent: title });
      if (selector === "#detail-fields") return routeElement();
      if (selector === "#status") return routeElement({ textContent: status });
      return null;
    },
    querySelectorAll() {
      return copy ? [{}] : [];
    },
  };
}

test("route probes return only fixed booleans and wipe only on a revoked or failed status", async () => {
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  const context = routeRevocationContext(source);
  const routeRevokedProbe = vm.runInContext("routeRevokedProbe", context);
  const routeWiped = vm.runInContext("routeWiped", context);
  const helpers = vm.runInContext("JSON.stringify(probes)", context);
  const {
    ROUTE_SWITCH_PROBE,
    ROUTE_NATIVE_ABSENT_LIMIT,
    ROUTE_SWITCH_SOURCE,
    ROUTE_RETURN,
    ROUTE_RELOAD,
    SOURCE_TITLE_PREFIX,
    ROUTE_TITLE_PREFIX,
  } = JSON.parse(helpers);
  const FIXTURE_TITLE = "SYNTHETIC-TITLE-CANARY";
  const FIXTURE_VALUE = "SYNTHETIC-VALUE-CANARY";
  const notRevoked = "正在请求桌面审批…";

  // Closed and wiped under the revoked and claim-failed statuses only.
  for (const [status, kind] of [
    ["条目已失效，请重新从金库打开", "route-revoked"],
    ["无法打开此条目", "claim-failed"],
  ]) {
    const page = routeFakePage({ status });
    const result = await routeProbeResult(
      context,
      routeRevokedProbe(FIXTURE_TITLE, FIXTURE_VALUE),
      page,
    );
    assert.equal(result.statusKind, kind);
    assert.deepEqual(Object.keys(result).sort(), [
      "closed",
      "copyAbsent",
      "detailHidden",
      "fieldsEmpty",
      "fixtureAbsent",
      "statusKind",
      "titleEmpty",
      "visible",
    ]);
    assert.equal(result.visible, true);
    assert.equal(routeWiped(result), true, kind);
  }
  // The full probe is the one the route-return wait uses, so it must report
  // the fixed visibility boolean that wait requires.
  for (const visible of [true, false]) {
    const returned = await routeProbeResult(
      context,
      routeRevokedProbe(FIXTURE_TITLE, FIXTURE_VALUE),
      routeFakePage({ visible }),
    );
    assert.equal(returned.visible, visible);
    assert.equal(routeWiped(returned), true);
  }
  // Any other status (pending, empty, closed text) is never a revocation.
  for (const status of ["", notRevoked, "已关闭此条目", "other text"]) {
    const result = await routeProbeResult(
      context,
      routeRevokedProbe(FIXTURE_TITLE, FIXTURE_VALUE),
      routeFakePage({ status }),
    );
    assert.equal(result.statusKind === "route-revoked" || result.statusKind === "claim-failed", false);
    assert.equal(routeWiped(result), false, status);
  }
  // Each remaining fixed condition alone fails the wipe.
  const failures = [
    { detailHidden: false },
    { view: "detail", detailHidden: false },
    { title: FIXTURE_TITLE },
    { copy: true },
    { bodyText: "note " + FIXTURE_VALUE },
    { bodyText: FIXTURE_TITLE + " elsewhere" },
  ];
  for (const override of failures) {
    const result = await routeProbeResult(
      context,
      routeRevokedProbe(FIXTURE_TITLE, FIXTURE_VALUE),
      routeFakePage(override),
    );
    assert.equal(routeWiped(result), false, JSON.stringify(Object.keys(override)));
  }
  // The reported shape never carries the fixture title or value.
  const withValues = JSON.stringify(
    await routeProbeResult(
      context,
      routeRevokedProbe(FIXTURE_TITLE, FIXTURE_VALUE),
      routeFakePage({ title: FIXTURE_TITLE }),
    ),
  );
  assert.doesNotMatch(withValues, /SYNTHETIC|条目|无法打开/);
  // The switch-only page state resolves at once with fixed booleans whether
  // the page is still visible or already hidden; the wait is host-side polling.
  for (const visible of [true, false]) {
    const switched = await routeProbeResult(context, ROUTE_SWITCH_PROBE, routeFakePage({ visible }));
    assert.deepEqual(Object.keys(switched).sort(), [
      "closed",
      "detailHidden",
      "fieldsEmpty",
      "titleEmpty",
      "visible",
    ]);
    assert.equal(switched.visible, visible);
    // The switch shape is closed and wiped by checkWipe in the harness, not
    // routeWiped (which, correctly, also requires the fixed status kind).
    assert.equal(
      ["closed", "detailHidden", "titleEmpty", "fieldsEmpty"].every(
        (key) => switched[key] === true,
      ),
      true,
    );
    assert.equal(routeWiped(switched), false);
  }
  // The same read-only probe is the background-revocation wait: host-side
  // polling of the fixed DOM probe, no page observer.
  const hidden = await routeProbeResult(context, ROUTE_SWITCH_PROBE, routeFakePage({ visible: false }));
  assert.equal(hidden.visible, false);
  assert.equal(
    ["closed", "detailHidden", "titleEmpty", "fieldsEmpty"].every(
      (key) => hidden[key] === true,
    ),
    true,
  );
  // The physical keys are the browser's own single-shot shortcuts; the
  // no-prompt bound is a fixed few seconds. Each key names its own browser
  // window title: the source tab "Locklark acceptance", the route tab exactly
  // "Locklark" (the route title does not start with a longer prefix).
  assert.deepEqual(ROUTE_SWITCH_SOURCE, [{ key: "Control_L+Shift_L+Tab" }]);
  assert.deepEqual(ROUTE_RETURN, [{ key: "Control_L+Tab" }]);
  assert.deepEqual(ROUTE_RELOAD, [{ key: "Control_L+r" }]);
  assert.equal(SOURCE_TITLE_PREFIX, "Locklark acceptance");
  assert.equal(ROUTE_TITLE_PREFIX, "Locklark");
  assert.ok(Number.isInteger(ROUTE_NATIVE_ABSENT_LIMIT));
  assert.ok(ROUTE_NATIVE_ABSENT_LIMIT > 0 && ROUTE_NATIVE_ABSENT_LIMIT <= 5000);
});

test("route revocation checkpoint switches, wipes, reloads and never prompts", () => {
  const source = readFileSync(
    new URL("./browser_native_acceptance.mjs", import.meta.url),
    "utf8",
  );
  const checkpoint = routeRevocationCheckpoint(source);
  const at = (needle) => {
    const index = checkpoint.indexOf(needle);
    assert.ok(index >= 0, "checkpoint is missing " + needle);
    return index;
  };
  // 1. One physical Control_L+Shift_L+Tab. The route tab is active when it is
  //    sent, so it is addressed by the active route page's title prefix.
  const switchKey = at("browserKey(ROUTE_SWITCH_SOURCE, ROUTE_TITLE_PREFIX);");
  const sourceVisible = at("Source tab did not become visible");
  const hiddenWait = checkpoint.indexOf("routeWiped(", sourceVisible);
  const returnKey = at("browserKey(ROUTE_RETURN, SOURCE_TITLE_PREFIX);");
  assert.ok(switchKey < sourceVisible && sourceVisible < hiddenWait && hiddenWait < returnKey);
  assert.match(source, /^const ROUTE_SWITCH_SOURCE = Object\.freeze\(\[\{ key: "Control_L\+Shift_L\+Tab" \}\]\);$/m);
  assert.match(source, /^const ROUTE_RETURN = Object\.freeze\(\[\{ key: "Control_L\+Tab" \}\]\);$/m);
  assert.match(source, /^const ROUTE_RELOAD = Object\.freeze\(\[\{ key: "Control_L\+r" \}\]\);$/m);
  // The hidden route page loses its detail on its own before the return, by
  // host-side polling of the fixed read-only DOM probe.
  assert.match(
    checkpoint.slice(hiddenWait, returnKey),
    /^routeWiped\(\n\s+await route\.evaluate\(routeRevokedProbe\(fixture\.Title, fixture\.Value\)\),\n\s+\);/,
  );
  assert.match(checkpoint, /Background revocation did not wipe the route detail/);
  assert.ok(at('recordRouteLifecycle("route-revoked")') > hiddenWait);
  assert.doesNotMatch(checkpoint, /MutationObserver|ROUTE_HIDDEN_PROBE|routeHiddenProbe/);
  // 2. The return proves the foreground and the same target, still wiped. The
  //    source tab is active when it is sent, so it is addressed by the source
  //    page's title prefix. The returned-route wait reads the full wipe probe
  //    (the same one the stale reload uses), never the incomplete page state,
  //    because routeWiped() also needs copyAbsent, fixtureAbsent and statusKind.
  assert.ok(at("Route page did not return to the foreground") > returnKey);
  const sameTarget = at('1, "Route target was replaced");');
  assert.ok(sameTarget > returnKey);
  const foreground = at("Route page did not return to the foreground");
  const returnedWait = checkpoint.indexOf(
    "routeRevokedProbe(fixture.Title, fixture.Value)",
    foreground,
  );
  assert.ok(returnedWait > foreground && returnedWait < at('mark("route:reload");'));
  assert.match(
    checkpoint.slice(checkpoint.lastIndexOf("await wait(async () => {", returnedWait)),
    /^await wait\(async \(\) => \{\n\s+const returned = await route\.evaluate\(\n\s+routeRevokedProbe\(fixture\.Title, fixture\.Value\),\n\s+\);\n\s+return returned\?\.visible === true && routeWiped\(returned\);\n\s+\}, "Returned route page kept its detail"\);/,
  );
  // The full probe result includes the fixed visibility boolean the return wait
  // requires, and the switch-only page state is never used for the return wait.
  assert.match(
    source,
    /^function routeRevokedProbe\(title, value\) \{\n\s+return `\(\(\)=>\{\n(?:[^\n]*\n)*?\s{6}visible:document\.visibilityState==='visible',$/m,
  );
  assert.equal(
    countMatches(checkpoint, /routeRevokedProbe\(fixture\.Title, fixture\.Value\)/g),
    4,
    "the background, return, reload and no-prompt waits share the full probe",
  );
  // No undefined probe name survives in the checkpoint or in the harness.
  assert.doesNotMatch(checkpoint, /routeSwitchProbe/);
  assert.doesNotMatch(source, /routeSwitchProbe\b/);
  // ROUTE_SWITCH_PROBE is a defined fixed DOM expression, not a page hook.
  assert.match(source, /^const ROUTE_SWITCH_PROBE = ROUTE_PAGE_STATE;$/m);
  assert.match(source, /^const ROUTE_PAGE_STATE = `\(\(\)=>\{$/m);
  assert.match(checkpoint, /Returned route page kept its detail/);
  // 3. One real XTest Control_L+r to the route tab, only after the captured
  //    target is proven still to be this route page and the route tab is
  //    proven to be the active tab; then the fixed fail-closed state (closed
  //    view, hidden detail, empty title/fields, no Copy, no fixture text)
  //    plus the fixed revoked/claim-failed status kind.
  const reload = at("browserKey(ROUTE_RELOAD, ROUTE_TITLE_PREFIX);");
  assert.ok(reload > sameTarget);
  // The captured target is proven still the one route page right before the
  // key; the route tab was proven active at the start of the checkpoint.
  const targetBefore = checkpoint.lastIndexOf(
    '1, "Route target was replaced");',
    reload,
  );
  assert.ok(targetBefore >= sameTarget && targetBefore < reload);
  const reloadStage = at('mark("route:reload");');
  assert.ok(switchKey < reloadStage && reloadStage < reload);
  assert.doesNotMatch(
    checkpoint.slice(targetBefore, reload),
    /route\.evaluate/,
    "the reload target checks stay read-only target lookups",
  );
  const failClosed = checkpoint.indexOf(
    "routeRevokedProbe(fixture.Title, fixture.Value)",
    reload,
  );
  assert.ok(failClosed > reload, "the stale fragment is probed after the reload");
  assert.match(checkpoint, /Stale route fragment did not fail closed/);
  // The fail-closed DOM probe is read both while waiting and, after the
  // bounded no-prompt observation, right before the Copy assertion; that
  // later probe is the one this ordering is anchored to.
  const lastWipedProbe = checkpoint.lastIndexOf(
    "routeRevokedProbe(fixture.Title, fixture.Value)",
  );
  assert.ok(lastWipedProbe > failClosed);
  assert.ok(lastWipedProbe > failClosed);
  const failClosedCopy = checkpoint.indexOf(
    '0,\n        "Stale route page rendered a copy control",',
    lastWipedProbe,
  );
  assert.ok(failClosedCopy > lastWipedProbe);
  // The reload is never driven through extension APIs, CDP navigation or page
  // injection: no reload expression, no chrome.tabs, no Page.* reload.
  for (const forbidden of [
    /routeReloadExpression/,
    /chrome\.tabs/,
    /Page\.navigate/,
    /Page\.reload/,
    /addInitScript/,
  ])
    assert.doesNotMatch(source, forbidden);
  assert.doesNotMatch(checkpoint, /\broute\.evaluate\("[^"]*reload/i);
  // 4. Every browser key goes through one helper: the X11 helper's exact
  //    title-prefix form, the exact launched Chromium executable and one
  //    single-shot action list. No prefix form or popup key remains.
  assert.match(
    source,
    /const chromiumExecutable = realpathSync\(chromium\.executablePath\(\)\);/,
  );
  assert.match(
    source,
    /function browserKey\(actions, titlePrefix\) \{\n\s+assert\(\n\s+titlePrefix === ROUTE_TITLE_PREFIX \|\|\n\s+titlePrefix === SOURCE_TITLE_PREFIX,\n\s+"Unsupported browser key target",\n\s+\);/,
  );
  assert.match(
    source,
    /const request = \{ title_prefix: titlePrefix, executable: chromiumExecutable, actions \};/,
  );
  assert.doesNotMatch(source, /title_prefix: browserWindowTitle|, false\);/);
  assert.match(
    source.slice(source.indexOf("function input("), source.indexOf("nativeInput = input;")),
    /assert\(native !== false, "Native window input only"\);/,
  );
  // Each key is addressed to the title of the tab that is ACTIVE when it is
  // sent: the active route page ("Locklark") for the switch away and the
  // Control_L+r reload, the source page for the return and the popup Escape /
  // open keys. Every call is a single fixed action array, exactly once.
  for (const [key, prefix] of [
    ["ROUTE_SWITCH_SOURCE", "ROUTE_TITLE_PREFIX"],
    ["ROUTE_RETURN", "SOURCE_TITLE_PREFIX"],
    ["ROUTE_RELOAD", "ROUTE_TITLE_PREFIX"],
    ['[{ key: "Escape" }]', "SOURCE_TITLE_PREFIX"],
    ['[{ key: "Control_L+Shift_L+y" }]', "SOURCE_TITLE_PREFIX"],
  ]) {
    const literal = "browserKey(" + key + ", " + prefix + ");";
    const call = new RegExp(literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
    assert.equal(countMatches(source, call), 1, literal);
  }
  const browserCalls = [...source.matchAll(/browserKey\((\[[^\n]*?\]|ROUTE_\w+), (\w+)\);/g)]
    .map((match) => match[1] + " -> " + match[2]);
  assert.deepEqual(browserCalls.sort((a, b) => a.localeCompare(b)), [
    "[{ key: \"Control_L+Shift_L+y\" }] -> SOURCE_TITLE_PREFIX",
    "[{ key: \"Escape\" }] -> SOURCE_TITLE_PREFIX",
    "ROUTE_RELOAD -> ROUTE_TITLE_PREFIX",
    "ROUTE_RETURN -> SOURCE_TITLE_PREFIX",
    "ROUTE_SWITCH_SOURCE -> ROUTE_TITLE_PREFIX",
  ]);
  assert.doesNotMatch(checkpoint, /input\(/);
  // 5. The native no-prompt check is a real, exact-title read-only inspection
  //    of the native window: inspect + preserve_focus, no actions, and it
  //    never swallows a failure. The old absence mode is gone.
  assert.match(
    source,
    /input\(\[\], true, \{\n\s+inspect: true,\n\s+title: ROUTE_NATIVE_TITLE,\n\s+preserve_focus: true,\n\s+\}\);/,
  );
  assert.equal(countMatches(source, /title: ROUTE_NATIVE_TITLE,/g), 1);
  assert.match(source, /^const ROUTE_NATIVE_TITLE = "Locklark · 浏览器原生确认";$/m);
  const inspection = at("nativeInspection()[ROUTE_COPY_REVIEW_LABEL]");
  assert.ok(inspection > failClosed);
  assert.doesNotMatch(
    checkpoint,
    /"absent"|\babsent:|\babsent\?|wait_absent|controls\?\.present !== true|\?\? true/,
  );
  // `present` without a reported state is the absent-or-non-actionable case,
  // never a prompt.
  assert.match(
    source,
    /const offered =\n\s+control\?\.present === true &&\n\s+\(control\.enabled === true \|\| control\.showing === true\);\n\s+if \(offered\) throw Error\("Native route prompt is still present"\);/,
  );
  assert.match(checkpoint, /Native route prompt is still present/);
  assert.match(checkpoint, /Date\.now\(\) \+ ROUTE_NATIVE_ABSENT_LIMIT/);
  assert.match(source, /function nativeInspection\(\) \{/);
  // The whole helper body: brace-matched from its declaration.
  const helperStart = source.indexOf("function nativeInspection()");
  let depth = 0,
    helperEnd = -1;
  for (let index = source.indexOf("{", helperStart); index >= 0; index++) {
    if (source[index] === "{") depth++;
    if (source[index] === "}" && --depth === 0) {
      helperEnd = index + 1;
      break;
    }
  }
  const inspectionHelper = source.slice(helperStart, helperEnd);
  assert.match(inspectionHelper, /throw Error\("Native no-prompt snapshot unavailable"\);/);
  assert.doesNotMatch(inspectionHelper, /catch|\?\? \{\}|\|\| \{\}/);
  // 6. The visible Copy assertion and the reviewed physical mouse wrapper run
  //    in that order; the wrapper's own fixed pre-dispatch rejection is the
  //    only mouse probe. No injected counter or trusted-event page probe.
  const mouseClick = at("await stale.click(ROUTE_COPY_FIELD_SELECTOR);");
  const absentCopy = checkpoint.indexOf(
    'await stale.count(ROUTE_COPY_FIELD_SELECTOR),\n        0,\n        "Stale route page rendered a copy control",',
  );
  assert.ok(
    absentCopy > failClosed && absentCopy < mouseClick,
    "the missing Copy element is proven before the mouse click",
  );
  assert.doesNotMatch(
    checkpoint.slice(absentCopy, mouseClick),
    /route\.evaluate\(/,
    "no page check runs between the Copy assertion and the mouse probe",
  );
  assert.equal(
    countMatches(checkpoint, /await stale\.click\(ROUTE_COPY_FIELD_SELECTOR\);/g),
    1,
  );
  assert.match(checkpoint, /rejected === "Popup control must be available"/);
  assert.doesNotMatch(source, /ROUTE_INPUT_COUNT_PROBE|__locklarkRouteInputCount|isTrusted|inputEvents/);
  assert.match(source, /^const ROUTE_COPY_FIELD_SELECTOR =\n  '\[data-field-id="password"\] \[data-action="copy-field"\]';$/m);
  const wrapper = source.slice(
    source.indexOf("click: async (selector) => {"),
    source.indexOf("\n      },", source.indexOf("click: async (selector) => {")),
  );
  assert.match(wrapper, /document\.visibilityState!=="visible"/);
  assert.match(wrapper, /Popup control must be available/);
  assert.ok(wrapper.indexOf("Popup control must be available") < wrapper.indexOf('type: "mousePressed"'));
  // No DOM event, worker message or target navigation is invented.
  for (const forbidden of [
    /dispatchEvent/,
    /tabs\.onActivated/,
    /relayMessage/,
    /postMessage/,
    /sendMessage/,
    /bringToFront/,
    /\.focus\(/,
    /click_label/,
    /wait_label/,
  ])
    assert.doesNotMatch(checkpoint, forbidden);
  // The DOM probes return only fixed booleans and enums.
  const helpers = routeRevocationHelpers(source).code;
  const probes = helpers.slice(
    helpers.indexOf("const ROUTE_PAGE_STATE ="),
    helpers.indexOf("// Route field-copy acceptance."),
  );
  const returned = new Set(
    [...probes.matchAll(/^\s{4,6}([a-zA-Z]+):/gm)].map((match) => match[1]),
  );
  assert.deepEqual([...returned].sort(), [
    "closed",
    "copyAbsent",
    "detailHidden",
    "fieldsEmpty",
    "fixtureAbsent",
    "statusKind",
    "titleEmpty",
    "visible",
  ]);
  assert.doesNotMatch(probes, /\b(title|value|url|token|count|id|text):/);
  // Nothing in the revocation path is logged, and the only diagnostics it adds
  // to a failure report are fixed booleans.
  const consoleLines = checkpoint.match(/console\.(log|error|warn)\(([^;]*)\);/g) || [];
  for (const line of consoleLines) assert.doesNotMatch(line, /fixture|routeTarget|targetId/);
  assert.match(source, /routeMouseRejected: \{\n\s+rejected: routeMouseRejected\.rejected === true,\n\s+\},/);
  assert.doesNotMatch(source, /routeGrant|sanitizeRouteGrantObservation|observeRouteGrantWindows|ROUTE_GRANT/);
  // The existing positive journey is untouched: the same route target is the
  // one page, the copy stays physical and the private pipe still decides.
  const copyProof = source.slice(
    source.indexOf('mark("route:native-approve")'),
    source.indexOf("// Route revocation checkpoint: the same tab and target"),
  );
  assert.match(copyProof, /await route\.click\(ROUTE_COPY_FIELD_SELECTOR\);/);
  assert.match(copyProof, /OS clipboard did not receive the approved field/);
  assert.match(copyProof, /Native field disclosure did not appear/);
  assert.match(copyProof, /Route detail did not survive native approval/);
});

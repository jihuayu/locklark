// Pure fixture and driver-order tests for the checkout acceptance module.
// These run without a browser, native host or private vault fixture.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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

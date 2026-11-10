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
} from "./browser_checkout_acceptance.mjs";

const TOP_ORIGIN = "https://login.locklark.test:8443";
const CARD_ORIGIN = "https://checkout.locklark.test:8443";
const OTHER_ORIGIN = "https://checkout.other.test:8443";
const TOP_LABEL = TOP_ORIGIN + "（当前页面）";
const FRAME_SUFFIX = "（页面中的表单框架）";

function countMatches(text, pattern) {
  return (text.match(pattern) || []).length;
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

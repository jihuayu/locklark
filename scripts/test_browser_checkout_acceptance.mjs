// Pure fixture and driver-order tests for the checkout acceptance module.
// These run without a browser, native host or private vault fixture.
import test from "node:test";
import assert from "node:assert/strict";
import {
  checkoutTopHTML,
  checkoutCardHTML,
  checkoutFrameOrigin,
  checkoutSameOrigin,
  checkoutRouteCase,
  chooseChildOrigin,
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

function pickerPopup(labels, options = {}) {
  const state = { open: true };
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
const eventually = async (check, message) => {
  assert.equal(await check(), true, message);
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

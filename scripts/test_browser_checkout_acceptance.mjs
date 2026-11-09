// Pure fixture and driver-order tests for the checkout acceptance module.
// These run without a browser, native host or private vault fixture.
import test from "node:test";
import assert from "node:assert/strict";
import {
  checkoutTopHTML,
  checkoutCardHTML,
  checkoutFrameOrigin,
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
  assert.deepEqual(checkoutRouteCase("/card"), { kind: "card" });
  assert.deepEqual(checkoutRouteCase("/card?changed"), { kind: "card" });
  assert.deepEqual(checkoutRouteCase("/login"), { kind: "other" });
  for (const bad of [
    "/checkout?variant=hidden",
    "/checkout?variant=cross-site&variant=sandbox",
    "/checkout?case=approve",
    "/checkout?variant=sandbox&case=deny",
    "/card?other",
    "/checkout?variant=cross-site&extra=1",
  ])
    assert.throws(() => checkoutRouteCase(bad), /checkout/i);
});

function pickerPopup(labels) {
  return {
    clicked: [],
    async click(selector) {
      this.clicked.push(selector);
    },
    async visible(selector) {
      return selector === "#checkout-picker";
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
      return selector.includes('button[data-action="checkout-select"]')
        ? labels.length
        : 0;
    },
  };
}

const eventually = async (check) => {
  assert.equal(await check(), true);
};

test("physical choice uses the exact public origin label, not an ordinal", async () => {
  const popup = pickerPopup([
    TOP_LABEL,
    CARD_ORIGIN + FRAME_SUFFIX,
    OTHER_ORIGIN + FRAME_SUFFIX,
  ]);
  assert.equal(
    await chooseChildOrigin(popup, TOP_ORIGIN, OTHER_ORIGIN, eventually),
    true,
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
  assert.equal(
    await chooseChildOrigin(reordered, TOP_ORIGIN, OTHER_ORIGIN, eventually),
    true,
  );
  assert.deepEqual(reordered.clicked, [
    "#detail-fill",
    '#checkout-choices button[data-action="checkout-select"]:nth-child(2)',
  ]);
});

test("missing or duplicate public origins are never guessed or forced", async () => {
  const missing = pickerPopup([TOP_LABEL, CARD_ORIGIN + FRAME_SUFFIX]);
  assert.equal(
    await chooseChildOrigin(missing, TOP_ORIGIN, OTHER_ORIGIN, eventually),
    false,
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

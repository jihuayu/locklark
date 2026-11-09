// Explicit cross-origin checkout acceptance: same-site top page plus an
// embedded card form served from checkout.locklark.test. The caller supplies
// the real browser page, popup adapter, native X11 input helper and the
// private synthetic fixture. This module never dispatches extension runtime
// messages, never asks for a Session approval directly and never submits a
// form. It only performs trusted pointer/click and native-label actions.
import assert from "node:assert/strict";

const CHECKOUT_DEFAULT_HOST = "checkout.locklark.test";
const CHECKOUT_CROSS_SITE_HOST = "checkout.other.test";
const CHECKOUT_HOSTS = new Set([
  CHECKOUT_DEFAULT_HOST,
  CHECKOUT_CROSS_SITE_HOST,
]);
const CHECKOUT_APPROVE_LABEL = "批准本次跨源银行卡填充";
const CHECKOUT_DENY_LABEL = "拒绝本次跨源银行卡填充";
const CHECKOUT_FRAME_LABEL = "（页面中的表单框架）";
const MONTH_OPTIONS = Array.from({ length: 12 }, (_, index) => {
  const value = String(index + 1).padStart(2, "0");
  return '<option value="' + value + '">' + value + "</option>";
}).join("");
const YEAR_OPTIONS = Array.from(
  { length: 15 },
  (_, index) => String(2026 + index),
)
  .map((value) => '<option value="' + value + '">' + value + "</option>")
  .join("");

function checkoutPort(port) {
  const text = String(port == null ? "" : port);
  assert(
    /^[1-9][0-9]{0,4}$/.test(text) && Number(text) <= 65535,
    "Ephemeral checkout HTTPS port required",
  );
  return text;
}

// Only the two synthetic hosts and the optional sandbox attribute are
// accepted. A caller cannot inject an arbitrary iframe source or sandbox
// tokens through the acceptance fixture.
export function checkoutVariant(options = {}) {
  assert(
    options && typeof options === "object" && !Array.isArray(options),
    "Checkout top variant must be an object",
  );
  for (const key of Object.keys(options))
    assert(
      key === "host" || key === "sandbox",
      "Unsupported checkout top variant option",
    );
  const host =
    options.host === undefined ? CHECKOUT_DEFAULT_HOST : options.host;
  assert(CHECKOUT_HOSTS.has(host), "Unsupported checkout card host");
  const sandbox = options.sandbox === undefined ? false : options.sandbox;
  assert(
    typeof sandbox === "boolean",
    "Checkout sandbox variant must be boolean",
  );
  return { host, sandbox };
}

function checkoutFrameSource(port, options = {}) {
  const { host } = checkoutVariant(options);
  return "https://" + host + ":" + checkoutPort(port) + "/card";
}

// The top page is same-site but cross-origin with the card frame. Both forms
// are ordinary DOM forms: no product hook, no synthetic runtime message. The
// optional variants are limited to an allowlisted card host and the exact
// opaque-origin sandbox token `allow-scripts` (never `allow-same-origin`).
export function checkoutTopHTML(port, options = {}) {
  const { sandbox } = checkoutVariant(options);
  const frameSource = checkoutFrameSource(port, options);
  const sandboxAttribute = sandbox ? ' sandbox="allow-scripts"' : "";
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    "<title>Locklark acceptance · checkout</title>" +
    "<style>body{font-family:sans-serif;margin:1rem}" +
    "label{display:block;margin:.5rem 0}" +
    "input,select{display:block;width:20rem;padding:.3rem}" +
    "iframe{width:30rem;height:26rem;border:1px solid #999}</style></head><body>" +
    "<h1>Checkout top</h1>" +
    '<form id="checkout-card-top" method="post">' +
    '<label>Cardholder name<input id="top-cc-name" autocomplete="cc-name"></label>' +
    '<label>Card number<input id="top-cc-number" autocomplete="cc-number"></label>' +
    '<label>Expiry month<select id="top-cc-exp-month" autocomplete="cc-exp-month">' +
    '<option value="">Month</option>' +
    MONTH_OPTIONS +
    "</select></label>" +
    '<label>Expiry year<select id="top-cc-exp-year" autocomplete="cc-exp-year">' +
    '<option value="">Year</option>' +
    YEAR_OPTIONS +
    "</select></label>" +
    '<label>Security code<input id="top-cc-csc" autocomplete="cc-csc"></label>' +
    '<label>PIN<input id="top-card-pin" name="card-pin" type="password" autocomplete="off"></label>' +
    '<button type="submit">Pay</button></form>' +
    '<iframe id="checkout-card-frame" title="Checkout card form"' +
    sandboxAttribute +
    ' src="' +
    frameSource +
    '"></iframe>' +
    "<script>window.submits=0;document.getElementById('checkout-card-top')" +
    ".addEventListener('submit',function(event){event.preventDefault();" +
    "window.submits++;});</script></body></html>"
  );
}

// The child document mirrors only the approved card selectors. Its PIN input
// intentionally has no autocomplete token, so a native card projection can
// never fill it. Expiry month/year are SELECT elements on purpose.
export function checkoutCardHTML() {
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    "<title>Locklark checkout card frame</title>" +
    "<style>body{font-family:sans-serif;margin:1rem}" +
    "label{display:block;margin:.5rem 0}" +
    "input,select{display:block;width:18rem;padding:.3rem}</style></head><body>" +
    "<h1>Card frame</h1>" +
    '<form id="checkout-card-frame-form" method="post">' +
    '<label>Cardholder name<input id="cc-name" autocomplete="cc-name"></label>' +
    '<label>Card number<input id="cc-number" autocomplete="cc-number"></label>' +
    '<label>Expiry month<select id="cc-exp-month" autocomplete="cc-exp-month">' +
    '<option value="">Month</option>' +
    MONTH_OPTIONS +
    "</select></label>" +
    '<label>Expiry year<select id="cc-exp-year" autocomplete="cc-exp-year">' +
    '<option value="">Year</option>' +
    YEAR_OPTIONS +
    "</select></label>" +
    '<label>Security code<input id="cc-csc" autocomplete="cc-csc"></label>' +
    '<label>PIN<input id="card-pin" name="card-pin" type="password" autocomplete="off"></label>' +
    '<button type="submit">Pay</button></form>' +
    "<script>window.submits=0;document.getElementById('checkout-card-frame-form')" +
    ".addEventListener('submit',function(event){event.preventDefault();" +
    "window.submits++;});</script></body></html>"
  );
}

export function checkoutFrameOrigin(topOrigin, options = {}) {
  let parsed;
  try {
    parsed = new URL(String(topOrigin || ""));
  } catch {
    throw Error("Checkout top origin must be an ephemeral HTTPS origin");
  }
  assert(
    parsed.protocol === "https:" && parsed.port,
    "Checkout top origin must be an ephemeral HTTPS origin",
  );
  const { host } = checkoutVariant(options);
  return "https://" + host + ":" + parsed.port;
}

// The local HTTPS fixture routes only the exact acceptance paths and query
// cases. Unknown paths fall through to the ordinary login fixture; unknown
// checkout variants/cases are refused instead of being silently treated as
// the default journey.
export function checkoutRouteCase(requestURL) {
  const url = new URL(String(requestURL == null ? "/" : requestURL),
    "https://checkout.route.invalid");
  if (url.pathname === "/card") {
    for (const key of url.searchParams.keys())
      assert(key === "changed", "Unsupported checkout card request");
    return { kind: "card" };
  }
  if (url.pathname !== "/checkout") return { kind: "other" };
  const variants = url.searchParams.getAll("variant");
  assert(variants.length <= 1, "Duplicate checkout variant");
  if (variants.length === 1) {
    for (const key of url.searchParams.keys())
      assert(key === "variant", "Unsupported checkout request");
    if (variants[0] === "cross-site")
      return { kind: "checkout", options: { host: CHECKOUT_CROSS_SITE_HOST } };
    if (variants[0] === "sandbox")
      return { kind: "checkout", options: { sandbox: true } };
    assert(false, "Unknown checkout variant");
  }
  const cases = url.searchParams.getAll("case");
  assert(cases.length <= 1, "Duplicate checkout case");
  for (const key of url.searchParams.keys())
    assert(key === "case", "Unsupported checkout request");
  if (cases.length === 1)
    assert(
      cases[0] === "deny" || cases[0] === "stale",
      "Unknown checkout case",
    );
  return { kind: "checkout", options: {} };
}

function checkedFixture(fixture) {
  assert(
    fixture && /^[a-f0-9]{32}$/.test(fixture.CardID || ""),
    "Synthetic checkout card ID missing",
  );
  assert(
    /^[a-f0-9]{64}$/.test(fixture.CardRevision || ""),
    "Synthetic checkout card revision missing",
  );
  for (const key of [
    "CardTitle",
    "CardNumber",
    "CardHolder",
    "CardVerification",
    "CardExpiry",
    "CardPIN",
  ])
    assert(
      typeof fixture[key] === "string" && fixture[key].length > 0,
      "Synthetic checkout card fixture is incomplete",
    );
  assert(
    /^[0-9]{4}-[0-9]{2}$/.test(fixture.CardExpiry),
    "Synthetic checkout card expiry missing",
  );
  return fixture;
}

// Runs in the page or the child frame. It returns only form state and public
// control tags; the caller never logs the private values it compares.
function readCheckoutForm(prefix) {
  const top = prefix === "top";
  const formID = top ? "checkout-card-top" : "checkout-card-frame-form";
  const ids = top
    ? {
        name: "top-cc-name",
        number: "top-cc-number",
        month: "top-cc-exp-month",
        year: "top-cc-exp-year",
        csc: "top-cc-csc",
        pin: "top-card-pin",
      }
    : {
        name: "cc-name",
        number: "cc-number",
        month: "cc-exp-month",
        year: "cc-exp-year",
        csc: "cc-csc",
        pin: "card-pin",
      };
  const values = {},
    visible = {},
    tags = {};
  for (const key of Object.keys(ids)) {
    const element = document.getElementById(ids[key]);
    values[key] =
      element && typeof element.value === "string" ? element.value : null;
    visible[key] = !!(
      element &&
      typeof element.getClientRects === "function" &&
      element.getClientRects().length > 0
    );
    tags[key] = element && element.tagName ? String(element.tagName) : "";
  }
  return {
    formPresent: !!document.getElementById(formID),
    values,
    visible,
    tags,
    submits: typeof window.submits === "number" ? window.submits : -1,
  };
}

function cardFrame(page, frameOrigin) {
  return page
    .frames()
    .find(
      (frame) =>
        frame.url() === frameOrigin + "/card" ||
        frame.url().startsWith(frameOrigin + "/card?"),
    );
}

async function childFormState(page, frameOrigin) {
  const frame = cardFrame(page, frameOrigin);
  if (!frame) return null;
  try {
    return await frame.evaluate(readCheckoutForm, "frame");
  } catch {
    return null;
  }
}

async function topFormState(page) {
  return page.evaluate(readCheckoutForm, "top");
}

// CDP exposes the browser's own loader id for the frame document. The stale
// case uses it to prove the changed child is a replacement document, not just
// a URL string changed in place.
async function childDocumentIdentity(page, frameURL) {
  const session = await page.context().newCDPSession(page);
  try {
    const { frameTree } = await session.send("Page.getFrameTree");
    const stack = [frameTree];
    while (stack.length) {
      const node = stack.pop();
      if (node?.frame?.url === frameURL)
        return {
          loaderId: node.frame.loaderId,
          url: node.frame.url,
        };
      for (const child of node?.childFrames || []) stack.push(child);
    }
    return null;
  } finally {
    await session.detach();
  }
}

function everyBlank(state) {
  return (
    !!state &&
    state.formPresent === true &&
    Object.values(state.values).every((value) => value === "")
  );
}

function noSubmit(state) {
  return !!state && state.submits === 0;
}

function expiryMatches(fixture, state) {
  const parts = fixture.CardExpiry.split("-");
  return (
    !!state &&
    state.values.month === parts[1] &&
    state.values.year === parts[0]
  );
}

function cardMatches(fixture, state) {
  return (
    !!state &&
    state.values.name === fixture.CardHolder &&
    state.values.number === fixture.CardNumber &&
    state.values.csc === fixture.CardVerification &&
    expiryMatches(fixture, state)
  );
}

function fieldsVisible(state) {
  return (
    !!state &&
    state.formPresent === true &&
    Object.values(state.visible).every((value) => value === true)
  );
}

async function assertBothBlank(page, frameOrigin, message) {
  const top = await topFormState(page);
  const child = await childFormState(page, frameOrigin);
  assert(everyBlank(top) && everyBlank(child), message);
  assert(noSubmit(top) && noSubmit(child), "Checkout forms must not submit");
}

async function assertControls(page, frameOrigin) {
  const top = await topFormState(page);
  const child = await childFormState(page, frameOrigin);
  assert(fieldsVisible(top), "Top checkout card fields must be visible");
  assert(fieldsVisible(child), "Checkout card frame fields must be visible");
  assert(
    child.tags.month === "SELECT" && child.tags.year === "SELECT",
    "Checkout expiry controls must be selects",
  );
}

async function assertOnlyChildFilled(page, frameOrigin, fixture) {
  const top = await topFormState(page);
  const child = await childFormState(page, frameOrigin);
  assert(
    cardMatches(fixture, child),
    "Child checkout card fields were not filled",
  );
  assert(everyBlank(top), "Top checkout form received a card value");
  assert(child.values.pin === "", "Checkout PIN must stay blank");
  assert(noSubmit(top) && noSubmit(child), "Checkout forms must not submit");
}

function nativeControls(input) {
  try {
    // A refused cross-site proposal or a sandbox-excluded page has no native
    // window at all. The native probe waits for its bounded discovery deadline
    // and reports that absence as a read-only result; no input is emitted.
    return input([], true, true)?.controls || null;
  } catch {
    return null;
  }
}

function nativeControl(controls, label) {
  const control = controls?.[label];
  return {
    present: control?.present === true,
    enabled: control?.enabled === true,
    showing: control?.showing === true,
  };
}

// Read-only native accessibility snapshot: no click, wait or text action is
// emitted. Both checkout decisions must be absent before any approval exists.
function assertNoNativeApproval(input) {
  const controls = nativeControls(input);
  for (const label of [CHECKOUT_APPROVE_LABEL, CHECKOUT_DENY_LABEL]) {
    const control = nativeControl(controls, label);
    assert(
      !control.enabled && !control.showing,
      "Checkout native approval must not be available",
    );
  }
}

// Opens the synthetic card from the vault list by its exact item id, then
// waits for the detail action that starts the real frame picker.
async function openCardDetail(popup, fixture, eventually) {
  assert(
    (await popup.disabled("#refresh")) === false,
    "Checkout popup is not connected",
  );
  assert(
    (await popup.count('#filter-tabs [data-filter="credit_card"]')) === 1,
    "Checkout card filter unavailable",
  );
  await popup.click('#filter-tabs [data-filter="credit_card"]');
  const row = '#vault-list [data-item-id="' + fixture.CardID + '"]';
  await eventually(
    async () => (await popup.count(row)) === 1,
    "Synthetic checkout card missing from the vault",
  );
  assert(
    (await popup.attribute(row, "data-item-revision")) === fixture.CardRevision,
    "Checkout card revision mismatch",
  );
  assert(
    (await popup.attribute(row, "data-category")) === "credit_card",
    "Checkout card category mismatch",
  );
  await popup.click(row);
  await eventually(
    async () => (await popup.text("#detail-title")) === fixture.CardTitle,
    "Synthetic checkout card detail did not open",
  );
  await eventually(
    async () =>
      (await popup.attribute("#detail-fill", "data-checkout")) === "1" &&
      (await popup.disabled("#detail-fill")) === false,
    "Checkout form picker control unavailable",
  );
  assert(
    ((await popup.text("#detail-fill")) || "").includes("选择结账表单并填充"),
    "Checkout form picker label missing",
  );
}

// Explicitly locate the non-top origin button by its exact public origin
// label, then use the popup adapter's trusted pointer click on that exact
// selector. No frame is chosen automatically, no ordinal position is assumed
// and no runtime message is synthesized. Returns false when the expected
// origin is absent from the public picker so the caller can prove exclusion.
export async function chooseChildOrigin(
  popup,
  topOrigin,
  frameOrigin,
  eventually,
) {
  await popup.click("#detail-fill");
  await eventually(
    async () => (await popup.visible("#checkout-picker")) === true,
    "Checkout origin picker missing",
  );
  assert(
    (await popup.text("#checkout-current-page")) ===
      "当前页面来源：" + topOrigin,
    "Checkout top origin mismatch",
  );
  assert(
    ((await popup.text("#checkout-status")) || "").includes("不会自动选择"),
    "Checkout picker must not auto-select a frame",
  );
  const total = await popup.count(
    '#checkout-choices button[data-action="checkout-select"]',
  );
  assert(total >= 1, "Checkout origin picker is incomplete");
  const matches = [];
  for (let index = 1; index <= total; index++) {
    const selector =
      '#checkout-choices button[data-action="checkout-select"]:nth-child(' +
      index +
      ")";
    if ((await popup.text(selector)) === frameOrigin + CHECKOUT_FRAME_LABEL)
      matches.push(index);
  }
  assert(
    matches.length <= 1,
    "Expected exactly one explicit checkout child origin",
  );
  if (!matches.length) return false;
  await popup.click(
    '#checkout-choices button[data-action="checkout-select"]:nth-child(' +
      matches[0] +
      ")",
  );
  return true;
}

async function runDefaultJourneys(driver, card, topOrigin, frameOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;

  phase("checkout-approve:blank");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Checkout card frame did not load",
  );
  await assertControls(page, frameOrigin);
  await assertBothBlank(page, frameOrigin, "Checkout forms must stay blank");

  let popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  assert(
    await chooseChildOrigin(popup, topOrigin, frameOrigin, eventually),
    "Expected exactly one explicit checkout child origin",
  );
  input([{ wait_label: CHECKOUT_APPROVE_LABEL }]);
  phase("checkout-approve:native-review");
  await assertBothBlank(
    page,
    frameOrigin,
    "Checkout forms changed before native approval",
  );
  phase("checkout-approve:approve");
  input([{ click_label: CHECKOUT_APPROVE_LABEL }]);
  await eventually(
    async () => cardMatches(card, await childFormState(page, frameOrigin)),
    "Approved checkout fill did not reach the child frame",
  );
  await assertOnlyChildFilled(page, frameOrigin, card);

  // The deny case uses a fresh top document so the previous approval and its
  // document identity cannot be reused. No value may be written.
  phase("checkout-deny:navigation");
  await page.goto(topOrigin + "/checkout?case=deny");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Fresh checkout card frame did not load",
  );
  await assertBothBlank(
    page,
    frameOrigin,
    "Fresh checkout forms must stay blank",
  );
  popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  assert(
    await chooseChildOrigin(popup, topOrigin, frameOrigin, eventually),
    "Expected exactly one explicit checkout child origin",
  );
  input([{ wait_label: CHECKOUT_APPROVE_LABEL }]);
  phase("checkout-deny:native-review");
  await assertBothBlank(
    page,
    frameOrigin,
    "Checkout forms changed before native refusal",
  );
  phase("checkout-deny:refuse");
  input([{ click_label: CHECKOUT_DENY_LABEL }]);
  await new Promise((resolve) => setTimeout(resolve, 500));
  await assertBothBlank(
    page,
    frameOrigin,
    "Refused checkout fill wrote a value",
  );
}

// A cross-site (different eTLD+1) child may be physically offered by the
// browser's public frame metadata. The native PSL policy must refuse it before
// any approval window, or the picker policy must omit it; either way no card
// value, PIN or submission may appear and an available picker is cancelled.
async function runCrossSiteJourney(driver, card, topOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;
  const frameOrigin = checkoutFrameOrigin(topOrigin, {
    host: CHECKOUT_CROSS_SITE_HOST,
  });
  phase("checkout-cross-site:navigation");
  await page.goto(topOrigin + "/checkout?variant=cross-site");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Checkout card frame did not load",
  );
  await assertControls(page, frameOrigin);
  await assertBothBlank(
    page,
    frameOrigin,
    "Cross-site checkout forms must stay blank",
  );

  const popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  phase("checkout-cross-site:picker");
  const selected = await chooseChildOrigin(
    popup,
    topOrigin,
    frameOrigin,
    eventually,
  );
  if (!selected) {
    phase("checkout-cross-site:excluded");
    assert(
      ((await popup.text("#checkout-status")) || "").includes("不会自动选择"),
      "Excluded checkout origin must not be auto-selected",
    );
    assertNoNativeApproval(input);
    await popup.click("#checkout-cancel");
    await eventually(
      async () => (await popup.visible("#checkout-picker")) === false,
      "Checkout picker cancel did not close",
    );
    await assertBothBlank(
      page,
      frameOrigin,
      "Excluded cross-site checkout wrote a value",
    );
    return;
  }
  phase("checkout-cross-site:native-review");
  // A same-site card listing is allowed, so the cross-site proposal reaches
  // the native host and must be refused there without an approval dialog.
  // Wait for the popup's public terminal status first: a still-pending native
  // review would not reach one of these fixed outcomes.
  await eventually(
    async () => {
      const status = String((await popup.text("#status")) || "");
      return (
        status.includes("未完成") ||
        status.includes("拒绝") ||
        status.includes("已取消") ||
        status.includes("已变化")
      );
    },
    "Cross-site checkout refusal did not finish",
    8000,
  );
  assertNoNativeApproval(input);
  await assertBothBlank(
    page,
    frameOrigin,
    "Cross-site checkout received a value without approval",
  );
}

// `sandbox="allow-scripts"` (without allow-same-origin) makes the child an
// opaque origin. The content-script fence latches the sandbox attribute on the
// top document, so the frame metadata probe must exclude the whole page rather
// than offer a candidate. This path never fabricates DOM permissions or
// evaluates a frame hook.
async function runSandboxJourney(driver, card, topOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;
  const frameOrigin = checkoutFrameOrigin(topOrigin, { sandbox: true });
  phase("checkout-sandbox:navigation");
  await page.goto(topOrigin + "/checkout?variant=sandbox");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Checkout card frame did not load",
  );
  await assertControls(page, frameOrigin);
  await assertBothBlank(
    page,
    frameOrigin,
    "Sandboxed checkout forms must stay blank",
  );

  const popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  phase("checkout-sandbox:picker");
  await popup.click("#detail-fill");
  await eventually(
    async () => {
      const status = String((await popup.text("#status")) || "");
      return status.includes("拒绝") || status.includes("不支持");
    },
    "Sandboxed checkout picker request did not finish",
    8000,
  );
  assert(
    (await popup.visible("#checkout-picker")) !== true,
    "Checkout sandboxed child must be excluded from the picker",
  );
  assert(
    (await popup.count('#checkout-choices button')) === 0,
    "Checkout sandboxed child must be excluded from the picker",
  );
  assertNoNativeApproval(input);
  await assertBothBlank(
    page,
    frameOrigin,
    "Sandboxed checkout received a value without approval",
  );
}

// The valid child was selected and its native approval was visible. Replace
// the child with a same-origin /card?changed document, then make exactly one
// old approval attempt if the stale control is still available. The extension
// document guard and native single-use reservation must leave the new child,
// top form and PIN blank with no automatic retry or replacement approval.
async function runStaleDocumentJourney(driver, card, topOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;
  const frameOrigin = checkoutFrameOrigin(topOrigin);
  phase("checkout-stale:navigation");
  await page.goto(topOrigin + "/checkout?case=stale");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Checkout card frame did not load",
  );
  await assertControls(page, frameOrigin);
  await assertBothBlank(
    page,
    frameOrigin,
    "Fresh checkout forms must stay blank",
  );

  let popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  assert(
    await chooseChildOrigin(popup, topOrigin, frameOrigin, eventually),
    "Expected exactly one explicit checkout child origin",
  );
  input([{ wait_label: CHECKOUT_APPROVE_LABEL }]);
  phase("checkout-stale:native-review");
  await assertBothBlank(
    page,
    frameOrigin,
    "Checkout forms changed before native approval",
  );

  const before = await childDocumentIdentity(page, frameOrigin + "/card");
  assert(before?.loaderId, "Checkout child document identity missing");
  phase("checkout-stale:child-navigation");
  const frame = cardFrame(page, frameOrigin);
  assert(frame, "Checkout card frame did not load");
  await frame.goto(frameOrigin + "/card?changed");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Changed checkout card frame did not load",
  );
  const after = await childDocumentIdentity(
    page,
    frameOrigin + "/card?changed",
  );
  assert(
    after?.loaderId && after.loaderId !== before.loaderId,
    "Checkout child document was not replaced",
  );

  phase("checkout-stale:old-approval");
  const stale = nativeControl(nativeControls(input), CHECKOUT_APPROVE_LABEL);
  if (stale.enabled && stale.showing)
    input([{ click_label: CHECKOUT_APPROVE_LABEL }]); // Exactly one stale click.
  // The native review owned focus, so reopen only to observe the fixed public
  // status. No fill control is selected and no new approval is requested.
  popup = await openPopup();
  await eventually(
    async () => {
      const status = String((await popup.text("#status")) || "");
      return (
        status.includes("已变化") ||
        status.includes("未完成") ||
        status.includes("已取消")
      );
    },
    "Changed checkout document did not finish",
    8000,
  );
  assertNoNativeApproval(input);
  await assertBothBlank(
    page,
    frameOrigin,
    "Changed checkout document received a value",
  );
}

export async function acceptCheckoutFrames(driver) {
  const { page, origin, input, fixture, openPopup, phase, eventually } = driver;
  assert(
    page &&
      typeof page.goto === "function" &&
      typeof page.frames === "function",
    "Checkout page driver required",
  );
  assert(
    typeof input === "function" &&
      typeof openPopup === "function" &&
      typeof phase === "function" &&
      typeof eventually === "function",
    "Checkout acceptance driver required",
  );
  const card = checkedFixture(fixture);
  const topOrigin = String(origin || "");
  const frameOrigin = checkoutFrameOrigin(topOrigin);
  let parsed;
  try {
    parsed = new URL(page.url());
  } catch {
    throw Error("Checkout top document URL missing");
  }
  assert(
    parsed.pathname === "/checkout",
    "Checkout contact route must be the top document",
  );

  await runDefaultJourneys(driver, card, topOrigin, frameOrigin);
  await runCrossSiteJourney(driver, card, topOrigin);
  await runSandboxJourney(driver, card, topOrigin);
  await runStaleDocumentJourney(driver, card, topOrigin);
}

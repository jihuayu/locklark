// Explicit cross-origin checkout acceptance: same-site top page plus an
// embedded card form served from checkout.locklark.test. The caller supplies
// the real browser page, popup adapter, native X11 input helper and the
// private synthetic fixture. This module never dispatches extension runtime
// messages, never asks for a Session approval directly and never submits a
// form. It only performs trusted pointer/click and native-label actions.
import assert from "node:assert/strict";

const CHECKOUT_DEFAULT_HOST = "checkout.locklark.test";
const CHECKOUT_CROSS_SITE_HOST = "checkout.other.test";
// The same-origin variant's child is the exact top HTTPS origin (same host
// and the same ephemeral port), so every frame on that page shares one origin.
const CHECKOUT_TOP_HOST = "login.locklark.test";
const CHECKOUT_HOSTS = new Set([
  CHECKOUT_DEFAULT_HOST,
  CHECKOUT_CROSS_SITE_HOST,
  CHECKOUT_TOP_HOST,
]);
// The real Chromium journey window is titled "Locklark · 浏览器原生确认".
// Focus-preserving probes match it by that exact title (and executable) only:
// browser_native_x11.py rejects a `title_prefix` on its read-only inspection
// path, and raising/focusing the window would close the open action popup.
const CHECKOUT_APPROVE_LABEL = "批准本次跨源银行卡填充";
const CHECKOUT_DENY_LABEL = "拒绝本次跨源银行卡填充";
// A same-origin child is not a cross-origin proposal: the extension omits the
// checkout assertion and the native owner sees the ordinary card profile
// review. These are different fixed labels on purpose.
const PROFILE_APPROVE_LABEL = "批准本次敏感字段填充";
const PROFILE_DENY_LABEL = "拒绝本次敏感字段填充";
const CHECKOUT_FRAME_LABEL = "（页面中的表单框架）";
// The existing general acceptance locks through these exact native labels.
const LOCK_LABEL = "立即锁定";
const UNLOCK_SCREEN_LABEL = "解锁";
// The only accepted result of the final journey: the real native lock already
// invalidated the session, so the caller must not disconnect a session again.
export const CHECKOUT_LOCKED = Object.freeze({ locked: true });
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

// Only the three synthetic hosts and the optional sandbox attribute are
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
// With the top host the child has the exact top origin (same port); a sandboxed
// same-host child would be an opaque origin, so that combination is refused.
export function checkoutTopHTML(port, options = {}) {
  const { host, sandbox } = checkoutVariant(options);
  assert(
    !(sandbox && host === CHECKOUT_TOP_HOST),
    "Same-origin checkout variant cannot be sandboxed",
  );
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

function checkedTopOrigin(topOrigin) {
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
  return parsed;
}

export function checkoutFrameOrigin(topOrigin, options = {}) {
  const parsed = checkedTopOrigin(topOrigin);
  const { host } = checkoutVariant(options);
  return "https://" + host + ":" + parsed.port;
}

// The same-origin variant's frame must be byte-identical to the top origin and
// served by the exact allowlisted top host. Anything else is refused rather
// than compared loosely.
export function checkoutSameOrigin(topOrigin) {
  const parsed = checkedTopOrigin(topOrigin);
  assert(
    parsed.hostname === CHECKOUT_TOP_HOST &&
      parsed.origin === String(topOrigin),
    "Checkout same-origin variant requires the exact top origin",
  );
  return parsed.origin;
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
    if (variants[0] === "same-origin")
      return { kind: "checkout", options: { host: CHECKOUT_TOP_HOST } };
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
        String(frame.url()).startsWith(frameOrigin + "/card?"),
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

// Probe option for every journey stage that is checked while the popup is
// still open and yet to be clicked.
const POPUP_OPEN = Object.freeze({ popupOpen: true });

// `options.popupOpen` requests the X11 helper's documented exact read-only
// inspection form (`preserve_focus` + `inspect`, no actions): it neither raises
// nor focuses the native window, which would close a Chromium action popup the
// journey is still clicking. It must not carry `title_prefix`: the helper
// accepts only the exact `title` and executable `input` supplies for this path
// and fails closed with "Exact read-only native inspection required"
// otherwise. Other callers keep the default probe. A probe error (unavailable,
// ambiguous or unresponsive window, X11 query failure) propagates: a failed
// probe observed no native UI and must never be read as "both controls
// absent".
function nativeControls(input, options) {
  // Read-only probe: no input is emitted.
  const result = options?.popupOpen
    ? input([], true, {
        preserve_focus: true,
        inspect: true,
      })
    : input([], true, true);
  const controls = result?.controls;
  if (
    !result ||
    typeof result !== "object" ||
    !controls ||
    typeof controls !== "object" ||
    Array.isArray(controls)
  )
    throw Error("Native control snapshot unavailable");
  return controls;
}

function nativeControl(controls, label) {
  const control = controls[label];
  return {
    present: control?.present === true,
    enabled: control?.enabled === true,
    showing: control?.showing === true,
  };
}

// Read-only native accessibility snapshot: no click, wait or text action is
// emitted. Both checkout decisions must be absent before any approval exists,
// and an unavailable native window/control snapshot fails instead of passing.
// `options.popupOpen` keeps the browser popup focused; omitting it uses the
// default probe that raises and focuses the native window.
function assertNoNativeApproval(input, options) {
  const controls = nativeControls(input, options);
  for (const label of [CHECKOUT_APPROVE_LABEL, CHECKOUT_DENY_LABEL]) {
    const control = nativeControl(controls, label);
    assert(
      !control.enabled && !control.showing,
      "Checkout native approval must not be available",
    );
  }
}

// The ordinary card profile review (same-origin child) must not be offered
// either, so no frame picker path can leak into the profile approval. Same
// `options` as `assertNoNativeApproval`.
function assertNoNativeProfileReview(input, options) {
  const controls = nativeControls(input, options);
  for (const label of [PROFILE_APPROVE_LABEL, PROFILE_DENY_LABEL]) {
    const control = nativeControl(controls, label);
    assert(
      !control.enabled && !control.showing,
      "Native profile approval must not be available",
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

// The popup's bounded public status lines that only a card form picker can
// set: the list was offered, the native host refused or does not support the
// picker. "不会自动选择" is deliberately absent: prose is not gesture evidence.
// Each remaining line maps to one fixed enum copied into the failure diagnostic.
const CHECKOUT_PICKER_STATUS = [
  ["不支持选择结账表单", "unsupported"],
  ["无法列出当前页面的结账表单", "list-failed"],
  ["已选择结账表单", "selected"],
  ["已取消本次填充", "cancelled"],
];
// An absent status is "unavailable" and an unrecognised one "other"; a
// recognisable line outside this set is still never echoed.
export const CHECKOUT_PICKER_STATUSES = Object.freeze([
  "no-gesture",
  "unavailable",
  "unsupported",
  "list-failed",
  "selected",
  "cancelled",
  "other",
]);

export const DETAIL_FILL_DIAGNOSTIC_PHASES = Object.freeze([
  "handler-entry",
  "early-guard",
  "gesture-refused",
  "request-sent",
  "reply-null",
  "reply-present",
  "adopt-refused",
  "adopted",
]);

// The harness reads only this fixed test-only record. Entry carries the two
// booleans; every async record carries only its phase. Unknown keys, phases or
// types are discarded rather than echoed.
export function sanitizeDetailFillDiagnostic(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const phases = new Set(DETAIL_FILL_DIAGNOSTIC_PHASES);
  const seen = new Set();
  const result = [];
  for (let index = 0; index < value.length; index++) {
    const record = value[index];
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      return null;
    }
    if (!phases.has(record.phase) || seen.has(record.phase)) return null;
    if (index === 0 && record.phase !== "handler-entry") return null;
    seen.add(record.phase);
    const keys = Object.keys(record);
    if (index === 0) {
      if (
        keys.sort().join(",") !== "isTrusted,phase,userActivation" ||
        typeof record.isTrusted !== "boolean" ||
        typeof record.userActivation !== "boolean"
      ) {
        return null;
      }
      result.push({
        phase: record.phase,
        isTrusted: record.isTrusted,
        userActivation: record.userActivation,
      });
    } else {
      if (keys.length !== 1 || keys[0] !== "phase") return null;
      result.push({ phase: record.phase });
    }
  }
  return result;
}

const DETAIL_FILL_DIAGNOSTIC_ENABLE =
  "(() => { globalThis.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC__ = true; return true; })()";
const DETAIL_FILL_DIAGNOSTIC_READ =
  "(() => globalThis.__LOCKLARK_TEST_DETAIL_FILL_DIAGNOSTIC_LOG__ ?? null)()";

// Requests the metadata frame picker with one explicit trusted pointer click
// on the real "#detail-fill" control. The popup only enumerates frames from a
// trusted gesture with an active user activation, so this control must not be
// clicked programmatically and the click must not be repeated: a second click
// would either be swallowed by the in-flight request or reveal a different
// failure. When no picker appears, the classified public status is attached
// to the same "Checkout origin picker missing" reason as the fixed
// `pickerStatus` enum, so the stage stays diagnosable.
export async function openCheckoutPicker(popup, eventually) {
  if (typeof popup.evaluate === "function") {
    await popup.evaluate(DETAIL_FILL_DIAGNOSTIC_ENABLE);
  }
  await popup.click("#detail-fill");
  let shown = false;
  const pickerMissing = "Checkout origin picker missing";
  try {
    await eventually(async () => {
      shown = (await popup.visible("#checkout-picker")) === true;
      return shown;
    }, pickerMissing);
  } catch (error) {
    let status = "";
    let readable = false;
    try {
      const text = await popup.text("#status");
      readable = text !== null && text !== undefined;
      status = String(text || "");
    } catch {}
    const match = CHECKOUT_PICKER_STATUS.find(([line]) =>
      status.includes(line),
    );
    const known = match ? match[1] : "";
    const pickerStatus = !readable || status === ""
      ? "unavailable"
      : known || "other";
    let pickerDiagnostic = null;
    try {
      if (typeof popup.evaluate === "function") {
        pickerDiagnostic = sanitizeDetailFillDiagnostic(
          await popup.evaluate(DETAIL_FILL_DIAGNOSTIC_READ),
        );
      }
    } catch {}
    assert(!shown, pickerMissing);
    throw Object.assign(
      Error(status
        ? pickerMissing + ": popup status " +
          (known
            ? `${known} (${match[0]})`
            : "other (unrecognised public status)")
        : pickerMissing + ": popup status unavailable"),
      { pickerStatus, pickerDiagnostic },
    );
  }
}

// A DOM `.click()` is dispatched as an ordinary untrusted click on the real
// popup control, from the popup document itself through the popup's CDP
// Runtime. The capture listener only receives the click the page dispatches;
// it never synthesizes a second one. The popup's own gesture check refuses an
// untrusted click before any frame listing is requested, so no picker may be
// shown.
const UNTRUSTED_FILL_CLICK = `(() => {
  const button = document.querySelector("#detail-fill");
  if (!button) return null;
  const seen = [];
  const record = (event) => { seen.push(event.isTrusted === true); };
  button.addEventListener("click", record, { capture: true, once: true });
  try { button.click(); } finally { button.removeEventListener("click", record, true); }
  return seen.length === 1 ? seen[0] : null;
})()`;

// Proves that programmatic activation cannot open the picker. Call it while
// the popup already shows the synthetic card detail and no native approval
// exists. Exactly one untrusted DOM click is dispatched; the picker must stay
// absent, the popup status must not change, and the caller re-proves the
// blank forms and native absence afterwards.
export async function assertProgrammaticClickRefused(popup, eventually) {
  const before = String((await popup.text("#status")) || "");
  assert(
    popup.visible &&
      popup.count &&
      (await popup.visible("#checkout-picker")) === false &&
      (await popup.count('#checkout-choices button')) === 0,
    "Checkout picker must be absent before the programmatic click",
  );
  assert(
    (await popup.disabled("#detail-fill")) === false,
    "Checkout form picker control unavailable",
  );
  const trusted = await popup.evaluate(UNTRUSTED_FILL_CLICK);
  // A refused gesture leaves nothing pending, so a short bounded wait settles
  // a harness failure quickly instead of hiding it behind a long timeout.
  await eventually(
    async () =>
      (await popup.visible("#checkout-picker")) !== true &&
      (await popup.count('#checkout-choices button')) === 0,
    "Programmatic checkout fill click opened the picker",
    1000,
  );
  // The received click itself must have been untrusted: a popup that opened
  // no picker by accident is not proof that the gesture was refused.
  assert(
    trusted === false,
    "Programmatic checkout fill click must be received as untrusted",
  );
  // An in-flight listing would set one of the bounded public status lines; an
  // unchanged status proves no frame request was started by the DOM click.
  assert(
    String((await popup.text("#status")) || "") === before,
    "Programmatic checkout fill click changed the popup status",
  );
  assert(
    (await popup.disabled("#detail-fill")) === false,
    "Programmatic checkout fill click consumed the picker control",
  );
}

// Explicitly locate the non-top origin button by its exact public origin
// label, then use the popup adapter's trusted pointer click on that exact
// selector. No frame is chosen automatically, no ordinal position is assumed
// and no runtime message is synthesized. Returns `selected: false` when the
// expected origin is absent from the public picker so the caller can prove
// exclusion, or when the user pressed the picker's own cancel control.
export async function chooseChildOrigin(
  popup,
  topOrigin,
  frameOrigin,
  eventually,
  options = {},
) {
  assert(
    options && typeof options === "object" && !Array.isArray(options),
    "Checkout choice options must be an object",
  );
  for (const key of Object.keys(options))
    assert(key === "cancel", "Unsupported checkout choice option");
  const cancel = options.cancel === undefined ? false : options.cancel;
  assert(typeof cancel === "boolean", "Checkout cancel must be boolean");
  await openCheckoutPicker(popup, eventually);
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
  // The top origin carries its own "（当前页面）" label, so even in the
  // same-origin variant the exact frame label identifies one child only.
  // Duplicate frame labels are ambiguous on every origin and are refused
  // rather than resolved by taking the first candidate.
  assert(
    matches.length <= 1,
    "Expected exactly one explicit checkout child origin",
  );
  // `null` means the requested child origin is absent from the public list.
  const match = matches.length === 1 ? matches[0] : null;
  const cancelSelector = "#checkout-cancel";
  assert(
    (await popup.count(cancelSelector)) === 1 &&
      (await popup.visible(cancelSelector)) === true &&
      (await popup.disabled(cancelSelector)) === false,
    "Checkout picker cancel control unavailable",
  );
  const target =
    match == null
      ? null
      : '#checkout-choices button[data-action="checkout-select"]:nth-child(' +
        match +
        ")";
  if (match != null && !cancel) {
    await popup.click(target);
    return { selected: true };
  }
  // An absent origin is a read-only result: the caller decides whether to
  // prove exclusion by cancelling. A candidate that exists but was not chosen
  // without an explicit cancel request would silently drop the picker.
  if (match == null && !cancel) return { selected: false };
  assert(cancel, "Checkout picker cancellation was not requested");
  // The actual popup cancel control, with a real trusted click while nothing
  // is selected. No candidate button is pressed.
  await popup.click(cancelSelector);
  await eventually(
    async () =>
      (await popup.visible("#checkout-picker")) === false &&
      (await popup.count('#checkout-choices button')) === 0,
    "Checkout picker cancel did not close",
  );
  return { selected: false };
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
  // Probe before the first selection, while this popup may still be focused:
  // a failed native probe fails the journey here instead of at a later stage.
  assertNoNativeApproval(input, POPUP_OPEN);
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
// Exported so its unit test can execute it through the real driver interface.
export async function runCrossSiteJourney(driver, card, topOrigin) {
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
  // `chooseChildOrigin` reports a present child only by its returned
  // `selected` boolean. The result object is always truthy, so branch on the
  // field itself: a truthiness check would claim a selection for an excluded
  // child.
  const choice = await chooseChildOrigin(
    popup,
    topOrigin,
    frameOrigin,
    eventually,
  );
  assert(
    choice !== null &&
      typeof choice === "object" &&
      typeof choice.selected === "boolean",
    "Checkout cross-site choice must report a boolean selection",
  );
  if (choice.selected === false) {
    phase("checkout-cross-site:excluded");
    assert(
      ((await popup.text("#checkout-status")) || "").includes("不会自动选择"),
      "Excluded checkout origin must not be auto-selected",
    );
    assertNoNativeApproval(input, POPUP_OPEN);
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
  } else {
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
    assertNoNativeApproval(input, POPUP_OPEN);
    await assertBothBlank(
      page,
      frameOrigin,
      "Cross-site checkout received a value without approval",
    );
  }
  // Both outcomes must prove the same refusal: no cross-site value and no
  // native approval. These common checks run before the completion marker is
  // emitted, so a run whose privacy proof fails never records the branch as
  // completed. The marker is last, after the branch that actually ran passed
  // its own assertions.
  assertNoNativeApproval(input, POPUP_OPEN);
  await assertBothBlank(
    page,
    frameOrigin,
    "Cross-site checkout received a value without approval",
  );
  phase("checkout-cross-site:refused");
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
  assertNoNativeApproval(input, POPUP_OPEN);
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
  assertNoNativeApproval(input, POPUP_OPEN);
  await assertBothBlank(
    page,
    frameOrigin,
    "Changed checkout document received a value",
  );
}

// The fixed public statuses that only a finished native review can set.
const CHECKOUT_TERMINAL_STATUS = ["已变化", "未完成", "已取消"];

function terminalStatus(status) {
  return CHECKOUT_TERMINAL_STATUS.some((line) => status.includes(line));
}

// The valid child was explicitly chosen and its real cross-origin native
// approval is visible. Navigate only the top tab to a fresh `/checkout?case=deny`
// document, which discards the reviewed top document and its child frame. Both
// approval and refusal must then leave the native review, the reloaded top and
// child forms stay blank and unsubmitted, and only after that the popup is
// reopened to observe one fixed terminal status. The stale approval is never
// clicked or otherwise acted on.
async function runDenyNavigationJourney(driver, card, topOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;
  const frameOrigin = checkoutFrameOrigin(topOrigin);
  phase("checkout-deny-navigation:navigation");
  await page.goto(topOrigin + "/checkout");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Checkout card frame did not load",
  );
  await assertBothBlank(
    page,
    frameOrigin,
    "Fresh checkout forms must stay blank",
  );

  const popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  assert(
    await chooseChildOrigin(popup, topOrigin, frameOrigin, eventually),
    "Expected exactly one explicit checkout child origin",
  );
  input([{ wait_label: CHECKOUT_APPROVE_LABEL }]);
  phase("checkout-deny-navigation:native-review");
  // The native review owns focus from here on, so its probes use the existing
  // default inspected probe rather than the popup-preserving one.
  for (const label of [CHECKOUT_APPROVE_LABEL, CHECKOUT_DENY_LABEL]) {
    const control = nativeControl(nativeControls(input), label);
    assert(
      control.enabled && control.showing,
      "Checkout native review must be visible before navigation",
    );
  }
  await assertBothBlank(
    page,
    frameOrigin,
    "Checkout forms changed before native approval",
  );

  phase("checkout-deny-navigation:top-navigation");
  await page.goto(topOrigin + "/checkout?case=deny");
  // Wait for both cross-origin decisions to leave the finished review. The
  // bounded diagnostic carries only public control states, never values.
  await eventually(
    async () => {
      const controls = nativeControls(input);
      const available = [];
      for (const [name, label] of [
        ["approve", CHECKOUT_APPROVE_LABEL],
        ["refuse", CHECKOUT_DENY_LABEL],
      ]) {
        const control = nativeControl(controls, label);
        if (control.present && control.enabled && control.showing)
          available.push(name);
      }
      // Only public control names: no label geometry, values or paths.
      assert(
        available.length === 0,
        "Native checkout review still available after top navigation: " +
          available.join("/"),
      );
      return true;
    },
    "Native checkout review did not finish after top navigation",
    8000,
  );
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Fresh checkout card frame did not load",
  );
  await assertBothBlank(
    page,
    frameOrigin,
    "Checkout forms received a value after top navigation",
  );

  // Only now, after the native review finished, does a second popup observe
  // the public result. Its first native probe runs while that popup is live.
  phase("checkout-deny-navigation:status");
  const reopened = await openPopup();
  assertNoNativeApproval(input, POPUP_OPEN);
  await eventually(
    async () => terminalStatus(String((await reopened.text("#status")) || "")),
    "Navigated checkout approval did not reach a terminal status",
    8000,
  );
  await assertBothBlank(
    page,
    frameOrigin,
    "Cancelled checkout approval received a value",
  );
}

// The same-origin variant embeds its child on the exact top origin (same host
// and port). The extension therefore sends no checkout proposal and the native
// owner shows the ordinary "敏感字段" card review. The journey proves both
// forms stay blank until that exact native approval, then that only the
// selected child document is filled: top form and PIN untouched, no submit.
async function runSameOriginJourney(driver, card, topOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;
  const frameOrigin = checkoutSameOrigin(topOrigin);
  const frameURL = frameOrigin + "/card";
  phase("checkout-same-origin:navigation");
  await page.goto(topOrigin + "/checkout?variant=same-origin");
  // Before any popup or selection action: the exact top-origin child exists,
  // both forms are blank and no native decision is available.
  await eventually(
    async () => cardFrame(page, frameOrigin) !== null,
    "Same-origin checkout card frame did not load",
  );
  const child = cardFrame(page, frameOrigin);
  assert(child && child !== page.mainFrame(), "Child must be an embedded frame");
  assert(
    child.url() === frameURL,
    "Same-origin child must be the exact top-origin card",
  );
  assert(
    checkoutFrameOrigin(topOrigin, { host: CHECKOUT_TOP_HOST }) === frameOrigin,
    "Same-origin frame origin must equal the top origin",
  );
  phase("checkout-same-origin:blank");
  await assertControls(page, frameOrigin);
  await assertBothBlank(
    page,
    frameOrigin,
    "Same-origin checkout forms must stay blank",
  );
  assertNoNativeApproval(input, POPUP_OPEN);
  assertNoNativeProfileReview(input, POPUP_OPEN);

  const popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  const choice = await chooseChildOrigin(
    popup,
    topOrigin,
    frameOrigin,
    eventually,
  );
  assert(choice.selected === true, "Same-origin child was not selected");
  input([{ wait_label: PROFILE_APPROVE_LABEL }]);
  phase("checkout-same-origin:native-review");
  await assertBothBlank(
    page,
    frameOrigin,
    "Same-origin checkout forms changed before native approval",
  );
  // The same-origin review is the ordinary profile review, not the checkout
  // one: the cross-origin labels stay absent while only the profile approval
  // is visible. The approve click below uses that profile label, so the journey
  // cannot pass through the cross-origin approval path.
  assertNoNativeApproval(input, POPUP_OPEN);
  const review = nativeControl(nativeControls(input), PROFILE_APPROVE_LABEL);
  assert(
    review.enabled && review.showing,
    "Same-origin native profile approval must be visible",
  );
  phase("checkout-same-origin:approve");
  input([{ click_label: PROFILE_APPROVE_LABEL }]);
  await eventually(
    async () => cardMatches(card, await childFormState(page, frameOrigin)),
    "Approved same-origin fill did not reach the child frame",
  );
  // The same-origin child still rides the checkout fill path, so its terminal
  // public status is the fixed "已请求填充结账表单…" one. The exact child,
  // top and PIN states are re-read after it settles.
  await eventually(
    async () =>
      String((await popup.text("#status")) || "").includes(
        "已请求填充结账表单",
      ),
    "Same-origin fill did not finish",
    8000,
  );
  assertNoNativeProfileReview(input, POPUP_OPEN);
  await assertOnlyChildFilled(page, frameOrigin, card);
}

// A fresh same-site cross-origin checkout page: the card picker is opened with
// real popup clicks and withdrawn through the popup's own cancel control while
// no native approval exists. Nothing may be written and no approval (checkout
// or profile) may become available afterwards.
async function runPickerCancelJourney(driver, card, topOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;
  const frameOrigin = checkoutFrameOrigin(topOrigin);
  phase("checkout-picker-cancel:navigation");
  // The deny case is an allowed fresh default-route document; the picker is
  // withdrawn before any choice, so the case never reaches the native owner.
  await page.goto(topOrigin + "/checkout?case=deny");
  await eventually(
    async () => (await childFormState(page, frameOrigin)) !== null,
    "Fresh checkout card frame did not load",
  );
  await assertControls(page, frameOrigin);
  await assertBothBlank(
    page,
    frameOrigin,
    "Fresh checkout forms must stay blank",
  );
  assertNoNativeApproval(input, POPUP_OPEN);
  assertNoNativeProfileReview(input, POPUP_OPEN);

  // Every native absence probe from here on runs while this popup stays open,
  // so it must use the focus-preserving form (POPUP_OPEN); the default probe
  // would focus the native window and close the popup.
  // A freshly opened popup: the picker is requested from this exact popup's
  // own trusted "#detail-fill" click, never from a popup that a previous
  // journey left open or that the harness closed by handling.
  const popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  // Programmatic activation is not a gesture: a DOM `.click()` on the real
  // picker control must be received untrusted and expose no checkout field.
  phase("checkout-picker-cancel:programmatic-refused");
  await assertProgrammaticClickRefused(popup, eventually);
  assertNoNativeApproval(input, POPUP_OPEN);
  assertNoNativeProfileReview(input, POPUP_OPEN);
  await assertBothBlank(
    page,
    frameOrigin,
    "Programmatic checkout fill click wrote a value",
  );
  phase("checkout-picker-cancel:picker");
  // The explicit trusted click must open the real picker before its cancel
  // control is clicked; a journey whose picker never appeared fails here and
  // never reports a cancellation.
  const choice = await chooseChildOrigin(
    popup,
    topOrigin,
    frameOrigin,
    eventually,
    { cancel: true },
  );
  assert(choice.selected === false, "Picker cancel must not select a frame");
  await eventually(
    async () => {
      const status = String((await popup.text("#status")) || "");
      return !status.includes("原生窗口核对");
    },
    "Cancelled checkout picker still requests native approval",
  );
  // The trusted picker was cancelled by the "#checkout-cancel" click above,
  // and the programmatic refusal was already proven on this popup. The same
  // popup is kept: closing it by physical Escape would disconnect this CDP
  // target, so no re-open or repeated refusal is checked here.
  assertNoNativeApproval(input, POPUP_OPEN);
  assertNoNativeProfileReview(input, POPUP_OPEN);
  // Give any stray native request time to surface before proving its absence.
  await new Promise((resolve) => setTimeout(resolve, 500));
  assertNoNativeApproval(input, POPUP_OPEN);
  assertNoNativeProfileReview(input, POPUP_OPEN);
  await assertBothBlank(
    page,
    frameOrigin,
    "Cancelled checkout picker wrote a value",
  );
  assert(
    (await popup.count('#checkout-choices button')) === 0,
    "Cancelled checkout picker must keep no candidate",
  );
}

// The last journey, because it locks the session. A fresh exact synthetic
// `/checkout` page, the same-site cross-origin child explicitly chosen and its
// real native cross-origin review visible: the existing native "立即锁定"
// action is then clicked while that review is pending and the lock screen's
// "解锁" control is awaited, exactly like the general acceptance. The review is
// never approved or refused. The lock must reject the pending review, leave
// both forms blank and unsubmitted and leave the popup locked/disconnected.
export async function runLockDuringReviewJourney(driver, card, topOrigin) {
  const { page, input, openPopup, phase, eventually } = driver;
  const frameOrigin = checkoutFrameOrigin(topOrigin);
  const documentURL = topOrigin + "/checkout";
  phase("checkout-lock-review:navigation");
  await page.goto(documentURL);
  assert(
    page.url() === documentURL,
    "Lock checkout document must be the exact /checkout page",
  );
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

  const popup = await openPopup();
  await openCardDetail(popup, card, eventually);
  assert(
    await chooseChildOrigin(popup, topOrigin, frameOrigin, eventually),
    "Expected exactly one explicit checkout child origin",
  );
  input([{ wait_label: CHECKOUT_APPROVE_LABEL }]);
  phase("checkout-lock-review:native-review");
  for (const label of [CHECKOUT_APPROVE_LABEL, CHECKOUT_DENY_LABEL]) {
    const control = nativeControl(nativeControls(input), label);
    assert(
      control.enabled && control.showing,
      "Checkout native review must be visible before lock",
    );
  }
  await assertBothBlank(
    page,
    frameOrigin,
    "Checkout forms changed before native lock",
  );

  phase("checkout-lock-review:lock");
  // One physical native lock with the review pending; approve/refuse untouched.
  input([{ click_label: LOCK_LABEL }, { wait_label: UNLOCK_SCREEN_LABEL }]);
  await eventually(
    async () => {
      const controls = nativeControls(input);
      const available = [];
      for (const [name, label] of [
        ["approve", CHECKOUT_APPROVE_LABEL],
        ["refuse", CHECKOUT_DENY_LABEL],
      ]) {
        const control = nativeControl(controls, label);
        if (control.present && control.enabled && control.showing)
          available.push(name);
      }
      // Only public control names: no label geometry, values or paths.
      assert(
        available.length === 0,
        "Native checkout review still available after lock: " +
          available.join("/"),
      );
      return true;
    },
    "Native checkout review did not finish after lock",
    8000,
  );
  await assertBothBlank(
    page,
    frameOrigin,
    "Locked checkout approval received a value",
  );

  phase("checkout-lock-review:status");
  const reopened = await openPopup();
  await eventually(
    async () => (await reopened.disabled("#refresh")) === true,
    "Locked host still allowed matching",
  );
  const status = String((await reopened.text("#status")) || "");
  assert(
    status.includes("锁定") || status.includes("断开"),
    "Lock status missing",
  );
  await assertBothBlank(
    page,
    frameOrigin,
    "Locked checkout approval received a value",
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
  const parsed = checkedTopOrigin(topOrigin);
  assert(
    parsed.hostname === CHECKOUT_TOP_HOST && parsed.origin === topOrigin,
    "Checkout acceptance requires the exact synthetic top origin",
  );
  const frameOrigin = checkoutFrameOrigin(topOrigin);
  let current;
  try {
    current = new URL(page.url());
  } catch {
    throw Error("Checkout top document URL missing");
  }
  assert(
    current.pathname === "/checkout" && current.origin === topOrigin,
    "Checkout contact route must be the top document",
  );

  await runDefaultJourneys(driver, card, topOrigin, frameOrigin);
  await runCrossSiteJourney(driver, card, topOrigin);
  await runSandboxJourney(driver, card, topOrigin);
  await runStaleDocumentJourney(driver, card, topOrigin);
  await runDenyNavigationJourney(driver, card, topOrigin);
  // Same-origin after the stale journey so its exact child assertion runs on
  // a fresh same-origin document rather than the stale replaced one.
  await runSameOriginJourney(driver, card, topOrigin);
  await runPickerCancelJourney(driver, card, topOrigin);
  // Last on purpose: locking the session invalidates it for every later stage.
  await runLockDuringReviewJourney(driver, card, topOrigin);
  return CHECKOUT_LOCKED;
}

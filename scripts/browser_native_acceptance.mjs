// External end-to-end acceptance: actual extension action, native messaging,
// MyGo UI input, and a controlled HTTPS document. No product test bypasses.
import { createRequire } from "node:module";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, existsSync, realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "node:https";
import { createHash, X509Certificate } from "node:crypto";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import {
  acceptBrowserSave,
  captureControllerOutput,
  browserScreenshotsAllowed,
  assertPrivateText,
  assertPrivateArtifacts,
  browserFixtureExecutable,
  fixtureCanaries,
  vaultObserver,
} from "./browser_save_acceptance.mjs";

import { acceptBrowserPasskey } from "./browser_passkey_acceptance.mjs";
import { acceptBrowserOTP, otpHTML } from "./browser_otp_acceptance.mjs";
import { acceptPopupVault } from "./browser_popup_vault_acceptance.mjs";
import {
  acceptSharedClipboard,
  prepareSharedEnvironment,
  PrivateClipboard,
} from "./browser_shared_clipboard_acceptance.mjs";
import { acceptCheckoutFrames, checkoutTopHTML, checkoutCardHTML, checkoutRouteCase } from "./browser_checkout_acceptance.mjs";
const checkoutFrames = process.env.LOCKLARK_TEST_CHECKOUT_FRAMES === "1";
// Explicit opt-in: a QuickFill=false action row opens one persistent route tab
// and its native per-operation approval, instead of the long default journeys.
const routeDetailRead = process.env.LOCKLARK_TEST_ROUTE_DETAIL_READ === "1";
// Opt-in on top of the route detail mode only: after every existing physical
// route switch/reload/no-prompt assertion has passed, one ordinary route
// journey is left idle through its full two-minute route TTL and must then be
// fully wiped. It never changes what the default route mode runs, and any
// value other than the exactly paired flags fails closed at import, before
// anything is launched.
const routeIdleValue = process.env.LOCKLARK_TEST_ROUTE_IDLE_TTL;
const routeIdleTtl = routeIdleValue === "1";
assert(
  routeIdleValue === undefined ||
    (routeIdleValue === "1" && routeDetailRead),
  "Route idle TTL mode requires route detail mode",
);
// Route pages are the fixed extension popup document plus exactly one 64-hex
// token fragment. Action popups are that same document with no fragment.
const ROUTE_PAGE = /^chrome-extension:\/\/[a-p]{32}\/popup\.html#route=[a-f0-9]{64}$/;
const ACTION_POPUP = /^chrome-extension:\/\/[a-p]{32}\/popup\.html$/;
// The source tab is titled "Locklark acceptance · …"; the route page is titled
// "Locklark". Each key goes to its own exact expected title prefix.
const SOURCE_TITLE_PREFIX = "Locklark acceptance";
const ROUTE_TITLE_PREFIX = "Locklark";
// The route checkpoint is the only requested journey in this mode, so every
// mode that would change what pairing, fill or checkout mean is refused before
// anything is launched.
function routeModeCompatible() {
  const off = (name) => !process.env[name];
  return (
    off("LOCKLARK_TEST_SHARED_CLIPBOARD") &&
    off("LOCKLARK_TEST_POPUP_VAULT") &&
    off("LOCKLARK_TEST_CHECKOUT_FRAMES") &&
    off("LOCKLARK_TEST_BROWSER_PARITY") &&
    off("LOCKLARK_TEST_FAILURE_STAGE") &&
    (process.env.LOCKLARK_TEST_BROWSER === undefined ||
      process.env.LOCKLARK_TEST_BROWSER === "chromium")
  );
}
const POPUP_CLOSED = ["Popup closed", "Popup CDP closed", "Popup CDP timed out"];
function popupClosed(error) {
  return POPUP_CLOSED.includes(error?.message);
}

const scanController = captureControllerOutput();
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "web/package.json"));
const { chromium } = process.env.LOCKLARK_TEST_PLAYWRIGHT
  ? require(process.env.LOCKLARK_TEST_PLAYWRIGHT)
  : require("playwright");
const go = process.env.LOCKLARK_GO || "go";
const host = process.env.LOCKLARK_BROWSER_HOST;
const register = process.env.LOCKLARK_BROWSER_REGISTER
  ? resolve(process.env.LOCKLARK_BROWSER_REGISTER)
  : null;
const browserName = process.env.LOCKLARK_TEST_BROWSER === "edge" ? "edge" : "chromium";
const browserExecutable = process.env.LOCKLARK_TEST_BROWSER_EXECUTABLE;
if (browserName === "edge")
  assert(browserExecutable && browserExecutable.startsWith("/"), "Edge requires an explicit absolute executable path");
if (routeDetailRead) {
  assert(routeModeCompatible(), "Route detail mode is incompatible");
  assert(browserName === "chromium", "Route detail mode requires Chromium");
}
if (register)
  assert(existsSync(register), "LOCKLARK_BROWSER_REGISTER must name a built executable");
assert(
  host && process.env.DISPLAY,
  "A built native host and real X display are required",
);
assert(
  !process.env.LOCKLARK_TEST_FAILURE_STAGE ||
    ["after-pair", "page-arguments", "otp-page-arguments"].includes(
      process.env.LOCKLARK_TEST_FAILURE_STAGE,
    ),
  "Unsupported acceptance failure stage",
);
const state = mkdtempSync("/tmp/locklark-browser-acceptance-");
const env = { ...process.env, GOTOOLCHAIN: "go1.27.3" };
// Explicit external test mode only: the actual desktop app and the browser it
// hosts share a private HOME/TMPDIR/broker endpoint, never the real user's.
const sharedEnvironment =
  process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1"
    ? prepareSharedEnvironment(state, env)
    : null;
const diagnostics = mkdtempSync(join(state, "diagnostics-"));
let stage = "fixture",
  lastPopup = null,
  lastRouteObservation = null,
  // Present only once the optional idle journey reached its post-approval
  // detail and wipe checks; reported on its failure as fixed booleans only.
  routeIdleObservation = null,
  routeAfterPopupClose = null,
  routeTargetAfterPopupClose = null,
  routeObservationHistory = [],
  nativeInput = null;
// Diagnostics only: keep at most ROUTE_HISTORY_LIMIT sanitized observations,
// appended only when one of the four fields actually changes, so a failure
// can show whether the route page ever reached locked/vault/detail first.
const ROUTE_HISTORY_LIMIT = 8;
function recordRouteObservation(observation) {
  const last = routeObservationHistory[routeObservationHistory.length - 1];
  if (
    last &&
    last.view === observation.view &&
    last.detailShown === observation.detailShown &&
    last.titleMatchesFixture === observation.titleMatchesFixture &&
    last.statusKind === observation.statusKind
  )
    return;
  routeObservationHistory = [
    ...routeObservationHistory,
    observation,
  ].slice(-ROUTE_HISTORY_LIMIT);
}
// Route lifecycle diagnostics. From the moment the exact route target is
// found, one best-effort websocket to that target's own
// webSocketDebuggerUrl (a direct page-target session: no Target.* usage, no
// invented session ids, no page code) records which real Page lifecycle
// events its main frame received. A route-detail failure can then tell "the
// route document was reloaded, navigated or detached" apart from "the same
// document stayed and only the UI differed". Only main-frame events count:
// Page.frameNavigated with no parent frame is the root document (and
// re-identifies the main frame after a navigation),
// Page.frameRequestedNavigation proves a not-yet-committed main-frame
// navigation, and other events are matched transiently against
// Page.getFrameTree's main-frame id. The retained record holds only fixed
// booleans and capped per-kind counts; frame and loader ids live only in this
// closure. The socket only acknowledges Page.enable (the captured page keeps
// running; intake is never gated on a reply) and stays open until the
// checkpoint's finally path closes it. Every CDP failure is swallowed.
const ROUTE_LIFECYCLE_EVENTS = [
  "frameStartedLoading",
  "frameStoppedLoading",
  "frameNavigated",
  "frameRequestedNavigation",
  "navigatedWithinDocument",
  "frameDetached",
];
const ROUTE_LIFECYCLE_LIMIT = 16;
let routeLifecycleObservation = null;
// Per-observation connection state (main-frame id, socket). It is reachable
// both from the event handlers and from the checkpoint's finally path, and is
// cleared on close. Nothing in it is ever reported.
let routeLifecycleState = null;
// Event method and params to the transient main-frame id, or an explicit
// undefined for "not a main-frame event".
function routeLifecycleFrame(method, params, mainFrame) {
  if (
    method === "Page.frameNavigated" &&
    params?.frame?.parentId === undefined &&
    typeof params.frame?.id === "string"
  )
    return params.frame.id;
  return mainFrame !== undefined && params?.frameId === mainFrame
    ? mainFrame
    : undefined;
}
// Fixed allowlisted shape only: unknown events, extra keys and non-boolean
// values are dropped, so malformed input can never widen what is reported.
function sanitizeRouteLifecycle(value) {
  const counts = value?.eventCounts;
  return {
    enabled: value?.enabled === true,
    mainFrame: value?.mainFrame === true,
    loadingStarted: value?.loadingStarted === true,
    loadingStopped: value?.loadingStopped === true,
    navigated: value?.navigated === true,
    navigationRequested: value?.navigationRequested === true,
    sameDocumentNavigation: value?.sameDocumentNavigation === true,
    mainFrameDetached: value?.mainFrameDetached === true,
    eventCounts: Object.fromEntries(
      ROUTE_LIFECYCLE_EVENTS.map((kind) => [
        kind,
        Number.isInteger(counts?.[kind]) && counts[kind] >= 0
          ? Math.min(counts[kind], ROUTE_LIFECYCLE_LIMIT)
          : 0,
      ]),
    ),
  };
}
// One fixed event kind of the main frame; the record never exceeds
// ROUTE_LIFECYCLE_LIMIT counted events in total.
function recordRouteLifecycle(kind) {
  const current = sanitizeRouteLifecycle(routeLifecycleObservation);
  if (!ROUTE_LIFECYCLE_EVENTS.includes(kind)) return;
  const total = Object.values(current.eventCounts).reduce(
    (sum, count) => sum + count,
    0,
  );
  if (total >= ROUTE_LIFECYCLE_LIMIT) return;
  routeLifecycleObservation = sanitizeRouteLifecycle({
    ...current,
    mainFrame: true,
    loadingStarted: current.loadingStarted || kind === "frameStartedLoading",
    loadingStopped: current.loadingStopped || kind === "frameStoppedLoading",
    navigated: current.navigated || kind === "frameNavigated",
    navigationRequested:
      current.navigationRequested || kind === "frameRequestedNavigation",
    sameDocumentNavigation:
      current.sameDocumentNavigation || kind === "navigatedWithinDocument",
    mainFrameDetached: current.mainFrameDetached || kind === "frameDetached",
    eventCounts: { ...current.eventCounts, [kind]: current.eventCounts[kind] + 1 },
  });
}
function closeRouteLifecycle() {
  const state = routeLifecycleState;
  routeLifecycleState = null;
  try {
    if (state) state.ws.close();
  } catch {}
}
// Best effort only: the caller never awaits it, and any failure leaves the
// record as it was. Exactly two fixed, read-only commands go out on ordinary
// request ids; page events are counted regardless of when (or whether) their
// replies arrive.
function observeRouteLifecycle(target) {
  try {
    if (typeof target?.webSocketDebuggerUrl !== "string") return;
    const state = {
      ws: new WebSocket(target.webSocketDebuggerUrl),
      // Transient only: the main frame's id for this observation.
      mainFrame: undefined,
    };
    routeLifecycleState = state;
    const { ws } = state;
    ws.addEventListener("message", (event) => {
      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      // Commands must never be mistaken for page events.
      if (typeof message?.method === "string") {
        if (!message.method.startsWith("Page.")) return;
        const frame = routeLifecycleFrame(
          message.method,
          message.params,
          state.mainFrame,
        );
        if (frame === undefined) return;
        // A main-frame navigation (re-)identifies the main frame; any other
        // main-frame event confirms the one already known.
        if (typeof frame === "string") state.mainFrame = frame;
        recordRouteLifecycle(message.method.slice("Page.".length));
        return;
      }
      if (message?.id === 1) {
        routeLifecycleObservation = {
          ...sanitizeRouteLifecycle(routeLifecycleObservation),
          enabled: true,
        };
        return;
      }
      if (message?.id === 2) {
        const main = message.result?.frameTree?.frame?.id;
        if (typeof main === "string" && state.mainFrame === undefined) {
          state.mainFrame = main;
          routeLifecycleObservation = {
            ...sanitizeRouteLifecycle(routeLifecycleObservation),
            mainFrame: true,
          };
        }
      }
    });
    ws.addEventListener("error", () => {});
    ws.addEventListener("open", () => {
      try {
        ws.send(JSON.stringify({ id: 1, method: "Page.enable" }));
        ws.send(JSON.stringify({ id: 2, method: "Page.getFrameTree" }));
      } catch {}
    });
  } catch {}
}
// The controlled source page's title; source-tab keys use exactly this prefix.
const browserWindowTitle = "Locklark acceptance";
let privacyValues = [];
let observedFixture = null;
function popupStatusKind(value) {
  const text = String(value || "");
  if (text.includes("已保存")) return "saved";
  if (text.includes("未找到")) return "no-candidates";
  if (text.includes("页面或活动标签")) return "context-changed";
  if (text.includes("已连接")) return "paired";
  if (text.includes("连接不可用")) return "popup-unavailable";
  if (text.includes("结果未确认")) return "unknown";
  if (text.includes("锁定")) return "locked";
  if (text.includes("未连接") || text.includes("断开")) return "disconnected";
  if (text.includes("原生") || text.includes("批准")) return "native-pending";
  if (text.includes("拒绝")) return "refused";
  if (text.includes("正在填充")) return "quick-filling";
  if (text.includes("个当前网站")) return "candidates-listed";
  if (text.includes("金库中有")) return "vault-listed";
  if (text.includes("Watchtower")) return "watchtower";
  if (text.includes("已填充") || text.includes("填充完成")) return "filled";
  return "other";
}
// Read-only observation of the attached route page for the failure report.
// Only fixed enums and booleans ever leave the page: never text, titles,
// field values, URLs, tokens, ids or hidden application state.
const ROUTE_VIEWS = ["locked", "vault", "detail", "closed", "editor"];
const ROUTE_STATUS_KINDS = [
  "native-pending",
  "claim-failed",
  "route-revoked",
  "other",
];
const ROUTE_CLAIM_PENDING_STATUS = "正在请求桌面审批…";
const ROUTE_CLAIM_FAILED_STATUS = "无法打开此条目";
const ROUTE_REVOKED_STATUS = "条目已失效，请重新从金库打开";
function sanitizeRouteObservation(value) {
  return {
    view: ROUTE_VIEWS.includes(value?.view) ? value.view : "other",
    detailShown: value?.detailShown === true,
    titleMatchesFixture: value?.titleMatchesFixture === true,
    statusKind: ROUTE_STATUS_KINDS.includes(value?.statusKind)
      ? value.statusKind
      : "other",
  };
}
// Visible DOM only: body[data-view], the detail section, its heading and the
// status line. The fixture comparison and the status categorisation happen
// inside the page; only their fixed outcomes are returned.
function routeStateProbe(title) {
  return `(()=>{
    const view=(document.body&&document.body.dataset.view)||'';
    const detail=document.querySelector('#detail-view');
    const heading=document.querySelector('#detail-title');
    const status=document.querySelector('#status');
    const statusText=status?String(status.textContent||'').trim():'';
    return {
      view:${JSON.stringify(ROUTE_VIEWS)}.includes(view)?view:'other',
      detailShown:!!detail&&!detail.hidden,
      titleMatchesFixture:!!heading&&String(heading.textContent||'')===${JSON.stringify(title)},
      statusKind:statusText===${JSON.stringify(ROUTE_CLAIM_PENDING_STATUS)}?'native-pending':statusText===${JSON.stringify(ROUTE_CLAIM_FAILED_STATUS)}?'claim-failed':statusText===${JSON.stringify(ROUTE_REVOKED_STATUS)}?'route-revoked':'other'
    };
  })()`;
}
// Route status trace. A visible-DOM MutationObserver on the exact route page
// records each observable status/state change from the moment the target is
// discovered, so a status written and overwritten before the next poll is not
// lost. The observer is installed immediately and holds no element references:
// every relevant mutation resolves the current #status, #detail-view and
// #detail-title, so nodes inserted after discovery (body parsing can follow
// target discovery) are still traced. Only records owned by the live #status
// element classify a status; unrelated page text never touches the trace. Each
// status record is classified here, in the page, against only the fixed
// literals below, and the added node's text is never stored. The trace keeps
// at most ROUTE_STATUS_TRACE_LIMIT entries, dropping consecutive repeats, of
// fixed view/status/detail/title enums only.
const ROUTE_STATUS_TRACE_LIMIT = 8;
const ROUTE_STATUS_TRACE_CHANNELS = ["status", "view", "detailShown", "titleKind"];
const ROUTE_TITLE_KINDS = ["fixture", "other"];
const ROUTE_CLOSED_STATUS = "已关闭此条目";
// Returns the page-side expression that installs the observer and exposes one
// read-only reader plus one stop function; both diagnostic hooks are removed
// by the stop function.
function routeStatusTraceProbe(title) {
  return `(()=>{
    if(globalThis.__locklarkRouteStatusTraceRead)return true;
    const LIMIT=${ROUTE_STATUS_TRACE_LIMIT};
    const VIEWS=${JSON.stringify(ROUTE_VIEWS)};
    const FIXTURE_TITLE=${JSON.stringify(title)};
    const kindOf=(text)=>text===${JSON.stringify(ROUTE_CLAIM_PENDING_STATUS)}?'native-pending':text===${JSON.stringify(ROUTE_CLAIM_FAILED_STATUS)}?'claim-failed':text===${JSON.stringify(ROUTE_REVOKED_STATUS)}?'route-revoked':text===${JSON.stringify(ROUTE_CLOSED_STATUS)}?'closed':text?'other':'empty';
    const entries=[];
    let last=null,observing=null;
    const push=(channel,value)=>{
      if(last&&last.channel===channel&&last.value===value)return;
      last={channel,value};
      if(entries.length<LIMIT)entries.push(last);
    };
    const q=(selector)=>document.querySelector(selector);
    const toArray=(list)=>list?Array.prototype.slice.call(list):[];
    const view=()=>VIEWS.includes(document.body?.dataset?.view)?document.body.dataset.view:'other';
    const shown=()=>{const el=q('#detail-view');return el?el.hidden!==true:false;};
    const titleKind=()=>{const el=q('#detail-title');return el?(String(el.textContent||'')===FIXTURE_TITLE?'fixture':'other'):'other';};
    const statusKind=(statusEl)=>statusEl?kindOf(String(statusEl.textContent||'').trim()):'other';
    // Seed state without inventing a status: absence is not an empty status,
    // and the first real #status write must stay the first status event.
    const sync=()=>{const statusEl=q('#status');if(statusEl)push('status',statusKind(statusEl));push('view',view());push('detailShown',shown());push('titleKind',titleKind());};
    // A childList record wholly inside the live #status element (or one that
    // inserted it) is one textContent/append write. Its own added text nodes
    // are classified in order and a write leaving it without text as 'empty',
    // so separate writes batched into one callback keep every transition.
    // Only the mounted #status subtree or a newly inserted #status element
    // reaches this path; unrelated nodes and text are never read.
    const statusWrite=(statusEl,record)=>{
      if(record.target!==statusEl)return false;
      const added=record.addedNodes?[...record.addedNodes]:[],removed=record.removedNodes?[...record.removedNodes]:[];
      const texts=[];
      for(const node of added)if(node?.nodeType===3&&String(node.data||'').trim())texts.push(String(node.data||'').trim());
      if(texts.length)for(const text of texts)push('status',kindOf(text));
      else if(added.length||removed.length)push('status',kindOf(String(statusEl.textContent||'').trim()));
      return true;
    };
    const handle=(record)=>{
      const statusEl=q('#status');
      if(record.type==='characterData'){
        // Only text owned by the live #status element is a status change.
        if(statusEl&&statusEl.contains?.(record.target))push('status',kindOf(String(record.target.data||'').trim()));
        return;
      }
      if(record.type==='attributes'){
        if(record.target===document.body)push('view',view());
        return;
      }
      if(!record.addedNodes&&!record.removedNodes)return;
      const current=q('#status');
      if(current&&current!==seenStatus)detectStatus();
      const live=q('#status');
      if(live&&(live.contains?.(record.target)&&statusWrite(live,record)))return;
      for(const node of record.addedNodes){
        if(node instanceof Element&&node.matches?.('#detail-view'))push('detailShown',node.hidden!==true);
        if(node instanceof Element&&node.matches?.('#detail-title, #detail-title *'))push('titleKind',titleKind());
      }
    };
    const observer=new MutationObserver((records)=>{for(const record of records)handle(record);});
    const start=()=>{
      if(observing||!document.body)return;
      observing=document.body;
      observer.observe(observing,{attributes:true,attributeFilter:['data-view','hidden'],childList:true,subtree:true,characterData:true});
      sync();
    };
    // Route target discovery can precede body parsing or the #status node, so
    // any mutation can be the one that makes #status live: record it then.
    let seenStatus=null;
    const detectStatus=()=>{
      const statusEl=q('#status');
      if(!statusEl||statusEl===seenStatus)return;
      seenStatus=statusEl;
      push('status',statusKind(statusEl));
    };
    start();
    detectStatus();
    for(const type of['DOMContentLoaded','pageshow'])globalThis.addEventListener?.(type,start,{once:true});
    globalThis.__locklarkRouteStatusTraceRead=()=>JSON.stringify(entries);
    globalThis.__locklarkRouteStatusTraceStop=()=>{
      observer.disconnect();
      for(const type of['DOMContentLoaded','pageshow'])globalThis.removeEventListener?.(type,start);
      delete globalThis.__locklarkRouteStatusTraceRead;
      delete globalThis.__locklarkRouteStatusTraceStop;
      return true;
    };
    return true;
  })()`;
}
// Sanitized again at the boundary: unknown channels, enums or shapes are
// dropped and the entry cap is enforced here as well.
function sanitizeRouteStatusTrace(value) {
  if (!Array.isArray(value)) return null;
  const trace = [];
  for (const entry of value.slice(0, ROUTE_STATUS_TRACE_LIMIT)) {
    const channel = entry?.channel;
    const allowed =
      channel === "status"
        ? ROUTE_STATUS_KINDS.concat("closed", "empty")
        : channel === "view"
          ? ROUTE_VIEWS.concat("other")
          : channel === "titleKind"
            ? ROUTE_TITLE_KINDS
            : channel === "detailShown"
              ? [true, false]
              : [];
    if (!ROUTE_STATUS_TRACE_CHANNELS.includes(channel)) continue;
    if (!allowed.includes(entry?.value)) continue;
    trace.push({ channel, value: entry.value });
  }
  return trace;
}
let routeStatusTrace = null;
let routeStatusTraceInstalled = false;
// Read-only: one evaluation over CDP, no wait and no gate.
async function readRouteStatusTrace(connection) {
  try {
    routeStatusTrace = sanitizeRouteStatusTrace(
      JSON.parse(
        await connection.evaluate(
          "globalThis.__locklarkRouteStatusTraceRead?.() ?? '[]'",
        ),
      ),
    );
  } catch {}
}
async function refreshRouteStatusTrace(attach, target, uninstall = false) {
  if (!routeStatusTraceInstalled) return;
  let connection = null;
  try {
    connection = await attach(target);
    await readRouteStatusTrace(connection);
    if (!uninstall) return;
    // Stop observing in the page: disconnect and remove both diagnostic hooks.
    await connection.evaluate(
      "globalThis.__locklarkRouteStatusTraceStop?.() ?? false",
    );
  } catch {} finally {
    try {
      await connection?.close();
    } catch {}
  }
}
// The concealed password row's own Copy control. The route field-copy proof
// clicks it; the revocation checkpoint proves it is absent after a reload.
const ROUTE_COPY_FIELD_SELECTOR =
  '[data-field-id="password"] [data-action="copy-field"]';
// Route revocation checkpoint (after the field-copy proof). The user starts on
// the route tab, physically switches to the source tab, comes back with
// Control_L+Tab and physically reloads the stale fragment with Control_L+r.
// Every key is one real XTest batch addressed to the exact Chromium window by
// its expected title prefix and executable. Only fixed booleans and enums ever
// leave either page: never title, value, text, URL, token, count, target or
// tab id, which stay in this closure.
const ROUTE_REVOKE_STATUS_KINDS = Object.freeze(["route-revoked", "claim-failed"]);
// Product design: the approved login detail shows the synthetic Username (the
// item's subtitle and the username field). Only this verified value is
// displayable; the password value stays masked and every other canary
// (password, secret, OTP seed/URI, other fixture values) must stay absent.
const ROUTE_DETAIL_VISIBLE_FIXTURE_KEYS = Object.freeze(["Username"]);
// Every fixture canary the page text must still not contain: all of them
// except only the allowlisted values above.
function routeForbiddenCanaries(fixture) {
  const displayable = ROUTE_DETAIL_VISIBLE_FIXTURE_KEYS.map((key) => fixture?.[key]);
  return fixtureCanaries(fixture).filter((value) => !displayable.includes(value));
}
// The route's own tab switch, return and reload; each is one real XTest key
// batch sent with the exact-title-prefix form (never the native-window form)
// and addressed to the title of the tab that is ACTIVE when the key is sent:
// the route tab ("Locklark") for the switch away and the reload, the source tab
// for the return.
const ROUTE_SWITCH_SOURCE = Object.freeze([{ key: "Control_L+Shift_L+Tab" }]);
const ROUTE_RETURN = Object.freeze([{ key: "Control_L+Tab" }]);
const ROUTE_RELOAD = Object.freeze([{ key: "Control_L+r" }]);
// The exact native approval title and the longest bounded no-prompt
// observation after the stale reload. Every poll must observe the real native
// window; a missing or unobservable one fails instead of passing the bound.
const ROUTE_NATIVE_TITLE = "Locklark · 浏览器原生确认";
const ROUTE_NATIVE_ABSENT_LIMIT = 3000;
let routeMouseRejected = null;
// Fixed fragments shared by the route page probes. Each handler resolves the
// current nodes on every read and never holds references to them.
const ROUTE_PAGE_STATE = `(()=>{
  const body=document.body;
  const detail=document.querySelector('#detail-view');
  const heading=document.querySelector('#detail-title');
  const fields=document.querySelector('#detail-fields');
  return {
    visible:document.visibilityState==='visible',
    closed:!!body&&body.dataset.view==='closed',
    detailHidden:!!detail&&detail.hidden===true,
    titleEmpty:!!heading&&String(heading.textContent||'')==='',
    fieldsEmpty:!!fields&&fields.childElementCount===0
  };
})()`;
// The first tab switch away uses the fixed read-only page state as its
// bounded host-side poll; no page observer is installed.
const ROUTE_SWITCH_PROBE = ROUTE_PAGE_STATE;
// The full wipe contract after the return to the route tab, after the stale
// reload and after the idle TTL: the same fixed page state (including its
// `visible` boolean) plus the two fixed revocation outcomes, the closed detail,
// the absent Copy control and one boolean for whether any supplied canary is
// anywhere in the body text. The comparison happens in the page. The
// route-return wait and the stale reload both call it with the title/value
// pair, unchanged; the idle expiry passes every fixture canary. Both waits use
// this one probe, so neither can pass the incomplete page state to
// routeWiped().
function routeRevokedProbe(title, value, canaries) {
  const absent = canaries === undefined ? [title, value] : [...new Set([title, value, ...canaries])];
  return `(()=>{
    const body=document.body;
    const detail=document.querySelector('#detail-view');
    const heading=document.querySelector('#detail-title');
    const fields=document.querySelector('#detail-fields');
    const status=document.querySelector('#status');
    const text=status?String(status.textContent||'').trim():'';
    const bodyText=body?String(body.innerText):'';
    const canaries=${JSON.stringify(absent)};
    return {
      visible:document.visibilityState==='visible',
      closed:!!body&&body.dataset.view==='closed',
      detailHidden:!!detail&&detail.hidden===true,
      titleEmpty:!!heading&&String(heading.textContent||'')==='',
      fieldsEmpty:!!fields&&fields.childElementCount===0,
      copyAbsent:document.querySelectorAll(${JSON.stringify(ROUTE_COPY_FIELD_SELECTOR)}).length===0,
      fixtureAbsent:canaries.every((value)=>!bodyText.includes(value)),
      statusKind:text===${JSON.stringify(ROUTE_REVOKED_STATUS)}?'route-revoked':text===${JSON.stringify(ROUTE_CLAIM_FAILED_STATUS)}?'claim-failed':'other'
    };
  })()`;
}
// Every fixed condition holds, including exactly one revoked/claim-failed
// status kind.
function routeWiped(value) {
  const clean = {
    closed: true,
    detailHidden: true,
    titleEmpty: true,
    fieldsEmpty: true,
    copyAbsent: true,
    fixtureAbsent: true,
  };
  return (
    Object.entries(clean).every(([key, expected]) => value?.[key] === expected) &&
    ROUTE_REVOKE_STATUS_KINDS.includes(value?.statusKind)
  );
}
// Route field-copy acceptance. The concealled password row's own Copy control
// is clicked physically; the worker then re-reads the value under the same
// native V2 approval, so either the field-disclosure review appears directly
// (native clipboard path) or one ordinary item-get review for this exact item
// precedes it (legacy path; only the exact route approval label is accepted).
// Clipboard bytes travel only on the private pipe; only booleans are kept.
const ROUTE_COPY_REVIEW_LABEL = "批准本次操作";
const ROUTE_COPY_DISCLOSURE_LABEL = "批准本次字段披露";
// The focus-preserving native inspect form shared by the default route
// approval wait and the opt-in idle journey. It never raises or focuses the
// native window.
const ROUTE_LABEL_INSPECT = Object.freeze({
  inspect: true,
  preserve_focus: true,
});
// Both native-lease success lines and the legacy manual-copy success line
// (popup.js writeClipboard -> copiedFeedback). Pending, refusal, unknown
// outcome and missing feedback are never accepted.
const ROUTE_COPY_FEEDBACK = [
  "已启用自动清理",
  "自动清理已关闭",
  "已复制；浏览器无法保证自动清除，请按需手动清理",
];
// The concealed row's revealed value is masked, never a copy of the secret.
function routePasswordRowProbe(password) {
  return `(()=>{
    const row=document.querySelector(${JSON.stringify(ROUTE_COPY_FIELD_SELECTOR.split(" ")[0])});
    const value=row?row.querySelector(".field-value"):null;
    return {masked:!!value&&/^[\u2022\u25cf*]+$/.test(String(value.textContent||"").trim()),leaked:!!document.body&&String(document.body.innerText).includes(${JSON.stringify(password)})};
  })()`;
}
// Read-only inspection of the exact page the harness itself controls: its own
// pathname and form controls. Only fixed booleans leave the page.
function sourcePageProbe(pathname) {
  return `(()=>{
    const username=document.getElementById('username');
    const password=document.getElementById('password');
    const form=username?username.form:null;
    return {
      visible:document.visibilityState==='visible',
      path:location.pathname===${JSON.stringify(pathname)},
      form:!!form&&!!password&&form.contains(password)&&username.type!=='password'&&password.type==='password'
    };
  })()`;
}
function sourcePageIntact(value) {
  return value?.form === true && value?.path === true;
}
// Diagnostics only: the six fixed predicates of the idle stale-close wait's
// latest poll. Null until the optional idle journey starts (and reset there),
// then refreshed on every poll. Only the fixed booleans are stored and
// reported; ids, URLs, titles, values, counts, text and canaries stay out.
let routeIdleCloseStaleObservation = null;
function sanitizeRouteIdleCloseStale(value) {
  return {
    staleIdAbsent: value?.staleIdAbsent === true,
    routesAbsent: value?.routesAbsent === true,
    popupAbsent: value?.popupAbsent === true,
    sourceSame: value?.sourceSame === true,
    sourceVisible: value?.sourceVisible === true,
    sourceIntact: value?.sourceIntact === true,
  };
}
// Optional idle-expiry journey (LOCKLARK_TEST_ROUTE_IDLE_TTL=1 in route detail
// mode). It starts only after all of the default route switch/reload/
// no-prompt/mouse-rejected assertions have passed, then runs one ordinary route
// journey and leaves it idle: exactly one physical Ctrl+W addressed to the
// stale route tab, an exact proof that the source page is back and that route
// target is gone, the ordinary action popup, match, exact synthetic row and
// physical row click, one physical 批准本次操作 click, and then no input at all
// until the worker's own two-minute TTL revokes the new route and its rendered
// detail wipes. Every page read is a read-only CDP DOM inspection by fixed
// booleans/enums; nothing navigates, messages the worker, dispatches DOM events
// or installs a hook. Secret values, tokens, URLs and raw logs never leave the
// page, a helper or this closure.
const ROUTE_IDLE_CLOSE_STALE = Object.freeze([{ key: "Control_L+w" }]);
// The worker's fixed route lifetime: the live detail must survive this long
// after the physical row click before any wipe may be accepted.
const ROUTE_IDLE_TTL = 120000;
// Bounded overall wipe window, measured from that same physical row click.
const ROUTE_IDLE_WIPE_LIMIT = 150000;
const ROUTE_IDLE_POLL = 2000;
function phase(value) {
  stage = value;
  console.log("Native browser stage: " + value);
}
const key = join(state, "tls.key"),
  cert = join(state, "tls.crt");
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    key,
    "-out",
    cert,
    "-subj",
    "/CN=login.locklark.test",
    "-addext",
    checkoutFrames
      ? "subjectAltName=DNS:login.locklark.test,DNS:checkout.locklark.test,DNS:checkout.other.test"
      : "subjectAltName=DNS:login.locklark.test",
  ],
  { stdio: "ignore" },
);
// Trust only this ephemeral test certificate, rather than disabling TLS checks.
const spki = createHash("sha256")
  .update(
    new X509Certificate(readFileSync(cert)).publicKey.export({
      type: "spki",
      format: "der",
    }),
  )
  .digest("base64");
const html = `<!doctype html><html><title>${browserWindowTitle}</title><body><h1>Synthetic login</h1><form method="post"><label>User<input id="username" autocomplete="username"></label><label>Password<input id="password" type="password" autocomplete="current-password"></label><button>Submit</button></form><script>window.submits=0;document.querySelector('form').addEventListener('submit',e=>{e.preventDefault();window.submits++;});</script></body></html>`;
const server = createServer(
  { key: readFileSync(key), cert: readFileSync(cert) },
  (req, res) => {
    res.setHeader("Content-Type", "text/html");
    if (checkoutFrames) {
      let route;
      try {
        route = checkoutRouteCase(req.url);
      } catch {
        res.statusCode = 404;
        res.end();
        return;
      }
      if (route.kind === "checkout") {
        res.end(checkoutTopHTML(server.address().port, route.options));
        return;
      }
      if (route.kind === "card") {
        res.end(checkoutCardHTML());
        return;
      }
    }
    res.end(
      req.url.startsWith("/otp")
        ? otpHTML.replace(
            "Locklark OTP acceptance",
            "Locklark acceptance · OTP",
          )
        : html,
    );
  },
);
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const origin = "https://login.locklark.test:" + server.address().port;
let browser;
const logs = [];
const delay = (ms) => new Promise((r) => setTimeout(r, ms));

// One ordinary route journey, then idle through the worker's full two-minute
// route TTL. It runs only in the opt-in route idle mode, after every default
// route assertion passed. Every action is real (the XTest key, the native
// pointer helper, the popup mouse wrapper); nothing messages the worker,
// navigates, dispatches DOM events, installs a hook or advances a synthetic
// clock. Only fixed booleans and enums leave each page, and secrets, tokens,
// URLs and raw logs are never read out or printed. It returns three fixed
// booleans for the failure report.
async function acceptRouteIdleExpiry(driver) {
  const {
    browser: context,
    input,
    fixture,
    phase: mark,
    eventually: wait,
    openPopup: openActionPopup,
    extensionTargets: targets,
    attachRoute: attach,
    closeAdapter,
    browserKey,
    labelInspect,
    vaultRows,
    // The already-tested approved-detail probe/verifier and the read-only
    // native no-prompt inspection are locals of the main acceptance block.
    routeSurfaceProbe,
    verifyRouteSurface,
    nativeInspection,
  } = driver;
  assert(
    typeof routeSurfaceProbe === "function" &&
      typeof verifyRouteSurface === "function" &&
      typeof nativeInspection === "function",
    "Idle route probes missing",
  );
  const idle = { approvedDetail: false, liveObserved: false, wipeCompleted: false };
  routeIdleObservation = idle;
  // Diagnostics only: records of earlier routes are already closed; the fresh
  // ones below describe this journey alone and are sanitized at the boundary.
  routeLifecycleObservation = null;
  routeStatusTrace = null;
  routeIdleCloseStaleObservation = null;
  // The controlled source page by reference only: never by URL, id or index.
  const sourcePage = context
    .pages()
    .find((entry) => !/^chrome-extension:\/\//.test(entry.url()));
  assert(sourcePage, "Original source tab missing");
  // The expected path is this exact controlled page's own pathname (opened at
  // origin + "/login"), not the bare origin's "/" path. The synthetic URL is
  // used only here to derive it and is never retained or reported.
  const sourcePath = new URL(sourcePage.url()).pathname;
  // The stale (closed/revoked) route left by the default checkpoint, found
  // through the fixed route fragment pattern. Its tab and token stay here.
  const staleRoutes = (await targets()).filter((target) =>
    ROUTE_PAGE.test(target.url),
  );
  assert(staleRoutes.length === 1, "Route target was replaced");
  const staleRoute = staleRoutes[0];
  assert(
    !(await targets()).some((target) => ACTION_POPUP.test(target.url)),
    "Action popup target stayed open",
  );
  // Read-only reattach to the stale route, proven complete and active before
  // the key.
  const stale = await attach(staleRoute);
  try {
    await wait(
      async () => (await stale.evaluate("document.readyState")) === "complete",
      "Route page did not load",
    );
    assert.equal(
      await stale.evaluate(
        'document.visibilityState === "visible" && document.hasFocus() === true',
      ),
      true,
      "Route tab is not the active tab",
    );
    mark("route:idle-close-stale");
    // Exactly one physical Ctrl+W addressed to the stale route tab by its
    // active title prefix; only this adapter's client is disconnected first.
    await closeAdapter(stale);
    browserKey(ROUTE_IDLE_CLOSE_STALE, ROUTE_TITLE_PREFIX);
    // The exact source page is back and intact, the stale target is gone and
    // no other route page or action popup is left.
    await wait(async () => {
      const live = await targets();
      const current = context
        .pages()
        .find((entry) => !/^chrome-extension:\/\//.test(entry.url()));
      const sourceSame = current === sourcePage;
      const state = sourceSame
        ? await current.evaluate(sourcePageProbe(sourcePath))
        : null;
      const staleIdAbsent = !live.some(
        (target) => target.id === staleRoute.id,
      );
      const routesAbsent = !live.some((target) => ROUTE_PAGE.test(target.url));
      const popupAbsent = !live.some((target) => ACTION_POPUP.test(target.url));
      const sourceVisible = state?.visible === true;
      const sourceIntact = sourcePageIntact(state);
      routeIdleCloseStaleObservation = sanitizeRouteIdleCloseStale({
        staleIdAbsent,
        routesAbsent,
        popupAbsent,
        sourceSame,
        sourceVisible,
        sourceIntact,
      });
      return (
        staleIdAbsent &&
        routesAbsent &&
        popupAbsent &&
        sourceSame &&
        sourceVisible &&
        sourceIntact
      );
    }, "Stale route tab was not closed");
  } finally {
    // Disconnecting an already disconnected adapter client is harmless.
    try {
      await closeAdapter(stale);
    } catch {}
  }
  assert(
    sourcePageIntact(await sourcePage.evaluate(sourcePageProbe(sourcePath))),
    "Original source tab missing",
  );
  mark("route:idle-source");
  // Second ordinary journey through the same rendered action popup. The host
  // is already paired, so only the dismissal key and the real actuation key
  // are sent: no connect or unlock is repeated.
  const action = await openActionPopup();
  await wait(
    async () => (await action.disabled("#search-input")) === false,
    "Paired popup not ready",
  );
  mark("route:idle-match");
  await action.click("#refresh");
  await wait(
    async () =>
      String(await action.text("#status")).includes("个当前网站") &&
      (await action.disabled("#refresh")) === false,
    "Exact-origin match missing",
  );
  mark("route:idle-vault-open");
  await action.click('#filter-tabs [data-filter="all"]');
  await wait(
    async () =>
      (await action.evaluate("document.readyState")) === "complete" &&
      (await action.count("#vault-list .vault-item")) > 0,
    "Vault rows missing",
  );
  mark("route:idle-exact-row");
  const rows = await action.evaluate(vaultRows);
  assert(
    Array.isArray(rows) &&
      rows.length === 1 &&
      rows[0].id === fixture.SeedID &&
      rows[0].title === fixture.Title &&
      rows[0].visible === true,
    "Exact synthetic vault row missing",
  );
  const rowSelector =
    '#vault-list .vault-item[data-item-id="' + fixture.SeedID + '"]';
  // The approved-detail probe: the tested route surface check with every
  // non-displayable fixture canary forbidden. The verified Username is the only
  // canary that may appear, and the masked password value may not.
  const liveProbe = routeSurfaceProbe(
    fixture.Title,
    fixture.Value,
    routeForbiddenCanaries(fixture),
  );
  const before = new Set((await targets()).map((target) => target.id));
  const pagesBefore = new Set(
    context
      .pages()
      .filter((entry) => !/^chrome-extension:\/\//.test(entry.url())),
  );
  mark("route:idle-row-click");
  // The TTL is measured from this physical row click, immediately before it.
  const idleStart = Date.now();
  // Exactly one real CDP mouse press/release through the popup wrapper.
  await action.click(rowSelector);
  mark("route:idle-page-opened");
  let opened;
  await wait(async () => {
    const candidates = (await targets()).filter(
      (target) =>
        !before.has(target.id) &&
        ROUTE_PAGE.test(target.url) &&
        (target.type === "page" || target.type === "tab"),
    );
    if (candidates.length > 1) throw Error("Route page must be unique");
    opened = candidates[0];
    return !!opened;
  }, "Route page did not open");
  const routeTarget = opened.id;
  assert.equal(
    (await targets()).filter((target) => ROUTE_PAGE.test(target.url)).length,
    1,
    "Route page must be unique",
  );
  // Diagnostics only: a bounded main-frame lifecycle record of this target.
  observeRouteLifecycle(opened);
  mark("route:idle-popup-closed");
  await wait(async () => !(await action.ready()), "Action popup stayed open");
  await wait(
    async () =>
      !(await targets()).some((target) => ACTION_POPUP.test(target.url)),
    "Action popup target stayed open",
  );
  // The route tab is the only new browser page.
  const pagesAfter = context
    .pages()
    .filter((entry) => !/^chrome-extension:\/\//.test(entry.url()));
  assert(
    pagesAfter.length === pagesBefore.size &&
      pagesAfter.every((entry) => pagesBefore.has(entry)),
    "Unexpected page opened",
  );
  mark("route:idle-attached");
  const fresh = await attach(opened);
  // Only a proven detail is ever read again by the diagnostics below.
  let proven = false;
  try {
    await wait(
      async () => (await fresh.evaluate("document.readyState")) === "complete",
      "Route page did not load",
    );
    // The route claim starts the same native V2 item-get review. Read-only,
    // focus-preserving inspections only; no label is clicked until it shows.
    mark("route:idle-native-label");
    await wait(async () => {
      lastRouteObservation = sanitizeRouteObservation(
        await fresh.evaluate(routeStateProbe(fixture.Title)),
      );
      try {
        const control =
          input([], true, labelInspect).controls?.[
            ROUTE_COPY_REVIEW_LABEL
          ];
        return control?.present === true && control?.showing === true;
      } catch {
        return false;
      }
    }, "Native route approval label missing");
    assert.equal(
      (await targets()).filter((target) => ROUTE_PAGE.test(target.url)).length,
      1,
      "Route page must be unique",
    );
    mark("route:idle-native-approve");
    // Exactly one real X11 pointer click on the native allowlisted label.
    input([{ click_label: ROUTE_COPY_REVIEW_LABEL }]);
    mark("route:idle-approved");
    // The same target is still the only route page and no popup reopened.
    const exactRoute = async () => {
      const routes = (await targets()).filter((target) =>
        ROUTE_PAGE.test(target.url),
      );
      assert(
        routes.length === 1 && routes[0].id === routeTarget,
        "Route target was replaced",
      );
      assert(
        !(await targets()).some((target) => ACTION_POPUP.test(target.url)),
        "Action popup reopened",
      );
    };
    // The native approval leaves the desktop app in front and changed no tab,
    // so the new route tab is foregrounded in place with the same
    // Page.bringToFront call the default copy proof uses: no navigation, no
    // reload and no document change. Visibility is then proven read-only.
    mark("route:idle-foreground");
    await fresh.bringToFront();
    await wait(
      async () =>
        (await fresh.evaluate("document.visibilityState")) === "visible",
      "Route page did not return to the foreground",
    );
    // The approved detail: the tested surface probe/verifier proves the route
    // is visible, shows the exact fixture title and keeps its password field
    // concealed; the page text contains no forbidden fixture canary.
    await wait(async () => {
      await exactRoute();
      const surface = await fresh.evaluate(liveProbe);
      return (
        surface?.visible === true &&
        verifyRouteSurface(surface, fixture.Title) === ""
      );
    }, "Idle route detail did not survive native approval");
    idle.approvedDetail = true;
    proven = true;
    // Nothing is touched from here: no key, pointer, CDP input or action.
    // Every probe before the worker's full two-minute TTL must confirm the
    // approved surface exactly, or fail; a wipe seen any earlier is a failure.
    mark("route:idle-live");
    mark("route:idle-wait");
    const minimumWipe = idleStart + ROUTE_IDLE_TTL;
    const wipeDeadline = idleStart + ROUTE_IDLE_WIPE_LIMIT;
    for (;;) {
      // The same target id is still the one route page between polls.
      await exactRoute();
      let wiped = false;
      try {
        wiped = routeWiped(
          await fresh.evaluate(
            routeRevokedProbe(
              fixture.Title,
              fixture.Value,
              fixtureCanaries(fixture),
            ),
          ),
        );
      } catch (error) {
        if (popupClosed(error)) throw Error("Route page was replaced");
        throw error;
      }
      const now = Date.now();
      if (now < minimumWipe) {
        // A wipe before the full original TTL is a contract failure, and any
        // other non-wiped probe must still show the approved surface.
        assert.equal(wiped, false, "Idle route detail did not stay live");
        const surface = await fresh.evaluate(liveProbe);
        assert.equal(
          surface?.visible,
          true,
          "Idle route detail left the foreground",
        );
        const finding = verifyRouteSurface(surface, fixture.Title);
        assert.equal(
          finding,
          "",
          finding || "Idle route detail did not stay live",
        );
      } else if (wiped) {
        idle.liveObserved = true;
        break;
      }
      if (Date.now() >= wipeDeadline)
        throw Error("Idle route detail did not expire");
      await delay(Math.min(ROUTE_IDLE_POLL, wipeDeadline - Date.now()));
    }
    // Bounded read-only inspection of the real native approval window after
    // the wipe. Either existing approval label offered means the trust prompt
    // is still there. An unobservable inspection throws and fails; it is never
    // read as "no prompt".
    mark("route:idle-native-absent");
    const promptDeadline = Date.now() + ROUTE_NATIVE_ABSENT_LIMIT;
    for (;;) {
      const controls = nativeInspection();
      const offered = [ROUTE_COPY_REVIEW_LABEL, ROUTE_COPY_DISCLOSURE_LABEL].some(
        (label) => {
          const control = controls?.[label];
          return (
            control?.present === true &&
            (control.enabled === true || control.showing === true)
          );
        },
      );
      if (offered) throw Error("Idle route native prompt is still present");
      if (Date.now() >= promptDeadline) break;
      await delay(200);
    }
    idle.wipeCompleted = true;
    mark("route:idle-wiped");
  } finally {
    try {
      await closeAdapter(fresh);
    } catch {}
    // Diagnostics only, once the detail was proven: one bounded final
    // lifecycle and visibility read of the same target, then the socket is
    // closed. Nothing is clicked or uninstalled.
    try {
      const routes = (await targets()).filter(
        (target) => target.id === routeTarget && ROUTE_PAGE.test(target.url),
      );
      if (proven && routes.length === 1) {
        const final = await attach(opened);
        try {
          lastRouteObservation = sanitizeRouteObservation(
            await final.evaluate(routeStateProbe(fixture.Title)),
          );
        } finally {
          try {
            await closeAdapter(final);
          } catch {}
        }
      }
    } catch {}
    closeRouteLifecycle();
  }
  // The same console canary checks the ordinary journeys apply.
  assert(
    !logs.some((s) =>
      fixtureCanaries(fixture).some((value) => s.includes(value)),
    ),
    "Synthetic secret found in browser console output",
  );
  for (const line of logs) assertPrivateText(line, fixture);
  mark("route:idle-passed");
  console.log(
    "PASS: an idle second route tab kept its approved detail without input, stayed live through its full two-minute route TTL and was fully wiped without a native prompt",
  );
  return idle;
}

async function eventually(check, message, limit = 10000) {
  const end = Date.now() + limit;
  while (Date.now() < end) {
    if (await check()) return;
    await delay(100);
  }
  throw Error(message);
}
try {
  // LOCKLARK_BROWSER_FIXTURE reuses one prebuilt fixture for this run, its
  // vault observers and the checkout step; otherwise the fixture is built.
  const fixtureExecutable = browserFixtureExecutable({ go, root, env, state });
  execFileSync(
    fixtureExecutable,
    [
      "-out",
      join(state, "vault"),
      "-origin",
      origin,
      ...(checkoutFrames ? ["-checkout-card"] : []),
    ],
    { cwd: root, env, stdio: "inherit" },
  );
  const fixture = JSON.parse(readFileSync(join(state, "vault/fixture.json")));
  observedFixture = fixture;
  privacyValues = fixtureCanaries(fixture);
  const profile = join(state, "profile");
  mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
  const registerArgs = [
    "--browser",
    browserName === "edge" ? "edge" : "chrome",
    "--host",
    resolve(host),
    "--output",
    join(profile, "NativeMessagingHosts/org.locklark.browser.json"),
  ];
  execFileSync(
    register || go,
    register ? registerArgs : ["run", "./cmd/locklark-browser-register", ...registerArgs],
    { cwd: root, env, stdio: "inherit" },
  );
  execFileSync(process.execPath, ["browser-extension/build.js", "chromium"], {
    cwd: root,
  });
  const extension = join(root, "browser-extension/dist/chromium");
  browser = await chromium.launchPersistentContext(profile, {
    headless: false,
    channel: browserName === "edge" ? undefined : "chromium",
    ...(browserExecutable ? { executablePath: browserExecutable } : {}),
    viewport: { width: 1100, height: 700 },
    ...(sharedEnvironment ? { env: sharedEnvironment } : {}),
    args: [
      "--no-sandbox",
      "--disable-extensions-except=" + extension,
      "--load-extension=" + extension,
      checkoutFrames
        ? "--host-resolver-rules=MAP login.locklark.test 127.0.0.1,MAP checkout.locklark.test 127.0.0.1,MAP checkout.other.test 127.0.0.1"
        : "--host-resolver-rules=MAP login.locklark.test 127.0.0.1",
      "--no-proxy-server",
      "--ignore-certificate-errors-spki-list=" + spki,
      "--window-size=1200,850",
      "--remote-debugging-port=0",
    ],
  });
  browser.on("console", (msg) => logs.push(msg.text()));
  const page = browser.pages()[0] || (await browser.newPage());
  await page.goto(origin + "/login");
  const worker =
    browser.serviceWorkers()[0] ||
    (await browser.waitForEvent("serviceworker"));
  assert(
    worker.url() ===
      "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/background.js",
    "Actual fixed extension identity required",
  );
  // Native-window form only. Browser-tab keys go through browserKey below,
  // which always names the Chromium window itself.
  function input(actions, native = true, inspect = false) {
    assert(native !== false, "Native window input only");
    const options = typeof inspect === "object" ? inspect : { inspect };
    const request = {
      title: "Locklark · 浏览器原生确认",
      executable: resolve(host),
      actions,
      ...options,
    };
    return JSON.parse(
      execFileSync("python3", [join(root, "scripts/browser_native_x11.py")], {
        input: JSON.stringify(request),
        env,
      }).toString(),
    );
  }
  nativeInput = input;
  // Browser-tab keys are real XTest input to the exact Chromium window. The
  // realpath comes from the launched browser, never from an environment
  // guess. Only these two fixed title prefixes are accepted, and the request
  // is always the helper's exact-title-prefix form: no native window title,
  // no inspection and no other request options.
  const chromiumExecutable = realpathSync(chromium.executablePath());
  function browserKey(actions, titlePrefix) {
    assert(
      titlePrefix === ROUTE_TITLE_PREFIX ||
        titlePrefix === SOURCE_TITLE_PREFIX,
      "Unsupported browser key target",
    );
    const request = { title_prefix: titlePrefix, executable: chromiumExecutable, actions };
    return JSON.parse(
      execFileSync("python3", [join(root, "scripts/browser_native_x11.py")], {
        input: JSON.stringify(request),
        env,
      }).toString(),
    );
  }
  // Read-only exact-title inspection of the native window that preserves
  // focus: no raise, focus or click. It never swallows a failure, so a missing
  // or unobservable window cannot be read as "no prompt".
  function nativeInspection() {
    const result = input([], true, {
      inspect: true,
      title: ROUTE_NATIVE_TITLE,
      preserve_focus: true,
    });
    const { controls } = result;
    if (
      !result ||
      typeof result !== "object" ||
      !controls ||
      typeof controls !== "object" ||
      Array.isArray(controls)
    )
      throw Error("Native no-prompt snapshot unavailable");
    return controls;
  }
  // Chrome action popups are real page targets but are not always surfaced by
  // Playwright Context.pages(). Attach to that popup through local test CDP.
  async function popupTargets() {
    const port = readFileSync(
      join(profile, "DevToolsActivePort"),
      "utf8",
    ).split("\n")[0];
    const targets = await (
      await fetch("http://127.0.0.1:" + port + "/json/list")
    ).json();
    return targets.filter(
      (target) =>
        target.url ===
        "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/popup.html",
    );
  }
  async function attachPopup(target) {
    const ws = new WebSocket(target.webSocketDebuggerUrl),
      calls = new Map();
    let seq = 0;
    const closed = (error) => popupClosed(error) || ws.readyState !== WebSocket.OPEN;
    ws.addEventListener("message", (event) => {
      const response = JSON.parse(event.data);
      if (response.method === "Runtime.consoleAPICalled")
        logs.push(JSON.stringify(response.params));
      const call = calls.get(response.id);
      if (call) {
        calls.delete(response.id);
        clearTimeout(call.timer);
        response.error
          ? call.reject(Error("Popup CDP failed"))
          : call.resolve(response.result);
      }
    });
    ws.addEventListener("close", () => {
      for (const c of calls.values()) {
        clearTimeout(c.timer);
        c.reject(Error("Popup closed"));
      }
      calls.clear();
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.close();
        reject(Error("Popup CDP connection timed out"));
      }, 3000);
      ws.addEventListener(
        "open",
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true },
      );
      ws.addEventListener(
        "error",
        () => {
          clearTimeout(timer);
          reject(Error("Popup CDP connection failed"));
        },
        { once: true },
      );
      ws.addEventListener(
        "close",
        () => {
          clearTimeout(timer);
          reject(Error("Popup CDP closed"));
        },
        { once: true },
      );
    });
    const call = (method, params = {}) =>
      new Promise((resolve, reject) => {
        if (ws.readyState !== WebSocket.OPEN) {
          reject(Error("Popup CDP closed"));
          return;
        }
        const id = ++seq,
          timer = setTimeout(() => {
            calls.delete(id);
            reject(Error("Popup CDP timed out"));
          }, 3000);
        calls.set(id, { resolve, reject, timer });
        ws.send(JSON.stringify({ id, method, params }));
      });
    await call("Runtime.enable");
    const evaluate = async (expression) => {
      const r = await call("Runtime.evaluate", {
        expression,
        returnByValue: true,
      });
      if (r.exceptionDetails) throw Error("Popup inspection failed");
      return r.result.value;
    };
    return {
      // Real evaluation in this exact popup document, used for a DOM-dispatched
      // event that is deliberately not a browser input gesture.
      evaluate,
      insertText: (text) => call("Input.insertText", { text }),
      attribute: (selector, name) => evaluate(
        "document.querySelector(" + JSON.stringify(selector) + ")?.getAttribute(" + JSON.stringify(name) + ")",
      ),
      setFile: async (selector, path) => {
        const { root } = await call("DOM.getDocument");
        const { nodeId } = await call("DOM.querySelector", { nodeId: root.nodeId, selector });
        assert(nodeId, "Attachment file control unavailable");
        await call("DOM.setFileInputFiles", { nodeId, files: [path] });
      },
      pressKey: async (key, keyCode) => {
        for (const type of ["keyDown", "keyUp"])
          await call("Input.dispatchKeyEvent", { type, key, code: key, windowsVirtualKeyCode: keyCode });
      },
      selectAll: async () => {
        for (const type of ["keyDown", "keyUp"])
          await call("Input.dispatchKeyEvent", {
            type, key: "a", code: "KeyA", modifiers: 2, windowsVirtualKeyCode: 65,
          });
      },
      // Focus the attached page itself through CDP; no other side effect.
      bringToFront: () => call("Page.bringToFront"),
      targetId: target.id,
      close: () => ws.close(),
      dismiss: async () => {
        await call("Page.close").catch(() => {});
        ws.close();
      },
      ready: async () => {
        try {
          return await evaluate(
            'document.readyState === "complete" && document.visibilityState === "visible" && document.hasFocus() && document.querySelector("#status")?.textContent.length > 0',
          );
        } catch (error) {
          if (closed(error)) return false;
          throw error;
        }
      },
      text: (selector) =>
        evaluate(
          "document.querySelector(" + JSON.stringify(selector) + ")?.innerText",
        ),
      count: (selector) =>
        evaluate(
          "document.querySelectorAll(" + JSON.stringify(selector) + ").length",
        ),
      disabled: (selector) =>
        evaluate(
          "document.querySelector(" + JSON.stringify(selector) + ")?.disabled",
        ),
      visible: (selector) => evaluate(
        "!!document.querySelector(" + JSON.stringify(selector) + ")?.getClientRects().length",
      ),
      value: (selector) => evaluate(
        "document.querySelector(" + JSON.stringify(selector) + ")?.value ?? null",
      ),
      selectOption: async (selector, value) => {
        const options = await evaluate(
          "Array.from(document.querySelector(" + JSON.stringify(selector) + ")?.options || []).map(option => option.value)",
        );
        const index = options.indexOf(value);
        assert(index > 0, "Exact popup option unavailable");
        const id = selector.startsWith("#") ? selector.slice(1) : "";
        const labelSelector = id ? 'label[for="' + id + '"]' : selector;
        const { root } = await call("DOM.getDocument");
        const label = await call("DOM.querySelector", { nodeId: root.nodeId, selector: labelSelector });
        const { nodeId } = label.nodeId ? label :
          await call("DOM.querySelector", { nodeId: root.nodeId, selector });
        assert(nodeId, "Popup select unavailable");
        const { model } = await call("DOM.getBoxModel", { nodeId });
        const x = (model.content[0] + model.content[4]) / 2;
        const y = (model.content[1] + model.content[5]) / 2;
        for (const type of ["mousePressed", "mouseReleased"])
          await call("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 });
        await eventually(async () =>
          await evaluate("document.activeElement === document.querySelector(" + JSON.stringify(selector) + ")"),
        "Popup select focus missing");
        const key = async (name, code, keyCode) => {
          for (const type of ["keyDown", "keyUp"])
            await call("Input.dispatchKeyEvent", { type, key: name, code, windowsVirtualKeyCode: keyCode });
        };
        await key("Home", "Home", 36);
        for (let step = 0; step < index; step++) await key("ArrowDown", "ArrowDown", 40);
        await eventually(async () =>
          (await evaluate("document.querySelector(" + JSON.stringify(selector) + ")?.value")) === value,
        "Physical popup select did not apply the exact option");
      },
      screenshot: async (path) => {
        const result = await call("Page.captureScreenshot", {
          format: "png",
          captureBeyondViewport: false,
        });
        writeFileSync(path, Buffer.from(result.data, "base64"), {
          mode: 0o600,
        });
      },
      click: async (selector) => {
        const rect = await evaluate(
          "(()=>{const e=document.querySelector(" +
            JSON.stringify(selector) +
            ');if(!e||e.disabled||document.visibilityState!=="visible"||!document.hasFocus())return null;e.scrollIntoView({block:"center",inline:"nearest"});const r=e.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,hit=document.elementFromPoint(x,y);if(!hit||(hit!==e&&!e.contains(hit)))return null;return {x,y};})()',
        );
        assert(rect, "Popup control must be available");
        await call("Input.dispatchMouseEvent", {
          type: "mousePressed",
          ...rect,
          button: "left",
          clickCount: 1,
        });
        await call("Input.dispatchMouseEvent", {
          type: "mouseReleased",
          ...rect,
          button: "left",
          clickCount: 1,
        });
      },
    };
  }
  async function openPopup() {
    const previous = new Set((await popupTargets()).map((target) => target.id));
    if (lastPopup) {
      previous.add(lastPopup.targetId);
      // Chrome closes the action popup itself after a request that needs the
      // native window, so dismissing an already-closed target is expected.
      await lastPopup.dismiss().catch(() => {});
      lastPopup = null;
    }
    await page.bringToFront();
    // Exactly one dismissal and one user action. Readiness is observed without
    // re-opening a popup or repeating a click/authorization request.
    browserKey([{ key: "Escape" }], SOURCE_TITLE_PREFIX);
    await eventually(
      async () =>
        !(await popupTargets()).some((target) => previous.has(target.id)),
      "Previous action popup did not close",
    );
    browserKey([{ key: "Control_L+Shift_L+y" }], SOURCE_TITLE_PREFIX);
    let target;
    await eventually(async () => {
      const targets = (await popupTargets()).filter(
        (target) => !previous.has(target.id),
      );
      if (targets.length > 1) throw Error("Action popup must be unique");
      target = targets[0];
      return !!target;
    }, "Action popup did not open");
    const popup = await attachPopup(target);
    lastPopup = popup;
    await eventually(
      async () => (await popup.ready()) === true,
      "Action popup is not visible and focused",
    );
    return popup;
  }
  // Rendered vault rows only: identity, title and hit-test visibility. Field
  // values, revisions and item URLs are never read here.
  const VAULT_ROWS =
    "[...document.querySelectorAll('#vault-list .vault-item')]" +
    ".map(row=>({id:row.dataset.itemId||''," +
    "title:row.querySelector('.vault-item-title')?.textContent??null," +
    "visible:row.getClientRects().length>0}))";
  // The route detail surface as rendered: visibility, view, visible title,
  // concealed password control, one private-value substring check and the same
  // check for every supplied forbidden canary. Callers that pass only the
  // title/value pair keep their exact previous gate (the private value). Page
  // text, values, identity, URL and token never leave the page.
  function routeSurfaceProbe(title, password, forbidden = [password]) {
    const forbiddenTexts = JSON.stringify([...forbidden]);
    return `(()=>{
      const body=document.body;
      const detail=document.querySelector('#detail-view');
      const heading=document.querySelector('#detail-title');
      const fields=document.querySelector('#detail-fields');
      const values=fields?[...fields.querySelectorAll('.field-value')]:[];
      const concealed=!!(
        fields?.querySelector('[data-field-type="password"],[data-field-type="concealed"],.concealed,[data-concealed="true"],input[type="password"]') ||
        values.some(value=>/^[\u2022\u25cf*]+$/.test(String(value.textContent||'').trim()))
      );
      const bodyText=body?String(body.innerText):'';
      const forbidden=${forbiddenTexts};
      return {
        visible:document.visibilityState==='visible',
        view:body?.dataset?.view||'',
        detailShown:!!detail&&!detail.hidden,
        title:heading?heading.textContent:null,
        concealed,
        passwordRendered:body?bodyText.includes(${JSON.stringify(password)}):true,
        forbiddenCanaryRendered:forbidden.some((value)=>bodyText.includes(value))
      };
    })()`;
  }
  // Fixed findings only; never text, ids, revisions, URLs or tokens.
  function verifyRouteSurface(surface, title) {
    if (surface?.detailShown !== true) return "route-detail-view-missing";
    if (surface.view !== "detail") return "route-detail-view-missing";
    if (surface.title !== title) return "route-detail-title-mismatch";
    if (surface.concealed !== true) return "route-concealed-control-missing";
    if (surface.passwordRendered !== false) return "route-password-rendered";
    if (surface.forbiddenCanaryRendered !== false)
      return "route-forbidden-canary-rendered";
    return "";
  }
  async function acceptRouteDetailRead(driver) {
    const {
      browser: context,
      fixture,
      phase: mark,
      eventually: wait,
      openPopup: openActionPopup,
      extensionTargets: targets,
      attachRoute: attach,
    } = driver;
    assert(
      typeof fixture.SeedID === "string" && /^[a-f0-9]{32}$/.test(fixture.SeedID),
      "Synthetic seed item identity missing",
    );
    assert(
      typeof fixture.Title === "string" && fixture.Title.length > 0,
      "Synthetic fixture title missing",
    );
    try {
    mark("route:popup");
    const action = await openActionPopup();
    // The ready control is the vault search field, not the refresh match.
    // Waiting on #refresh here would consume the wait before the ordinary
    // match step below, even though the popup already rendered vault status.
    await wait(
      async () => (await action.disabled("#search-input")) === false,
      "Paired popup not ready",
    );
    // The worker binds a route only to a source document captured by the
    // ordinary match the user starts from this popup. One physical refresh
    // click is that user action; its rendered status proves the capture.
    mark("route:match");
    await action.click("#refresh");
    await wait(
      async () =>
        String(await action.text("#status")).includes("个当前网站") &&
        (await action.disabled("#refresh")) === false,
      "Exact-origin match missing",
    );
    mark("route:vault-open");
    await action.click('#filter-tabs [data-filter="all"]');
    await wait(
      async () =>
        (await action.evaluate("document.readyState")) === "complete" &&
        (await action.count("#vault-list .vault-item")) > 0,
      "Vault rows missing",
    );
    mark("route:exact-row");
    // Exactly one rendered vault row, the fixture's seed item, its title.
    const rows = await action.evaluate(VAULT_ROWS);
    assert(
      Array.isArray(rows) &&
        rows.length === 1 &&
        rows[0].id === fixture.SeedID &&
        rows[0].title === fixture.Title &&
        rows[0].visible === true,
      "Exact synthetic vault row missing",
    );
    const rowSelector =
      '#vault-list .vault-item[data-item-id="' + fixture.SeedID + '"]';
    const before = new Set((await targets()).map((target) => target.id));
    // The original source tab is the one non-extension page the popup matched;
    // it is kept by reference only, never by URL, id or index in a report.
    const sourcePage = context
      .pages()
      .find((entry) => !/^chrome-extension:\/\//.test(entry.url()));
    assert(sourcePage, "Original source tab missing");
    const pagesBefore = new Set(
      context
        .pages()
        .filter((entry) => !/^chrome-extension:\/\//.test(entry.url())),
    );
    mark("route:row-click");
    // Exactly one real CDP mouse press/release through the popup wrapper.
    await action.click(rowSelector);
    mark("route:page-opened");
    let opened;
    await wait(async () => {
      const candidates = (await targets()).filter(
        (target) =>
          !before.has(target.id) &&
          ROUTE_PAGE.test(target.url) &&
          (target.type === "page" || target.type === "tab"),
      );
      if (candidates.length > 1) throw Error("Route page must be unique");
      opened = candidates[0];
      return !!opened;
    }, "Route page did not open");
    const routeTarget = opened.id;
    assert.equal(
      (await targets()).filter((target) => ROUTE_PAGE.test(target.url)).length,
      1,
      "Route page must be unique",
    );
    // Diagnostics only: from this exact target's discovery on, keep a bounded
    // main-frame lifecycle record across the popup-close waits and the route
    // attachment. It adds no wait, gate or behaviour, and any failure stays
    // swallowed; the socket is closed in this checkpoint's finally path.
    observeRouteLifecycle(opened);
    // Diagnostics only: take one best-effort visible-DOM snapshot right after
    // the exact route target is found and verified, before any popup-closed
    // wait, so a later failure can distinguish a route that was still locked
    // from one that was already closed at first sight. It uses a short-lived
    // CDP connection with no added wait or timeout, and any failure is
    // swallowed so no acceptance step can fail or skip because of it.
    try {
      // Diagnostics only: install the visible-DOM status trace on this exact
      // route document in this same earliest connection, before any
      // popup-closed wait, so a fast overwrite or disconnect is still recorded.
      const initial = await attach(opened);
      try {
        await initial.evaluate(routeStatusTraceProbe(fixture.Title));
        routeStatusTraceInstalled = true;
        await readRouteStatusTrace(initial);
        lastRouteObservation = sanitizeRouteObservation(
          await initial.evaluate(routeStateProbe(fixture.Title)),
        );
        recordRouteObservation(lastRouteObservation);
      } finally {
        try {
          await initial.close();
        } catch {}
      }
    } catch {}
    mark("route:popup-closed");
    await wait(async () => !(await action.ready()), "Action popup stayed open");
    await wait(
      async () =>
        !(await targets()).some((target) => ACTION_POPUP.test(target.url)),
      "Action popup target stayed open",
    );
    // Diagnostics only: one best-effort visible-DOM snapshot of the same exact
    // route target right after both popup-closed waits, before the pagesAfter
    // check and the route attachment, so a route-detail failure can tell
    // whether the page was still locked or already closed at that point. No
    // added wait or timeout; any failure is swallowed so no acceptance step
    // can fail or skip because of it. It is stored separately from
    // lastRouteObservation and the bounded history.
    try {
      const afterClose = await attach(opened);
      try {
        await readRouteStatusTrace(afterClose);
        routeAfterPopupClose = sanitizeRouteObservation(
          await afterClose.evaluate(routeStateProbe(fixture.Title)),
        );
      } finally {
        try {
          await afterClose.close();
        } catch {}
      }
    } catch {}
    // Diagnostics only: the same targets() list, read once, answers whether
    // the exact captured route target still exists and still carries the route
    // URL at this checkpoint. Only these two fixed booleans are kept; any
    // failure leaves the checkpoint absent and cannot affect acceptance.
    try {
      const live = await targets();
      const route = live.find((target) => target.id === routeTarget);
      routeTargetAfterPopupClose = {
        routeTargetExists: !!route,
        routeTargetStillRoute: !!route && ROUTE_PAGE.test(route.url),
      };
    } catch {}
    // The route tab is the only new browser page: every non-extension page
    // present now must be one of the controlled-login pages seen before.
    const pagesAfter = context
      .pages()
      .filter((entry) => !/^chrome-extension:\/\//.test(entry.url()));
    assert(
      pagesAfter.length === pagesBefore.size &&
        pagesAfter.every((entry) => pagesBefore.has(entry)),
      "Unexpected page opened",
    );
    mark("route:attached");
    const route = await attach(opened);
    try {
      await wait(
        async () =>
          (await route.evaluate("document.readyState")) === "complete",
        "Route page did not load",
      );
      // The route claim starts the same native V2 item-get review the action
      // popup would have used, so the real per-operation approval appears only
      // after this tab exists. A missing window/label is retried inside the
      // bounded wait; no inspect output is retained or logged.
      mark("route:native-label");
      // Read-only visible-DOM observation refreshed on every bounded attempt,
      // so a failure can say whether this page never left startup, closed
      // after a rejected claim, or reached its detail. It never reads a
      // runtime message and retains no text, value, URL, token or hidden
      // state; it cannot make the wait pass.
      const observeRouteState = async () => {
        try {
          await readRouteStatusTrace(route);
          lastRouteObservation = sanitizeRouteObservation(
            await route.evaluate(routeStateProbe(fixture.Title)),
          );
          recordRouteObservation(lastRouteObservation);
        } catch {}
      };
      // Ready-label polling is read-only. It must never raise or focus the
      // native window: doing so can hide the route page behind the idle native
      // window before any approval exists. The shared focus-preserving inspect
      // form (same exact native title and executable supplied by `input`, no
      // prefix form, empty action list) keeps the window where it is, exactly
      // like the popup-stage absence probes.
      const approveLabel = async () => {
        await observeRouteState();
        try {
          const control = input([], true, ROUTE_LABEL_INSPECT).controls?.["批准本次操作"];
          return control?.present === true && control?.showing === true;
        } catch {
          return false;
        }
      };
      await wait(approveLabel, "Native route approval label missing");
      assert.equal(
        (await targets()).filter((target) => ROUTE_PAGE.test(target.url))
          .length,
        1,
        "Route page must be unique",
      );
      mark("route:native-approve");
      // Exactly one real X11 pointer click on the native allowlisted label.
      input([{ click_label: "批准本次操作" }]);
      mark("route:approved");
      let finding = "";
      const verified = async () => {
        const live = await targets();
        const routes = live.filter((target) => ROUTE_PAGE.test(target.url));
        assert(
          routes.length === 1 && routes[0].id === routeTarget,
          "Route target was replaced",
        );
        assert(
          !live.some((target) => ACTION_POPUP.test(target.url)),
          "Action popup reopened",
        );
        finding = verifyRouteSurface(
          await route.evaluate(
            routeSurfaceProbe(fixture.Title, fixture.Value),
          ),
          fixture.Title,
        );
        return finding === "";
      };
      try {
        await wait(verified, "Route detail did not survive native approval");
      } catch (error) {
        // Only the fixed allowlisted finding id leaves this checkpoint.
        if (finding) throw Error(finding);
        throw error;
      }
      mark("route:verified");
      // The same target id is still the one route page, after approval.
      const routes = (await targets()).filter((target) =>
        ROUTE_PAGE.test(target.url),
      );
      assert.equal(routes.length, 1, "Route target was replaced");
      assert.equal(routes[0].id, routeTarget, "Route target was replaced");
      // Per-field copy proof. The harness only performs mouse input and reads
      // fixed labels/booleans; it never dispatches DOM events or messages.
      mark("route:copy-focus");
      // The native read approval leaves the desktop app in front, so the
      // route tab must be returned to the foreground as an ordinary user
      // would. The reviewed mouse wrapper only clicks a visible, focused page.
      await route.bringToFront();
      await wait(
        async () =>
          (await route.evaluate(
            'document.visibilityState === "visible" && document.hasFocus() === true',
          )) === true,
        "Route page did not return to the foreground",
      );
      mark("route:copy-field");
      assert.equal(
        await route.count(ROUTE_COPY_FIELD_SELECTOR),
        1,
        "Route password copy control missing",
      );
      // The rendered value stays concealed: only the masked marker, and the
      // raw password is nowhere in the page text.
      const rowBefore = await route.evaluate(
        routePasswordRowProbe(fixture.Value),
      );
      assert.equal(rowBefore?.masked, true, "Route password is not concealed");
      assert.equal(rowBefore?.leaked, false, "Route displayed the password");
      await route.click(ROUTE_COPY_FIELD_SELECTOR);
      mark("route:field-approval");
      const nativeControl = (label) => {
        try {
          return (
            input([], true, {
              inspect: true,
              preserve_focus: true,
            }).controls?.[label] ?? null
          );
        } catch {
          return null;
        }
      };
      const nativeShown = (label) => {
        const control = nativeControl(label);
        return control?.present === true && control?.showing === true;
      };
      // Only the fixed approval label requested for this field disclosure, or
      // (legacy fallback) the exact route item-get review, may be accepted.
      await wait(
        () => nativeShown(ROUTE_COPY_DISCLOSURE_LABEL) || nativeShown(ROUTE_COPY_REVIEW_LABEL),
        "Native field disclosure did not appear",
      );
      // Legacy fallback: approve the pending item-get review physically once.
      // A disclosure already present is the native path, never preceded.
      let approvedReview = false;
      if (
        nativeShown(ROUTE_COPY_REVIEW_LABEL) &&
        !nativeShown(ROUTE_COPY_DISCLOSURE_LABEL)
      ) {
        input([{ click_label: ROUTE_COPY_REVIEW_LABEL }]);
        approvedReview = true;
      }
      // The requested field disclosure itself is always approved physically.
      await wait(
        () => nativeShown(ROUTE_COPY_DISCLOSURE_LABEL),
        approvedReview
          ? "Native field disclosure did not follow its review"
          : "Native field disclosure did not appear",
      );
      mark("route:field-approve");
      input([{ click_label: ROUTE_COPY_DISCLOSURE_LABEL }]);
      mark("route:field-approved");
      // The same UI shows its fixed successful-copy feedback.
      await wait(
        async () => {
          const feedback = await route.text("#toast");
          return ROUTE_COPY_FEEDBACK.some((text) => String(feedback ?? "").includes(text));
        },
        "Route copy feedback missing",
      );
      // Independent OS comparison: the expectation travels only on the
      // private pipe; only the boolean comparison is kept.
      mark("route:clipboard");
      const clipboardReader = new PrivateClipboard({ root, state, env });
      try {
        await clipboardReader.start();
        await wait(
          () => clipboardReader.matches(fixture.Value),
          "OS clipboard did not receive the approved field",
        );
      } finally {
        clipboardReader.stop();
      }
      // The route page is still the same page after the copy.
      const routesAfterCopy = (await targets()).filter((target) =>
        ROUTE_PAGE.test(target.url),
      );
      assert.equal(routesAfterCopy.length, 1, "Route target was replaced");
      assert.equal(routesAfterCopy[0].id, routeTarget, "Route target was replaced");
      // The same console canary checks the ordinary native journeys apply
      // before this checkpoint may claim a pass. Logs are never printed.
      assert(
        !logs.some((s) =>
          fixtureCanaries(fixture).some((value) => s.includes(value)),
        ),
        "Synthetic secret found in browser console output",
      );
      for (const line of logs) assertPrivateText(line, fixture);
      console.log(
        "PASS: real popup exact row opened one persistent route tab; native approval kept the same tab's detail without revealing values; its concealed field copy was disclosed through native approval and only the independent OS clipboard comparison matched",
      );
    } finally {
      try {
        await route.close();
      } catch {}
      // Diagnostics only: one final read, then stop observing in the page where
      // it is still reachable; a closed page fails this read and the trace
      // stays as last observed.
      await refreshRouteStatusTrace(attach, opened, true);
    }
    // Route revocation checkpoint: the same tab and target, after the copy
    // proof. The positive block's CDP client and diagnostics trace are already
    // closed above; the revocation reads use only a fresh client reconnected
    // to the same captured target.
    let stale = null;
    let revoked = null;
    try {
      // The route tab outlived the positive block; only the test's websocket
      // client was closed. Reattach a fresh client to the same captured
      // target, proven still to be the exact route page by the targets list
      // first, and use it for every route-page read below. A failed attach or
      // a page whose readyState is not complete throws and fails the
      // checkpoint; it is never read as success.
      assert.equal(
        (await targets()).filter(
          (target) => target.id === routeTarget && ROUTE_PAGE.test(target.url),
        ).length,
        1,
        "Route target was replaced",
      );
      revoked = await attach(opened);
      await wait(
        async () => (await revoked.evaluate("document.readyState")) === "complete",
        "Route page did not load",
      );
      // The route page is still the active tab, so the active window is titled
      // exactly "Locklark". Exactly one XTest key batch, addressed to the
      // Chromium window by the ACTIVE route tab's exact title prefix and
      // executable, switches to the original source tab. Nothing is messaged
      // to the worker, navigated via CDP or injected.
      mark("route:switch-source");
      assert.equal(
        await revoked.evaluate(
          'document.visibilityState === "visible" && document.hasFocus() === true',
        ),
        true,
        "Route tab is not the active tab",
      );
      browserKey(ROUTE_SWITCH_SOURCE, ROUTE_TITLE_PREFIX);
      // The source tab became visible and focused again.
      await wait(
        async () =>
          (await sourcePage.evaluate(
            'document.visibilityState === "visible" && document.hasFocus() === true',
          )) === true,
        "Source tab did not become visible",
      );
      // The hidden route page then wipes itself: the real background switch
      // revocation reaches its lifecycle port. Only booleans are read.
      await wait(async () => {
        try {
          return routeWiped(
            await revoked.evaluate(routeRevokedProbe(fixture.Title, fixture.Value)),
          );
        } catch (error) {
          if (popupClosed(error)) throw Error("Route page was replaced");
          throw error;
        }
      }, "Background revocation did not wipe the route detail");
      recordRouteLifecycle("route-revoked");
      // Back to that same route tab by one physical Control_L+Tab. The source
      // tab is now the active one, so the key is addressed by the source
      // page's own title prefix.
      mark("route:return");
      browserKey(ROUTE_RETURN, SOURCE_TITLE_PREFIX);
      await wait(
        async () =>
          (await revoked.evaluate(
            'document.visibilityState === "visible" && document.hasFocus() === true',
          )) === true,
        "Route page did not return to the foreground",
      );
      // The returned foreground page must still satisfy the full wipe contract,
      // read by the same full probe as the reload below.
      await wait(async () => {
        const returned = await revoked.evaluate(
          routeRevokedProbe(fixture.Title, fixture.Value),
        );
        return returned?.visible === true && routeWiped(returned);
      }, "Returned route page kept its detail");
      // The captured route target still exists and is still this one route
      // page, both before the reload key and still after it; the route tab is
      // the active tab before the key, so the key reaches it.
      const routeTargets = async () =>
        (await targets()).filter(
          (target) => target.id === routeTarget && ROUTE_PAGE.test(target.url),
        );
      assert.equal((await routeTargets()).length, 1, "Route target was replaced");
      // The reload must reach the route tab itself: one real XTest Control_L+r
      // reloads its current document. The reload
      // replaces that document, so its CDP session ends and the fresh page is
      // re-attached: the fragment loaded again is exactly the stale one.
      mark("route:reload");
      browserKey(ROUTE_RELOAD, ROUTE_TITLE_PREFIX);
      await wait(
        async () =>
          (await revoked.evaluate(
            'document.visibilityState === "visible" && document.hasFocus() === true',
          )) === true,
        "Route tab was not active before reload",
      );
      assert.equal((await routeTargets()).length, 1, "Route target was replaced");
      stale = await attach(opened);
      await wait(async () => {
        if ((await stale.evaluate("document.readyState")) !== "complete")
          return false;
        return routeWiped(
          await stale.evaluate(routeRevokedProbe(fixture.Title, fixture.Value)),
        );
      }, "Stale route fragment did not fail closed");
      assert.equal(
        await stale.count(ROUTE_COPY_FIELD_SELECTOR),
        0,
        "Stale route page rendered a copy control",
      );
      // Bounded no-prompt observation: only read-only, focus-preserving
      // snapshots of the exact native window, no click and no authorization,
      // so a late native request would be seen. A missing or unobservable
      // window throws through the helper and fails here; it is never read as
      // "no prompt".
      mark("route:native-absent");
      const promptDeadline = Date.now() + ROUTE_NATIVE_ABSENT_LIMIT;
      for (;;) {
        const control = nativeInspection()[ROUTE_COPY_REVIEW_LABEL];
        const offered =
          control?.present === true &&
          (control.enabled === true || control.showing === true);
        if (offered) throw Error("Native route prompt is still present");
        // The route-page read comes from the revocation client, not the stale
        // one: a client failure fails here rather than reading as wiped.
        if (
          routeWiped(
            await revoked.evaluate(routeRevokedProbe(fixture.Title, fixture.Value)),
          ) !== true
        )
          throw Error("Stale route detail opened after reload");
        if (Date.now() >= promptDeadline) break;
        await delay(200);
      }
      // With the Copy control still missing, the reviewed physical mouse
      // wrapper is run against its selector. Its fixed pre-dispatch rejection
      // ("Popup control must be available", before Input.dispatchMouseEvent)
      // proves the control is not there, without any injected counter or
      // synthetic event.
      assert.equal(
        await stale.count(ROUTE_COPY_FIELD_SELECTOR),
        0,
        "Stale route page rendered a copy control",
      );
      mark("route:mouse-rejected");
      let rejected = "";
      try {
        await stale.click(ROUTE_COPY_FIELD_SELECTOR);
      } catch (error) {
        rejected = error?.message;
      }
      routeMouseRejected = Object.freeze({
        rejected: rejected === "Popup control must be available",
      });
      assert.equal(
        rejected,
        "Popup control must be available",
        "Popup control must be available",
      );
      // The whole page's own log stays free of every fixture canary.
      assert(
        !logs.some((s) =>
          fixtureCanaries(fixture).some((value) => s.includes(value)),
        ),
        "Synthetic secret found in browser console output",
      );
      for (const line of logs) assertPrivateText(line, fixture);
      console.log(
        "PASS: a physical tab switch reached the route page's lifecycle port and wiped its detail; the same target reopened only as closed/revoked, one physical Control_L+r reload of its stale fragment failed closed without a native prompt, and the mouse wrapper rejected the absent Copy control before input",
      );
    } finally {
      try {
        await stale?.close();
      } catch {}
      // The revocation client never outlives this checkpoint, on success or
      // failure. A failed attach leaves it null and nothing is closed.
      try {
        await revoked?.close();
      } catch {}
    }
    } finally {
      // Diagnostics only: the lifecycle socket never outlives this checkpoint.
      closeRouteLifecycle();
    }
  // OPT-IN: The optional idle-expiry journey starts only here, after the route
    // checkpoint's own finally completed: every route switch, reload,
    // no-prompt and mouse-rejected assertion above has passed.
    if (routeIdleTtl) {
      routeIdleObservation = await acceptRouteIdleExpiry({
        browser: context,
        input,
        fixture,
        phase: mark,
        eventually: wait,
        openPopup: openActionPopup,
        extensionTargets: targets,
        attachRoute: attach,
        // Only the adapter's CDP disconnect; the stale tab itself is closed
        // by the one physical key.
        closeAdapter: (client) => client.close(),
        browserKey,
        labelInspect: ROUTE_LABEL_INSPECT,
        vaultRows: VAULT_ROWS,
        // The approved-detail probe/verifier and the no-prompt inspection are
        // locals of this main acceptance block, so they cross the module-scope
        // helper boundary explicitly.
        routeSurfaceProbe,
        verifyRouteSurface,
        nativeInspection,
      });
    }
  }
  async function blank() {
    assert(
      (await page.locator("#username").inputValue()) === "",
      "Unexpected username disclosure",
    );
    assert(
      (await page.locator("#password").inputValue()) === "",
      "Unexpected password disclosure",
    );
    assert(
      (await page.evaluate(() => window.submits)) === 0,
      "Automatic submission is forbidden",
    );
  }
  async function select(scenario) {
    phase(scenario + ":popup");
    const popup = await openPopup();
    await eventually(
      async () => (await popup.disabled("#refresh")) === false,
      "Paired popup not ready",
    );
    await popup.click("#refresh");
    await eventually(
      async () =>
        (await popup.count('#candidates [data-action="fill"]')) === 1 &&
        (await popup.disabled('#candidates [data-action="fill"]')) === false &&
        (await popup.disabled("#refresh")) === false,
      "Exact-origin candidate missing",
    );
    await popup.click('#candidates [data-action="fill"]');
    await eventually(
      async () => (await popup.text("#status"))?.includes("原生窗口核对"),
      "Native confirmation was not requested",
    );
    input([{ wait_label: "批准本次填充" }]);
    phase(scenario + ":native-confirmation");
    return popup;
  }
  if (process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1") {
    // Explicit external test mode: the actual desktop app is the shared
    // broker and sole clipboard owner; the extension uses its normal port.
    await acceptSharedClipboard({
      fixture,
      root,
      state,
      env: sharedEnvironment,
      openPopup,
      eventually,
      delay,
      phase,
    });
  } else {
  phase("native-connect");
  let popup = await openPopup();
  phase("save-new:control");
  assert.equal(await popup.count("#save-new"), 1);
  await popup.click("#connect");
  phase("native-unlock");
  input([
    { click_label: "金库文件" },
    { text: fixture.Path },
    { click_label: "主密码" },
    { text: fixture.Password },
    { click_label: "Secret Key" },
    { text: fixture.Secret },
    { click_label: "解锁" },
  ]);
  phase("native-pair");
  // The popup-vault run pairs with the real quick-fill choice; no host status
  // text is observable in the native accessibility tree, so the successful
  // popup-vault commits below are the only pairing proof needed.
  input([
    {
      click_label:
        process.env.LOCKLARK_TEST_POPUP_VAULT === "1" || checkoutFrames
          ? "连接并启用快捷填充"
          : "确认连接此扩展",
    },
  ]);
  if (routeDetailRead) {
    // The route checkpoint reuses the existing action-popup CDP wrapper and
    // the real native X11 helper. It never navigates, messages the worker or
    // injects a page hook: only the rendered popup/route UI is observed.
    async function extensionTargets() {
      const port = readFileSync(
        join(profile, "DevToolsActivePort"),
        "utf8",
      ).split("\n")[0];
      const targets = await (
        await fetch("http://127.0.0.1:" + port + "/json/list")
      ).json();
      return targets.filter((target) =>
        target.url.startsWith(
          "chrome-extension://geldnhjapnackobgknocomedmjgphnpe/popup.html",
        ),
      );
    }
    async function attachRoute(target) {
      const route = await attachPopup(target);
      return {
        evaluate: (expression) => route.evaluate(expression),
        count: (selector) => route.count(selector),
        text: (selector) => route.text(selector),
        bringToFront: () => route.bringToFront(),
        // The reviewed real CDP mouse wrapper (visibility/hit-test, then
        // mousePressed/mouseReleased). No second click path exists here.
        click: (selector) => route.click(selector),
        // The adapter's own CDP connection only; never the page or the tab.
        close: () => route.close(),
      };
    }
    await acceptRouteDetailRead({
      browser,
      input,
      fixture,
      phase,
      eventually,
      openPopup,
      extensionTargets,
      attachRoute,
    });
  } else if (checkoutFrames) {
    await page.goto(origin + "/checkout");
    const checkout = await acceptCheckoutFrames({ page, origin, input, fixture, openPopup, phase, eventually });
    // The final lock journey already invalidated/cleaned up the session; only
    // any other result still needs the redundant popup disconnect.
    if (checkout?.locked !== true) {
      popup = await openPopup();
      await popup.click("#disconnect");
    }
  } else {
  if (process.env.LOCKLARK_TEST_POPUP_VAULT) {
    const downloadDirectory = join(state, "attachment-downloads");
    mkdirSync(downloadDirectory, { recursive: true });
    const fileName = "popup-attachment.bin";
    const sourcePath = join(state, fileName);
    const content = Buffer.alloc(2 << 20);
    for (let index = 0; index < content.length; index++) content[index] = index % 251;
    writeFileSync(sourcePath, content, { mode: 0o600 });
    const digest = createHash("sha256").update(content).digest("hex");
    content.fill(0);
    const downloadSession = await browser.newCDPSession(page);
    await downloadSession.send("Browser.setDownloadBehavior", {
      behavior: "allow", downloadPath: downloadDirectory,
    });
    const observe = vaultObserver({ go, root, env, state });
    const { didCommit } = await acceptPopupVault({
      openPopup, input, fixture, phase, eventually, observe,
      attachment: {
        sourcePath, fileName,
        downloaded: () => {
          const path = join(downloadDirectory, fileName);
          return existsSync(path) && createHash("sha256").update(readFileSync(path)).digest("hex") === digest;
        },
      },
    });
    await downloadSession.detach();
    // acceptPopupVault dismisses its popup in `finally`, so that target is
    // closed by the time it returns. Open a fresh, currently-open target before
    // physically clicking disconnect; the observer already proved the commits.
    assert(didCommit, "Popup vault commits are the quick-fill pairing proof");
    phase("native-disconnect");
    popup = await openPopup();
    await popup.click("#disconnect");
    input([], true, { wait_absent: true });
    phase("native-reconnect");
    popup = await openPopup();
    await popup.click("#connect");
    input([
      { click_label: "金库文件" },
      { text: fixture.Path },
      { click_label: "主密码" },
      { text: fixture.Password },
      { click_label: "Secret Key" },
      { text: fixture.Secret },
      { click_label: "解锁" },
    ]);
    input([{ click_label: "确认连接此扩展" }]);
    // Native re-pair closes the popup that requested it; only openPopup returns
    // the focused, visible action popup again, so discard the stale handle.
    popup = await openPopup();
    await eventually(async () => await popup.disabled("#search-input") === false,
      "Normal-mode vault refresh did not settle");
    // In normal mode an item-get needs the native V2 review. Rejecting it
    // proves the refusal path without approving or disclosing the item.
    phase("post-repair:item-get-observe");
    const edited = observe().rows.find((item) => item.title === "Popup native contract edited");
    assert(edited, "Synthetic edited item missing after normal re-pair");
    phase("post-repair:item-get-open");
    const target = '#vault-list [data-item-id="' + edited.id + '"]';
    await popup.click('#filter-tabs [data-filter="all"]');
    await eventually(async () => await popup.count(target) === 1,
      "Edited item row absent");
    phase("post-repair:item-get-click");
    // The physical row click starts one native item-get review.
    await popup.click(target);
    phase("post-repair:item-get-refusal");
    input([{ wait_label: "批准本次操作" }]);
    const refusal = input([], true, true).controls;
    for (const label of ["批准本次操作", "拒绝本次操作"]) {
      assert(refusal[label]?.present === true && refusal[label]?.showing === true,
        "Exact native item-get control missing");
    }
    input([{ click_label: "拒绝本次操作" }]);
    phase("post-repair:item-get-refetched");
    // A fresh popup is the only trusted view after the refusal; the rejected
    // detail must never render.
    popup = await openPopup();
    await eventually(async () => await popup.disabled("#search-input") === false,
      "Refused popup not ready");
    assert.equal(await popup.count("#detail-view:not([hidden])"), 0,
      "Refused item-get opened the detail view");
    // No detail is rendered, so only the visible body text could disclose.
    const body = String(await popup.text("body"));
    for (const [name, value] of [
      ["password", fixture.Value],
      ["note", fixture.SaveValue],
      ["update", fixture.UpdateValue],
    ]) {
      assert(!body.includes(value), "Refused item-get disclosed a synthetic " + name);
    }
    phase("post-repair:item-get-refused");
    console.log("PASS: real popup native item-get refusal disclosed nothing");
  }
  await blank();
  popup = await openPopup();
  if (await popup.count(".site-preferences:not([open]) > summary"))
    await popup.click(".site-preferences > summary");
  await popup.click("#auto-login"); // Existing manual-mode scenarios intentionally disable auto-submit.

  if (
    !process.env.LOCKLARK_TEST_BROWSER_PARITY &&
    process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments"
  ) {
    await select("approved-fill");
    await blank(); // No field is released before native approval.
    if (process.env.LOCKLARK_TEST_FAILURE_STAGE === "after-pair")
      throw Error(fixtureCanaries(fixture).join("\n"));
    if (process.env.LOCKLARK_TEST_FAILURE_STAGE === "page-arguments") {
      phase("driver-arguments-failure");
      await page.evaluate(
        ([username, password]) => {
          document.querySelector("#username").value = username;
          document.querySelector("#password").value = password;
          throw Error("Controlled driver argument failure");
        },
        [fixture.SaveUsername, fixture.SaveValue],
      );
    }
    execFileSync(
      "import",
      [
        "-window",
        String(input([], true, true).window),
        join(diagnostics, "native-confirm.png"),
      ],
      { env },
    );
    phase("approved-fill:approve");
    input([{ click_label: "批准本次填充" }]);
    await eventually(
      async () =>
        (await page.locator("#password").inputValue()) === fixture.Value,
      "Approved fill did not reach the bound document",
    );
    assert(
      (await page.locator("#username").inputValue()) === fixture.Username,
      "Approved username mismatch",
    );
    assert(
      (await page.evaluate(() => window.submits)) === 0,
      "Fill submitted the form",
    );

    await page.locator("#username").fill("");
    await page.locator("#password").fill("");
    await select("rejected-fill");
    input([{ click_label: "拒绝本次填充" }]); // One actual native rejection.
    await delay(500);
    await blank();

    await select("navigated-fill");
    await page.goto(origin + "/different-document");
    await eventually(async () => {
      const control = input([], true, true).controls["批准本次填充"];
      return !control.enabled && !control.showing;
    }, "Navigated native intent remained available");
    await blank();

    await select("locked-fill");
    input([{ click_label: "立即锁定" }, { wait_label: "解锁" }]); // One actual native lock with approval pending.
    await delay(300);
    await blank();
    popup = await openPopup();
    await eventually(
      async () => await popup.disabled("#refresh"),
      "Locked host still allowed matching",
    );
    assert(
      (await popup.text("#status"))?.includes("锁定") ||
        (await popup.text("#status"))?.includes("断开"),
      "Lock status missing",
    );
  }
  const acceptanceDriver = {
    fixture,
    origin,
    phase,
    input,
    inspect: () => input([], true, true),
    observe: vaultObserver({ go, root, env, state }),
    captureNative: (kind) => {
      assert(
        browserScreenshotsAllowed(stage),
        "OTP stage forbids diagnostic screenshots",
      );
      const window = input([], true, true).window;
      assert(
        Number.isSafeInteger(window) && window > 0,
        "Strict native XID required",
      );
      execFileSync(
        "import",
        [
          "-window",
          String(window),
          join(diagnostics, "native-save-" + kind + ".png"),
        ],
        { env, stdio: "ignore" },
      );
    },
    openPopup,
    setLogin: async (username, password) => {
      await page.evaluate(
        ([username, password]) => {
          document.querySelector("#username").value = username;
          document.querySelector("#password").value = password;
        },
        [username, password],
      );
    },
    loginEquals: async (username, password) =>
      page.evaluate(
        ([username, password]) =>
          document.querySelector("#username").value === username &&
          document.querySelector("#password").value === password &&
          window.submits === 0,
        [username, password],
      ),
    navigate: (url) => page.goto(url),
    reconnect: async () => {
      let popup = await openPopup();
      await popup.click("#disconnect");
      input([], true, { wait_absent: true });
      popup = await openPopup();
      await popup.click("#connect");
      input([
        { click_label: "金库文件" },
        { text: fixture.Path },
        { click_label: "主密码" },
        { text: fixture.Password },
        { click_label: "Secret Key" },
        { text: fixture.Secret },
        { click_label: "解锁" },
      ]);
      input([{ click_label: "确认连接此扩展" }]);
    },
    // Explicit quick pairing for non-destructive Passkey metadata: disconnect
    // the current session, reopen the popup, unlock and physically choose the
    // real quick-fill pairing control. Nothing is approved implicitly.
    reconnectQuickFill: async () => {
      let popup = await openPopup();
      await popup.click("#disconnect");
      input([], true, { wait_absent: true });
      popup = await openPopup();
      await popup.click("#connect");
      input([
        { click_label: "金库文件" },
        { text: fixture.Path },
        { click_label: "主密码" },
        { text: fixture.Password },
        { click_label: "Secret Key" },
        { text: fixture.Secret },
        { click_label: "解锁" },
      ]);
      input([{ click_label: "连接并启用快捷填充" }]);
    },
    root,
    state,
    env,
    pageEval: (fn, arg) => page.evaluate(fn, arg),
  };
  if (!process.env.LOCKLARK_TEST_BROWSER_PARITY) {
    if (process.env.LOCKLARK_TEST_FAILURE_STAGE !== "otp-page-arguments")
      await acceptBrowserSave(acceptanceDriver);
    await acceptBrowserOTP(acceptanceDriver);
  }
  await acceptBrowserPasskey({
    page,
    browser,
    origin,
    input,
    fixture,
    openPopup,
    eventually,
    phase,
    observe: acceptanceDriver.observe,
    reconnect: acceptanceDriver.reconnect,
    reconnectQuickFill: acceptanceDriver.reconnectQuickFill,
  });
  assert(
    !logs.some((s) =>
      fixtureCanaries(fixture).some((value) => s.includes(value)),
    ),
    "Synthetic secret found in browser console output",
  );
  for (const line of logs) assertPrivateText(line, fixture);
  popup = await openPopup();
  await popup.click("#disconnect");
  }
  }
} catch (error) {
  // Deliberately omit fixture files and exception/command bodies. The only
  // inspection text is the trusted popup's bounded status; native metadata is
  // a fixed control-name allowlist and never asks accessibility for values.
  // The route page contributes only its fixed view/status enums and booleans.
  const safeReasons = [
    "Action popup did not open",
    "Previous action popup did not close",
    "Action popup is not visible and focused",
    "AbortSignal not honored",
    "Popup CDP failed",
    "Popup CDP closed",
    "Popup CDP timed out",
    "Popup control must be available",
    "Inline control unavailable",
    "Synthetic secret found in browser console output",
    "Popup inspection failed",
    "Popup CDP connection failed",
    "Popup CDP connection timed out",
    "Action popup must be unique",
    "Shared native clipboard acceptance failed",
    "Shared clipboard mode must be requested explicitly",
    "Shared desktop host must be an absolute executable path",
    "Synthetic fixture vault path is required",
    "Synthetic fixture password is required",
    "Checkout card filter unavailable",
    "Synthetic checkout card missing from the vault",
    "Checkout card revision mismatch",
    "Checkout card category mismatch",
    "Synthetic checkout card detail did not open",
    "Checkout form picker control unavailable",
    "Checkout form picker label missing",
    "Checkout origin picker missing",
    "Checkout origin picker is incomplete",
    "Expected exactly one explicit checkout child origin",
    "Checkout popup is not connected",
    "Checkout card frame did not load",
    "Top checkout card fields must be visible",
    "Checkout card frame fields must be visible",
    "Approved checkout fill did not reach the child frame",
    "Checkout picker cancel did not close",
    "Checkout native approval must not be available",
    "Cross-site checkout forms must stay blank",
    "Cross-site checkout refusal did not finish",
    "Cross-site checkout received a value without approval",
    "Excluded checkout origin must not be auto-selected",
    "Excluded cross-site checkout wrote a value",
    "Checkout sandboxed child must be excluded from the picker",
    "Sandboxed checkout picker request did not finish",
    "Sandboxed checkout forms must stay blank",
    "Sandboxed checkout received a value without approval",
    "Checkout child document identity missing",
    "Checkout child document was not replaced",
    "Changed checkout document did not finish",
    "Changed checkout document received a value",
    "Native checkout review must be visible before lock",
    "Checkout forms changed before native lock",
    "Native checkout review still available after lock",
    "Native checkout review did not finish after lock",
    "Locked host still allowed matching",
    "Lock status missing",
    "Locked checkout approval received a value",
    "Route detail mode is incompatible",
    "Route detail mode requires Chromium",
    "Paired popup not ready",
    "Exact-origin match missing",
    "Vault rows missing",
    "Exact synthetic vault row missing",
    "Synthetic seed item identity missing",
    "Synthetic fixture title missing",
    "Route page did not open",
    "Route page must be unique",
    "Action popup stayed open",
    "Action popup target stayed open",
    "Unexpected page opened",
    "Route page did not load",
    "Route detail did not render",
    "Native route approval label missing",
    "Route detail did not survive native approval",
    "Route target was replaced",
    "Action popup reopened",
    "route-detail-view-missing",
    "route-detail-title-mismatch",
    "route-concealed-control-missing",
    "route-password-rendered",
    "Route page did not return to the foreground",
    "Route password copy control missing",
    "Route password is not concealed",
    "Route displayed the password",
    "Native field disclosure did not appear",
    "Native field disclosure did not follow its review",
    "Route copy feedback missing",
    "OS clipboard did not receive the approved field",
    "Original source tab missing",
    "Route tab is not the active tab",
    "Source tab did not become visible",
    "Background revocation did not wipe the route detail",
    "Route page was replaced",
    "Route page did not return to the foreground",
    "Returned route page kept its detail",
    "Stale route fragment did not fail closed",
    "Stale route page rendered a copy control",
    "Native no-prompt window unavailable",
    "Native route prompt is still present",
    "Stale route detail opened after reload",
    "Mouse wrapper dispatched input",
    "Stale route tab was not closed",
    "Idle route detail did not survive native approval",
    "Idle route detail did not stay live",
    "Idle route detail did not expire",
    "Route page text unavailable",
    "Popup template unavailable",
  ];
  const report = {
    reason: safeReasons.includes(error?.message)
      ? error.message
      : "unclassified acceptance failure",
    frames:
      typeof error?.stack === "string"
        ? error.stack.match(/browser_(?:native|checkout|passkey_management|conditional_passkey|passkey)_acceptance\.mjs:[0-9]+:[0-9]+/g)
        : [],
    stage,
    // Latest fixed-enum route-page observation from the bounded native-label
    // wait, plus its bounded state-transition history where consecutive
    // entries differ. Both only ever contain the four sanitized fields.
    ...(routeDetailRead
      ? {
          routePage: sanitizeRouteObservation(lastRouteObservation),
          routeHistory: routeObservationHistory.map(sanitizeRouteObservation),
          // Present only once the post-popup-close snapshot was taken, and only
          // for route-detail failures; same four sanitized fields.
          ...(routeAfterPopupClose
            ? {
                routeAfterPopupClose: sanitizeRouteObservation(
                  routeAfterPopupClose,
                ),
              }
            : {}),
          // Present only once the post-popup-close target checkpoint was read;
          // two fixed booleans, never an id, URL, fragment, token or count.
          ...(routeTargetAfterPopupClose
            ? {
                routeTargetAfterPopupClose: {
                  routeTargetExists:
                    routeTargetAfterPopupClose.routeTargetExists === true,
                  routeTargetStillRoute:
                    routeTargetAfterPopupClose.routeTargetStillRoute === true,
                },
              }
            : {}),
          // Present only once the visible-DOM status trace recorded at least
          // one entry: fixed channel/value enums only, at most eight entries.
          ...(routeStatusTrace
            ? { routeStatusTrace: sanitizeRouteStatusTrace(routeStatusTrace) }
            : {}),
          // Present only once the direct route-target observer connected or
          // saw a main-frame event; fixed booleans and capped per-kind counts
          // only, never an id, URL, fragment, token, text, value or protocol
          // payload.
          ...(routeLifecycleObservation
            ? {
                routeTargetLifecycle: sanitizeRouteLifecycle(
                  routeLifecycleObservation,
                ),
              }
            : {}),
          // Present only once the physical mouse wrapper was run against the
          // absent Copy selector: one fixed boolean.
          ...(routeMouseRejected
            ? {
                routeMouseRejected: {
                  rejected: routeMouseRejected.rejected === true,
                },
              }
            : {}),
          // Present only once the optional idle journey started: three fixed
          // booleans, never a target, tab, token, URL or page text.
          ...(routeIdleObservation
            ? {
                routeIdle: {
                  approvedDetail:
                    routeIdleObservation.approvedDetail === true,
                  liveObserved: routeIdleObservation.liveObserved === true,
                  wipeCompleted: routeIdleObservation.wipeCompleted === true,
                },
              }
            : {}),
          // Present only once the idle stale-close wait polled: exactly the
          // six fixed predicates, never an id, URL, title, value, count, text
          // or canary. This identifies which close predicate failed.
          ...(routeIdleCloseStaleObservation
            ? {
                routeIdleCloseStale: sanitizeRouteIdleCloseStale(
                  routeIdleCloseStaleObservation,
                ),
              }
            : {}),
        }
      : {}),
    popup: { available: false },
    native: { available: false },
  };
  if (lastPopup) {
    try {
      report.popup = {
        available: true,
        status: popupStatusKind(await lastPopup.text("#status")),
        refreshDisabled: await lastPopup.disabled("#refresh"),
        candidates: await lastPopup.count("#candidates button"),
      };
    } catch {}
  }
  try {
    if (lastPopup && browserScreenshotsAllowed(stage)) {
      const text = String((await lastPopup.text("body")) || "");
      if (!privacyValues.some((value) => text.includes(value)))
        await lastPopup.screenshot(join(diagnostics, "failure-popup.png"));
    }
  } catch {}
  if (nativeInput) {
    try {
      report.native = { available: true, ...nativeInput([], true, true) };
      if (browserScreenshotsAllowed(stage)) {
        execFileSync(
          "import",
          [
            "-window",
            String(report.native.window),
            join(diagnostics, "failure-native.png"),
          ],
          { env, stdio: "ignore" },
        );
      }
    } catch {}
  }
  writeFileSync(
    join(diagnostics, "failure.json"),
    JSON.stringify(report, null, 2) + "\n",
    { mode: 0o600 },
  );
  console.error("Native browser diagnostic: " + JSON.stringify(report));
  console.error("Synthetic diagnostic directory: " + diagnostics);
  throw Error("Native browser acceptance failed at " + stage);
} finally {
  if (browser) await browser.close();
  await new Promise((r) => server.close(r));
  if (observedFixture) {
    assertPrivateArtifacts(state, observedFixture);
    scanController(observedFixture);
  }
}
console.log(
  process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1"
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} extension shared Locklark desktop native clipboard lease, private OS reads, foreign-owner TTL preservation, lock clearing and hidden-popup prepare cancellation`
    : checkoutFrames
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} checkout same-origin child approval (profile review) and picker cancellation, cross-origin approval/refusal, cross-site, opaque sandbox, changed-document and top-navigation rejection, and lock while cross-origin card review is pending`
    : routeIdleTtl
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} route UI closed by an idle two-minute TTL`
    : routeDetailRead
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} QuickFill=false action row opened exactly one persistent route tab, the native per-operation approval kept that same tab, and its rendered detail matched the synthetic fixture without revealing a value`
    : process.env.LOCKLARK_TEST_BROWSER_PARITY
    ? `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} quick pairing, inline fill, automatic sign-in, Passkey creation/assertion, relying-party signature verification and abort`
    : `PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} fill/save/update/OTP and Passkey with native approval and private diagnostics`,
);
// The optional idle journey waits two fixed observation/TTL bounds and never
// runs without both flags; the default-checks summary printed by the route
// journey above stays unchanged in every mode.
if (routeIdleTtl)
  console.log(
    "PASS: default physical route revoke checks completed first, then an idle two-minute route TTL wiped the second route detail",
  );
console.log("Private synthetic artifacts: " + state);

if (observedFixture) scanController(observedFixture);

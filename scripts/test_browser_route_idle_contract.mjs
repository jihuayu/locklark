// Pure contract tests for the opt-in route idle-expiry journey of the native
// browser acceptance harness. They run without a browser, native host or
// private vault fixture; the harness itself is only read, never imported.
// The file is imported by test_browser_checkout_acceptance.mjs, so its tests
// run in that targeted suite and also when run on their own.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const SOURCE = readFileSync(
  new URL("./browser_native_acceptance.mjs", import.meta.url),
  "utf8",
);
// The CI contract reads the checked-in workflow itself, so a change to the
// Chromium native step must update the workflow and this contract together.
const WORKFLOW = readFileSync(
  new URL("../.github/workflows/check.yml", import.meta.url),
  "utf8",
);
const WORKFLOW_LINES = WORKFLOW.split(/\r?\n/);

function countMatches(text, pattern) {
  return (text.match(pattern) || []).length;
}

// The import-time flag block, from the first mode flag to the helper that
// follows it (the module imports are skipped). It only reads process.env and
// asserts, so it can be evaluated in a minimal context with a controlled
// environment.
const IMPORT_HEAD = SOURCE.slice(
  SOURCE.indexOf("const checkoutFrames ="),
  SOURCE.indexOf("\nconst POPUP_CLOSED"),
);
assert.ok(
  IMPORT_HEAD.includes("const routeIdleTtl") &&
    IMPORT_HEAD.includes("function routeModeCompatible()"),
  "the flag block must stay at import time",
);

function evaluateHead(env) {
  const context = vm.createContext({
    process: { env },
    assert,
    join: () => "",
    resolve: () => "",
    dirname: () => "",
    existsSync: () => true,
  });
  new vm.Script(
    IMPORT_HEAD + "\n;globalThis.__decision={routeDetailRead,routeIdleTtl};",
  ).runInContext(context);
  return JSON.parse(JSON.stringify(context.__decision));
}

const ROUTE_IDLE_ANCHOR =
  "// OPT-IN: The optional idle-expiry journey starts only here";
const ROUTE_START = SOURCE.indexOf("async function acceptRouteDetailRead");
const ROUTE_END = SOURCE.indexOf("\n  async function blank() {", ROUTE_START);

function routeDriver() {
  assert.ok(ROUTE_START > 0 && ROUTE_END > ROUTE_START, "route driver must exist");
  return SOURCE.slice(ROUTE_START, ROUTE_END);
}

// The default revocation checkpoint inside the route driver; it ends where
// the opt-in journey's anchor starts.
function revocationCheckpoint() {
  const start = SOURCE.indexOf(
    "    // Route revocation checkpoint: the same tab and target",
    ROUTE_START,
  );
  const stop = SOURCE.indexOf(ROUTE_IDLE_ANCHOR, start);
  assert.ok(start > ROUTE_START && stop > start, "revocation checkpoint must exist");
  return SOURCE.slice(start, stop);
}

// The harness's own route copy selector literal.
const ROUTE_COPY_FIELD_SELECTOR_VALUE =
  '[data-field-id="password"] [data-action="copy-field"]';

// The idle journey from its comment header to the next top-level helper.
function idleJourney() {
  const start = SOURCE.indexOf("async function acceptRouteIdleExpiry(driver) {");
  const next = SOURCE.indexOf("\nasync function eventually(", start);
  assert.ok(start > 0 && next > start, "idle journey must be a top-level function");
  const header = SOURCE.lastIndexOf("// One ordinary route journey", start);
  assert.ok(header > 0, "idle journey must keep its comment header");
  return SOURCE.slice(header, next);
}

// The executable helper only, without its comment header.
function idleHelper() {
  const start = SOURCE.indexOf("async function acceptRouteIdleExpiry(driver) {");
  const next = SOURCE.indexOf("\nasync function eventually(", start);
  assert.ok(start > 0 && next > start, "idle helper must be a top-level function");
  return SOURCE.slice(start, next);
}

// The actual source-form/path gate, so the synthetic driver test can execute
// the expression the helper generates instead of a stand-in.
function sourceProbeHelper() {
  const start = SOURCE.indexOf("function sourcePageProbe(pathname) {");
  const stop = SOURCE.indexOf("\n// Diagnostics only:", start);
  assert.ok(start > 0 && stop > start, "source page probe must exist");
  return SOURCE.slice(start, stop);
}

// The actual six-boolean sanitizer the stale-close wait stores through.
function closeStaleSanitizer() {
  const start = SOURCE.indexOf("function sanitizeRouteIdleCloseStale(value) {");
  const stop = SOURCE.indexOf("\n}", start) + 2;
  assert.ok(start > 0 && stop > start, "stale-close sanitizer must exist");
  return SOURCE.slice(start, stop);
}

// Every needle must appear once, in order, inside `text`.
function assertOrder(text, needles) {
  let previous = -1;
  for (const needle of needles) {
    const at = text.indexOf(needle, previous + 1);
    assert.ok(at > previous, needle);
    previous = at;
  }
}

test("the idle-expiry mode is a strict opt-in paired with the route detail flag", () => {
  // Absent: the default route mode is unchanged and the idle journey never
  // runs.
  assert.deepEqual(evaluateHead({}), {
    routeDetailRead: false,
    routeIdleTtl: false,
  });
  assert.deepEqual(evaluateHead({ LOCKLARK_TEST_ROUTE_DETAIL_READ: "1" }), {
    routeDetailRead: true,
    routeIdleTtl: false,
  });
  // Both flags, exactly "1": the opt-in mode.
  assert.deepEqual(
    evaluateHead({
      LOCKLARK_TEST_ROUTE_DETAIL_READ: "1",
      LOCKLARK_TEST_ROUTE_IDLE_TTL: "1",
    }),
    { routeDetailRead: true, routeIdleTtl: true },
  );
  // Without the route detail flag, paired with a conflicting mode, or with
  // any other value, the run fails closed before anything is launched.
  const closed = (pattern) => (error) => pattern.test(error.message);
  for (const env of [
    { LOCKLARK_TEST_ROUTE_IDLE_TTL: "1" },
    { LOCKLARK_TEST_ROUTE_DETAIL_READ: "0", LOCKLARK_TEST_ROUTE_IDLE_TTL: "1" },
    { LOCKLARK_TEST_ROUTE_IDLE_TTL: "1", LOCKLARK_TEST_CHECKOUT_FRAMES: "1" },
  ])
    assert.throws(
      () => evaluateHead(env),
      closed(/^Route idle TTL mode requires route detail mode$/),
      JSON.stringify(env),
    );
  // Any value that is not exactly "1" never enables the idle journey, and is
  // refused rather than silently ignored.
  for (const [name, env] of [
    ["zero", { LOCKLARK_TEST_ROUTE_DETAIL_READ: "1", LOCKLARK_TEST_ROUTE_IDLE_TTL: "0" }],
    ["word", { LOCKLARK_TEST_ROUTE_DETAIL_READ: "1", LOCKLARK_TEST_ROUTE_IDLE_TTL: "true" }],
    ["empty", { LOCKLARK_TEST_ROUTE_DETAIL_READ: "1", LOCKLARK_TEST_ROUTE_IDLE_TTL: "" }],
  ])
    assert.throws(
      () => evaluateHead(env),
      closed(/^Route idle TTL mode requires route detail mode$/),
      name,
    );
  // Edge needs an explicit absolute browser executable before any mode check,
  // so that refusal is asserted from the source instead.
  assert.ok(
    SOURCE.includes(
      '"Edge requires an explicit absolute executable path"',
    ),
  );
  assert.ok(
    SOURCE.includes('assert(browserName === "chromium", "Route detail mode requires Chromium");'),
  );
  // The strict pairing and the fail-closed reasons are asserted at import.
  assert.match(SOURCE, /^const routeIdleValue = process\.env\.LOCKLARK_TEST_ROUTE_IDLE_TTL;$/m);
  assert.match(SOURCE, /^const routeIdleTtl = routeIdleValue === "1";$/m);
  assert.match(
    SOURCE,
    /assert\(\n\s+routeIdleValue === undefined \|\|\n\s+\(routeIdleValue === "1" && routeDetailRead\),\n\s+"Route idle TTL mode requires route detail mode",\n\);/,
  );
  assert.ok(SOURCE.includes('"Route idle TTL mode requires route detail mode"'));
});

test("the default physical revoke stages stay present and precede the opt-in journey", () => {
  const driver = routeDriver();
  const positive = driver.slice(
    0,
    driver.indexOf("    // Route revocation checkpoint:", ROUTE_START),
  );
  const checkpoint = revocationCheckpoint();
  // The positive read/copy proof still runs first.
  assertOrder(positive, [
    "Route detail did not survive native approval",
    "await route.click(ROUTE_COPY_FIELD_SELECTOR);",
    "OS clipboard did not receive the approved field",
    "PASS: real popup exact row opened one persistent route tab",
  ]);
  // Every default negative assertion and its physical key still runs, in
  // order, inside the revocation checkpoint.
  assertOrder(checkpoint, [
    'mark("route:switch-source")',
    "browserKey(ROUTE_SWITCH_SOURCE, ROUTE_TITLE_PREFIX);",
    "Source tab did not become visible",
    "Background revocation did not wipe the route detail",
    'mark("route:return")',
    "browserKey(ROUTE_RETURN, SOURCE_TITLE_PREFIX);",
    "Returned route page kept its detail",
    'mark("route:reload")',
    "browserKey(ROUTE_RELOAD, ROUTE_TITLE_PREFIX);",
    "Stale route fragment did not fail closed",
    'mark("route:native-absent")',
    "Native route prompt is still present",
    'mark("route:mouse-rejected")',
    'rejected === "Popup control must be available"',
    "PASS: a physical tab switch reached the route page's lifecycle port",
  ]);
  assert.match(
    SOURCE,
    /^const ROUTE_SWITCH_SOURCE = Object\.freeze\(\[\{ key: "Control_L\+Shift_L\+Tab" \}\]\);$/m,
  );
  assert.match(SOURCE, /^const ROUTE_RETURN = Object\.freeze\(\[\{ key: "Control_L\+Tab" \}\]\);$/m);
  assert.match(SOURCE, /^const ROUTE_RELOAD = Object\.freeze\(\[\{ key: "Control_L\+r" \}\]\);$/m);
  // The default checkpoint sends exactly its three physical keys and never
  // the idle journey's close key.
  assert.equal(countMatches(checkpoint, /browserKey\(/g), 3);
  assert.doesNotMatch(checkpoint, /ROUTE_IDLE_CLOSE_STALE/);
  // The opt-in call is the last step of the driver: it follows the revocation
  // checkpoint's own finally, which closed the lifecycle socket.
  const optIn = driver.indexOf(ROUTE_IDLE_ANCHOR);
  assert.ok(optIn > 0, "the driver must wire the opt-in journey");
  const finallyAt = checkpoint.lastIndexOf("closeRouteLifecycle();");
  assert.ok(finallyAt > 0 && finallyAt + "closeRouteLifecycle();".length <= checkpoint.length);
  assert.ok(!checkpoint.includes("acceptRouteIdleExpiry"));
  const guard = driver.lastIndexOf("if (routeIdleTtl) {");
  const call = driver.lastIndexOf("routeIdleObservation = await acceptRouteIdleExpiry({");
  assert.ok(guard > optIn && call > guard);
  assert.match(
    driver.slice(call),
    /^routeIdleObservation = await acceptRouteIdleExpiry\(\{\n\s+browser: context,\n\s+input,\n\s+fixture,\n\s+phase: mark,\n\s+eventually: wait,\n\s+openPopup: openActionPopup,\n\s+extensionTargets: targets,\n\s+attachRoute: attach,/,
  );
  // The idle helper is module scope, so every outer-block local it uses is
  // passed explicitly; the production callback stays the main try's local.
  assert.match(
    driver.slice(call),
    /\n\s+closeAdapter: \(client\) => client\.close\(\),\n\s+browserKey,\n\s+labelInspect: ROUTE_LABEL_INSPECT,\n\s+vaultRows: VAULT_ROWS,/,
  );
  // The tested probe/verifier and the native inspection are block locals too.
  assert.match(
    driver.slice(call),
    /\n\s+routeSurfaceProbe,\n\s+verifyRouteSurface,\n\s+nativeInspection,\n\s+\}\);/,
  );
  // The opt-in journey lives in its own function: the route driver mentions it
  // exactly once, in the guarded call, and never declares it.
  assert.equal(countMatches(driver, /acceptRouteIdleExpiry/g), 1);
  assert.doesNotMatch(driver, /function acceptRouteIdleExpiry/);
  assert.ok(SOURCE.includes("\nasync function acceptRouteIdleExpiry(driver) {\n"));
});

test("the idle helper takes every outer-block local from the driver", () => {
  const body = idleHelper();
  assert.match(
    body,
    /^  const \{\n\s+browser: context,\n\s+input,\n\s+fixture,\n\s+phase: mark,\n\s+eventually: wait,\n\s+openPopup: openActionPopup,\n\s+extensionTargets: targets,\n\s+attachRoute: attach,\n\s+closeAdapter,\n\s+browserKey,\n\s+labelInspect,\n\s+vaultRows,\n/m,
  );
  // These names are block locals in the main try/route checkpoint and must
  // not be resolved implicitly from the module-level helper.
  assert.doesNotMatch(body, /\bROUTE_LABEL_INSPECT\b|\bVAULT_ROWS\b/);
  assert.doesNotMatch(body, /\b(?:const|let|var|function)\s+browserKey\b/);
  assert.match(
    body,
    /\n\s+routeSurfaceProbe,\n\s+verifyRouteSurface,\n\s+nativeInspection,\n\s+\} = driver;/,
  );
  // The one physical stale-route key goes through the supplied callback.
  assert.match(body, /browserKey\(ROUTE_IDLE_CLOSE_STALE, ROUTE_TITLE_PREFIX\);/);
  // The local callback and the audited outer locals are passed explicitly at
  // the actual production call site.
  const call = SOURCE.indexOf("routeIdleObservation = await acceptRouteIdleExpiry({");
  assert.ok(call > 0);
  assert.match(
    SOURCE.slice(call),
    /\n\s+browserKey,\n\s+labelInspect: ROUTE_LABEL_INSPECT,\n\s+vaultRows: VAULT_ROWS,/,
  );
});

test("the idle helper reaches the stale-close wait and the actual /login source gate before the next popup", async () => {
  const staleRouteURL =
    "chrome-extension://" + "a".repeat(32) + "/popup.html#route=" + "b".repeat(64);
  // The real driver keeps the origin bare and opens the controlled source page
  // at origin + "/login"; the helper must derive the path from that page, not
  // from the origin (whose pathname is "/").
  const originURL = "https://login.locklark.test:8443";
  const sourcePageURL = originURL + "/login";
  const closeKey = Object.freeze([{ key: "Control_L+w" }]);
  const stop = new Error("stop at the next action-popup call");
  const events = [];
  const keyCalls = [];
  const evaluateCalls = [];
  const probeExpressions = [];
  let staleClosed = false;
  // The stale route is a real browser/CDP dependency only. Its two
  // prerequisite reads answer like the production stale route: ready and the
  // active tab; no other page expression is reached before the key.
  const staleClient = {
    evaluate: async (expression) => {
      events.push("evaluate:" + expression);
      evaluateCalls.push(expression);
      if (expression === "document.readyState") return "complete";
      if (
        expression ===
        'document.visibilityState === "visible" && document.hasFocus() === true'
      )
        return true;
      throw new Error("Unexpected route evaluate: " + expression);
    },
    close: async () => {
      events.push("closeAdapter");
    },
  };
  const staleTarget = { id: "stale-route", url: staleRouteURL };
  // The smallest controlled source page: only the form controls and pathname
  // the generated probe reads. Its location is the real /login page.
  const password = { type: "password" };
  const form = { contains: (value) => value === password };
  const username = { form, type: "text" };
  const probeContext = vm.createContext({
    location: { pathname: "/login" },
    document: {
      visibilityState: "visible",
      getElementById: (id) =>
        id === "username" ? username : id === "password" ? password : null,
    },
  });
  const sourcePage = {
    url: () => sourcePageURL,
    evaluate: async (expression) => {
      events.push("sourceProbe");
      probeExpressions.push(expression);
      return vm.runInContext(expression, probeContext);
    },
  };
  const context = vm.createContext({
    URL,
    assert,
    origin: originURL,
    ROUTE_PAGE: /^chrome-extension:\/\/[a-p]{32}\/popup\.html#route=[a-f0-9]{64}$/,
    ACTION_POPUP: /^chrome-extension:\/\/[a-p]{32}\/popup\.html$/,
    ROUTE_TITLE_PREFIX: "Locklark",
    ROUTE_IDLE_CLOSE_STALE: closeKey,
    routeIdleObservation: null,
    routeIdleCloseStaleObservation: null,
    routeLifecycleObservation: null,
    routeStatusTrace: null,
  });
  vm.runInContext(
    sourceProbeHelper() +
      "\n" +
      closeStaleSanitizer() +
      "\n" +
      idleHelper() +
      "\nthis.acceptRouteIdleExpiry = acceptRouteIdleExpiry;" +
      "\nthis.sourcePageProbe = sourcePageProbe;",
    context,
  );
  // There is deliberately no browserKey global: the only one the helper can
  // see is the callback on the driver.
  assert.equal(vm.runInContext("typeof browserKey", context), "undefined");
  const driver = {
    browser: {
      pages: () => [
        { url: () => "chrome-extension://" + "a".repeat(32) + "/popup.html" },
        sourcePage,
      ],
    },
    input: () => {
      throw new Error("input must not be reached before the key");
    },
    fixture: Object.freeze({ Title: "Synthetic title", SeedID: "synthetic-seed" }),
    phase: (stage) => {
      events.push("mark:" + stage);
    },
    eventually: async (check, message) => {
      events.push("wait:" + message);
      assert.equal(await check(), true, message);
    },
    openPopup: async () => {
      events.push("openPopup");
      throw stop;
    },
    // Before the key the stale route is still live; after it the close key
    // removes exactly that target.
    extensionTargets: async () => (staleClosed ? [] : [staleTarget]),
    attachRoute: async (target) => {
      events.push("attach");
      assert.equal(target, staleTarget);
      return staleClient;
    },
    closeAdapter: (client) => client.close(),
    browserKey: (actions, titlePrefix) => {
      events.push("browserKey");
      keyCalls.push([actions, titlePrefix]);
      staleClosed = true;
    },
    labelInspect: Object.freeze({ inspect: true, preserve_focus: true }),
    vaultRows: "synthetic-vault-rows",
    routeSurfaceProbe: () => "synthetic-surface-probe",
    verifyRouteSurface: () => "",
    nativeInspection: () => ({}),
  };
  // The synthetic wait runs the stale-close predicate for real, then stops at
  // the next action-popup call, so the 120-second journey is never run here.
  await assert.rejects(
    context.acceptRouteIdleExpiry(driver),
    (error) => error === stop,
  );
  assert.equal(vm.runInContext("typeof browserKey", context), "undefined");
  // Both prerequisite reads ran before the mark, the adapter disconnect and
  // the one physical key; the key callback is the supplied one.
  assert.deepEqual(evaluateCalls, [
    "document.readyState",
    'document.visibilityState === "visible" && document.hasFocus() === true',
  ]);
  // The stale-close wait and the post-wait gate both executed the actual
  // generated expression with the corrected /login path, not the origin's "/".
  assert.equal(probeExpressions.length, 2);
  for (const expression of probeExpressions)
    assert.equal(expression, context.sourcePageProbe("/login"));
  // All six stale-close predicates are true before the next popup is reached.
  assert.deepEqual(
    JSON.parse(JSON.stringify(context.routeIdleCloseStaleObservation)),
    {
      staleIdAbsent: true,
      routesAbsent: true,
      popupAbsent: true,
      sourceSame: true,
      sourceVisible: true,
      sourceIntact: true,
    },
  );
  assert.deepEqual(events, [
    "attach",
    "wait:Route page did not load",
    "evaluate:document.readyState",
    'evaluate:document.visibilityState === "visible" && document.hasFocus() === true',
    "mark:route:idle-close-stale",
    "closeAdapter",
    "browserKey",
    "wait:Stale route tab was not closed",
    "sourceProbe",
    "closeAdapter",
    "sourceProbe",
    "mark:route:idle-source",
    "openPopup",
  ]);
  assert.equal(keyCalls.length, 1);
  assert.equal(keyCalls[0][0], closeKey);
  assert.equal(keyCalls[0][1], "Locklark");
});

test("the idle journey closes only the stale route tab with one physical key", () => {
  const body = idleJourney();
  assert.match(
    SOURCE,
    /^const ROUTE_IDLE_CLOSE_STALE = Object\.freeze\(\[\{ key: "Control_L\+w" \}\]\);$/m,
  );
  // Exactly one browser key, the stale-tab close, addressed to the active
  // route tab's title prefix; no default key is repeated here.
  const keys = [...body.matchAll(/browserKey\((\[[^\n]*?\]|ROUTE_\w+), (\w+)\);/g)];
  assert.deepEqual(
    keys.map((match) => match[1] + " -> " + match[2]),
    ["ROUTE_IDLE_CLOSE_STALE -> ROUTE_TITLE_PREFIX"],
  );
  // The stale route is found through the fixed route fragment, proven active,
  // and only the adapter's CDP client is disconnected before the key.
  const closeAt = body.indexOf("browserKey(ROUTE_IDLE_CLOSE_STALE");
  assertOrder(body, [
    "ROUTE_PAGE.test(target.url)",
    '"Route tab is not the active tab"',
    'mark("route:idle-close-stale")',
    "await closeAdapter(stale);",
    "browserKey(ROUTE_IDLE_CLOSE_STALE, ROUTE_TITLE_PREFIX);",
  ]);
  assert.ok(closeAt > 0);
  assert.doesNotMatch(body, /dismiss\(|Page\.close|stale\.close\(/);
  // The exact source page is back and intact, and the stale target is gone.
  const afterClose = body.slice(closeAt);
  for (const needle of [
    "sourcePageProbe(sourcePath)",
    "sourcePageIntact(state)",
    "const staleIdAbsent = !live.some(",
    "const routesAbsent = !live.some((target) => ROUTE_PAGE.test(target.url));",
    "const popupAbsent = !live.some((target) => ACTION_POPUP.test(target.url));",
    '"Stale route tab was not closed"',
  ])
    assert.ok(afterClose.includes(needle), needle);
  // The expected path comes from the exact controlled source page (opened at
  // origin + "/login"), never from the bare origin whose pathname is "/".
  assertOrder(body, [
    'assert(sourcePage, "Original source tab missing");',
    "const sourcePath = new URL(sourcePage.url()).pathname;",
  ]);
  assert.ok(!body.includes("new URL(origin).pathname"));
  // The source probe returns fixed booleans only.
  assert.match(
    SOURCE,
    /^function sourcePageProbe\(pathname\) \{\n\s+return `\(\(\)=>\{\n\s+const username=document\.getElementById\('username'\);/m,
  );
  assert.match(
    SOURCE,
    /^function sourcePageIntact\(value\) \{\n\s+return value\?\.form === true && value\?\.path === true;\n\}$/m,
  );
});

test("the idle stale-close wait computes exactly the six fixed diagnostic booleans", () => {
  const body = idleHelper();
  // The observation is nullable module state, reset when the idle journey
  // starts, before the stale route is touched.
  assert.match(SOURCE, /^let routeIdleCloseStaleObservation = null;$/m);
  const reset = body.indexOf("routeIdleCloseStaleObservation = null;");
  const closeMark = body.indexOf('mark("route:idle-close-stale")');
  assert.ok(reset > 0 && closeMark > reset, "the observation must reset at idle start");
  // The same bounded wait keeps its 10-second default budget.
  assert.match(SOURCE, /^async function eventually\(check, message, limit = 10000\) \{$/m);
  const pollStart = body.indexOf("const sourceSame = current === sourcePage;");
  const pollStop = body.indexOf('"Stale route tab was not closed"', pollStart);
  assert.ok(pollStart > 0 && pollStop > pollStart, "the stale-close wait must exist");
  const poll = body.slice(pollStart, pollStop);
  const compactPoll = poll.replace(/[\s,]+/g, "");
  // Each fixed boolean is recomputed inside that poll from the same predicate.
  const fields = [
    ["staleIdAbsent", "!live.some((target) => target.id === staleRoute.id)"],
    ["routesAbsent", "!live.some((target) => ROUTE_PAGE.test(target.url))"],
    ["popupAbsent", "!live.some((target) => ACTION_POPUP.test(target.url))"],
    ["sourceSame", "current === sourcePage"],
    ["sourceVisible", "state?.visible === true"],
    ["sourceIntact", "sourcePageIntact(state)"],
  ];
  for (const [name, expression] of fields)
    assert.ok(
      compactPoll.includes(
        `const${name}=${expression.replace(/[\s,]+/g, "")};`,
      ),
      name,
    );
  // The pass condition is exactly their conjunction.
  assert.ok(
    compactPoll.includes(
      "return(staleIdAbsent&&routesAbsent&&popupAbsent&&sourceSame&&sourceVisible&&sourceIntact);",
    ),
    "the pass condition must be the six-boolean conjunction",
  );
  // The observation is refreshed with exactly those six keys, in order.
  const snapshot = poll.indexOf(
    "routeIdleCloseStaleObservation = sanitizeRouteIdleCloseStale({",
  );
  assert.ok(snapshot > 0);
  const keys = [...poll.slice(snapshot).matchAll(/\b(staleIdAbsent|routesAbsent|popupAbsent|sourceSame|sourceVisible|sourceIntact),/g)]
    .map((match) => match[1]);
  assert.deepEqual(keys, fields.map(([name]) => name));
});

test("the idle stale-close diagnostic serializes only the six strict booleans", () => {
  const start = SOURCE.indexOf("function sanitizeRouteIdleCloseStale(value) {");
  const stop = SOURCE.indexOf("\n}", start);
  assert.ok(start > 0 && stop > start, "the sanitizer must exist");
  const fields = [
    "staleIdAbsent",
    "routesAbsent",
    "popupAbsent",
    "sourceSame",
    "sourceVisible",
    "sourceIntact",
  ];
  const sanitized = SOURCE.slice(start, stop);
  assert.deepEqual(
    [...sanitized.matchAll(/^\s+([A-Za-z]+):/gm)].map((match) => match[1]),
    fields,
  );
  const context = vm.createContext({});
  vm.runInContext(
    SOURCE.slice(start, stop + 2) +
      "\nthis.sanitize = sanitizeRouteIdleCloseStale;",
    context,
  );
  const all = Object.fromEntries(fields.map((name) => [name, true]));
  const empty = Object.fromEntries(fields.map((name) => [name, false]));
  // Raw target/page fields are dropped, never serialized.
  assert.deepEqual(
    {
      ...context.sanitize({
        ...all,
        id: "synthetic-id",
        url: "synthetic-url",
        title: "synthetic-title",
        value: "synthetic-value",
        count: 1,
      }),
    },
    all,
  );
  // A null or malformed record still yields exactly the six strict booleans.
  assert.deepEqual({ ...context.sanitize(null) }, empty);
  assert.deepEqual(
    { ...context.sanitize({ staleIdAbsent: "true", routesAbsent: 1 }) },
    empty,
  );
  // The failure report exposes only that sanitized observation under its own
  // fixed key.
  const reportAt = SOURCE.indexOf(
    "routeIdleCloseStale: sanitizeRouteIdleCloseStale(",
  );
  assert.ok(reportAt > 0);
  const reportStop = SOURCE.indexOf("),", reportAt);
  assert.ok(reportStop > reportAt);
  const reportBlock = SOURCE.slice(reportAt, reportStop);
  assert.doesNotMatch(reportBlock, /\b(?:id|url|title|value|count)\b/i);
  assert.match(
    reportBlock.trimEnd(),
    /^routeIdleCloseStale: sanitizeRouteIdleCloseStale\(\n\s+routeIdleCloseStaleObservation,$/,
  );
});

test("the idle journey reuses the ordinary popup, match, row and approval path", () => {
  const body = idleJourney();
  // The ordinary action popup driver, with no connect or unlock repeated.
  assert.match(body, /const action = await openActionPopup\(\);/);
  assert.doesNotMatch(body, /"#connect"|click_label: "解锁"|wait_absent/);
  assertOrder(body, [
    'mark("route:idle-source")',
    'await action.click("#refresh");',
    "个当前网站",
    'await action.click(\'#filter-tabs [data-filter="all"]\');',
    "const rows = await action.evaluate(vaultRows);",
    "rows[0].id === fixture.SeedID &&",
    'mark("route:idle-row-click")',
    "const idleStart = Date.now();",
    "await action.click(rowSelector, { expectedRouteClose: true });",
    "Route page did not open",
    "Route page must be unique",
    'mark("route:idle-native-label")',
    "labelInspect",
    'mark("route:idle-native-approve")',
    "input([{ click_label: ROUTE_COPY_REVIEW_LABEL }]);",
    'mark("route:idle-approved")',
  ]);
  // Exactly one native click label, the route lifecycle claim's review, and
  // that label is the real popup approval text.
  assert.equal(countMatches(body, /click_label:/g), 1);
  assert.match(SOURCE, /^const ROUTE_COPY_REVIEW_LABEL = "批准本次操作";$/m);
  // Exactly one real mouse click on the exact synthetic row, through the
  // popup wrapper, and no row click is made elsewhere in the journey.
  assert.equal(
    countMatches(
      body,
      /action\.click\(rowSelector, \{ expectedRouteClose: true \}\);/g,
    ),
    1,
  );
  // No DOM event, worker message, navigation or page hook is used.
  assert.doesNotMatch(body, /dispatchEvent|sendMessage|relayMessage|postMessage/);
  assert.doesNotMatch(body, /\b(goto|navigate)\b|Page\.navigate|Page\.reload|chrome\.tabs/);
  assert.doesNotMatch(body, /bringToFront[^\n]*\n(?:[^\n]*\n){0,3}[^\n]*input\(/);
});

test("the idle row click accepts only its one final-release popup close", () => {
  // The opt-in exists exactly once, on the idle row click.
  assert.equal(
    countMatches(
      SOURCE,
      /action\.click\(rowSelector, \{ expectedRouteClose: true \}\);/g,
    ),
    1,
  );
  // Execute the real predicate: only a pending "Popup closed" on the final
  // release, for the explicitly opted-in click, is expected. A press close,
  // a timeout, another CDP failure or an absent opt-in all stay fatal.
  const helperStart = SOURCE.indexOf("function expectedRouteClickClose(");
  const helperStop = SOURCE.indexOf("\n}", helperStart) + 2;
  assert.ok(helperStart > 0 && helperStop > helperStart, "helper must exist");
  const context = vm.createContext({});
  vm.runInContext(
    SOURCE.slice(helperStart, helperStop) +
      "\nthis.expectedRouteClickClose = expectedRouteClickClose;",
    context,
  );
  const expected = context.expectedRouteClickClose;
  assert.equal(expected(Error("Popup closed"), "mouseReleased", true), true);
  for (const [error, event, optedIn] of [
    [Error("Popup closed"), "mousePressed", true],
    [Error("Popup closed"), "mouseReleased", false],
    [Error("Popup closed"), "mouseReleased", "true"],
    [Error("Popup CDP closed"), "mouseReleased", true],
    [Error("Popup CDP timed out"), "mouseReleased", true],
    [Error("Popup inspection failed"), "mouseReleased", true],
    [undefined, "mouseReleased", true],
  ])
    assert.equal(expected(error, event, optedIn), false);
  // The wrapper sends press and release once each. Only the final release is
  // inside the catch, there is no retry, and the allowed close is the exact
  // helper call rather than a broad popupClosed() match.
  const clickStart = SOURCE.indexOf("      click: async (selector");
  const clickStop = SOURCE.indexOf("\n      },", clickStart);
  assert.ok(clickStart > 0 && clickStop > clickStart, "click wrapper must exist");
  const click = SOURCE.slice(clickStart, clickStop);
  assert.equal(countMatches(click, /type: "mousePressed"/g), 1);
  assert.equal(countMatches(click, /type: "mouseReleased"/g), 1);
  assert.match(
    click,
    /await call\("Input\.dispatchMouseEvent", \{\n\s+type: "mousePressed"/,
  );
  assert.match(
    click,
    /try \{\n\s+await call\("Input\.dispatchMouseEvent", \{\n\s+type: "mouseReleased"/,
  );
  assert.match(
    click,
    /!expectedRouteClickClose\(error, "mouseReleased", expectedRouteClose\)/,
  );
  assert.doesNotMatch(click, /popupClosed|for \(|while \(|retry/i);
});

test("the idle journey proves the tested surface, then wipes only after the full TTL", () => {
  const body = idleJourney();
  assert.match(SOURCE, /^const ROUTE_IDLE_TTL = 120000;$/m);
  assert.match(SOURCE, /^const ROUTE_IDLE_WIPE_LIMIT = 150000;$/m);
  assert.match(SOURCE, /^const ROUTE_IDLE_POLL = 2000;$/m);
  // The recursive template/baseline machinery, popup.html read and its text
  // policy are gone; the approved detail is the tested route surface probe.
  assert.doesNotMatch(
    SOURCE,
    /templateShaped|ROUTE_TEMPLATE_READ|routeBaselineProbe|routeIdleLiveProbe|routeIdleLive\(|ROUTE_DETAIL_DYNAMIC_CONTAINERS|routeDetailPrivacyPolicy/,
  );
  assert.match(
    body,
    /const liveProbe = routeSurfaceProbe\(\n\s+fixture\.Title,\n\s+fixture\.Value,\n\s+routeForbiddenCanaries\(fixture\),\n\s+\);/,
  );
  // The TTL journey starts immediately before the physical row click.
  assertOrder(body, [
    'mark("route:idle-row-click")',
    "const idleStart = Date.now();",
    "await action.click(rowSelector, { expectedRouteClose: true });",
  ]);
  // The minimum wipe is the worker's full two minutes from that click; the
  // overall wipe bound is the existing 150 seconds from the same click.
  assertOrder(body, [
    'mark("route:idle-live")',
    'mark("route:idle-wait")',
    "const minimumWipe = idleStart + ROUTE_IDLE_TTL;",
    "const wipeDeadline = idleStart + ROUTE_IDLE_WIPE_LIMIT;",
  ]);
  // Every poll reads both the wipe observation and the approved surface from
  // one snapshot; the verdict uses only that snapshot's own time.
  assert.match(
    body,
    /const idleProbe = idleRouteSnapshotProbe\(\n\s+fixture\.Title,\n\s+fixture\.Value,\n\s+fixtureCanaries\(fixture\),\n\s+liveProbe,\n\s+\);/,
  );
  assert.match(
    body,
    /snapshot = await fresh\.evaluate\(idleProbe\);/,
  );
  assert.match(
    body,
    /const verdict = idleRouteSnapshotVerdict\(\n\s+snapshot,\n\s+minimumWipe,\n\s+fixture\.Title,\n\s+verifyRouteSurface,\n\s+\);/,
  );
  assert.match(
    body,
    /assert\.notEqual\(\n\s+verdict\.kind,\n\s+"early-wipe",\n\s+"Idle route detail did not stay live",\n\s+\);/,
  );
  assert.match(
    body,
    /assert\.notEqual\(\n\s+verdict\.kind,\n\s+"surface-failure",\n\s+verdict\.finding \|\| "Idle route detail did not stay live",\n\s+\);/,
  );
  assert.match(body, /if \(Date\.now\(\) >= wipeDeadline\)\n\s+throw Error\("Idle route detail did not expire"\);/);
  // After the wipe, both existing native approval labels must be absent in a
  // bounded read-only inspection; the callback throws when unobservable.
  const nativeAbsent = body.indexOf('mark("route:idle-native-absent")');
  const wipedMark = body.indexOf('mark("route:idle-wiped")');
  assert.ok(nativeAbsent > 0 && wipedMark > nativeAbsent);
  const inspection = body.slice(nativeAbsent, wipedMark);
  assertOrder(inspection, [
    "const controls = nativeInspection();",
    "[ROUTE_COPY_REVIEW_LABEL, ROUTE_COPY_DISCLOSURE_LABEL].some(",
    "control?.present === true &&",
    "(control.enabled === true || control.showing === true)",
    'throw Error("Idle route native prompt is still present")',
  ]);
  // Once the detail is shown, nothing but read-only probes runs: no observer,
  // key, pointer, CDP page input or action.
  const live = body.indexOf('mark("route:idle-live")');
  assert.doesNotMatch(
    body.slice(live, wipedMark),
    /browserKey|input\(|\.click\(|dispatchEvent|addInitScript|MutationObserver|bringToFront|sendMessage/,
  );
  // A dedicated fixed stage label and one fixed safe PASS line.
  const stages = [...body.matchAll(/mark\("(route:idle-[a-z-]+)"\)/g)].map(
    (match) => match[1],
  );
  for (const stage of [
    "route:idle-close-stale",
    "route:idle-source",
    "route:idle-native-label",
    "route:idle-native-approve",
    "route:idle-approved",
    "route:idle-foreground",
    "route:idle-live",
    "route:idle-wait",
    "route:idle-native-absent",
    "route:idle-wiped",
    "route:idle-passed",
  ])
    assert.ok(stages.includes(stage), stage);
  assert.ok(
    body.includes(
      '"PASS: an idle second route tab kept its approved detail without input, stayed live through its full two-minute route TTL and was fully wiped without a native prompt"',
    ),
  );
  // The whole-run summaries name the opt-in mode and the default order.
  assert.ok(
    SOURCE.includes(
      '`PASS: real ${browserName === "edge" ? "Edge" : "Chromium"} route UI closed by an idle two-minute TTL`',
    ),
  );
  assert.ok(
    SOURCE.includes(
      '"PASS: default physical route revoke checks completed first, then an idle two-minute route TTL wiped the second route detail"',
    ),
  );
  assert.match(
    SOURCE,
    /^if \(routeIdleTtl\)\n  console\.log\(\n\s+"PASS: default physical route revoke checks completed first, then an idle two-minute route TTL wiped the second route detail",\n\s+\);\nconsole\.log\("Private synthetic artifacts: " \+ state\);/m,
  );
});

test("the idle journey keeps output privacy and reports only fixed booleans", () => {
  const body = idleJourney();
  // The only console output is the one fixed PASS line.
  const consoleLines = body.match(/console\.(log|error|warn)\(([\s\S]*?)\);/g) || [];
  assert.equal(consoleLines.length, 1);
  assert.doesNotMatch(consoleLines[0], /fixture|target|token|url|template|baseline/i);
  // No target id, token URL or clipboard content is read in the host: the
  // targets list only ever matches the fixed route and popup patterns by
  // `target.url`/`entry.url()`, exactly like the default journeys. The one
  // further URL read is the controlled source page's own pathname, used only
  // to derive the expected /login path and never retained or reported.
  assert.doesNotMatch(body, /webSocketDebuggerUrl|DevToolsActivePort|fetch\(/);
  const offPattern = body
    .replace(/\.test\(entry\.url\(\)\)/g, "")
    .replace(/\.test\(target\.url\)/g, "")
    .replace("const sourcePath = new URL(sourcePage.url()).pathname;", "");
  assert.doesNotMatch(offPattern, /\.url\b/);
  // No secret value or clipboard content is read in the host: the two probes
  // receive only the non-secret title/value pair and the canary lists.
  assert.doesNotMatch(body, /fixture\.Password|fixture\.Secret/);
  assert.equal(countMatches(body, /fixture\.Value/g), 2);
  assert.match(body, /routeForbiddenCanaries\(fixture\)/);
  assert.match(
    body,
    /idleRouteSnapshotProbe\(\n\s+fixture\.Title,\n\s+fixture\.Value,\n\s+fixtureCanaries\(fixture\),/,
  );
  assert.doesNotMatch(body, /clipboard|readText/);
  // The same console canary and private-text checks the ordinary journeys
  // apply still decide the pass.
  assert.match(body, /"Synthetic secret found in browser console output"/);
  assert.match(body, /for \(const line of logs\) assertPrivateText\(line, fixture\);/);
  // The failure report adds only three fixed booleans under routeIdle.
  assert.match(
    SOURCE,
    /routeIdle: \{\n\s+approvedDetail:\n\s+routeIdleObservation\.approvedDetail === true,\n\s+liveObserved: routeIdleObservation\.liveObserved === true,\n\s+wipeCompleted: routeIdleObservation\.wipeCompleted === true,\n\s+\},/,
  );
  for (const reason of [
    "Stale route tab was not closed",
    "Idle route probes missing",
    "Idle route detail did not survive native approval",
    "Idle route snapshot unavailable",
    "Idle route detail did not stay live",
    "Idle route detail left the foreground",
    "Idle route detail did not expire",
    "Idle route native prompt is still present",
  ])
    assert.ok(SOURCE.includes('"' + reason + '"'), reason);
});

// A wholly synthetic login: Title and Username are visible fixture text, every
// other canary must stay off the page. No real fixture value is used.
const FIXTURE = Object.freeze({
  Title: "Synthetic title",
  Username: "synthetic-user",
  Password: "SyntheticPass",
  Value: "SyntheticPass-value",
  Secret: "SyntheticSeed",
});
// The harness's fixture canaries exclude the non-secret Title.
const CANARY_KEYS = Object.freeze(["Password", "Username", "Value", "Secret"]);
const ALL_CANARIES = Object.freeze(CANARY_KEYS.map((key) => FIXTURE[key]));
const FORBIDDEN_CANARIES = Object.freeze(
  ALL_CANARIES.filter((value) => value !== FIXTURE.Username),
);

// The harness's forbidden-canary filter, given a synthetic canary function.
function forbiddenFor(fixture) {
  const start = SOURCE.indexOf("const ROUTE_DETAIL_VISIBLE_FIXTURE_KEYS =");
  const stop = SOURCE.indexOf("\n// The route's own tab switch", start);
  assert.ok(start > 0 && stop > start, "the forbidden-canary filter must exist");
  const context = vm.createContext({ fixtureCanaries: () => ALL_CANARIES });
  vm.runInContext(
    SOURCE.slice(start, stop) + "\nthis.filter = routeForbiddenCanaries;",
    context,
  );
  return [...context.filter(fixture)];
}

// The actual generated routeSurfaceProbe/verifyRouteSurface source, evaluated
// with no harness imports. Only the page document is supplied at call time.
function surfaceHarness() {
  const start = SOURCE.indexOf("  function routeSurfaceProbe(");
  const stop = SOURCE.indexOf("\n  async function acceptRouteDetailRead(", start);
  assert.ok(start > 0 && stop > start, "route surface probe must exist");
  const context = vm.createContext({});
  vm.runInContext(
    SOURCE.slice(start, stop) +
      "\nthis.routeSurfaceProbe = routeSurfaceProbe;" +
      "\nthis.verifyRouteSurface = verifyRouteSurface;",
    context,
  );
  return context;
}

// The smallest read-only page the generated surface probe reads. It has only
// the queried nodes; no product code or full popup DOM is fabricated.
function surfacePage(overrides = {}) {
  const {
    title = FIXTURE.Title,
    titleNode = true,
    detail = true,
    view = "detail",
    visible = true,
    fields = true,
    concealed = true,
    bodyText = [FIXTURE.Title, FIXTURE.Username].join("\n"),
  } = overrides;
  const value = { textContent: concealed ? "••••••••" : FIXTURE.Value };
  const fieldsNode = fields
    ? { querySelector: () => null, querySelectorAll: () => [value] }
    : null;
  return {
    visibilityState: visible ? "visible" : "hidden",
    body: { dataset: { view }, innerText: bodyText },
    querySelector: (selector) => {
      if (selector === "#detail-view") return detail ? { hidden: false } : null;
      if (selector === "#detail-title") return titleNode ? { textContent: title } : null;
      if (selector === "#detail-fields") return fieldsNode;
      return null;
    },
  };
}

function runSurface(overrides) {
  const harness = surfaceHarness();
  const expression = harness.routeSurfaceProbe(
    FIXTURE.Title,
    FIXTURE.Value,
    FORBIDDEN_CANARIES,
  );
  assert.equal(typeof expression, "string");
  const page = vm.createContext({ document: surfacePage(overrides) });
  const surface = new vm.Script("(" + expression + ")").runInContext(page);
  return { surface, finding: harness.verifyRouteSurface(surface, FIXTURE.Title) };
}

// The actual generated routeRevokedProbe/routeWiped source, with only the
// fixed selector/status literals it reads from the harness.
function revocationHarness() {
  const statusStart = SOURCE.indexOf("const ROUTE_CLAIM_FAILED_STATUS =");
  const revokedAt = SOURCE.indexOf("const ROUTE_REVOKED_STATUS =");
  const statusStop = SOURCE.indexOf("\n", revokedAt) + 1;
  const kindsStart = SOURCE.indexOf("const ROUTE_REVOKE_STATUS_KINDS =");
  const kindsStop = SOURCE.indexOf("\n", kindsStart) + 1;
  const start = SOURCE.indexOf("function routeRevokedProbe(");
  const stop = SOURCE.indexOf("\n// Route field-copy acceptance", start);
  assert.ok(
    statusStart > 0 && revokedAt > statusStart && statusStop > revokedAt,
    "revocation status literals must exist",
  );
  assert.ok(kindsStart > 0 && kindsStop > kindsStart, "revocation kinds must exist");
  assert.ok(start > 0 && stop > start, "route revocation probe must exist");
  const context = vm.createContext({});
  vm.runInContext(
    "const ROUTE_COPY_FIELD_SELECTOR=" +
      JSON.stringify(ROUTE_COPY_FIELD_SELECTOR_VALUE) +
      ";\n" +
      SOURCE.slice(statusStart, statusStop) +
      SOURCE.slice(kindsStart, kindsStop) +
      SOURCE.slice(start, stop) +
      "\nthis.routeRevokedProbe = routeRevokedProbe;" +
      "\nthis.routeWiped = routeWiped;" +
      "\nthis.ROUTE_REVOKED_STATUS = ROUTE_REVOKED_STATUS;" +
      "\nthis.ROUTE_CLAIM_FAILED_STATUS = ROUTE_CLAIM_FAILED_STATUS;",
    context,
  );
  return context;
}

// The smallest read-only wiped page the generated revocation probe reads.
function revocationPage(overrides = {}) {
  const {
    view = "closed",
    detailHidden = true,
    title = "",
    fields = 0,
    status,
    bodyText = "",
    copy = 0,
    visible = true,
    body = true,
    missing = [],
  } = overrides;
  const nodes = {
    "#detail-view": { hidden: detailHidden },
    "#detail-title": { textContent: title },
    "#detail-fields": { childElementCount: fields },
    "#status": { textContent: status ?? revocationHarness().ROUTE_REVOKED_STATUS },
  };
  return {
    visibilityState: visible ? "visible" : "hidden",
    body: body ? { dataset: { view }, innerText: bodyText } : null,
    querySelector: (selector) =>
      missing.includes(selector) ? null : (nodes[selector] ?? null),
    querySelectorAll: () => Array.from({ length: copy }, () => ({})),
  };
}

function runRevoked(overrides = {}, canaries) {
  const harness = revocationHarness();
  const expression = harness.routeRevokedProbe(
    FIXTURE.Title,
    FIXTURE.Value,
    canaries,
  );
  const page = vm.createContext({ document: revocationPage(overrides) });
  const value = new vm.Script("(" + expression + ")").runInContext(page);
  return { value, wiped: harness.routeWiped(value), harness };
}

// The real snapshot verdict, with the real wipe predicate and status literals
// from revocationHarness. The surface verifier stays a caller-supplied
// function, exactly as the idle journey passes its tested verifier.
function verdictHarness() {
  const start = SOURCE.indexOf("function idleRouteSnapshotVerdict(");
  const stop = SOURCE.indexOf("\n}", start) + 2;
  assert.ok(start > 0 && stop > start, "idle snapshot verdict must exist");
  const context = revocationHarness();
  vm.runInContext(
    SOURCE.slice(start, stop) +
      "\nthis.idleRouteSnapshotVerdict = idleRouteSnapshotVerdict;",
    context,
  );
  return context;
}

test("routeForbiddenCanaries allows only the verified Username", () => {
  const forbidden = forbiddenFor(FIXTURE);
  assert.deepEqual(forbidden, FORBIDDEN_CANARIES);
  assert.equal(forbidden.includes(FIXTURE.Username), false);
  assert.equal(forbidden.includes(FIXTURE.Password), true);
  assert.equal(forbidden.includes(FIXTURE.Value), true);
});

test("the generated surface expression accepts a masked, username-only detail", () => {
  const good = runSurface();
  assert.equal(good.finding, "");
  assert.equal(good.surface.visible, true);
  assert.equal(good.surface.view, "detail");
  assert.equal(good.surface.detailShown, true);
  assert.equal(good.surface.title, FIXTURE.Title);
  assert.equal(good.surface.concealed, true);
  assert.equal(good.surface.passwordRendered, false);
  assert.equal(good.surface.forbiddenCanaryRendered, false);
  // The verified Username is visible and is not a forbidden canary.
  assert.match(good.surface.title, new RegExp(FIXTURE.Title));
  assert.equal(FORBIDDEN_CANARIES.includes(FIXTURE.Username), false);
});

test("the generated surface expression fails private/forbidden text and missing nodes", () => {
  // A forbidden canary and the private password value both fail closed.
  assert.equal(
    runSurface({
      bodyText: [FIXTURE.Title, FIXTURE.Username, FIXTURE.Password].join("\n"),
    }).finding,
    "route-forbidden-canary-rendered",
  );
  assert.equal(
    runSurface({
      bodyText: [FIXTURE.Title, FIXTURE.Username, FIXTURE.Value].join("\n"),
    }).finding,
    "route-password-rendered",
  );
  // Missing, hidden or unobservable required nodes fail closed.
  assert.equal(runSurface({ title: "Other" }).finding, "route-detail-title-mismatch");
  assert.equal(runSurface({ titleNode: false }).finding, "route-detail-title-mismatch");
  assert.equal(runSurface({ detail: false }).finding, "route-detail-view-missing");
  assert.equal(runSurface({ view: "locked" }).finding, "route-detail-view-missing");
  assert.equal(runSurface({ fields: false }).finding, "route-concealed-control-missing");
  assert.equal(runSurface({ concealed: false }).finding, "route-concealed-control-missing");
  // The generated expression is a real page script: without the page document
  // it throws instead of reporting a surface.
  const expression = surfaceHarness().routeSurfaceProbe(
    FIXTURE.Title,
    FIXTURE.Value,
    FORBIDDEN_CANARIES,
  );
  assert.throws(
    () => new vm.Script("(" + expression + ")").runInContext(vm.createContext({})),
    /document is not defined/,
  );
});

test("the generated revoked expression keeps the existing two-argument contract", () => {
  // A complete wipe passes with the title/value pair alone.
  assert.equal(runRevoked().wiped, true);
  // Existing callers only forbid the title/value pair: another fixture canary
  // in the body text does not change their result.
  const ignored = runRevoked({ bodyText: FIXTURE.Password });
  assert.equal(ignored.value.fixtureAbsent, true);
  assert.equal(ignored.wiped, true);
});

test("the generated revoked expression requires every fixture canary absent", () => {
  for (const status of [
    revocationHarness().ROUTE_REVOKED_STATUS,
    revocationHarness().ROUTE_CLAIM_FAILED_STATUS,
  ]) {
    const clean = runRevoked({ status }, ALL_CANARIES);
    assert.equal(clean.wiped, true, status);
  }
  // Every canary, including the Username, must be gone after the TTL wipe.
  for (const canary of ALL_CANARIES) {
    const leaked = runRevoked({ bodyText: canary }, ALL_CANARIES);
    assert.equal(leaked.value.fixtureAbsent, false, canary);
    assert.equal(leaked.wiped, false, canary);
  }
});

test("the generated revoked expression fails any remaining title, field, copy, status or node", () => {
  const cases = [
    ["remaining title", { title: FIXTURE.Title }],
    ["remaining field", { fields: 1 }],
    ["remaining copy", { copy: 1 }],
    ["visible detail", { detailHidden: false }],
    ["still open", { view: "detail" }],
    ["unknown status", { status: "other" }],
    ["missing status", { missing: ["#status"] }],
    ["missing title", { missing: ["#detail-title"] }],
    ["missing fields", { missing: ["#detail-fields"] }],
    ["missing detail", { missing: ["#detail-view"] }],
    ["missing body", { body: false }],
  ];
  for (const [name, overrides] of cases)
    assert.equal(
      runRevoked(overrides, ALL_CANARIES).wiped,
      false,
      name,
    );
  // The generated expression throws when its page is unobservable; it can
  // never be read as a complete wipe.
  const expression = revocationHarness().routeRevokedProbe(
    FIXTURE.Title,
    FIXTURE.Value,
    ALL_CANARIES,
  );
  assert.throws(
    () => new vm.Script("(" + expression + ")").runInContext(vm.createContext({})),
    /document is not defined/,
  );
});

test("the idle snapshot reads and decides in one turn across the TTL boundary", () => {
  const body = idleJourney();
  const loopStart = body.indexOf('mark("route:idle-wait")');
  const loopStop = body.indexOf('mark("route:idle-native-absent")', loopStart);
  assert.ok(loopStart > 0 && loopStop > loopStart, "idle wait loop must exist");
  const loop = body.slice(loopStart, loopStop);
  // One page evaluate per poll; neither reading is a separate round trip.
  assert.equal(countMatches(loop, /fresh\.evaluate\(/g), 1);
  assert.match(loop, /snapshot = await fresh\.evaluate\(idleProbe\);/);
  assert.doesNotMatch(
    loop,
    /fresh\.evaluate\(liveProbe\)|fresh\.evaluate\(\s*routeRevokedProbe/,
  );
  assert.match(loop, /const verdict = idleRouteSnapshotVerdict\(/);

  // Execute the real probe generator: both reads run before the timestamp.
  const probeStart = SOURCE.indexOf("function idleRouteSnapshotProbe(");
  const probeStop = SOURCE.indexOf("\n}", probeStart) + 2;
  assert.ok(probeStart > 0 && probeStop > probeStart, "snapshot probe must exist");
  const order = [];
  const probeContext = vm.createContext({
    order,
    Date: { now: () => (order.push("at"), 123456) },
    routeRevokedProbe: () =>
      "(()=>{order.push('wiped');return {closed:true};})()",
  });
  vm.runInContext(
    SOURCE.slice(probeStart, probeStop) +
      "\nthis.idleRouteSnapshotProbe = idleRouteSnapshotProbe;",
    probeContext,
  );
  const expression = probeContext.idleRouteSnapshotProbe(
    "title",
    "value",
    [],
    "(()=>{order.push('surface');return {visible:true};})()",
  );
  const snapshot = new vm.Script("(" + expression + ")").runInContext(probeContext);
  assert.deepEqual([...probeContext.order], ["wiped", "surface", "at"]);
  assert.equal(snapshot.at, 123456);

  // The real verdict uses that snapshot's own time. A snapshot exactly at the
  // TTL may accept a wipe; one millisecond earlier must reject it. A good
  // surface remains live, while a visible private leak still fails.
  const verdict = verdictHarness().idleRouteSnapshotVerdict;
  const minimumWipe = 1000;
  const live = runSurface();
  const cleanWipe = runRevoked().value;
  const at = (time, wiped, surface) =>
    verdict(
      { at: time, wiped, surface },
      minimumWipe,
      FIXTURE.Title,
      () => live.finding,
    );
  assert.equal(at(minimumWipe - 1, cleanWipe, live.surface).kind, "early-wipe");
  assert.equal(at(minimumWipe - 1, {}, live.surface).kind, "early-live");
  assert.equal(at(minimumWipe, cleanWipe, live.surface).kind, "wiped");
  assert.equal(at(minimumWipe, {}, live.surface).kind, "late-live");
  assert.equal(
    at(minimumWipe - 1, {}, { ...live.surface, visible: false }).kind,
    "left-foreground",
  );
  assert.equal(
    verdict({}, minimumWipe, FIXTURE.Title, () => "").kind,
    "unobservable",
  );

  const leaked = runSurface({
    bodyText: [FIXTURE.Title, FIXTURE.Username, FIXTURE.Password].join("\n"),
  });
  const leakedVerdict = verdict(
    { at: minimumWipe - 1, wiped: {}, surface: leaked.surface },
    minimumWipe,
    FIXTURE.Title,
    () => leaked.finding,
  );
  assert.equal(leakedVerdict.kind, "surface-failure");
  assert.equal(leakedVerdict.finding, "route-forbidden-canary-rendered");
});

// ---------------------------------------------------------------------------
// Focused static contract for the Chromium route + idle TTL checkpoint.
//
// Only the fixed Chromium and Firefox acceptance steps and the artifact
// download the Chromium step relies on are read, and only inside the
// `web-browsers` job that actually runs them. The workflow layout is known, so
// this is a line-block extraction rather than a YAML parser.
// ---------------------------------------------------------------------------
const CHROMIUM_NATIVE_STEP =
  "Test native browser approval, popup editing, fill, save and OTP";
const FIREFOX_NATIVE_STEP =
  "Test Firefox native approval, fill, save, OTP and Passkey";
const DOWNLOAD_LINUX_BINARIES = "Download Linux primary binaries";
const BROWSER_WRAPPER =
  "dbus-run-session -- xvfb-run -a -s '-screen 0 1280x900x24'";
const ROUTE_FLAGS = [
  "LOCKLARK_TEST_ROUTE_DETAIL_READ",
  "LOCKLARK_TEST_ROUTE_IDLE_TTL",
];

// The lines of one top-level job, from its exact `  <name>:` line to the next
// `  <job>:` line. This keeps the browser steps and their artifact download
// from being satisfied by the same-named steps in another job.
function jobBlock(name) {
  const start = WORKFLOW_LINES.indexOf(`  ${name}:`);
  assert.ok(start >= 0, `check.yml must keep the "${name}" job`);
  let end = start + 1;
  while (end < WORKFLOW_LINES.length && !/^  [A-Za-z0-9_-]+:\s*$/.test(WORKFLOW_LINES[end]))
    end++;
  return { start, lines: WORKFLOW_LINES.slice(start, end) };
}

// The entries of the single strategy.matrix.browser flow list inside a job
// slice. The job slice keeps the read scoped to that job's own matrix.
function matrixBrowsers(job) {
  const strategy = job.lines.indexOf("    strategy:");
  assert.ok(strategy > 0, "job must keep a strategy block");
  const matrix = job.lines.indexOf("      matrix:", strategy);
  assert.ok(matrix > strategy, "job strategy must keep a matrix block");
  let entries;
  for (let index = matrix + 1; index < job.lines.length; index++) {
    const line = job.lines[index];
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    if (!/^ {8}/.test(line)) break;
    const match = /^ {8}browser:\s*\[(.*)\]\s*$/.exec(line);
    if (!match) continue;
    assert.equal(entries, undefined, "the matrix must declare one browser list");
    entries = match[1].split(",").map((entry) => entry.trim()).filter(Boolean);
  }
  assert.ok(entries, "the matrix must declare a browser list");
  return entries;
}

// The lines of one six-space step item inside a job slice, from its exact
// `- name:` line to the next item or job level (a non-blank line indented less
// than eight spaces). The step must be unique within that job.
function stepBlock(job, name) {
  const matches = [];
  for (let index = 0; index < job.lines.length; index++)
    if (job.lines[index] === `      - name: ${name}`) matches.push(index);
  assert.equal(
    matches.length,
    1,
    `job must declare exactly one "${name}" step, got ${matches.length}`,
  );
  const offset = matches[0];
  let end = offset + 1;
  while (
    end < job.lines.length &&
    (job.lines[end].trim() === "" || /^ {8,}\S/.test(job.lines[end]))
  )
    end++;
  return {
    start: job.start + offset,
    lines: job.lines.slice(offset, end),
  };
}

// The value of the single step-level field at eight spaces.
function stepField(block, key) {
  const pattern = new RegExp(`^ {8}${key}:(?: (.*))?$`);
  const matches = block
    .map((line) => pattern.exec(line))
    .filter(Boolean)
    .map((match) => (match[1] ?? "").trim());
  assert.equal(matches.length, 1, `step must declare exactly one ${key}: field`);
  return matches[0].replace(/^(['"])(.*)\1$/, "$2");
}

// The entries of the single ten-space mapping (env or with) in the step.
function stepMapping(block, key) {
  const at = block.indexOf(`        ${key}:`);
  assert.ok(at >= 0, `step must declare ${key}:`);
  const entries = {};
  for (let index = at + 1; index < block.length; index++) {
    const line = block[index];
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    if (!/^ {10}\S/.test(line)) break;
    const match = /^ {10}([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/.exec(line);
    assert.ok(match, `unsupported ${key} line: ${line}`);
    entries[match[1]] = match[2].trim().replace(/^(['"])(.*)\1$/, "$2");
  }
  return entries;
}

// The command lines of the step's single `run: |` block.
function stepRun(block) {
  assert.equal(
    block.filter((line) => /^ {8}run:/.test(line)).length,
    1,
    "step must declare exactly one run: field",
  );
  const at = block.indexOf("        run: |");
  assert.ok(at >= 0, "step must keep a run: | block");
  const commands = [];
  for (let index = at + 1; index < block.length; index++) {
    const line = block[index];
    if (line.trim() === "") continue;
    if (!/^ {10}/.test(line)) break;
    const command = line.slice(10).trimEnd();
    if (!command.startsWith("#")) commands.push(command);
  }
  return commands;
}

test("CI runs the Chromium route and idle TTL acceptance once, after the unchanged native and OTP journeys", () => {
  const browsers = jobBlock("web-browsers");
  // The Chromium-only condition below is only meaningful while the job's own
  // matrix really schedules Chromium: a deleted entry would skip that step
  // forever while the rest of the matrix still passes.
  const matrix = matrixBrowsers(browsers);
  for (const browser of ["chromium", "firefox"])
    assert.ok(
      matrix.includes(browser),
      `the web-browsers matrix must still include ${browser}, got: ${matrix.join(", ")}`,
    );
  const chromium = stepBlock(browsers, CHROMIUM_NATIVE_STEP);
  // The step is still the Chromium-only, bounded native acceptance step.
  assert.equal(
    stepField(chromium.lines, "if"),
    "${{ matrix.browser == 'chromium' }}",
    "the Chromium native step must keep its exact matrix condition",
  );
  const timeout = stepField(chromium.lines, "timeout-minutes");
  assert.match(
    timeout,
    /^\d+$/,
    `timeout-minutes must be a bounded integer, got: ${timeout}`,
  );
  assert.equal(Number(timeout), 15, `timeout-minutes must be 15, got: ${timeout}`);

  // The original two commands stay verbatim and first; the route run is the
  // only additional command, after them.
  const native = `${BROWSER_WRAPPER} node scripts/browser_native_acceptance.mjs`;
  const otp = `${BROWSER_WRAPPER} python3 scripts/browser_otp_privacy_acceptance.py chromium`;
  const route =
    `${BROWSER_WRAPPER} env -u LOCKLARK_TEST_POPUP_VAULT ` +
    "LOCKLARK_TEST_ROUTE_DETAIL_READ=1 LOCKLARK_TEST_ROUTE_IDLE_TTL=1 " +
    "node scripts/browser_native_acceptance.mjs";
  assert.deepEqual(
    stepRun(chromium.lines),
    [native, otp, route],
    "the Chromium step must run the unchanged native and OTP commands, then one route command",
  );

  // The route mode refuses the step-level popup-vault override, so exactly the
  // third command clears it; the opt-ins stay on that command only.
  assert.ok(
    route.includes("env -u LOCKLARK_TEST_POPUP_VAULT "),
    "the route command must clear the popup-vault override",
  );
  for (const command of [native, otp])
    assert.ok(
      !command.includes("env -u LOCKLARK_TEST_POPUP_VAULT"),
      "the original commands must not clear the popup-vault override",
    );
  const env = stepMapping(chromium.lines, "env");
  assert.equal(
    env.LOCKLARK_TEST_POPUP_VAULT,
    "1",
    "the Chromium step must keep its default popup-vault coverage",
  );
  for (const flag of ROUTE_FLAGS) {
    assert.ok(!(flag in env), `${flag} must not be a step-level env value`);
    assert.equal(
      route.split(flag).length - 1,
      1,
      `the route command must set ${flag} exactly once`,
    );
    assert.ok(
      !native.includes(flag) && !otp.includes(flag),
      `${flag} must not change the original native or OTP command`,
    );
  }

  // The binaries still come from the shared runner temp directory.
  assert.deepEqual(
    {
      LOCKLARK_BROWSER_HOST: env.LOCKLARK_BROWSER_HOST,
      LOCKLARK_BROWSER_REGISTER: env.LOCKLARK_BROWSER_REGISTER,
      LOCKLARK_BROWSER_FIXTURE: env.LOCKLARK_BROWSER_FIXTURE,
    },
    {
      LOCKLARK_BROWSER_HOST:
        "${{ runner.temp }}/locklark-bin/locklark-browser-${{ matrix.browser }}",
      LOCKLARK_BROWSER_REGISTER:
        "${{ runner.temp }}/locklark-bin/locklark-browser-register",
      LOCKLARK_BROWSER_FIXTURE:
        "${{ runner.temp }}/locklark-bin/browser-acceptance-fixture",
    },
    "the Chromium step must keep its binaries under $RUNNER_TEMP/locklark-bin",
  );
  const download = stepBlock(browsers, DOWNLOAD_LINUX_BINARIES);
  assert.ok(
    download.start < chromium.start,
    "Download Linux primary binaries must precede the Chromium native step",
  );
  assert.match(
    stepField(download.lines, "uses"),
    /^actions\/download-artifact@/,
    "Download Linux primary binaries must stay an artifact download",
  );
  assert.deepEqual(
    stepMapping(download.lines, "with"),
    { name: "locklark-linux-bin", path: "${{ runner.temp }}/locklark-bin" },
    "the shared binaries must still be downloaded as locklark-linux-bin into $RUNNER_TEMP/locklark-bin",
  );

  // Firefox keeps its original native/OTP scope and never receives the route
  // opt-ins.
  const firefox = stepBlock(browsers, FIREFOX_NATIVE_STEP);
  assert.equal(
    stepField(firefox.lines, "if"),
    "${{ matrix.browser == 'firefox' }}",
    "the Firefox native step must keep its exact matrix condition",
  );
  assert.deepEqual(
    stepRun(firefox.lines),
    [
      `${BROWSER_WRAPPER} node scripts/browser_firefox_native_acceptance.mjs`,
      `${BROWSER_WRAPPER} python3 scripts/browser_otp_privacy_acceptance.py firefox`,
    ],
    "the Firefox step must keep its original native and OTP commands",
  );
  assert.ok(
    !ROUTE_FLAGS.some((flag) => firefox.lines.join("\n").includes(flag)),
    "the Firefox step must not carry the Chromium route flags",
  );
});

// ---------------------------------------------------------------------------
// Focused static contract for the single extension producer's Edge ordering.
//
// The Edge install contract reads the already-produced main Chromium dist; it
// must run once in extension-producer after the official Chromium prepare and
// strict verifier, and never in web-core's early browser test command.
// ---------------------------------------------------------------------------
const EARLY_BROWSER_TEST_STEP = "Test browser extension";
const PRODUCER_JOB = "extension-producer";
const CHROMIUM_PREPARE_STEP = "Prepare Chromium once and strict smoke";
const RELEASE_UNIT_STEP = "Run original release and legacy unit tests";
const EDGE_INSTALL_TEST = "scripts/test_browser_edge_install.mjs";
const CHROMIUM_PREPARE_COMMAND =
  'python3 -m browserrelease --product chromium --output "$out/prepared/v2pairs"';
const STRICT_CHROMIUM_COMMAND =
  "python3 -m browserrelease.prebuilt --product chromium \\";

test("CI runs the Edge install contract once, after the official Chromium producer step", () => {
  // Scope to the web-core job so another job's same-named files cannot satisfy
  // this contract.
  const webCore = jobBlock("web-core");
  const early = stepBlock(webCore, EARLY_BROWSER_TEST_STEP);
  const earlyRun = stepField(early.lines, "run");
  assert.ok(
    earlyRun.startsWith("node --test "),
    "the early browser test step must keep its node --test command",
  );
  assert.equal(
    countMatches(" " + earlyRun + " ", new RegExp(`\\s${EDGE_INSTALL_TEST.replace(/\./g, "\\.")}\\s`)),
    0,
    "the Edge install contract must not run in the early browser test command",
  );

  const producer = jobBlock(PRODUCER_JOB);
  const prepare = stepBlock(producer, CHROMIUM_PREPARE_STEP);
  const units = stepBlock(producer, RELEASE_UNIT_STEP);
  assert.ok(
    prepare.start < units.start,
    "the Chromium producer step must stay before the release/legacy unit step",
  );
  const commands = stepRun(prepare.lines);
  const prepareAt = commands.indexOf(CHROMIUM_PREPARE_COMMAND);
  assert.ok(
    prepareAt >= 0,
    "the producer step must contain the official Chromium prepare command",
  );
  assert.equal(
    commands[prepareAt + 1],
    STRICT_CHROMIUM_COMMAND,
    "the strict Chromium verifier must immediately follow the official prepare",
  );
  assert.match(
    commands[prepareAt + 2],
    /--prepared-dir "\$out\/prepared\/v2pairs" --dist browser-extension\/dist\/chromium/,
    "the strict verifier must consume the official prepared pair and dist",
  );

  const unitCommands = stepRun(units.lines);
  const edgeCommands = unitCommands.filter(
    (line) => line === `node --test ${EDGE_INSTALL_TEST}`,
  );
  assert.equal(
    edgeCommands.length,
    1,
    "the release/legacy unit step must run the Edge install contract once",
  );
  assert.equal(
    countMatches(WORKFLOW, new RegExp(EDGE_INSTALL_TEST.replace(/\./g, "\\."), "g")),
    1,
    "the Edge install contract must be referenced exactly once in check.yml",
  );
});

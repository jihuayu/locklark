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

test("the idle helper reaches the ready and visible gates, then invokes only the supplied browser key", async () => {
  const staleRouteURL =
    "chrome-extension://" + "a".repeat(32) + "/popup.html#route=" + "b".repeat(64);
  const sourcePageURL = "https://login.locklark.test:8443/acceptance";
  const closeKey = Object.freeze([{ key: "Control_L+w" }]);
  const stop = new Error("stop after the injected browser key");
  const events = [];
  const keyCalls = [];
  const evaluateCalls = [];
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
  const sourcePage = { url: () => sourcePageURL };
  const context = vm.createContext({
    URL,
    assert,
    origin: sourcePageURL,
    ROUTE_PAGE: /^chrome-extension:\/\/[a-p]{32}\/popup\.html#route=[a-f0-9]{64}$/,
    ACTION_POPUP: /^chrome-extension:\/\/[a-p]{32}\/popup\.html$/,
    ROUTE_TITLE_PREFIX: "Locklark",
    ROUTE_IDLE_CLOSE_STALE: closeKey,
    routeIdleObservation: null,
    routeLifecycleObservation: null,
    routeStatusTrace: null,
  });
  vm.runInContext(
    idleHelper() + "\nthis.acceptRouteIdleExpiry = acceptRouteIdleExpiry;",
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
      throw new Error("popup must not be reached before the key");
    },
    extensionTargets: async () => [staleTarget],
    attachRoute: async (target) => {
      events.push("attach");
      assert.equal(target, staleTarget);
      return staleClient;
    },
    closeAdapter: (client) => client.close(),
    browserKey: (actions, titlePrefix) => {
      events.push("browserKey");
      keyCalls.push([actions, titlePrefix]);
      throw stop;
    },
    labelInspect: Object.freeze({ inspect: true, preserve_focus: true }),
    vaultRows: "synthetic-vault-rows",
    routeSurfaceProbe: () => "synthetic-surface-probe",
    verifyRouteSurface: () => "",
    nativeInspection: () => ({}),
  };
  // The synthetic wait stops at the first key, so the 120-second journey is
  // never run here.
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
  assert.deepEqual(events, [
    "attach",
    "wait:Route page did not load",
    "evaluate:document.readyState",
    'evaluate:document.visibilityState === "visible" && document.hasFocus() === true',
    "mark:route:idle-close-stale",
    "closeAdapter",
    "browserKey",
    "closeAdapter",
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
    "!live.some((target) => target.id === staleRoute.id)",
    "!live.some((target) => ROUTE_PAGE.test(target.url))",
    '"Stale route tab was not closed"',
  ])
    assert.ok(afterClose.includes(needle), needle);
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
    "await action.click(rowSelector);",
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
  assert.equal(countMatches(body, /action\.click\(rowSelector\)/g), 1);
  // No DOM event, worker message, navigation or page hook is used.
  assert.doesNotMatch(body, /dispatchEvent|sendMessage|relayMessage|postMessage/);
  assert.doesNotMatch(body, /\b(goto|navigate)\b|Page\.navigate|Page\.reload|chrome\.tabs/);
  assert.doesNotMatch(body, /bringToFront[^\n]*\n(?:[^\n]*\n){0,3}[^\n]*input\(/);
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
    "await action.click(rowSelector);",
  ]);
  // The minimum wipe is the worker's full two minutes from that click; the
  // overall wipe bound is the existing 150 seconds from the same click.
  assertOrder(body, [
    'mark("route:idle-live")',
    'mark("route:idle-wait")',
    "const minimumWipe = idleStart + ROUTE_IDLE_TTL;",
    "const wipeDeadline = idleStart + ROUTE_IDLE_WIPE_LIMIT;",
  ]);
  // A wipe before the minimum is a failure; every other pre-minimum probe must
  // still satisfy the tested surface and stay visible.
  assert.match(
    body,
    /if \(now < minimumWipe\) \{\n\s+\/\/ A wipe before the full original TTL is a contract failure, and any\n\s+\/\/ other non-wiped probe must still show the approved surface\.\n\s+assert\.equal\(wiped, false, "Idle route detail did not stay live"\);\n\s+const surface = await fresh\.evaluate\(liveProbe\);\n\s+assert\.equal\(\n\s+surface\?\.visible,\n\s+true,\n\s+"Idle route detail left the foreground",\n\s+\);\n\s+const finding = verifyRouteSurface\(surface, fixture\.Title\);/,
  );
  // The wipe poll uses the shared full wipe probe with every fixture canary.
  assert.match(
    body,
    /routeWiped\(\n\s+await fresh\.evaluate\(\n\s+routeRevokedProbe\(\n\s+fixture\.Title,\n\s+fixture\.Value,\n\s+fixtureCanaries\(fixture\),\n\s+\),\n\s+\),\n\s+\);/,
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
  // `target.url`/`entry.url()`, exactly like the default journeys.
  assert.doesNotMatch(body, /webSocketDebuggerUrl|DevToolsActivePort|fetch\(/);
  const offPattern = body.replace(/\.test\(entry\.url\(\)\)/g, "").replace(/\.test\(target\.url\)/g, "");
  assert.doesNotMatch(offPattern, /\.url\b/);
  // No secret value or clipboard content is read in the host: the two probes
  // receive only the non-secret title/value pair and the canary lists.
  assert.doesNotMatch(body, /fixture\.Password|fixture\.Secret/);
  assert.equal(countMatches(body, /fixture\.Value/g), 2);
  assert.match(body, /routeForbiddenCanaries\(fixture\)/);
  assert.match(body, /routeRevokedProbe\(\n\s+fixture\.Title,\n\s+fixture\.Value,\n\s+fixtureCanaries\(fixture\),/);
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

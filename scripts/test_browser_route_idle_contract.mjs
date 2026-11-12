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
  const header = SOURCE.lastIndexOf("// One second ordinary route journey", start);
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
    /\n\s+closeAdapter: \(client\) => client\.close\(\),\n\s+browserKey,\n\s+labelInspect: ROUTE_LABEL_INSPECT,\n\s+vaultRows: VAULT_ROWS,\n\s+\}\);/,
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
    /^  const \{\n\s+browser: context,\n\s+input,\n\s+fixture,\n\s+phase: mark,\n\s+eventually: wait,\n\s+openPopup: openActionPopup,\n\s+extensionTargets: targets,\n\s+attachRoute: attach,\n\s+closeAdapter,\n\s+browserKey,\n\s+labelInspect,\n\s+vaultRows,\n\s+\} = driver;/m,
  );
  // These names are block locals in the main try/route checkpoint and must
  // not be resolved implicitly from the module-level helper.
  assert.doesNotMatch(body, /\bROUTE_LABEL_INSPECT\b|\bVAULT_ROWS\b/);
  assert.doesNotMatch(body, /\b(?:const|let|var|function)\s+browserKey\b/);
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

test("the idle journey proves the approved detail, then wipes only by its TTL", () => {
  const body = idleJourney();
  assert.match(SOURCE, /^const ROUTE_IDLE_LIVE_OBSERVATION = 10000;$/m);
  assert.match(SOURCE, /^const ROUTE_IDLE_WIPE_LIMIT = 150000;$/m);
  // The detail is verified by the fixed visible-DOM/concealment probe and
  // against popup.html's own markup, read read-only through the adapter.
  assert.match(body, /return routeIdleLive\(await fresh\.evaluate\(liveProbe\)\);/);
  assert.match(body, /await fresh\.evaluate\(ROUTE_TEMPLATE_READ\)/);
  assert.match(body, /routeBaselineProbe\(fixtureCanaries\(fixture\)\)/);
  // The initial observation precedes the bounded wipe window.
  const live = body.indexOf('mark("route:idle-live")');
  const wiped = body.indexOf('mark("route:idle-wiped")');
  const observation = body.indexOf("await delay(ROUTE_IDLE_LIVE_OBSERVATION);");
  const waitMark = body.indexOf('mark("route:idle-wait")');
  const limit = body.indexOf("Date.now() + ROUTE_IDLE_WIPE_LIMIT");
  assert.ok(live > 0 && live < observation && observation < waitMark);
  assert.ok(waitMark < limit && limit < wiped && wiped < body.length);
  assert.match(body, /"Idle route detail did not stay live"/);
  assert.match(body, /"Idle route detail did not expire"/);
  // The wipe poll is the shared full wipe probe, and the same target must
  // still be the one route page between polls.
  const poll = body.slice(waitMark, wiped);
  assert.match(
    poll,
    /routeWiped\(\n\s+await fresh\.evaluate\(\n\s+routeRevokedProbe\(fixture\.Title, fixture\.Value\),/,
  );
  assert.match(poll, /target\.id === routeTarget && ROUTE_PAGE\.test\(target\.url\)/);
  assert.match(poll, /Date\.now\(\) >= deadline/);
  // Once the approved detail is shown, nothing but read-only probes runs
  // until the wipe is complete: no observer, key, pointer, CDP input or
  // action.
  assert.doesNotMatch(
    body.slice(live, wiped),
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
    "route:idle-wiped",
    "route:idle-passed",
  ])
    assert.ok(stages.includes(stage), stage);
  assert.ok(
    body.includes(
      '"PASS: an idle second route tab kept its approved detail without input, stayed live through the initial observation and was fully wiped by its own two-minute route TTL"',
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
  // No secret value or clipboard content is read in the host: the one shared
  // full-wipe probe receives only the non-secret title and note canary.
  assert.doesNotMatch(body, /fixture\.Password|fixture\.Secret/);
  assert.equal(countMatches(body, /fixture\.Value/g), 1);
  assert.match(body, /routeWiped\(\n\s+await fresh\.evaluate\(\n\s+routeRevokedProbe\(fixture\.Title, fixture\.Value\),/);
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
    "Idle route detail did not survive native approval",
    "Idle route detail did not stay live",
    "Idle route detail did not expire",
    "Route page text unavailable",
    "Popup template unavailable",
  ])
    assert.ok(SOURCE.includes('"' + reason + '"'), reason);
});

test("the idle live probe compares fixed booleans inside the page", () => {
  const start = SOURCE.indexOf(
    "function routeIdleLiveProbe(title, texts, forbidden, detailTemplateHTML, baselineText) {",
  );
  const stop = SOURCE.indexOf("\nfunction routeIdleLive(", start);
  assert.ok(start > 0 && stop > start);
  // The selector split helper and the text policy the probe embeds are the
  // only harness functions/constants it uses.
  const context = vm.createContext({
    ROUTE_COPY_FIELD_SELECTOR: ROUTE_COPY_FIELD_SELECTOR_VALUE,
    ROUTE_DETAIL_DYNAMIC_CONTAINERS: dynamicContainersSource(),
  });
  vm.runInContext(policySource() + "\n" + SOURCE.slice(start, stop) + "\nthis.probe = routeIdleLiveProbe;", context);
  const expression = context.routeIdleLiveProbe(
    "Fixture title",
    ["Fixture title", "canary"],
    ["canary"],
    '<body><section id="detail-view"></section></body>',
    ["static"],
  );
  assert.equal(typeof expression, "string");
  // Only fixed keys and per-condition booleans leave the page: the probe's
  // final return object (the embedded policy only feeds the page).
  const returns = expression.lastIndexOf("    return {");
  assert.ok(returns > 0);
  const keys = [...expression.slice(returns).matchAll(/^\s{6}([a-zA-Z]+):/gm)].map((m) => m[1]);
  assert.deepEqual(keys.sort(), [
    "copyControl",
    "detailShown",
    "fixtureAbsent",
    "fixtureOnly",
    "masked",
    "titleMatchesFixture",
    "view",
    "visible",
  ]);
  // The expected value only ever accepts the fixed true/known values.
  const verifierSrc = SOURCE.slice(stop, SOURCE.indexOf("\nfunction phase(", stop));
  vm.runInContext(verifierSrc + "\nthis.live = routeIdleLive;", context);
  const live = context.live;
  const good = {
    visible: true,
    view: "detail",
    detailShown: true,
    titleMatchesFixture: true,
    copyControl: true,
    masked: true,
    fixtureAbsent: true,
    fixtureOnly: true,
  };
  assert.equal(live(good), true);
  for (const key of Object.keys(good)) {
    assert.equal(live({ ...good, [key]: false }), false, key);
    assert.equal(live({ ...good, [key]: undefined }), false, key);
  }
  assert.equal(live(null), false);
  assert.equal(live({ ...good, view: "other" }), false);
});

// The harness's route detail text policy, as its own source.
function policySource() {
  const start = SOURCE.indexOf("function routeDetailPrivacyPolicy(texts, forbidden) {");
  const stop = SOURCE.indexOf("\n// The route's own tab switch", start);
  assert.ok(start > 0 && stop > start, "the text policy must exist");
  return SOURCE.slice(start, stop);
}

// A wholly synthetic login: Title and Username are visible fixture text,
// every other canary must stay off the page. No real fixture value is used.
const SYNTHETIC = Object.freeze({
  Title: "Synthetic title",
  Username: "synthetic-user",
  Password: "SyntheticPass",
  Secret: "SyntheticSeed",
  Value: "SyntheticPass-value",
  OTPSeed: "SyntheticOTPSeed",
});
const SYNTHETIC_KEYS = [
  "Password", "Secret", "Username", "Value", "SaveUsername", "SaveValue",
  "UpdateUsername", "UpdateValue", "RejectedUsername", "RejectedValue",
  "OTPSeed", "OTPURI", "CardNumber", "CardHolder", "CardVerification",
  "CardExpiry", "CardPIN",
];
const VISIBLE_KEYS = ["Username"];
const allTexts = () => SYNTHETIC_KEYS.map((key) => SYNTHETIC[key]).filter((v) => typeof v === "string" && v);
const forbiddenTexts = () => allTexts().filter((v) => !VISIBLE_KEYS.map((key) => SYNTHETIC[key]).includes(v));

// The harness's forbidden-canary filter, given a synthetic canary function.
function forbiddenFor(fixture) {
  const context = vm.createContext({ fixtureCanaries: allTexts });
  vm.runInContext(
    SOURCE.slice(
      SOURCE.indexOf("const ROUTE_DETAIL_VISIBLE_FIXTURE_KEYS ="),
      SOURCE.indexOf("\n// The route detail's text policy"),
    ) + "\nthis.filter = routeForbiddenCanaries;",
    context,
  );
  return [...context.filter(fixture)];
}

function policyScreen(overrides = {}) {
  return {
    title: SYNTHETIC.Title,
    headingText: SYNTHETIC.Title,
    detailText: [SYNTHETIC.Title, "用户名", SYNTHETIC.Username, "密码", "••••••••"].join("\n"),
    pageText: [SYNTHETIC.Title, SYNTHETIC.Username, "••••••••", "static note"].join("\n"),
    noteTexts: [SYNTHETIC.Username],
    staticLines: ["用户名", "密码", "••••••••", "static note"],
    ...overrides,
  };
}

function runPolicy(overrides) {
  const context = vm.createContext({});
  vm.runInContext(policySource() + "\nthis.policy = routeDetailPrivacyPolicy;", context);
  return { ...context.policy(allTexts(), forbiddenTexts())(policyScreen(overrides)) };
}

test("the route text policy allows the verified Username and every secret stays forbidden", () => {
  // Only the verified Username is excluded from the forbidden set.
  assert.deepEqual(forbiddenFor(SYNTHETIC), forbiddenTexts());
  assert.equal(forbiddenFor(SYNTHETIC).includes(SYNTHETIC.Username), false);
  // The allowed title, Username and static text all pass.
  assert.deepEqual(runPolicy(), {
    forbiddenAbsent: true,
    titleMatchesFixture: true,
    detailOnlyKnown: true,
    notesOnlyFixture: true,
  });
  // Any leaked Password, Secret, Value or OTP value fails the absence check
  // even when it would otherwise be fixture-supplied detail text.
  for (const key of ["Password", "Secret", "Value", "OTPSeed"]) {
    const leaked = runPolicy({
      pageText: [policyScreen().pageText, SYNTHETIC[key]].join("\n"),
    });
    assert.equal(leaked.forbiddenAbsent, false, key);
  }
});

test("the route text policy refuses text that is neither template nor fixture text", () => {
  // An unknown detail line and an unknown note fail their known-text checks.
  assert.equal(runPolicy({ detailText: "unrelated detail text" }).detailOnlyKnown, false);
  assert.equal(runPolicy({ noteTexts: ["unrelated note"] }).notesOnlyFixture, false);
  // A heading that is not the fixture title fails too.
  assert.equal(runPolicy({ headingText: "Other title" }).titleMatchesFixture, false);
  // A missing note still fails closed, and a non-array note list fails closed.
  assert.equal(runPolicy({ noteTexts: null }).notesOnlyFixture, false);
});

test("the idle live probe embeds the shared text policy with both canary inputs", () => {
  const probe = SOURCE.slice(
    SOURCE.indexOf("function routeIdleLiveProbe(title, texts, forbidden, detailTemplateHTML, baselineText) {"),
    SOURCE.indexOf("\nfunction routeIdleLive("),
  );
  // The page probe embeds the policy's self-contained factory (never its
  // returned closure) and calls it with both serialized arrays.
  assert.match(probe, /const policyFactory = routeDetailPrivacyPolicy\.toString\(\);/);
  assert.match(probe, /const forbiddenTexts=\$\{JSON\.stringify\(forbidden\)\};/);
  assert.match(
    probe,
    /const privacy=\$\{policyFactory\}\(\$\{JSON\.stringify\(texts\)\},\$\{JSON\.stringify\(forbidden\)\}\);/,
  );
  assert.match(probe, /fixtureAbsent:privacyVerdict\.forbiddenAbsent,/);
  // The call passes all fixture canaries for known text and only the
  // non-displayable ones as forbidden.
  assert.match(
    idleJourney(),
    /routeIdleLiveProbe\(\n\s+fixture\.Title,\n\s+fixtureCanaries\(fixture\),\n\s+routeForbiddenCanaries\(fixture\),\n/,
  );
  assert.match(SOURCE, /^const ROUTE_DETAIL_VISIBLE_FIXTURE_KEYS = Object\.freeze\(\["Username"\]\);$/m);
});

// The smallest read-only document the generated probe reads: the page text,
// the detail section/title/fields and the notes. Built by generated code inside
// the page context itself; no writes, hooks or events exist.
const MINIMAL_DOCUMENT_SOURCE = `function (pageText, heading, username) {
  const empty = { children: [], childNodes: [], querySelector: () => null,
    querySelectorAll: () => [], getAttribute: () => null, hidden: true,
    textContent: "" };
  const text = (value) => ({ children: [], childNodes: [{ nodeType: 3, data: value }],
    querySelector: () => null, querySelectorAll: () => [],
    getAttribute: () => null, hidden: false, textContent: value });
  const nodes = {
    "#detail-view": { ...empty, hidden: false },
    "#detail-title": text(heading),
    "#detail-fields": empty,
    "#detail-notes": text(username),
  };
  return {
    body: { dataset: { view: "detail" }, innerText: pageText,
      childNodes: [], children: [] },
    visibilityState: "visible",
    querySelector: (selector) => nodes[selector] ?? null,
    implementation: { createHTMLDocument: () => ({ body: {}, querySelector: () => null }) },
  };
}`;

// The harness's detail-owned dynamic containers, evaluated by the harness.
function dynamicContainersSource() {
  const start = SOURCE.indexOf("const ROUTE_DETAIL_DYNAMIC_CONTAINERS =");
  const end = SOURCE.indexOf("]);\n", start);
  assert.ok(start > 0 && end > start, "the dynamic containers must exist");
  const stop = end + "]);".length;
  const context = vm.createContext({});
  vm.runInContext(
    SOURCE.slice(start, stop) + "\nthis.list = ROUTE_DETAIL_DYNAMIC_CONTAINERS;",
    context,
  );
  return context.list;
}

// The harness's own probe generator, loaded with synthetic inputs only.
function harnessProbe() {
  const start = SOURCE.indexOf("const ROUTE_DETAIL_VISIBLE_FIXTURE_KEYS =");
  const stop = SOURCE.indexOf("// The route's own tab switch", start);
  const probeStart = SOURCE.indexOf("function routeIdleLiveProbe(");
  const probeStop = SOURCE.indexOf("\nfunction routeIdleLive(", probeStart);
  assert.ok(start > 0 && stop > start && probeStart > 0 && probeStop > probeStart);
  const harness = vm.createContext({
    ROUTE_COPY_FIELD_SELECTOR: ROUTE_COPY_FIELD_SELECTOR_VALUE,
    ROUTE_DETAIL_DYNAMIC_CONTAINERS: dynamicContainersSource(),
  });
  vm.runInContext(SOURCE.slice(start, stop) + "\n" + SOURCE.slice(probeStart, probeStop), harness);
  return harness;
}

// Generate the expression with that probe, compile it as one page script, and
// run it on the synthetic page text. Only fixed booleans leave the page.
function runGeneratedProbe(innerText) {
  const harness = harnessProbe();
  const expression = harness.routeIdleLiveProbe(
    SYNTHETIC.Title,
    allTexts(),
    forbiddenFor(SYNTHETIC),
    ROUTE_IDLE_PAGE_TEMPLATE,
    [],
  );
  assert.equal(typeof expression, "string");
  const page = vm.createContext({
    pageText: innerText,
    heading: SYNTHETIC.Title,
    username: SYNTHETIC.Username,
  });
  // The fake document builder runs inside the page context.
  new vm.Script(
    "this.document = (" + MINIMAL_DOCUMENT_SOURCE + ")(pageText, heading, username);" +
      "this.result = (function (observed) {" +
      " return { forbiddenAbsent: observed.fixtureAbsent," +
      " titleMatchesFixture: observed.titleMatchesFixture," +
      " fixtureOnly: observed.fixtureOnly };" +
      "})((0, " + expression + "));",
  ).runInContext(page);
  // Only one fixed number leaves the page: bit 0 is the forbidden-absence
  // verdict, bit 1 the title match, bit 2 the fixture-only verdict.
  const bits = vm.runInContext(
    "((result.forbiddenAbsent === true ? 1 : 0) |" +
      "(result.titleMatchesFixture === true ? 2 : 0) |" +
      "(result.fixtureOnly === true ? 4 : 0))",
    page,
  );
  return bits;
}

const ROUTE_IDLE_PAGE_TEMPLATE = '<body><section id="detail-view"></section></body>';

test("the generated page expression compiles and enforces the text policy", () => {
  // The visible synthetic Username is allowed and the title is the fixture's.
  const allowed = runGeneratedProbe([SYNTHETIC.Title, SYNTHETIC.Username].join("\n"));
  assert.equal((allowed & 1) === 1, true, "visible Username must not be forbidden");
  assert.equal(allowed & 2, 2, "title must match the fixture");
  // Any forbidden canary in the page text fails closed.
  for (const key of ["Password", "Secret", "Value", "OTPSeed"]) {
    const leaked = runGeneratedProbe(
      [SYNTHETIC.Title, SYNTHETIC.Username, SYNTHETIC[key]].join("\n"),
    );
    assert.equal(leaked % 2, 0, key);
  }
});

// A synthetic page for the generated shape check. The template (static
// popup.html skeleton) leaves the four detail-owned containers empty; the live
// page has the same fixed skeleton filled with obtainable field and URL rows.
// Only the nodes the probe reads exist; nothing is written or hooked.
function shapedPage(live, options = {}) {
  const node = (tag, id = "", children = [], text = "") => ({
    tagName: tag.toUpperCase(), id, children, childNodes: text ? [{ nodeType: 3, data: text }] : [],
    attributes: id ? [{ name: "id" }] : [], textContent: text, hidden: false,
    getAttribute: () => null, querySelector: () => null, querySelectorAll: () => [],
  });
  // The copy proof's password row: its masked value and one Copy control.
  const value = node("SPAN", "", [], "••••••••");
  value.attributes = [{ name: "class" }];
  value.getAttribute = (name) => (name === "class" ? "field-value" : null);
  const copy = node("BUTTON", "", [], "复制");
  copy.getAttribute = (name) => (name === "data-action" ? "copy-field" : null);
  const row = node("DIV", "password", [value, copy]);
  row.getAttribute = (name) => (name === "data-field-id" ? "password" : null);
  row.querySelector = (selector) => (selector === ".field-value" ? value : null);
  row.querySelectorAll = (selector) =>
    selector === '[data-action="copy-field"]' ? [copy] : [];
  const heading = node("H2", "detail-title", [], live ? SYNTHETIC.Title : "");
  const rows = [
    heading,
    node("DIV", "detail-fields", live ? [row] : []),
    node("DIV", "detail-urls", live ? [node("DIV", "", [node("SPAN", "", [], "synthetic.example")])] : []),
    node("DIV", "detail-tags"),
    node("DIV", "attachment-list"),
    node("P", "detail-notes", [], live ? SYNTHETIC.Username : ""),
  ];
  // An extra outer child breaks the fixed detail skeleton.
  if (options.extraOuterChild) rows.push(node("P", "note", [], "extra"));
  const detail = node("SECTION", "detail-view", rows);
  const fields = detail.children[1];
  fields.querySelector = (selector) =>
    selector === '[data-field-id="password"]' ? (live ? row : null) : null;
  const byId = {
    "#detail-view": detail,
    "#detail-title": heading,
    "#detail-fields": fields,
    "#detail-notes": detail.children[5],
  };
  return {
    body: { dataset: { view: "detail" }, childNodes: [], children: [], innerText: [SYNTHETIC.Title, SYNTHETIC.Username].join("\n") },
    visibilityState: "visible",
    querySelector: (selector) => byId[selector] ?? null,
    implementation: {
      // The static page's own detail tree, as parsed from popup.html: the same
      // fixed skeleton, its containers empty and its title carrying no text.
      createHTMLDocument: () => {
        const template = shapedPage(false).querySelector("#detail-view");
        template.querySelector = (selector) =>
          selector === "#detail-title" ? template.children[0] : null;
        return {
          body: {},
          querySelector: (selector) => (selector === "#detail-view" ? template : null),
        };
      },
    },
  };
}

test("the generated probe accepts a filled detail whose skeleton matches", () => {
  const harness = harnessProbe();
  const expression = harness.routeIdleLiveProbe(
    SYNTHETIC.Title, allTexts(), forbiddenFor(SYNTHETIC), "<static popup.html detail>", []);
  const result = new vm.Script("(" + expression + ")").runInContext(
    vm.createContext({ document: shapedPage(true) }),
  );
  assert.equal(result.fixtureOnly, true);
  assert.equal(result.fixtureAbsent, true);
});

test("the generated probe still refuses a static outer-structure mismatch", () => {
  const harness = harnessProbe();
  const expression = harness.routeIdleLiveProbe(
    SYNTHETIC.Title, allTexts(), forbiddenFor(SYNTHETIC), "<static popup.html detail>", []);
  const page = shapedPage(true, { extraOuterChild: true });
  const result = new vm.Script("(" + expression + ")").runInContext(
    vm.createContext({ document: page }),
  );
  assert.equal(result.fixtureOnly, false);
});

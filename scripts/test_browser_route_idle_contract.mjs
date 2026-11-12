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
  // The opt-in journey lives in its own function: the route driver mentions it
  // exactly once, in the guarded call, and never declares it.
  assert.equal(countMatches(driver, /acceptRouteIdleExpiry/g), 1);
  assert.doesNotMatch(driver, /function acceptRouteIdleExpiry/);
  assert.ok(SOURCE.includes("\nasync function acceptRouteIdleExpiry(driver) {\n"));
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
    "const rows = await action.evaluate(VAULT_ROWS);",
    "rows[0].id === fixture.SeedID &&",
    "await action.click(rowSelector);",
    "Route page did not open",
    "Route page must be unique",
    'mark("route:idle-native-label")',
    "ROUTE_LABEL_INSPECT",
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
    "function routeIdleLiveProbe(title, canaries, detailTemplateHTML, baselineText) {",
  );
  const stop = SOURCE.indexOf("\nfunction routeIdleLive(", start);
  assert.ok(start > 0 && stop > start);
  // The selector split helper is the only harness constant the probe uses.
  const context = vm.createContext({
    ROUTE_COPY_FIELD_SELECTOR: ROUTE_COPY_FIELD_SELECTOR_VALUE,
  });
  vm.runInContext(
    SOURCE.slice(start, stop) + "\nthis.probe = routeIdleLiveProbe;",
    context,
  );
  const expression = context.probe(
    "Fixture title",
    ["canary"],
    '<body><section id="detail-view"></section></body>',
    ["static"],
  );
  assert.equal(typeof expression, "string");
  // Only fixed keys and per-condition booleans leave the page.
  const keys = [...expression.matchAll(/^\s{6}([a-zA-Z]+):/gm)].map((m) => m[1]);
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

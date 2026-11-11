const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function waitFor(pred, label = "condition") {
  for (let i = 0; i < 200; i++) {
    const value = pred();
    if (value) return value;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error("timed out waiting for " + label);
}
function harness(options = {}) {
  const RealDate = Date;
  let clock = options.clock ?? RealDate.now();
  class ClockDate extends RealDate {
    constructor(...args) {
      if (args.length) super(...args);
      else super(clock);
    }
    static now() {
      return clock;
    }
  }
  const timers = new Map();
  const listeners = {},
    sent = [],
    injected = [],
    otpProbes = [];
  const messageListeners = [];
  const connectListeners = [];
  const notifications = [];
  let idleListener = null,
    idleInterval = 0;
  let fillWait = null;
  let messageListener,
    portMessage,
    portDisconnect,
    doc = "doc-1",
    tabId = 1,
    windowId = 1,
    captureValue = null,
    captured = [],
    captureWait = null,
    readyIds = new Set(),
    hangProbe = false,
    hangProbeAfterInjection = false,
    probeCount = 0,
    probeGate = null,
    probeBlocked = false,
    probeWaiters = [],
    autoCommit = true,
    otpClock = 0,
    otpProbeWait = null,
    otpFillWait = null,
    otpCancelResult = "cancelled",
    autoOTPCancel = true,
    tabUrl = options.tabUrl || "https://example.test/login",
    capabilities = Array.isArray(options.capabilities)
      ? [...options.capabilities]
      : [],
    nativePassword = options.nativePassword || "Native-Generated-1!",
    generatedFillResult = options.generatedFillResult || {
      ok: true,
      filledCount: 2,
      username: "fill-user",
      isPasswordChange: false,
    };
  const tabMessages = [];
  const port = {
    onMessage: { addListener: (f) => (portMessage = f) },
    onDisconnect: { addListener: (f) => (portDisconnect = f) },
    disconnect: () => portDisconnect?.(),
    postMessage: (r) => {
      sent.push(r);
      if (r.type === "hello")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "paired",
            capability: "a".repeat(32),
            capabilities,
          }),
        );
      if (r.type === "match")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "candidates",
            candidates: [
              {
                id: "b".repeat(32),
                revision: "c".repeat(64),
                state: "active",
                title: "Fixture",
              },
            ],
          }),
        );
      if (r.type === "unlock-request")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "status",
            desktop_connected: true,
            unlocked: false,
            vault_locked: true,
            paired: false,
            capabilities: [],
          }),
        );
      if (r.type === "commit-ready" && autoCommit)
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "saved",
            item_id: "d".repeat(32),
            revision: "e".repeat(64),
          }),
        );
      if (r.type === "cancel-save") {
        if (
          !readyIds.has(r.request_id) &&
          sent.some(
            (q) =>
              q.id === r.request_id &&
              (q.type === "save-new" || q.type === "save-update"),
          )
        )
          queueMicrotask(() =>
            portMessage({
              v: 1,
              id: r.request_id,
              type: "error",
              error: "refused",
            }),
          );
        queueMicrotask(() =>
          portMessage({ v: 1, id: r.id, type: "cancelled" }),
        );
      }
      if (r.type === "cancel-otp" && autoOTPCancel)
        queueMicrotask(() =>
          portMessage({ v: 1, id: r.id, type: otpCancelResult }),
        );
      if (r.type === "cancel")
        queueMicrotask(() =>
          portMessage({ v: 1, id: r.id, type: "cancelled" }),
        );
      if (r.type === "generate" && capabilities.includes("generate-v1"))
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "generated",
            generated_password: nativePassword,
            profile: {
              mode: "random",
              length: nativePassword.length,
              alphabet_size: 84,
              entropy_bits_floor: 100,
            },
            history_id: "7".repeat(32),
          }),
        );
      if (r.type === "stage-save" && capabilities.includes("stage-save-v1"))
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "save-staged",
            staged_save: {
              stage_id: "9".repeat(32),
              origin: r.origin,
              username: r.username,
              title: r.title,
              mode: r.mode,
              existing_item_id: r.item_id || "",
              existing_revision: r.revision || "",
              expires_at: Date.now() + 60000,
            },
          }),
        );
      if (
        r.type === "commit-staged-save" &&
        capabilities.includes("stage-save-v1")
      )
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "saved",
            item_id: "d".repeat(32),
            revision: "e".repeat(64),
          }),
        );
      if (r.type === "dismiss-save" && capabilities.includes("stage-save-v1"))
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "save-dismissed",
            never_origins: [],
          }),
        );
      if (r.type === "prepare-copy-field" && !options.holdCopyPrepare)
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "copy-prepared",
            item_id: r.item_id,
            revision: r.revision,
            field: r.field,
            copy_mode: "native",
            copy_ticket: options.copyTicket || "f".repeat(64),
            expires_in_seconds: 10,
            cleanup_ttl_seconds: 30,
          }),
        );
      if (r.type === "cancel-copy-field")
        queueMicrotask(() =>
          portMessage({
            v: 1,
            id: r.id,
            type: "copy-cancelled",
            copy_ticket: r.copy_ticket,
            copy_mode: "native",
          }),
        );
      if (typeof options.onRequest === "function") {
        const reply = options.onRequest(r);
        if (reply) queueMicrotask(() => portMessage(reply));
      }
    },
  };
  const api = {
    storage: {
      onChanged: { addListener: (f) => (listeners.storage = f) },
      local: {
        get: async () => {
          if (options.readSettingsError) throw Error("storage unavailable");
          return { ...(options.settings || {}) };
        },
        set: async () => {
          if (options.writeSettingsError) throw Error("storage unavailable");
        },
      },
    },
    runtime: {
      id: "fixed",
      getURL: (p) => "chrome-extension://fixed/" + p,
      connectNative: () => {
        if (options.connectNativeError)
          throw Error(options.connectNativeError);
        return port;
      },
      onMessage: { addListener: (f) => messageListeners.push(f) },
      onConnect: { addListener: (f) => connectListeners.push(f) },
    },
    tabs: {
      query: async () => [{ id: tabId, url: tabUrl, windowId }],
      sendMessage: (targetTab, message, sendOptions) => {
        tabMessages.push({ tabId: targetTab, message, options: sendOptions });
        return Promise.resolve();
      },
      onActivated: { addListener: (f) => (listeners.active = f) },
      onUpdated: { addListener: (f) => (listeners.updated = f) },
      onRemoved: { addListener: (f) => (listeners.removed = f) },
    },
    windows: {
      WINDOW_ID_NONE: -1,
      onFocusChanged: { addListener: (f) => (listeners.focus = f) },
    },
    idle: {
      setDetectionInterval: (seconds) => {
        idleInterval = seconds;
      },
      onStateChanged: { addListener: (f) => (idleListener = f) },
    },
    notifications: {
      create: (options) => {
        notifications.push(options);
        return Promise.resolve("n1");
      },
    },
    scripting: {
      executeScript: async (options) => {
        if (options.target.frameIds && options.target.documentIds)
          throw Error("Cannot specify both 'frameIds' and 'documentIds'.");
        if (options.func === core.probe) probeCount++;
        if (
          options.func === core.probe &&
          (hangProbe || (hangProbeAfterInjection && injected.length > 0))
        )
          return new Promise(() => {});
        if (options.func === core.probe) {
          const probe = [
            {
              frameId: 0,
              documentId: doc,
              result: { top: true, origin: "https://example.test" },
            },
          ];
          if (probeGate) {
            if (probeGate.remaining > 0) probeGate.remaining -= 1;
            else {
              const gate = probeGate;
              probeGate = null;
              probeBlocked = true;
              for (const wake of probeWaiters.splice(0)) wake();
              return gate.wait.then(() => probe);
            }
          }
          return probe;
        }
        if (options.func === core.otpDocument && options.args[1] === "probe") {
          otpProbes.push([...options.args]);
          if (otpProbeWait) return await otpProbeWait;
          return [
            {
              frameId: 0,
              documentId: doc,
              result: {
                top: true,
                origin: "https://example.test",
                timeOrigin: 1000,
                now: 50,
                wall: Date.now(),
              },
            },
          ];
        }
        if (options.func === core.fillGeneratedPassword) {
          injected.push(options);
          return [
            {
              frameId: 0,
              documentId: doc,
              result: { ...generatedFillResult },
            },
          ];
        }
        if (options.func === core.fillDocument && options.args[4] === true) {
          if (captureWait) return await captureWait;
          const result = {
            username: captureValue?.username ?? "save-user",
            password: captureValue?.password ?? "save-password",
          };
          captured.push(result);
          return [{ frameId: 0, documentId: doc, result }];
        }
        injected.push(options);
        if (options.func === core.fillDocument && fillWait)
          return await fillWait;
        if (options.func === core.otpDocument && otpFillWait)
          return await otpFillWait;
        return [{ frameId: 0, documentId: doc, result: true }];
      },
    },
  };
  const context = {
    chrome: api,
    LocklarkCore: core,
    crypto: webcrypto,
    Date: options.clock === undefined ? RealDate : ClockDate,
    setTimeout: (fn, ms) => {
      const h = setTimeout(fn, ms);
      h.unref?.();
      timers.set(h, { fn, ms });
      return h;
    },
    clearTimeout: (h) => {
      timers.delete(h);
      clearTimeout(h);
    },
    console: {},
    importScripts: () => {},
    URL,
    Uint8Array,
    TextEncoder,
    performance: { now: () => otpClock },
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../background.js"), "utf8"),
    context,
  );
  const sender = { id: "fixed", url: "chrome-extension://fixed/popup.html" };
  return {
    api,
    docId: () => doc,
    routeToken: (url) => /#route=([a-f0-9]{64})$/.exec(String(url || ""))?.[1] || "",
    sent,
    notifications,
    advanceClock: (ms) => (clock += ms),
    // The timer armed for this exact delay, if any (deadline pruning).
    timerFor: (ms) => [...timers].find(([, timer]) => timer.ms === ms),
    pendingDelays: () => [...timers].map(([, timer]) => timer.ms),
    idleInterval: () => idleInterval,
    fireIdle: (state) => idleListener?.(state),
    holdFill: (promise) => (fillWait = promise),
    injected,
    otpProbes,
    listeners,
    hangProbe: () => (hangProbe = true),
    hangPostInjectionProbe: () => (hangProbeAfterInjection = true),
    probeCount: () => probeCount,
    expireFillBound: () => {
      // Fire every still-pending bounded (1500ms) operation. Resolved calls
      // clear their timer, so only the live injection/probe wait is left.
      const found = [...timers].filter(([, t]) => t.ms === 1500);
      assert.ok(found.length > 0, "missing bounded fill timer");
      for (const [handle, timer] of found) {
        clearTimeout(handle);
        timers.delete(handle);
        timer.fn();
      }
    },
    // Defer the Nth probe so a context recheck can be held in flight while the
    // page, vault or intent changes around it.  The deferred probe resolves
    // with the document that was current when it started, like the real
    // scripting call it models.
    deferProbe: (after = 0) => {
      let release;
      const wait = new Promise((resolve) => (release = resolve));
      probeGate = { remaining: after, wait };
      return () => {
        probeBlocked = false;
        release();
      };
    },
    waitProbe: () =>
      probeBlocked
        ? Promise.resolve()
        : new Promise((resolve) => probeWaiters.push(resolve)),
    holdCommits: () => (autoCommit = false),
    losePort: () => portDisconnect?.(),
    expireCommit: () => {
      const found = [...timers].find(([, t]) => t.ms === 15000);
      assert.ok(found);
      clearTimeout(found[0]);
      timers.delete(found[0]);
      found[1].fn();
    },
    captured,
    expireOTPBounded: () => {
      const found = [...timers]
        .filter(([, t]) => t.ms > 0 && t.ms <= 1500)
        .at(-1);
      assert.ok(found);
      clearTimeout(found[0]);
      timers.delete(found[0]);
      found[1].fn();
    },
    expireOTP: () => {
      const found = [...timers].find(([, t]) => t.ms > 0 && t.ms <= 1500);
      assert.ok(found);
      clearTimeout(found[0]);
      timers.delete(found[0]);
      found[1].fn();
    },
    advanceOTPClock: (ms) => (otpClock += ms),
    holdOTPFill: (promise) => (otpFillWait = promise),
    holdOTPCancel: () => (autoOTPCancel = false),
    otpCancelResult: (value) => (otpCancelResult = value),
    holdOTPProbe: (promise) => (otpProbeWait = promise),
    setWindow: (x) => (windowId = x),
    setTabUrl: (x) => (tabUrl = x),
    setCapture: (x) => (captureValue = x),
    waitCapture: (promise) => (captureWait = promise),
    setDoc: (x) => (doc = x),
    tabMessages,
    setTab: (x) => (tabId = x),
    // Emit the popup-private native-clipboard runtime port via onConnect.
    emitPort: (name = "native-clipboard", overrides = {}) => {
      assert.ok(connectListeners.length, "background never registered onConnect");
      let onMessageFn, onDisconnectFn;
      const port = {
        name,
        received: [],
        disconnected: false,
        onMessage: { addListener: (f) => (onMessageFn = f) },
        onDisconnect: { addListener: (f) => (onDisconnectFn = f) },
        postMessage: (m) => port.received.push(m),
        disconnect: () => {
          port.disconnected = true;
          onDisconnectFn?.();
        },
      };
      const portSender = {
        id: "fixed",
        url: "chrome-extension://fixed/popup.html",
        ...overrides,
      };
      port.sender = portSender;
      for (const listen of connectListeners) listen(port, portSender);
      return {
        port,
        received: port.received,
        post: (m) => onMessageFn?.(m),
        disconnect: () => port.disconnect(),
        get disconnected() {
          return port.disconnected;
        },
        waitFor: (pred, label = "clipboard port message") =>
          waitFor(() => port.received.find(pred), label),
        waitReady: () =>
          waitFor(
            () => port.received.find((m) => m.type === "ready"),
            "native-clipboard ready",
          ),
      };
    },
    deliver: (r) => {
      if (r.type === "save-ready") readyIds.add(r.id);
      portMessage(r);
    },
    send: (m, s = sender) =>
      new Promise((resolve) => {
        let handled = false;
        for (const listener of messageListeners)
          if (listener(m, s, resolve) === true) handled = true;
        if (!handled) resolve(undefined);
      }),
  };
}
async function ready(h) {
  await h.send({ type: "connect" });
  await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, true);
  await h.send({ type: "match" });
}
// The exact production text of one top-level function in background.js,
// cut at its matching closing brace so following listeners never leak in.
async function waitForSource(header) {
  const source = fs.readFileSync(path.join(__dirname, "../background.js"), "utf8");
  const from = source.indexOf(header);
  assert.ok(from > 0, "missing production function " + header);
  let at = source.indexOf("{", from);
  assert.ok(at > 0, "missing body for " + header);
  let depth = 0;
  for (; at < source.length; at++) {
    if (source[at] === "{") depth++;
    else if (source[at] === "}") {
      depth--;
      if (depth === 0) return source.slice(from, at + 1);
    }
  }
  throw Error("unterminated production function " + header);
}
test("an ordinary route opens its own tab and claims the approved detail", async () => {
  const ROUTE_TAB = 7;
  const ITEM_ID = "b".repeat(32);
  const ITEM_REV = "c".repeat(64);
  let sourceTab = null;
  let routeTab = null;
  const h = harness({
    onRequest: (r) => {
      // The native V2 reply type the route read consumes. Using it here keeps
      // this checkpoint isolated from the popup's later type/alias mapping.
      if (r.type === "vault-search")
        return {
          v: 1, id: r.id, type: "items", vaults: [],
          items: [{ id: ITEM_ID, revision: ITEM_REV, category: "login", title: "Target" }],
        };
      if (r.type === "item-get")
        return {
          v: 1, id: r.id, type: "item-detail",
          item: {
            id: ITEM_ID, revision: ITEM_REV, category: "login", title: "Target",
            username: "ada", has_password: true,
          },
        };
      return undefined;
    },
  });
  // ready()/match() captures the real source HTTPS tab and top document.
  await ready(h);
  // Browser tab state the worker can re-read after every await: the source
  // keeps its exact URL/document but goes inactive; the route tab is active.
  sourceTab = { id: 1, windowId: 1, active: true, url: "https://example.test/login" };
  h.api.tabs.get = async (tabId) =>
    tabId === sourceTab.id ? { ...sourceTab } : tabId === ROUTE_TAB && routeTab ? { ...routeTab } : null;
  h.api.scripting.executeScript = async (options) =>
    options.target.tabId === sourceTab.id
      ? [{ frameId: 0, documentId: h.docId(), result: { top: true, origin: "https://example.test" } }]
      : [{ frameId: 0, documentId: "route-doc", result: { top: true, origin: "chrome-extension://fixed" } }];
  h.api.tabs.create = (options) => {
    // `options` crosses the vm realm boundary, so compare fields, not identity.
    assert.equal(options.active, true);
    assert.equal(
      options.url,
      "chrome-extension://fixed/popup.html#route=" + h.routeToken(options.url),
    );
    // Browser ordering: activation and the initial load of the new route tab
    // arrive before tabs.create resolves.
    sourceTab = { ...sourceTab, active: false };
    routeTab = { id: ROUTE_TAB, windowId: sourceTab.windowId, active: true, url: options.url };
    h.listeners.active({ tabId: ROUTE_TAB, windowId: sourceTab.windowId });
    h.listeners.updated(ROUTE_TAB, { status: "loading" });
    h.listeners.updated(ROUTE_TAB, { url: options.url });
    return { id: ROUTE_TAB, windowId: sourceTab.windowId, status: "loading" };
  };
  // An ordinary (non-QuickFill) click asks for a route, never a popup read.
  const reply = await h.send({ type: "open-route", id: ITEM_ID, revision: ITEM_REV });
  assert.ok(reply?.routeCreated, "route was refused: " + reply?.status);
  assert.equal(reply.routeCreated.token.length, 64);
  assert.equal(h.sent.filter((r) => r.type === "item-get").length, 0);
  // The route's own startup must not have advanced the captured epoch.
  assert.equal(await h.send({ type: "state" }).then((s) => s.candidates.length), 1);
  h.listeners.updated(ROUTE_TAB, { status: "complete" });
  // The route tab is now the active tab; the source is still open, exact and
  // inactive.
  assert.equal(routeTab.active, true);
  assert.equal(sourceTab.active, false);
  assert.equal(sourceTab.url, "https://example.test/login");
  const routeSender = ({ url = routeTab.url, tabId = ROUTE_TAB } = {}) => ({
    id: "fixed",
    url,
    origin: "chrome-extension://fixed",
    frameId: 0,
    documentId: "route-doc",
    tab: { id: tabId, url, windowId: 1 },
  });
  const refused = (reply) =>
    !reply || (reply.error === "refused" && reply.detail === undefined);
  const nativeReads = () =>
    h.sent.filter((r) => r.type === "vault-search" || r.type === "item-get");

  // Exact token: any other token is refused before a native read.
  assert.ok(refused(await h.send({ type: "route-claim", token: "e".repeat(64) }, routeSender())));
  // Exact sender tab and URL: another tab id is refused.
  assert.ok(refused(
    await h.send(
      { type: "route-claim", token: reply.routeCreated.token },
      routeSender({ tabId: 99 }),
    ),
  ));
  // Exact route URL: a different fragment is refused.
  assert.ok(refused(
    await h.send(
      { type: "route-claim", token: reply.routeCreated.token },
      routeSender({ url: "chrome-extension://fixed/popup.html#route=" + "d".repeat(64) }),
    ),
  ));
  assert.equal(nativeReads().length, 0, "refusals must not reach the native host");

  // --- the two state issues, isolated from the later response-shape fix ---
  // (a) routeClaim() moves the grant to `claimed` and then starts the approved
  // read, so routeLive() must accept exactly `open` and `claimed`; anything
  // else is refused before any native read. This evaluates the real
  // routeLive() text from background.js.
  const liveRoute = await waitForSource("function routeLive(grant) {");
  const routeLife = (state, { registered = true } = {}) => {
    const token = "f".repeat(64);
    const grant = {
      token,
      tabId: ROUTE_TAB,
      state,
      epoch: 3,
      capability: "a".repeat(32),
      expiresAt: Date.now() + 60000,
    };
    const grants = new Map(registered ? [[token, grant]] : []);
    const tabs = new Map([[ROUTE_TAB, grant]]);
    const live = new Function(
      "routeGrants", "routeTabs", "capability", "epoch", "Date",
      '"use strict";' + liveRoute + "\nreturn routeLive;",
    );
    return live(grants, tabs, grant.capability, 3, Date)(grant);
  };
  assert.equal(routeLife("open"), true);
  assert.equal(routeLife("claimed"), true, "a claimed grant must stay live for its read");
  assert.equal(routeLife("revoked"), false);
  assert.equal(routeLife("claimed", { registered: false }), false);

  // (b) Only the route tab must be active. The captured source is inactive
  // because the route tab was activated, but it is still the same tab in the
  // same window at the same URL.
  const anchorsSource = await waitForSource("async function routeAnchors(grant) {");
  const anchors = (routeAnchor, sourceAnchor) =>
    new Function(
      "routeTabAt", "routeSourceAt", "epoch", "capability", "Date",
      '"use strict";' + anchorsSource + "\nreturn routeAnchors;",
    )(
      async () => routeAnchor,
      async () => sourceAnchor,
      3,
      "a".repeat(32),
      Date,
    )({ tabId: ROUTE_TAB, windowId: 1, routeURL: "u", source: {}, epoch: 3, capability: "a".repeat(32) });
  const routeAnchor = { id: ROUTE_TAB, windowId: 1, active: true, url: "u" };
  const sourceAnchor = { id: 1, windowId: 1, active: false, url: "https://example.test/login" };
  assert.equal(await anchors(routeAnchor, sourceAnchor), true, "inactive source is fine");
  assert.equal(await anchors({ ...routeAnchor, active: false }, sourceAnchor), false);
  assert.equal(await anchors(routeAnchor, null), false);

  // The claim that started the approved native read completes and returns the
  // target detail, in order: fresh search, then the exact item-get.
  const claim = await h.send(
    { type: "route-claim", token: reply.routeCreated.token },
    routeSender(),
  );
  assert.deepEqual(nativeReads().map((r) => r.type), ["vault-search", "item-get"]);
  const read = nativeReads()[1];
  assert.equal(read.item_id, ITEM_ID);
  assert.equal(read.revision, ITEM_REV);
  assert.equal(claim?.detail?.id, ITEM_ID);
  assert.equal(claim.detail.revision, ITEM_REV);
  assert.equal(claim.detail.title, "Target");
  assert.equal(claim.detail.username, "ada");

  // Switching to a different ordinary tab still cancels and revokes.
  h.listeners.active({ tabId: 2, windowId: 1 });
  assert.equal(await h.send({ type: "state" }).then((s) => s.candidates.length), 0);
  assert.ok(refused(
    await h.send(
      { type: "route-claim", token: reply.routeCreated.token },
      routeSender(),
    ),
  ));
  await h.send({ type: "disconnect" });
});

// One ordinary route in front of a captured source tab. The source tab's
// state is the browser's, re-read through tabs.get on every check; tests move
// it to prove a route dies with its source page.
async function openRouteFixture() {
  const ROUTE_TAB = 7;
  const ITEM_ID = "b".repeat(32);
  const ITEM_REV = "c".repeat(64);
  let sourceTab = null;
  let routeTab = null;
  const h = harness({
    onRequest: (r) => {
      if (r.type === "vault-search")
        return {
          v: 1, id: r.id, type: "items", vaults: [],
          items: [{ id: ITEM_ID, revision: ITEM_REV, category: "login", title: "Target" }],
        };
      if (r.type === "item-get")
        return {
          v: 1, id: r.id, type: "item-detail",
          item: {
            id: ITEM_ID, revision: ITEM_REV, category: "login", title: "Target",
            username: "ada", has_password: true,
          },
        };
      return undefined;
    },
  });
  await ready(h);
  sourceTab = { id: 1, windowId: 1, active: true, url: "https://example.test/login" };
  h.api.tabs.get = async (tabId) =>
    tabId === sourceTab.id ? { ...sourceTab } : tabId === ROUTE_TAB && routeTab ? { ...routeTab } : null;
  h.api.scripting.executeScript = async (options) =>
    options.target.tabId === sourceTab.id
      ? [{ frameId: 0, documentId: h.docId(), result: { top: true, origin: "https://example.test" } }]
      : [{ frameId: 0, documentId: "route-doc", result: { top: true, origin: "chrome-extension://fixed" } }];
  h.api.tabs.create = (options) => {
    sourceTab = { ...sourceTab, active: false };
    routeTab = { id: ROUTE_TAB, windowId: sourceTab.windowId, active: true, url: options.url };
    h.listeners.active({ tabId: ROUTE_TAB, windowId: sourceTab.windowId });
    h.listeners.updated(ROUTE_TAB, { status: "loading" });
    h.listeners.updated(ROUTE_TAB, { url: options.url });
    return { id: ROUTE_TAB, windowId: sourceTab.windowId, status: "loading" };
  };
  const reply = await h.send({ type: "open-route", id: ITEM_ID, revision: ITEM_REV });
  assert.ok(reply?.routeCreated, "route was refused: " + reply?.status);
  h.listeners.updated(ROUTE_TAB, { status: "complete" });
  return {
    h,
    token: reply.routeCreated.token,
    ITEM_ID,
    ITEM_REV,
    source: () => ({ ...sourceTab }),
    setSource(next) {
      sourceTab = { ...sourceTab, ...next };
    },
    claim: () =>
      h.send(
        { type: "route-claim", token: reply.routeCreated.token },
        {
          id: "fixed",
          url: routeTab.url,
          origin: "chrome-extension://fixed",
          frameId: 0,
          documentId: "route-doc",
          tab: { id: ROUTE_TAB, url: routeTab.url, windowId: 1 },
        },
      ),
    nativeReads: () => h.sent.filter((r) => r.type === "vault-search" || r.type === "item-get"),
  };
}

test("a same-origin source URL change revokes the open route", async () => {
  const route = await openRouteFixture();
  assert.equal(route.nativeReads().length, 0, "opening a route reads nothing");
  // Same tab, same window, same HTTPS origin: only the path changed. The
  // browser's re-read must compare the exact captured URL, not just origin.
  route.setSource({ url: "https://example.test/account/settings" });
  const claim = await route.claim();
  assert.ok(!claim || claim.error === "refused", "route survived a source URL change");
  assert.equal(claim?.detail, undefined);
  assert.equal(route.nativeReads().length, 0, "no native read after the source changed");
  await route.h.send({ type: "disconnect" });
});

test("a same-URL source reload revokes the open route", async () => {
  const route = await openRouteFixture();
  // A reload or document replacement keeps the URL but starts a new load.
  route.h.listeners.updated(1, { status: "loading" });
  const claim = await route.claim();
  assert.ok(!claim || claim.error === "refused", "route survived a source reload");
  assert.equal(claim?.detail, undefined);
  assert.equal(route.nativeReads().length, 0, "no native read after the source reloaded");
  await route.h.send({ type: "disconnect" });
});

test("source navigation events revoke the route itself", async () => {
  // The route-local handler, evaluated from the real background.js text with
  // only route state: a same-origin URL change and a same-URL load must both
  // end the grant, independent of the popup context lifecycle.
  const sourceUpdate = await waitForSource("function routeSourceUpdated(tabId, change) {");
  const updates = (change) => {
    const token = "f".repeat(64);
    const grant = {
      token,
      tabId: 7,
      source: { tabId: 1, windowId: 1, origin: "https://example.test", url: "https://example.test/login" },
      epoch: 3,
      capability: "a".repeat(32),
      expiresAt: Date.now() + 60000,
    };
    const revoked = [];
    const run = new Function(
      "routeGrants", "routeTabs", "core", "revokeRoute",
      '"use strict";' + sourceUpdate +
        "\nreturn routeSourceUpdated;",
    );
    run(
      new Map([[token, grant]]),
      new Map([[7, grant]]),
      core,
      (candidate) => revoked.push(candidate.token),
    )(1, change);
    return revoked.length;
  };
  assert.equal(updates({ url: "https://example.test/account/settings" }), 1);
  assert.equal(updates({ status: "loading" }), 1);
  assert.equal(updates({ status: "complete" }), 0);
});

test("page sender cannot connect or choose a field", async () => {
  const h = harness();
  assert.equal(
    await h.send(
      { type: "connect" },
      { id: "fixed", url: "https://example.test", tab: { id: 1 } },
    ),
    undefined,
  );
  assert.equal(h.sent.length, 0);
});
test("missing document identity fails closed", async () => {
  const h = harness();
  h.setDoc(undefined);
  await h.send({ type: "connect" });
  await tick();
  await h.send({ type: "match" });
  assert.equal(h.sent.filter((x) => x.type === "match").length, 0);
  await h.send({ type: "disconnect" });
});
test("native values require fresh tab and document; never retarget navigation", async () => {
  for (const navigate of [false, true]) {
    const h = harness();
    await ready(h);
    await h.send({
      type: "fill",
      id: "b".repeat(32),
      revision: "c".repeat(64),
    });
    await tick();
    const fill = h.sent.find((x) => x.type === "fill");
    assert.ok(fill);
    if (navigate) {
      h.setDoc("doc-2");
      h.listeners.updated(1, { status: "loading" });
    }
    h.deliver({
      v: 1,
      id: fill.id,
      type: "fill",
      username: "fixture-user",
      password: "fixture-password",
    });
    await tick();
    await tick();
    assert.equal(h.injected.length, navigate ? 0 : 1);
    if (!navigate) {
      assert.equal(h.injected[0].target.documentIds[0], "doc-1");
      assert.equal(h.injected[0].target.tabId, 1);
    }
    await h.send({ type: "disconnect" });
  }
});
test("duplicate popup fill clicks create only one pending request", async () => {
  const h = harness();
  await ready(h);
  await Promise.all([
    h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) }),
    h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) }),
  ]);
  await tick();
  assert.equal(h.sent.filter((x) => x.type === "fill").length, 1);
  await h.send({ type: "disconnect" });
});
test("lock status survives late fill rejection and requires fresh pairing", async () => {
  const h = harness();
  await ready(h);
  await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
  await tick();
  h.deliver({ v: 1, type: "locked" });
  await tick();
  await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, false);
  assert.match(state.status, /锁定/);
  assert.equal(h.injected.length, 0);
  await h.send({ type: "disconnect" });
});
test("late fill completion cannot clear a newly matched context", async () => {
  const h = harness();
  await ready(h);
  await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
  await tick();
  const fill = h.sent.find((x) => x.type === "fill");
  h.listeners.active();
  await h.send({ type: "match" });
  h.deliver({ v: 1, id: fill.id, type: "error", error: "refused" });
  await tick();
  await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.candidates.length, 1);
  assert.equal(state.origin, "https://example.test");
  await h.send({ type: "disconnect" });
});
test("capability expiry clears candidates and survives late refusal", async () => {
  const h = harness();
  await ready(h);
  await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
  await tick();
  const fill = h.sent.find((x) => x.type === "fill");
  h.deliver({ v: 1, type: "unpaired", error: "expired" });
  h.deliver({ v: 1, id: fill.id, type: "error", error: "refused" });
  await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, false);
  assert.equal(state.candidates.length, 0);
  assert.match(state.status, /到期/);
  await h.send({ type: "disconnect" });
});
test("unrelated tab navigation cannot cancel a pending fill", async () => {
  const h = harness();
  await ready(h);
  await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
  await tick();
  h.listeners.updated(200, { status: "loading" });
  const state = await h.send({ type: "state" });
  assert.equal(state.pending, true);
  assert.equal(h.sent.filter((r) => r.type === "cancel").length, 0);
  await h.send({ type: "disconnect" });
});

test("received fields are released when a browser API hangs, on lock and deadline", async () => {
  for (const lock of [true, false]) {
    const h = harness();
    await ready(h);
    await h.send({
      type: "fill",
      id: "b".repeat(32),
      revision: "c".repeat(64),
    });
    await tick();
    const request = h.sent.find((r) => r.type === "fill");
    h.hangProbe();
    const values = {
      v: 1,
      id: request.id,
      type: "fill",
      username: "fixture-user",
      password: "fixture-password",
    };
    h.deliver(values);
    await tick();
    if (lock) h.deliver({ v: 1, type: "locked" });
    else await new Promise((resolve) => setTimeout(resolve, 1700));
    await tick();
    await tick();
    assert.ok(
      values.username === "" && values.password === "",
      "received fields retained by hung API",
    );
    assert.equal(h.injected.length, 0);
    await h.send({ type: "disconnect" });
  }
});
test("failed refresh cannot resurrect previous candidates on state polling", async () => {
  const h = harness();
  await ready(h);
  h.setDoc(undefined);
  await h.send({ type: "match" });
  const state = await h.send({ type: "state" });
  assert.equal(state.candidates.length, 0);
  assert.equal(state.origin, "");
  await h.send({ type: "disconnect" });
});

async function saveRequest(h) {
  await h.send({ type: "save-new" });
  for (let i = 0; i < 8; i++) await tick();
  const r = h.sent.find((r) => r.type === "save-new");
  assert.ok(r, "save request not sent");
  return r;
}
test("save capture stays private and two-RPC challenge commits only the same window/document", async () => {
  const h = harness();
  await h.send({ type: "connect" });
  await tick();
  const r = await saveRequest(h);
  assert.equal(r.window_id, 1);
  assert.equal(r.username, "save-user");
  assert.equal(r.password, "save-password");
  const state = await h.send({ type: "state" });
  assert.ok(!JSON.stringify(state).includes("save-password"));
  assert.equal(h.captured[0].password, "");
  assert.equal(h.sent.filter((r) => r.type === "commit-ready").length, 0);
  h.deliver({ v: 1, id: r.id, type: "save-ready", nonce: "f".repeat(64) });
  for (let i = 0; i < 8; i++) await tick();
  const commit = h.sent.find((r) => r.type === "commit-ready");
  assert.ok(commit);
  assert.equal(commit.request_id, r.id);
  assert.notEqual(commit.id, r.id);
  assert.equal((await h.send({ type: "state" })).status, "已保存");
  await h.send({ type: "disconnect" });
});
test("save-new without prior match cancels on a different window; same window and native focus are allowed", async () => {
  const h = harness();
  await h.send({ type: "connect" });
  await tick();
  const r = await saveRequest(h);
  h.listeners.focus(-1);
  h.listeners.focus(1);
  assert.equal((await h.send({ type: "state" })).pending, true);
  h.setWindow(2);
  h.listeners.focus(2);
  await tick();
  assert.ok(
    h.sent.find((q) => q.type === "cancel-save" && q.request_id === r.id),
  );
  assert.equal(h.sent.filter((q) => q.type === "commit-ready").length, 0);
  await h.send({ type: "disconnect" });
});
test("late capture after navigation is cleared and never sent", async () => {
  const h = harness();
  let release;
  const deferred = new Promise((resolve) => (release = resolve));
  h.waitCapture(deferred);
  await h.send({ type: "connect" });
  await tick();
  await h.send({ type: "save-new" });
  for (let i = 0; i < 5; i++) await tick();
  h.listeners.active();
  const result = { username: "late-user", password: "late-password" };
  release([{ frameId: 0, documentId: "doc-1", result }]);
  for (let i = 0; i < 6; i++) await tick();
  assert.equal(result.username, "");
  assert.equal(result.password, "");
  assert.equal(h.sent.filter((q) => q.type === "save-new").length, 0);
  await h.send({ type: "disconnect" });
});

test("save-ready itself rechecks stale document/window even without navigation events", async () => {
  for (const kind of ["document", "window"]) {
    const h = harness();
    await h.send({ type: "connect" });
    await tick();
    const r = await saveRequest(h);
    if (kind === "document") h.setDoc("doc-2");
    else h.setWindow(2);
    h.deliver({ v: 1, id: r.id, type: "save-ready", nonce: "f".repeat(64) });
    for (let i = 0; i < 8; i++) await tick();
    assert.equal(h.sent.filter((q) => q.type === "commit-ready").length, 0);
    assert.equal((await h.send({ type: "state" })).status, "未保存");
    await h.send({ type: "disconnect" });
  }
});
test("hung final probe expires without sending commit-ready", async () => {
  const h = harness();
  await h.send({ type: "connect" });
  await tick();
  const r = await saveRequest(h);
  h.hangProbe();
  h.deliver({ v: 1, id: r.id, type: "save-ready", nonce: "f".repeat(64) });
  await new Promise((resolve) => setTimeout(resolve, 1700));
  assert.equal(h.sent.filter((q) => q.type === "commit-ready").length, 0);
  assert.ok(
    h.sent.find((q) => q.type === "cancel-save" && q.request_id === r.id),
  );
  await h.send({ type: "disconnect" });
});
async function committingSave(h) {
  h.holdCommits();
  await h.send({ type: "connect" });
  await tick();
  const r = await saveRequest(h);
  h.deliver({ v: 1, id: r.id, type: "save-ready", nonce: "f".repeat(64) });
  for (let i = 0; i < 8; i++) await tick();
  const commit = h.sent.find((q) => q.type === "commit-ready");
  assert.ok(commit);
  return commit;
}
for (const reason of [
  "lock",
  "disconnect",
  "manual",
  "timeout",
  "protocol",
  "unknown",
]) {
  test(
    "connection clear after commit preserves unknown: " + reason,
    async () => {
      const h = harness();
      const commit = await committingSave(h);
      if (reason === "lock") h.deliver({ v: 1, type: "locked" });
      if (reason === "disconnect") h.losePort();
      if (reason === "manual") await h.send({ type: "disconnect" });
      if (reason === "timeout") h.expireCommit();
      if (reason === "protocol") h.deliver({ v: 2, type: "locked" });
      if (reason === "unknown")
        h.deliver({ v: 1, id: commit.id, type: "unknown" });
      for (let i = 0; i < 4; i++) await tick();
      assert.match(
        (await h.send({ type: "state" })).status,
        /结果未确认/,
        reason,
      );
      assert.equal(h.sent.filter((q) => q.type === "commit-ready").length, 1);
      await h.send({ type: "disconnect" });
    },
  );
}
test("old save finalizer after disconnect cannot overwrite newly paired candidates", async () => {
  const h = harness();
  await committingSave(h);
  h.losePort();
  await h.send({ type: "connect" });
  await tick();
  await h.send({ type: "match" });
  for (let i = 0; i < 5; i++) await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.candidates.length, 1);
  assert.match(state.status, /1 个/);
  await h.send({ type: "disconnect" });
});

test("unknown survives navigation followed by all later invalidation events", async () => {
  for (const reason of ["lock", "expiry", "disconnect"]) {
    const h = harness();
    const commit = await committingSave(h);
    h.listeners.active();
    await tick();
    if (reason === "lock") h.deliver({ v: 1, type: "locked" });
    if (reason === "expiry")
      h.deliver({ v: 1, type: "unpaired", error: "expired" });
    if (reason === "disconnect") h.losePort();
    for (let i = 0; i < 4; i++) await tick();
    assert.match(
      (await h.send({ type: "state" })).status,
      /结果未确认/,
      reason,
    );
    h.deliver({
      v: 1,
      id: commit.id,
      type: "saved",
      item_id: "d".repeat(32),
      revision: "e".repeat(64),
    });
    await tick();
    assert.match((await h.send({ type: "state" })).status, /结果未确认/);
    await h.send({ type: "disconnect" });
  }
});
test("unknown blocks further save clicks but preserves candidate reads until explicit reconnect", async () => {
  const h = harness();
  const commit = await committingSave(h);
  h.deliver({ v: 1, id: commit.id, type: "unknown" });
  for (let i = 0; i < 4; i++) await tick();
  assert.equal((await h.send({ type: "state" })).saveBlocked, true);
  await h.send({ type: "match" });
  assert.equal((await h.send({ type: "state" })).candidates.length, 1);
  await h.send({ type: "save-new" });
  await h.send({
    type: "save-update",
    id: "b".repeat(32),
    revision: "c".repeat(64),
  });
  await tick();
  const blocked = await h.send({ type: "state" });
  assert.equal(blocked.saveBlocked, true);
  assert.match(blocked.status, /结果未确认/);
  assert.equal(h.sent.filter((q) => q.type === "save-new").length, 1);
  assert.equal(h.sent.filter((q) => q.type === "save-update").length, 0);
  await h.send({ type: "connect" });
  await tick();
  assert.equal((await h.send({ type: "state" })).saveBlocked, false);
  await h.send({ type: "disconnect" });
});
test("confirmed transaction refusal clears uncertainty and reports unsaved", async () => {
  const h = harness();
  const commit = await committingSave(h);
  h.deliver({ v: 1, id: commit.id, type: "error", error: "refused" });
  for (let i = 0; i < 4; i++) await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.status, "未保存");
  assert.equal(state.saveBlocked, false);
  await h.send({ type: "disconnect" });
});

const otpChoice = { type: "otp", id: "b".repeat(32), revision: "c".repeat(64) };
async function otpReady(h) {
  await ready(h);
  await h.send(otpChoice);
  await tick();
  await tick();
  const original = h.sent.find((x) => x.type === "otp");
  assert.ok(original, "OTP intent missing");
  return original;
}
test("OTP probe scripting args reach the native request through the JSON transport", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    assert.ok(original, "native OTP approval must be requested after a probe");
    assert.ok(h.otpProbes.length >= 1);
    for (const args of h.otpProbes) {
      // Chrome serializes undefined array entries as null: no undefined may
      // remain in the args the injected probe receives.
      const transported = JSON.parse(JSON.stringify(args));
      assert.deepEqual(transported.slice(0, 2), ["https://example.test", "probe"]);
      assert.equal(transported[2], null);
      assert.equal(transported[3], null);
      assert.equal(transported[4], false);
      assert.equal(JSON.stringify(args).includes("undefined"), false);
    }
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("OTP has distinct O/A, metadata-only ready, fixed document and no popup code", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    assert.equal(original.window_id, 1);
    assert.equal(original.document_id, "doc-1");
    assert.equal("nonce" in original || "request_id" in original, false);
    await h.send(otpChoice);
    await h.send({
      type: "fill",
      id: otpChoice.id,
      revision: otpChoice.revision,
    });
    assert.equal(
      h.sent.filter((x) => ["otp", "fill"].includes(x.type)).length,
      1,
    );
    h.deliver({
      v: 1,
      id: original.id,
      type: "otp-ready",
      nonce: "d".repeat(64),
    });
    await tick();
    await tick();
    const ack = h.sent.find((x) => x.type === "otp-ack");
    assert.ok(ack);
    assert.notEqual(ack.id, original.id);
    assert.equal(
      Object.keys(ack).sort().join(","),
      "capability,id,nonce,request_id,type,v",
    );
    assert.equal(ack.request_id, original.id);
    const reply = { v: 1, id: ack.id, type: "otp-fill", code: "012345" };
    h.deliver(reply);
    await tick();
    await tick();
    const injected = h.injected.find((x) => x.func === core.otpDocument);
    assert.ok(injected);
    assert.equal(injected.target.documentIds[0], "doc-1");
    assert.equal(injected.args[1], "fill");
    assert.equal(reply.code, "");
    assert.equal(
      JSON.stringify(await h.send({ type: "state" })).includes("012345"),
      false,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("OTP ready keeps O for targeted cancellation and rejects navigation before ack", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    h.holdOTPProbe(new Promise(() => {}));
    h.deliver({
      v: 1,
      id: original.id,
      type: "otp-ready",
      nonce: "d".repeat(64),
    });
    await tick();
    h.listeners.updated(1, { status: "loading" });
    await tick();
    const cancel = h.sent.find((x) => x.type === "cancel-otp");
    assert.ok(cancel);
    assert.equal(cancel.request_id, original.id);
    assert.notEqual(cancel.id, original.id);
    assert.equal("nonce" in cancel, false);
    assert.equal(
      h.sent.some((x) => x.type === "otp-ack"),
      false,
    );
    assert.equal(
      h.injected.some((x) => x.func === core.otpDocument),
      false,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("OTP original monotonic budget is not reopened on code reply", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    h.deliver({
      v: 1,
      id: original.id,
      type: "otp-ready",
      nonce: "d".repeat(64),
    });
    await tick();
    await tick();
    const ack = h.sent.find((x) => x.type === "otp-ack");
    assert.ok(ack);
    h.advanceOTPClock(1501);
    const reply = { v: 1, id: ack.id, type: "otp-fill", code: "01234567" };
    h.deliver(reply);
    await tick();
    await tick();
    assert.equal(
      h.injected.some((x) => x.func === core.otpDocument),
      false,
    );
    assert.equal(reply.code, "");
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("OTP explicit cancel and lock never inject a late native code", async () => {
  for (const stop of ["cancel-otp", "locked"]) {
    const h = harness();
    try {
      const original = await otpReady(h);
      h.deliver({
        v: 1,
        id: original.id,
        type: "otp-ready",
        nonce: "d".repeat(64),
      });
      await tick();
      await tick();
      const ack = h.sent.find((x) => x.type === "otp-ack");
      assert.ok(ack);
      if (stop === "locked") h.deliver({ v: 1, type: "locked" });
      else await h.send({ type: "cancel-otp" });
      const reply = { v: 1, id: ack.id, type: "otp-fill", code: "012345" };
      h.deliver(reply);
      await tick();
      await tick();
      assert.equal(
        h.injected.some((x) => x.func === core.otpDocument),
        false,
      );
      assert.equal(reply.code, "");
    } finally {
      await h.send({ type: "disconnect" });
    }
  }
});

test("cancel after injection starts cannot claim DOM cancellation even when C is cancelled", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    h.deliver({
      v: 1,
      id: original.id,
      type: "otp-ready",
      nonce: "d".repeat(64),
    });
    await tick();
    await tick();
    const ack = h.sent.find((x) => x.type === "otp-ack");
    h.holdOTPFill(new Promise(() => {}));
    h.deliver({ v: 1, id: ack.id, type: "otp-fill", code: "012345" });
    await tick();
    await tick();
    assert.equal(
      h.injected.some((x) => x.func === core.otpDocument),
      true,
    );
    await h.send({ type: "cancel-otp" });
    await tick();
    await tick();
    assert.equal(
      (await h.send({ type: "state" })).status.includes("未确认"),
      true,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("C unknown cannot be represented as confirmed cancellation", async () => {
  const h = harness();
  try {
    await otpReady(h);
    h.otpCancelResult("unknown");
    await h.send({ type: "cancel-otp" });
    await tick();
    await tick();
    assert.equal(
      (await h.send({ type: "state" })).status.includes("未确认"),
      true,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("ACK uncertainty survives disconnect, timeout, lock and a new explicit OTP operation", async () => {
  for (const stop of ["manual", "disconnect", "locked", "timeout"]) {
    const h = harness();
    try {
      const original = await otpReady(h);
      h.deliver({
        v: 1,
        id: original.id,
        type: "otp-ready",
        nonce: "d".repeat(64),
      });
      await tick();
      await tick();
      const ack = h.sent.find((x) => x.type === "otp-ack");
      assert.ok(ack);
      if (stop === "manual") await h.send({ type: "disconnect" });
      else if (stop === "disconnect") h.losePort();
      else if (stop === "locked") h.deliver({ v: 1, type: "locked" });
      else h.expireOTP();
      await tick();
      await tick();
      assert.equal(
        (await h.send({ type: "state" })).status.includes("未确认"),
        true,
      );
      const late = { v: 1, id: ack.id, type: "otp-fill", code: "012345" };
      h.deliver(late);
      await tick();
      assert.equal(late.code, "");
      assert.equal(
        h.injected.some((x) => x.func === core.otpDocument),
        false,
      );
      await ready(h);
      await h.send(otpChoice);
      await tick();
      await tick();
      assert.equal(h.sent.filter((x) => x.type === "otp").length, 2);
      assert.equal((await h.send({ type: "state" })).otpPending, true);
    } finally {
      await h.send({ type: "disconnect" });
    }
  }
});
test("reconnection before an explicit new O preserves OTP uncertainty", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    h.deliver({
      v: 1,
      id: original.id,
      type: "otp-ready",
      nonce: "d".repeat(64),
    });
    await tick();
    await tick();
    assert.ok(h.sent.find((x) => x.type === "otp-ack"));
    h.losePort();
    await tick();
    await ready(h);
    assert.equal(
      (await h.send({ type: "state" })).status.includes("未确认"),
      true,
    );
    await h.send(otpChoice);
    await tick();
    assert.equal(
      (await h.send({ type: "state" })).status.includes("未确认"),
      false,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("ACK local bounded timeout before RPC timeout stays unknown", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    h.deliver({
      v: 1,
      id: original.id,
      type: "otp-ready",
      nonce: "d".repeat(64),
    });
    await tick();
    await tick();
    assert.ok(h.sent.find((x) => x.type === "otp-ack"));
    h.expireOTPBounded();
    await tick();
    await tick();
    assert.equal(
      (await h.send({ type: "state" })).status.includes("未确认"),
      true,
    );
    h.expireOTP();
    await tick();
    assert.equal(
      (await h.send({ type: "state" })).status.includes("未确认"),
      true,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("definite native ACK refusal remains a refusal without a code injection", async () => {
  const h = harness();
  try {
    const original = await otpReady(h);
    h.deliver({
      v: 1,
      id: original.id,
      type: "otp-ready",
      nonce: "d".repeat(64),
    });
    await tick();
    await tick();
    const ack = h.sent.find((x) => x.type === "otp-ack");
    h.deliver({ v: 1, id: ack.id, type: "error", error: "refused" });
    await tick();
    await tick();
    const state = await h.send({ type: "state" });
    assert.equal(state.status.includes("拒绝"), true);
    assert.equal(state.status.includes("未确认"), false);
    assert.equal(
      h.injected.some((x) => x.func === core.otpDocument),
      false,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});

async function beginAfterOTPCancel(h, kind) {
  await otpReady(h);
  h.holdOTPCancel();
  await h.send({ type: "cancel-otp" });
  await tick();
  const cancel = h.sent.find((request) => request.type === "cancel-otp");
  if (kind === "fill") {
    await h.send({ type: "match" });
    await h.send({
      type: "fill",
      id: otpChoice.id,
      revision: otpChoice.revision,
    });
  } else await h.send({ type: "save-new" });
  await tick();
  await tick();
  const before = await h.send({ type: "state" });
  assert.equal(before.pending, true);
  return { cancel, before };
}
test("late OTP C outcome updates its fact without replacing a new ordinary save or fill status", async () => {
  for (const kind of ["save-new", "fill"])
    for (const result of ["cancelled", "unknown", "error"]) {
      const h = harness();
      try {
        const { cancel, before } = await beginAfterOTPCancel(h, kind);
        h.deliver({
          v: 1,
          id: cancel.id,
          type: result,
          ...(result === "error" ? { error: "refused" } : {}),
        });
        await tick();
        await tick();
        const after = await h.send({ type: "state" });
        assert.equal(after.pending, true);
        assert.equal(after.status.includes("本次验证码填充已取消"), false);
        assert.equal(
          after.status.split(" · ")[0],
          before.status.split(" · ")[0],
        );
        assert.equal(
          after.status.includes("验证码填充结果未确认"),
          result !== "cancelled",
        );
      } finally {
        await h.send({ type: "disconnect" });
      }
    }
});
test("lost OTP C response preserves the later ordinary save status, then disconnect remains unknown", async () => {
  const h = harness();
  try {
    const { before } = await beginAfterOTPCancel(h, "save-new");
    await tick();
    await tick();
    const waiting = await h.send({ type: "state" });
    assert.equal(waiting.status, before.status);
    assert.equal(waiting.status.includes("验证码填充结果未确认"), true);
    h.losePort();
    await tick();
    await tick();
    const disconnected = await h.send({ type: "state" });
    assert.equal(disconnected.status.includes("验证码填充结果未确认"), true);
    assert.equal(disconnected.status.includes("本次验证码填充已取消"), false);
  } finally {
    await h.send({ type: "disconnect" });
  }
});

const contentSender = (doc = "doc-1", frame = 0) => ({
  id: "fixed",
  url: "https://example.test/login",
  documentId: doc,
  frameId: frame,
  tab: { id: 1, windowId: 1, url: "https://example.test/login" },
});
test("inline channel is bound to browser sender document and cannot connect", async () => {
  const h = harness();
  await ready(h);
  const linked = await h.send({ type: "inline-match" }, contentSender());
  assert.equal(linked.candidates.length, 1);
  assert.equal(linked.siteLinked, true);
  for (const sender of [contentSender("old-doc"), contentSender("doc-1", 2)]) {
    const before = h.sent.length;
    await h.send(
      { type: "inline-fill", id: "b".repeat(32), revision: "c".repeat(64) },
      sender,
    );
    assert.equal(h.sent.length, before);
  }
  const before = h.sent.length;
  await h.send({ type: "connect" }, contentSender());
  assert.equal(h.sent.length, before);
});
test("inline site-link metadata stays unknown when no login match ran", async () => {
  const h = harness();
  await ready(h);
  const identity = await h.send(
    { type: "inline-match", category: "identity" },
    contentSender(),
  );
  assert.equal(identity.siteLinked, null);
  await h.send({ type: "disconnect" });
  const disconnected = await h.send({ type: "inline-match" }, contentSender());
  assert.equal(disconnected.connected, false);
  assert.equal(disconnected.siteLinked, null);
  assert.equal(disconnected.candidates.length, 0);
});
test("two-factor setup capture is document-bound and saves through item-edit", async () => {
  const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const otpauth = "otpauth://totp/ACME:john?secret=" + secret;
  const h = harness({
    onRequest: (r) => {
      if (r.type === "item-save")
        return {
          v: 1,
          id: r.id,
          type: "item-saved",
          item_id: r.item_id,
          revision: "f".repeat(64),
        };
    },
  });
  await ready(h);
  const captured = await h.send(
    { type: "inline-otp-capture", otpauth },
    contentSender(),
  );
  assert.equal(captured.ok, true);
  assert.equal(captured.label, "ACME · john");
  assert.equal(captured.items.length, 1);
  assert.equal(captured.items[0].id, "b".repeat(32));
  assert.equal(
    JSON.stringify(captured).includes(secret),
    false,
    "the seed must not return to the page",
  );

  h.setDoc("doc-2");
  const foreignDocument = await h.send(
    { type: "inline-otp-save", captureId: captured.captureId, itemId: "b".repeat(32) },
    contentSender("doc-2"),
  );
  assert.equal(foreignDocument.ok, false);
  h.setDoc("doc-1");
  const foreignItem = await h.send(
    { type: "inline-otp-save", captureId: captured.captureId, itemId: "d".repeat(32) },
    contentSender(),
  );
  assert.equal(foreignItem.ok, false);
  assert.equal(
    h.sent.some((r) => r.type === "item-save"),
    false,
    "a refused owner must not write",
  );

  const saved = await h.send(
    { type: "inline-otp-save", captureId: captured.captureId, itemId: "b".repeat(32) },
    contentSender(),
  );
  assert.equal(saved.ok, true, JSON.stringify(saved));
  assert.equal(saved.revision, "f".repeat(64));
  const edit = h.sent.find((r) => r.type === "item-save");
  assert.equal(edit.item_id, "b".repeat(32));
  assert.equal(edit.revision, "c".repeat(64));
  assert.deepEqual(JSON.parse(edit.item_json), {
    title: "Fixture",
    category: "login",
    otp: otpauth,
  });

  const replay = await h.send(
    { type: "inline-otp-save", captureId: captured.captureId, itemId: "b".repeat(32) },
    contentSender(),
  );
  assert.equal(replay.ok, false, "a capture is single use");
  assert.equal(h.sent.filter((r) => r.type === "item-save").length, 1);
});

test("two-factor capture needs a connected host and a matching login", async () => {
  const otpauth =
    "otpauth://totp/ACME:john?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  const h = harness();
  const disconnected = await h.send(
    { type: "inline-otp-capture", otpauth },
    contentSender(),
  );
  assert.equal(disconnected.ok, false);
  assert.equal(disconnected.reason, "busy");
  await ready(h);
  const invalid = await h.send(
    { type: "inline-otp-capture", otpauth: "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP" },
    contentSender(),
  );
  assert.equal(invalid.ok, false);
  assert.equal(invalid.reason, "invalid");
});

test("passkey uses authenticated sender origin and cancels on navigation", async () => {
  const h = harness();
  await ready(h);
  const result = h.send(
    {
      type: "passkey",
      id: "12345678-1234-1234-1234-123456789012",
      operation: "create",
      options: "{}",
      origin: "https://evil.test",
    },
    contentSender(),
  );
  await tick();
  const native = h.sent.find((r) => r.type === "passkey-create");
  assert.equal(native.origin, "https://example.test");
  assert.equal(native.document_id, "doc-1");
  h.setDoc("doc-2");
  h.listeners.updated(1, { status: "loading" });
  h.deliver({
    v: 1,
    id: native.id,
    type: "passkey-result",
    credential: JSON.stringify({ id: "late" }),
  });
  assert.equal((await result).error, "NotAllowedError");
  assert.match(
    (await h.send({ type: "state" })).status,
    /Passkey 创建结果未确认/,
  );
  assert(h.sent.some((r) => r.type === "cancel"));
});
test("password injection cancellation preserves unknown after disconnect and late completion", async () => {
  const h = harness();
  await ready(h);
  let release;
  h.holdFill(new Promise((resolve) => (release = resolve)));
  await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
  await tick();
  const native = h.sent.find((r) => r.type === "fill");
  h.deliver({
    v: 1,
    id: native.id,
    type: "fill",
    username: "fixture-user",
    password: "fixture-password",
  });
  await tick();
  assert.equal(h.injected.length, 1);
  h.losePort();
  let state = await h.send({ type: "state" });
  assert.match(state.status, /登录填充结果未确认/);
  release([{ frameId: 0, documentId: "doc-1", result: true }]);
  await tick();
  state = await h.send({ type: "state" });
  assert.match(state.status, /登录填充结果未确认/);
});

test("automatic submission respects global/item opt-outs and fails closed on preference read failure", async () => {
  for (const mode of ["global", "item", "storage"]) {
    const h = harness({ readSettingsError: mode === "storage" });
    await ready(h);
    if (mode === "global") await h.send({ type: "settings", autoLogin: false });
    if (mode === "item")
      await h.send({ type: "settings", id: "b".repeat(32), enabled: false });
    await h.send({
      type: "fill",
      id: "b".repeat(32),
      revision: "c".repeat(64),
    });
    await tick();
    const request = h.sent.find((m) => m.type === "fill");
    h.deliver({
      v: 1,
      id: request.id,
      type: "fill",
      username: "user",
      password: "password",
    });
    await tick();
    assert.equal(h.injected.length, 1);
    assert.equal(h.injected[0].args[5], false, mode);
  }
});
test("failed preference persistence does not change the active setting", async () => {
  const h = harness({ writeSettingsError: true });
  await ready(h);
  await h.send({ type: "settings", autoLogin: false });
  assert.equal((await h.send({ type: "state" })).autoLogin, true);
});

async function stageOffline(h, overrides = {}) {
  return h.send(
    {
      type: "inline-stage-save",
      username: "alice",
      password: "staged-password",
      isNewPassword: true,
      isPasswordChange: false,
      ...overrides,
    },
    contentSender(),
  );
}
test("inline staged save survives loading and complete navigation in the same tab", async () => {
  const h = harness();
  try {
    const staged = await stageOffline(h);
    assert.equal(staged.mode, "new");
    assert.match(staged.stageId, /^[a-f0-9]{32}$/);
    assert.equal(staged.pendingSave.stageId, staged.stageId);
    assert.ok(!JSON.stringify(staged).includes("staged-password"));
    h.setDoc("doc-2");
    h.listeners.updated(1, { status: "loading" });
    h.listeners.updated(1, { status: "complete" });
    const pending = await h.send(
      { type: "inline-pending-save" },
      contentSender("doc-2"),
    );
    assert.equal(pending.pendingSave.stageId, staged.stageId);
    const state = await h.send({ type: "state" });
    assert.equal(state.pendingSave.stageId, staged.stageId);
    assert.equal(state.pendingSave.origin, "https://example.test");
    assert.equal(state.generatedHistory.length, 0);
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("stageSave classifies new, update, never and unchanged submissions", async () => {
  const fresh = harness();
  try {
    assert.equal((await stageOffline(fresh)).mode, "new");
    const update = await stageOffline(fresh, {
      isNewPassword: false,
      isPasswordChange: true,
    });
    assert.equal(update.mode, "update");
  } finally {
    await fresh.send({ type: "disconnect" });
  }

  const never = harness({
    settings: { neverSaveOrigins: ["https://example.test"] },
  });
  try {
    const staged = await stageOffline(never);
    assert.equal(staged.mode, "never");
    assert.equal(staged.pendingSave, null);
    assert.equal((await never.send({ type: "inline-pending-save" }, contentSender())).pendingSave, null);
  } finally {
    await never.send({ type: "disconnect" });
  }

  const filled = harness();
  try {
    await ready(filled);
    await filled.send({
      type: "fill",
      id: "b".repeat(32),
      revision: "c".repeat(64),
    });
    await tick();
    await tick();
    const request = filled.sent.find((r) => r.type === "fill");
    assert.ok(request);
    filled.deliver({
      v: 1,
      id: request.id,
      type: "fill",
      username: "fixture-user",
      password: "fixture-password",
    });
    for (let i = 0; i < 8; i++) await tick();
    const unchanged = await filled.send(
      {
        type: "inline-stage-save",
        username: "fixture-user",
        password: "fixture-password",
        isNewPassword: false,
        isPasswordChange: false,
      },
      contentSender(),
    );
    assert.equal(unchanged.mode, "unchanged");
    assert.equal(unchanged.pendingSave, null);
    const changed = await filled.send(
      {
        type: "inline-stage-save",
        username: "fixture-user",
        password: "different-password",
        isNewPassword: false,
        isPasswordChange: false,
      },
      contentSender(),
    );
    assert.equal(changed.mode, "new");
  } finally {
    await filled.send({ type: "disconnect" });
  }
});
test("popup commit over the v1 protocol creates a new login with the edited title", async () => {
  const h = harness();
  try {
    const staged = await stageOffline(h);
    const pending = h.send({
      type: "commit-staged-save",
      stageId: staged.stageId,
      title: "Edited Login",
    });
    for (let i = 0; i < 20; i++) await tick();
    const save = h.sent.find((r) => r.type === "save-new");
    assert.ok(save, "v1 save-new was not sent");
    assert.equal(save.username, "alice");
    assert.equal(save.password, "staged-password");
    assert.equal(save.title, "Edited Login");
    assert.equal(save.origin, "https://example.test");
    h.deliver({
      v: 1,
      id: save.id,
      type: "save-ready",
      nonce: "f".repeat(64),
    });
    for (let i = 0; i < 12; i++) await tick();
    assert.ok(h.sent.find((r) => r.type === "commit-ready"));
    const response = await pending;
    assert.equal(response.saved, true);
    assert.match(response.status, /已保存/);
    assert.equal(response.pendingSave, null);
    assert.equal(
      (await h.send({ type: "inline-pending-save" }, contentSender()))
        .pendingSave,
      null,
    );
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("popup commit over the v1 protocol updates an existing row without a title", async () => {
  const h = harness();
  try {
    const staged = await stageOffline(h, {
      isNewPassword: false,
      isPasswordChange: true,
      password: "new-password",
    });
    assert.equal(staged.mode, "update");
    const pending = h.send({
      type: "commit-staged-save",
      stageId: staged.stageId,
      mode: "update",
      title: "Must not leak into save-update",
    });
    for (let i = 0; i < 22; i++) await tick();
    const update = h.sent.find((r) => r.type === "save-update");
    assert.ok(update, "v1 save-update was not sent");
    assert.equal(update.item_id, "b".repeat(32));
    assert.equal(update.revision, "c".repeat(64));
    assert.equal(update.username, "alice");
    assert.equal(update.password, "new-password");
    assert.equal("title" in update, false);
    assert.equal(h.sent.filter((r) => r.type === "save-new").length, 0);
    h.deliver({
      v: 1,
      id: update.id,
      type: "save-ready",
      nonce: "f".repeat(64),
    });
    for (let i = 0; i < 12; i++) await tick();
    const response = await pending;
    assert.equal(response.saved, true);
    assert.equal(response.mode, "update");
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("M2 stage-save-v1 host stages and commits without the v1 save handshake", async () => {
  const h = harness({ capabilities: ["stage-save-v1"] });
  try {
    await ready(h);
    const staged = await stageOffline(h);
    assert.equal(staged.stageId, "9".repeat(32));
    assert.equal(staged.mode, "new");
    const nativeStage = h.sent.find((r) => r.type === "stage-save");
    assert.ok(nativeStage);
    assert.equal(nativeStage.password, "staged-password");
    const response = await h.send({
      type: "commit-staged-save",
      stageId: staged.stageId,
      title: "M2 title",
    });
    assert.equal(response.saved, true);
    const nativeCommit = h.sent.find((r) => r.type === "commit-staged-save");
    assert.ok(nativeCommit);
    assert.equal(nativeCommit.stage_id, "9".repeat(32));
    assert.equal(nativeCommit.title, "M2 title");
    assert.equal(h.sent.filter((r) => r.type === "save-new").length, 0);
    assert.equal(h.sent.filter((r) => r.type === "save-update").length, 0);
  } finally {
    await h.send({ type: "disconnect" });
  }
});
test("inline-generate uses generate-v1 when advertised and local CSPRNG otherwise", async () => {
  const native = harness({
    capabilities: ["generate-v1"],
    nativePassword: "Native-Pass-42!",
  });
  try {
    await ready(native);
    const generated = await native.send(
      {
        type: "inline-generate",
        mode: "random",
        length: 20,
        digits: true,
        symbols: true,
        username: "alice",
        recordHistory: true,
      },
      contentSender(),
    );
    assert.equal(generated.password, "Native-Pass-42!");
    const request = native.sent.find((r) => r.type === "generate");
    assert.ok(request);
    const options = JSON.parse(request.options);
    assert.equal(options.mode, "random");
    assert.equal(options.length, 20);
    const state = await native.send({ type: "state" });
    assert.equal(state.generatedHistory.length, 1);
    assert.equal(state.generatedHistory[0].password, "Native-Pass-42!");
    assert.equal(state.generatedHistory[0].origin, "https://example.test");
  } finally {
    await native.send({ type: "disconnect" });
  }

  const local = harness();
  try {
    await ready(local);
    const generated = await local.send(
      { type: "inline-generate", mode: "pin", length: 8, recordHistory: true },
      contentSender(),
    );
    assert.match(generated.password, /^[0-9]{8}$/);
    assert.equal(generated.profile.mode, "pin");
    assert.equal(local.sent.filter((r) => r.type === "generate").length, 0);
    const state = await local.send({ type: "state" });
    assert.equal(state.generatedHistory[0].password, generated.password);
  } finally {
    await local.send({ type: "disconnect" });
  }
});
test("inline-generate-fill reuses a previewed password and stages the save", async () => {
  const h = harness();
  try {
    await ready(h);
    const profile = {
      mode: "random",
      length: 14,
      alphabet_size: 84,
      entropy_bits_floor: 89,
    };
    const result = await h.send(
      {
        type: "inline-generate-fill",
        mode: "random",
        length: 24,
        password: "Chosen-Pass-1!",
        profile,
        username: "alice",
      },
      contentSender(),
    );
    assert.equal(result.password, "Chosen-Pass-1!");
    assert.equal(result.filledCount, 2);
    const injected = h.injected.find(
      (item) => item.func === core.fillGeneratedPassword,
    );
    assert.ok(injected);
    assert.equal(injected.args[1], "Chosen-Pass-1!");
    const state = await h.send({ type: "state" });
    assert.equal(state.generatedHistory[0].password, "Chosen-Pass-1!");
    assert.ok(state.pendingSave);
    const fresh = await h.send(
      { type: "inline-generate-fill", mode: "pin", length: 6 },
      contentSender(),
    );
    assert.notEqual(fresh.password, "Chosen-Pass-1!");
    const injections = h.injected.filter(
      (item) => item.func === core.fillGeneratedPassword,
    );
    assert.equal(injections.at(-1).args[1], fresh.password);
  } finally {
    await h.send({ type: "disconnect" });
  }
});
for (const stop of ["locked", "disconnect"]) {
  test("vault " + stop + " clears staged saves and generated history", async () => {
    const h = harness();
    try {
      await ready(h);
      const staged = await stageOffline(h);
      assert.ok(staged.pendingSave);
      const generated = await h.send(
        {
          type: "inline-generate",
          mode: "random",
          length: 20,
          recordHistory: true,
        },
        contentSender(),
      );
      assert.match(generated.password, /^[A-Za-z0-9!@#$%^&*()._+\[\]{}|;:,<>?=/-]{20}$/);
      assert.equal((await h.send({ type: "state" })).generatedHistory.length, 1);
      if (stop === "locked") h.deliver({ v: 1, type: "locked" });
      else h.losePort();
      await tick();
      await tick();
      const state = await h.send({ type: "state" });
      assert.equal(state.connected, false);
      assert.equal(state.pendingSave, null);
      assert.equal(state.generatedHistory.length, 0);
      assert.equal(
        (await h.send({ type: "inline-pending-save" }, contentSender()))
          .pendingSave,
        null,
      );
    } finally {
      await h.send({ type: "disconnect" });
    }
  });
}
test("popup generator commands fill the preview, stage history and manage never-save", async () => {
  const h = harness();
  try {
    await ready(h);
    const profile = {
      mode: "random",
      length: 14,
      alphabet_size: 84,
      entropy_bits_floor: 89,
    };
    const filled = await h.send({
      type: "generator-fill",
      mode: "random",
      length: 24,
      password: "Popup-Pass-1!",
      profile,
    });
    assert.equal(filled.password, "Popup-Pass-1!");
    assert.equal(filled.filledCount, 2);
    const injection = h.injected.find(
      (item) => item.func === core.fillGeneratedPassword,
    );
    assert.equal(injection.args[1], "Popup-Pass-1!");
    let state = await h.send({ type: "state" });
    assert.ok(state.pendingSave);
    assert.equal(state.generatedHistory.length, 1);
    const historyId = state.generatedHistory[0].id;
    const saved = await h.send({
      type: "generator-history-save",
      historyId,
    });
    assert.equal(saved.mode, "new");
    assert.match(saved.status, /暂存/);
    state = await h.send({ type: "state" });
    assert.ok(state.pendingSave);
    const dismissed = await h.send({
      type: "never-save-origin",
      stageId: state.pendingSave.stageId,
    });
    assert.equal(dismissed.pendingSave, null);
    assert.ok(dismissed.neverSaveOrigins.includes("https://example.test"));
    state = await h.send({ type: "state" });
    assert.equal(state.pendingSave, null);
    assert.ok(state.neverSaveOrigins.includes("https://example.test"));
    await h.send({ type: "clear-never-save-origin" });
    state = await h.send({ type: "state" });
    assert.equal(state.neverSaveOrigins.includes("https://example.test"), false);
  } finally {
    await h.send({ type: "disconnect" });
  }
});

test("native v2 detail projects has-value rows and URLs without secret values", async () => {
  const id = "b".repeat(32), rev = "c".repeat(64);
  const nativeDetail = {
    id, revision: rev, category: "login", vault_id: "personal", title: "Example",
    username: "ada", has_password: true, has_otp: true, has_notes: true,
    url: "https://example.test/login",
    urls: [
      { url: "https://example.test/login", primary: true, match_mode: "origin" },
      { url: "https://alt.example.test/login", label: "Alt" },
    ],
    state: "active",
    sections: [{ id: "sec1", title: "Extra", fields: [
      { id: "f1", label: "Recovery", type: "concealed", value: "••••••••", concealed: true },
    ] }],
  };
  const h = harness({ onRequest: (r) => {
    if (r.type === "item-get") return { v: 1, id: r.id, type: "item-detail", item: nativeDetail };
    if (r.type === "item-save") return { v: 1, id: r.id, type: "item-saved", item_id: id, revision: rev };
  } });
  await ready(h);
  const reply = await h.send({ type: "item-get", id, revision: rev });
  const detail = reply.detail;
  assert.ok(detail, "item-get failed: " + reply.status);
  assert.deepEqual(Array.from(detail.urls), [
    "https://example.test/login",
    "https://alt.example.test/login",
  ]);
  assert.equal(detail.primary_url, "https://example.test/login");
  assert.equal(detail.password, undefined);
  assert.equal(detail.otp_secret, undefined);
  const password = detail.fields.find((field) => field.id === "password");
  assert.equal(password.has_value, true);
  assert.equal(password.value, "");
  assert.equal(password.concealed, true);
  assert.ok(detail.fields.find((field) => field.id === "notes").has_value);
  assert.equal(detail.fields.filter((field) => field.id === "section:sec1:f1").length, 1);
  assert.equal(detail.fields.some((field) => field.id === "f1"), false);
  assert.equal(detail.fields.find((field) => field.id === "password").revealable, true);
});

test("native v2 save sends only whitelisted DTO keys and explicit reveal is audited", async () => {
  const id = "b".repeat(32), rev = "c".repeat(64);
  const reveals = [];
  const h = harness({ onRequest: (r) => {
    if (r.type === "item-get")
      return { v: 1, id: r.id, type: "item-detail", item: {
        id, revision: rev, category: "login", vault_id: "personal", title: "Example",
        username: "ada", has_password: true, has_notes: true, has_otp: true, state: "active",
        urls: [{ url: "https://example.test/login", primary: true, match_mode: "origin" }],
      } };
    if (r.type === "item-save")
      return { v: 1, id: r.id, type: "item-saved", item_id: id, revision: rev };
    if (r.type === "item-reveal-field" || r.type === "item-copy-field") {
      reveals.push(r);
      return {
        v: 1, id: r.id, type: "field-value", item_id: id, revision: rev,
        field: r.field, value: "native-secret-value",
        copied: r.type === "item-copy-field",
        expires_in_seconds: r.field === "otp" ? 7 : 0,
      };
    }
  } });
  await ready(h);
  await h.send({ type: "item-save", mode: "create", item: {
    category: "card", title: "Card", cardholder: "Ada", brand: "Visa",
    card_number: "4111111111111111", expiry: "12/30", cvv: "123",
    urls: ["https://example.test/login"],
    fields: [], otp_secret: "", notes: "",
  } });
  await tick();
  const save = h.sent.find((r) => r.type === "item-save");
  const outgoing = JSON.parse(save.item_json);
  assert.equal(outgoing.category, "credit_card");
  assert.equal(outgoing.credit_card.number, "4111111111111111");
  assert.deepEqual(Object.keys(outgoing.credit_card).sort(), [
    "cardholder_name", "expiry_date", "number", "type", "verification",
  ]);
  assert.deepEqual(outgoing.urls[0], {
    url: "https://example.test/login", primary: true, match_mode: "origin",
  });
  for (const forbidden of ["fields", "otp_secret", "card_number", "cardholder", "brand", "expiry", "cvv"])
    assert.equal(Object.hasOwn(outgoing, forbidden), false, forbidden);
  assert.equal(reveals.length, 0, "detail rendering must not auto-reveal");
  const revealed = await h.send({ type: "reveal-field", id, revision: rev, field: "password" });
  assert.ok(revealed.revealedField, "reveal failed: " + revealed.status);
  assert.equal(revealed.revealedField.value, "native-secret-value");
  assert.equal(revealed.revealedField.expires_in_seconds, 30);
  assert.equal(reveals.length, 1);
  assert.equal(reveals[0].action, "reveal");
  assert.equal(Object.hasOwn(reveals[0], "field_action"), false);
  const otpReveal = await h.send({ type: "reveal-field", id, revision: rev, field: "otp" });
  assert.equal(otpReveal.revealedField.expires_in_seconds, 7, "OTP window must not be extended");
  const denied = await h.send({ type: "reveal-field", id, revision: rev, field: "cc-csc" });
  assert.equal(denied.revealedField, undefined);
  assert.equal(reveals.length, 2, "unknown field must not reach the host");
  const state = await h.send({ type: "state" });
  assert.doesNotMatch(JSON.stringify(state), /native-secret-value/);
});

test("inline save during password injection cannot create a false staged banner", async () => {
  const h = harness();
  let release;
  h.holdFill(new Promise((resolve) => (release = resolve)));
  try {
    await ready(h);
    await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
    await tick();
    const native = h.sent.find((r) => r.type === "fill");
    h.deliver({
      v: 1, id: native.id, type: "fill",
      username: "fixture-user", password: "fixture-password",
    });
    await tick();
    const during = await h.send(
      {
        type: "inline-stage-save",
        username: "fixture-user",
        password: "fixture-password",
        isNewPassword: false,
        isPasswordChange: false,
      },
      contentSender(),
    );
    assert.equal(during.mode, "unchanged");
    assert.equal(during.pendingSave, null);
    release([{ frameId: 0, documentId: "doc-1", result: true }]);
    for (let i = 0; i < 6; i++) await tick();
    const state = await h.send({ type: "state" });
    assert.equal(state.pendingSave, null);
  } finally {
    await h.send({ type: "disconnect" });
  }
});

test("failed injection rolls back remembered credentials so a real submit still offers save", async () => {
  const h = harness();
  let release;
  h.holdFill(new Promise((resolve) => (release = resolve)));
  try {
    await ready(h);
    await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
    await tick();
    const native = h.sent.find((r) => r.type === "fill");
    h.deliver({
      v: 1, id: native.id, type: "fill",
      username: "fixture-user", password: "fixture-password",
    });
    await tick();
    release([{ frameId: 0, documentId: "doc-1", result: false }]);
    for (let i = 0; i < 8; i++) await tick();
    const staged = await h.send(
      {
        type: "inline-stage-save",
        username: "fixture-user",
        password: "fixture-password",
        isNewPassword: false,
        isPasswordChange: false,
      },
      contentSender(),
    );
    assert.equal(staged.mode, "new");
    assert.match(staged.stageId, /^[a-f0-9]{32}$/);
  } finally {
    await h.send({ type: "disconnect" });
  }
});

const PASSKEY_CAP = "passkey-management-v1";
const PASSKEY_ID = "b".repeat(32);
const PASSKEY_REV = "c".repeat(64);
const PASSKEY_NEXT = "d".repeat(64);
const PASSKEY_CRED = core.base64URLEncode(new Uint8Array(32).fill(7));

function passkeyMeta(overrides = {}) {
  return {
    credential_id: PASSKEY_CRED,
    rp_id: "example.test",
    user_name: "ada",
    display_name: "Ada Lovelace",
    ...overrides,
  };
}

test("passkey metadata is a safe DTO and searches forward the server filter", async () => {
  const h = harness({
    capabilities: [PASSKEY_CAP],
    onRequest: (r) => {
      if (r.type === "vault-search")
        return {
          v: 1, id: r.id, type: "vault-items",
          items: [{
            id: PASSKEY_ID, revision: PASSKEY_REV, category: "login",
            title: "Example", passkey: passkeyMeta(), has_passkey: true,
          }],
        };
      if (r.type === "item-get")
        return {
          v: 1, id: r.id, type: "item-detail",
          item: {
            id: PASSKEY_ID, revision: PASSKEY_REV, category: "login",
            title: "Example", username: "ada", has_passkey: true,
            passkey: passkeyMeta({ private_key: "secret", user_handle: "hidden" }),
          },
        };
    },
  });
  await ready(h);
  const search = await h.send({
    type: "vault-search", query: "exa", category: "all", passkeysOnly: true,
  });
  const native = h.sent.find((r) => r.type === "vault-search");
  assert.equal(native.passkeys_only, true);
  assert.equal(native.query, "exa");
  assert.equal(search.vaultItems[0].passkey.user_name, "ada");
  assert.equal(search.passkeysUnsupported, false);
  const detail = await h.send({ type: "item-get", id: PASSKEY_ID, revision: PASSKEY_REV });
  assert.equal(detail.detail.has_passkey, true);
  assert.equal(detail.detail.passkey, undefined, "extra host metadata must not be projected");
  assert.equal(JSON.stringify(search).includes("secret"), false);
  const state = await h.send({ type: "state" });
  assert.equal(state.passkeyManagementSupported, true);
  await h.send({ type: "disconnect" });
});

test("old host gets an explicit Passkey upgrade notice and no new wire fields", async () => {
  const h = harness({ capabilities: [] });
  await ready(h);
  const sentBefore = h.sent.length;
  const reply = await h.send({
    type: "vault-search", query: "ada", category: "all", passkeysOnly: true,
  });
  assert.equal(h.sent.length, sentBefore, "must not call the native host");
  assert.equal(reply.passkeysUnsupported, true);
  assert.deepEqual(Array.from(reply.vaultItems), []);
  assert.match(reply.status, /升级原生宿主/);
  assert.equal(reply.passkeyManagementSupported, false);
  const remove = await h.send({
    type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV,
    credential_id: PASSKEY_CRED,
  });
  assert.equal(remove.passkeyRemoved, undefined);
  assert.equal(remove.passkeyRemoveError, "refused");
  assert.equal(h.sent.some((r) => r.type === "passkey-remove"), false);
  await h.send({ type: "disconnect" });
});

test("passkey removal is popup-only and binds exact item, revision and credential", async () => {
  const removals = [];
  const h = harness({
    capabilities: [PASSKEY_CAP],
    onRequest: (r) => {
      if (r.type === "passkey-remove") {
        removals.push(r);
        return {
          v: 1, id: r.id, type: "passkey-removed", item_id: r.item_id,
          revision: PASSKEY_NEXT, credential_id: r.credential_id,
        };
      }
    },
  });
  await ready(h);
  const reply = await h.send({
    type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV,
    credential_id: PASSKEY_CRED,
  });
  assert.equal(removals.length, 1);
  assert.equal(removals[0].item_id, PASSKEY_ID);
  assert.equal(removals[0].revision, PASSKEY_REV);
  assert.equal(removals[0].credential_id, PASSKEY_CRED);
  assert.match(removals[0].capability, /^[a-f0-9]{32}$/);
  assert.equal(Object.hasOwn(removals[0], "origin"), false);
  assert.equal(reply.passkeyRemoved.item_id, PASSKEY_ID);
  assert.equal(reply.passkeyRemoved.revision, PASSKEY_NEXT);
  assert.equal(reply.passkeyRemoved.credential_id, PASSKEY_CRED);
  assert.equal(Object.hasOwn(reply.passkeyRemoved, "user_handle"), false);

  const contentAttempt = await h.send(
    { type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV, credential_id: PASSKEY_CRED },
    contentSender(),
  );
  assert.equal(contentAttempt?.passkeyRemoved, undefined);
  assert.equal(removals.length, 1, "web content cannot remove passkeys");

  const extra = await h.send({
    type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV,
    credential_id: PASSKEY_CRED, origin: "https://evil.test",
  });
  assert.equal(extra.passkeyRemoved, undefined);
  assert.equal(removals.length, 1, "unknown fields must not reach the host");
  await h.send({ type: "disconnect" });
});

test("unknown passkey commit outcome is reported as unconfirmed", async () => {
  const h = harness({
    capabilities: [PASSKEY_CAP],
    onRequest: (r) =>
      r.type === "passkey-remove"
        ? { v: 1, id: r.id, type: "unknown" }
        : undefined,
  });
  await ready(h);
  const reply = await h.send({
    type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV,
    credential_id: PASSKEY_CRED,
  });
  assert.equal(reply.passkeyRemoved, undefined);
  assert.equal(reply.passkeyRemoveError, "uncertain");
  assert.match(reply.status, /结果未确认/);
  assert.doesNotMatch(reply.status, /未删除/);
  await h.send({ type: "disconnect" });
});

test("reordered vault searches cannot poison the latest passkey snapshot", async () => {
  const h = harness({ capabilities: [PASSKEY_CAP] });
  await ready(h);
  const oldSearch = h.send({
    type: "vault-search", query: "all-items", category: "all",
  });
  await tick();
  const oldRequest = h.sent.filter((r) => r.type === "vault-search").at(-1);
  const newSearch = h.send({
    type: "vault-search", query: "passkeys", category: "all", passkeysOnly: true,
  });
  await tick();
  const newRequest = h.sent.filter((r) => r.type === "vault-search").at(-1);
  assert.notEqual(oldRequest.id, newRequest.id);

  h.deliver({
    v: 1, id: newRequest.id, type: "vault-items",
    items: [{
      id: "1".repeat(32), revision: "2".repeat(64), category: "login",
      title: "Passkey only", has_passkey: true, passkey: passkeyMeta(),
    }],
  });
  const newest = await newSearch;
  assert.equal(newest.vaultItems.length, 1);
  assert.equal(newest.vaultItems[0].title, "Passkey only");

  h.deliver({
    v: 1, id: oldRequest.id, type: "vault-items",
    items: [{
      id: "3".repeat(32), revision: "4".repeat(64), category: "login",
      title: "Ordinary login", has_passkey: false,
    }],
  });
  const stale = await oldSearch;
  assert.equal(stale.vaultStale, true);
  assert.deepEqual(Array.from(stale.vaultItems), []);

  const state = await h.send({ type: "state" });
  assert.equal(state.vaultItems.length, 1);
  assert.equal(state.vaultItems[0].title, "Passkey only");
  assert.match(state.status, /Passkey/);
  await h.send({ type: "disconnect" });
});

test("late vault search after lock or passkey removal cannot revive old rows", async () => {
  for (const mode of ["lock", "remove"]) {
    const h = harness({
      capabilities: [PASSKEY_CAP],
      onRequest: (r) =>
        r.type === "passkey-remove"
          ? {
              v: 1, id: r.id, type: "passkey-removed", item_id: r.item_id,
              revision: PASSKEY_NEXT, credential_id: r.credential_id,
            }
          : undefined,
    });
    await ready(h);
    const search = h.send({ type: "vault-search", query: "queued", category: "all" });
    await tick();
    const request = h.sent.filter((r) => r.type === "vault-search").at(-1);
    if (mode === "lock") await h.send({ type: "disconnect" });
    else
      await h.send({
        type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV,
        credential_id: PASSKEY_CRED,
      });
    h.deliver({
      v: 1, id: request.id, type: "vault-items",
      items: [{
        id: PASSKEY_ID, revision: PASSKEY_REV, category: "login",
        title: "Deleted passkey", has_passkey: true, passkey: passkeyMeta(),
      }],
    });
    const result = await search;
    assert.deepEqual(Array.from(result.vaultItems), [], mode);
    const state = await h.send({ type: "state" });
    assert.deepEqual(Array.from(state.vaultItems), [], mode);
  }
});

async function ticks(n) {
  for (let i = 0; i < n; i++) await tick();
}
async function sendFill(h) {
  await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
  await tick();
  const native = h.sent.filter((r) => r.type === "fill").at(-1);
  assert.ok(native, "fill request not sent");
  return native;
}
async function deliverFill(h, native) {
  h.deliver({
    v: 1,
    id: native.id,
    type: "fill",
    username: "fixture-user",
    password: "fixture-password",
  });
  for (let i = 0; i < 12 && h.injected.length === 0; i++) await tick();
  assert.equal(h.injected.length, 1, "fill was not dispatched");
}

test("hung post-injection probe keeps a dispatched login fill unknown", async () => {
  const h = harness();
  try {
    await ready(h);
    h.hangPostInjectionProbe();
    const probesBefore = h.probeCount();
    const native = await sendFill(h);
    await deliverFill(h, native);
    for (let i = 0; i < 12 && h.probeCount() < probesBefore + 4; i++)
      await tick();
    assert.ok(
      h.probeCount() >= probesBefore + 4,
      "post-injection probe never started: " + (h.probeCount() - probesBefore),
    );
    h.expireFillBound();
    await ticks(6);
    const state = await h.send({ type: "state" });
    assert.match(state.status, /登录填充结果未确认/);
    assert.doesNotMatch(state.status, /本次填充未完成/);
    assert.equal(state.pending, false);
  } finally {
    await h.send({ type: "disconnect" });
  }
});

test("lost injection promise at its bounded timeout is unknown", async () => {
  const h = harness();
  try {
    await ready(h);
    h.holdFill(new Promise(() => {}));
    const native = await sendFill(h);
    await deliverFill(h, native);
    h.expireFillBound();
    await ticks(6);
    const state = await h.send({ type: "state" });
    assert.match(state.status, /登录填充结果未确认/);
    assert.doesNotMatch(state.status, /本次填充未完成/);
    assert.equal(state.pending, false);
  } finally {
    await h.send({ type: "disconnect" });
  }
});

for (const reason of ["navigation", "lock", "disconnect"]) {
  test(
    "dispatched login fill stays unknown after " + reason,
    async () => {
      const h = harness();
      let release;
      await ready(h);
      h.holdFill(new Promise((resolve) => (release = resolve)));
      const native = await sendFill(h);
      await deliverFill(h, native);
      if (reason === "navigation") {
        h.setDoc("doc-2");
        h.listeners.updated(1, { status: "loading" });
      }
      if (reason === "lock") h.deliver({ v: 1, type: "locked" });
      if (reason === "disconnect") h.losePort();
      await ticks(4);
      let state = await h.send({ type: "state" });
      assert.match(state.status, /登录填充结果未确认/);
      assert.doesNotMatch(state.status, /本次填充未完成/);
      release([{ frameId: 0, documentId: "doc-1", result: true }]);
      await ticks(6);
      state = await h.send({ type: "state" });
      assert.match(state.status, /登录填充结果未确认/);
      assert.doesNotMatch(state.status, /本次填充未完成/);
      assert.equal(h.injected.length, 1, "late fill repeated injection");
    },
  );
}

test("native refusal before dispatch is a definite failure with no injection", async () => {
  const h = harness({
    onRequest: (r) =>
      r.type === "fill"
        ? { v: 1, id: r.id, type: "error", error: "refused" }
        : undefined,
  });
  try {
    await ready(h);
    await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
    await ticks(4);
    assert.equal(h.injected.length, 0, "refused fill was injected");
    const state = await h.send({ type: "state" });
    assert.equal(state.status, "本次填充未完成；未自动重试");
    assert.doesNotMatch(state.status, /未确认/);
    assert.equal(state.pending, false);
  } finally {
    await h.send({ type: "disconnect" });
  }
});

test("late completion of an older fill cannot overwrite a newer operation", async () => {
  const h = harness();
  try {
    await ready(h);
    let release;
    h.holdFill(new Promise((resolve) => (release = resolve)));
    const native = await sendFill(h);
    await deliverFill(h, native);
    h.setDoc("doc-2");
    h.listeners.updated(1, { status: "loading" });
    await ticks(3);
    assert.match(
      (await h.send({ type: "state" })).status,
      /登录填充结果未确认/,
    );
    await h.send({ type: "match" });
    await ticks(2);
    assert.equal((await h.send({ type: "state" })).candidates.length, 1);
    await h.send({ type: "fill", id: "b".repeat(32), revision: "c".repeat(64) });
    await ticks(2);
    const newer = h.sent.filter((r) => r.type === "fill").at(-1);
    assert.notEqual(newer.id, native.id, "newer fill request not sent");
    const before = await h.send({ type: "state" });
    assert.equal(before.pending, true);
    assert.match(before.status, /请在原生窗口核对/);
    release([{ frameId: 0, documentId: "doc-1", result: true }]);
    await ticks(8);
    const after = await h.send({ type: "state" });
    assert.equal(after.pending, true, "late completion dropped the newer fill");
    assert.equal(after.status, before.status);
    assert.match(after.status, /请在原生窗口核对/);
    assert.doesNotMatch(after.status, /本次填充未完成/);
    assert.equal(h.injected.length, 1, "late fill repeated injection");
  } finally {
    await h.send({ type: "disconnect" });
  }
});
// ---- Conditional (autofill) Passkey frontend ---------------------------------
const CONDITIONAL_CAP = "passkey-conditional-v1";
const conditionalID = (n = 1) =>
  "12345678-1234-1234-1234-12345678901" + String(n % 10);
const conditionalEntry = (n) => ({
  item_id: n.toString(16).padStart(32, "0"),
  revision: n.toString(16).padStart(64, "0"),
  title: "Item " + n,
  credential_id: core.base64URLEncode(new Uint8Array(32).fill(n % 250)),
  rp_id: "example.test",
  user_name: "user" + n + "@example.test",
  display_name: "User " + n,
});
const conditionalOptions = (n = 1) =>
  JSON.stringify({
    challenge: core.base64URLEncode(new Uint8Array([n, n + 1, n + 2])),
    rpId: "example.test",
    allowCredentials: [
      { type: "public-key", id: core.base64URLEncode(new Uint8Array(32).fill(9)) },
    ],
  });
const conditionalHarness = (entries, options = {}) =>
  harness({
    capabilities: [CONDITIONAL_CAP],
    ...options,
    onRequest: (r) => {
      if (options.onRequest) {
        const reply = options.onRequest(r);
        if (reply !== undefined) return reply;
      }
      if (r.type === "passkey-list" && options.holdList !== true)
        return {
          v: 1,
          id: r.id,
          type: "passkey-candidates",
          passkeys: entries.map((entry) => ({ ...entry })),
          truncated: options.truncated === true,
        };
      if (r.type === "passkey-get" && options.holdGet !== true)
        return {
          v: 1,
          id: r.id,
          type: "passkey-result",
          credential: JSON.stringify({ id: "native-credential", rawId: "AQID" }),
        };
      if (r.type === "fill")
        return {
          v: 1,
          id: r.id,
          type: "fill",
          username: "fill-user",
          password: "fill-password",
        };
      return undefined;
    },
  });

async function conditionalReady(entries, options) {
  const h = conditionalHarness(entries, options);
  await ready(h);
  return h;
}

test("conditional list is public metadata only and never starts a native get", async () => {
  const entries = [conditionalEntry(1), conditionalEntry(2)];
  const h = await conditionalReady(entries);
  const options = conditionalOptions(1);
  const reply = await h.send(
    { type: "passkey-conditional-open", id: conditionalID(1), options },
    contentSender(),
  );
  assert.deepEqual(JSON.parse(JSON.stringify(reply)), {
    passkeys: entries,
    truncated: false,
  });
  const list = h.sent.filter((r) => r.type === "passkey-list");
  assert.equal(list.length, 1);
  assert.deepEqual(Object.keys(list[0]).sort(), [
    "capability",
    "document_id",
    "id",
    "options",
    "origin",
    "tab_id",
    "type",
    "v",
  ]);
  assert.equal(list[0].origin, "https://example.test");
  assert.equal(list[0].tab_id, 1);
  assert.equal(list[0].document_id, "doc-1");
  assert.equal(list[0].options, options);
  assert.equal(h.sent.some((r) => r.type === "passkey-get"), false);
  const state = await h.send({ type: "state" });
  assert.equal(state.passkeyConditionalSupported, true);
  assert.equal(state.pending, false);
});

test("diagnostics describe the session without vault data or secrets", async () => {
  const h = harness();
  await ready(h);
  const reply = await h.send({ type: "diagnostics" });
  const report = reply.diagnostics;
  assert.ok(report, JSON.stringify(reply));
  const text = JSON.stringify(report);
  assert.equal(text.includes("Fixture"), false);
  assert.equal(text.includes("b".repeat(32)), false);
  assert.equal(text.includes("password"), false);
  assert.deepEqual(Object.keys(report).sort(), [
    "connection",
    "counts",
    "extension",
    "generated_at",
    "permissions",
    "settings",
  ]);
  assert.equal(report.connection.connected, true);
  assert.equal(Array.isArray(report.connection.capabilities), true);
  assert.equal(report.counts.candidates, 1);
  assert.equal(report.settings.otp_capture, true);
  assert.equal(report.counts.vault_items >= 0, true);
  const refused = await h.send({ type: "diagnostics", extra: true });
  assert.equal(refused.diagnostics, undefined);
});

test("a missing native host is reported with actionable guidance", async () => {
  const h = harness({
    connectNativeError: "Specified native messaging host not found.",
  });
  await h.send({ type: "connect" });
  await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, false);
  assert.equal(state.hostState, "missing");
  assert.match(state.status, /未找到 Locklark 原生宿主/);
});

test("an old native host is flagged when shared session exists without vault", async () => {
  const h = harness({ capabilities: ["shared-session-v1"] });
  await h.send({ type: "connect" });
  await tick();
  const state = await h.send({ type: "state" });
  assert.equal(state.hostState, "outdated");
  assert.equal(state.hostOutdated, true);
  assert.match(state.status, /版本过旧/);
});

test("native unlock asks the host to focus the desktop window", async () => {
  const h = harness();
  await ready(h);
  const reply = await h.send({ type: "native-unlock" });
  assert.equal(reply.nativeUnlock.ok, true);
  assert.equal(
    h.sent.some((r) => r.type === "unlock-request"),
    true,
  );
  assert.match(reply.nativeUnlock.status, /完成解锁/);
});

test("idle auto-lock needs the opt-in setting and a live capability", async () => {
  const h = harness({
    settings: { idleLockMinutes: 1, notifications: true },
  });
  await ready(h);
  assert.equal(h.idleInterval(), 60);
  h.fireIdle("active");
  assert.equal(h.sent.some((r) => r.type === "lock"), false);
  h.fireIdle("idle");
  await tick();
  assert.equal(
    h.sent.some((r) => r.type === "lock"),
    true,
    "the native lock request is sent",
  );
  assert.equal(h.notifications.length, 1);
  assert.equal(h.notifications[0].title, "Locklark 已锁定");
  assert.equal((await h.send({ type: "state" })).connected, false);
});

test("idle events do nothing when auto-lock is off", async () => {
  const h = harness({ settings: { notifications: true } });
  await ready(h);
  h.fireIdle("idle");
  await tick();
  assert.equal(h.sent.some((r) => r.type === "lock"), false);
  assert.equal(h.notifications.length, 0);
});

test("adding a site preserves existing URL metadata", async () => {
  const id = "b".repeat(32),
    rev = "c".repeat(64);
  const h = harness({
    onRequest: (r) => {
      if (r.type === "item-get")
        return {
          v: 1,
          id: r.id,
          type: "item-detail",
          item: {
            id,
            revision: rev,
            category: "login",
            title: "Example",
            urls: [
              {
                url: "https://example.test/login",
                primary: true,
                match_mode: "exact",
                label: "Main",
              },
              { url: "https://alt.example.test/", match_mode: "host" },
            ],
          },
        };
      if (r.type === "item-save")
        return {
          v: 1,
          id: r.id,
          type: "item-saved",
          item_id: r.item_id,
          revision: "f".repeat(64),
        };
    },
  });
  await ready(h);
  const reply = await h.send({
    type: "add-site",
    id,
    revision: rev,
    origin: "https://new.example.test",
  });
  assert.equal(reply.added.origin, "https://new.example.test");
  assert.equal(reply.added.saved.revision, "f".repeat(64));
  const save = JSON.parse(
    h.sent.find((r) => r.type === "item-save").item_json,
  );
  assert.deepEqual(save.urls, [
    {
      url: "https://example.test/login",
      label: "Main",
      primary: true,
      match_mode: "exact",
    },
    { url: "https://alt.example.test/", match_mode: "host" },
    { url: "https://new.example.test", match_mode: "origin" },
  ]);
  assert.equal(save.username, undefined);
  assert.equal(save.password, undefined);
  const before = h.sent.filter((r) => r.type === "item-save").length;
  const http = await h.send({
    type: "add-site",
    id,
    revision: rev,
    origin: "http://new.example.test",
  });
  assert.equal(http.added, undefined);
  const duplicate = await h.send({
    type: "add-site",
    id,
    revision: rev,
    origin: "https://example.test",
  });
  assert.equal(duplicate.added, undefined);
  assert.equal(
    h.sent.filter((r) => r.type === "item-save").length,
    before,
    "refused requests must not write",
  );
});

test("history entries are projected without password values", async () => {
  const h = harness({
    capabilities: ["history-v1"],
    onRequest: (r) => {
      if (r.type === "item-history")
        return {
          v: 1,
          id: r.id,
          type: "item-history",
          item_id: r.item_id,
          revision: r.revision,
          entries: [
            {
              index: 0,
              timestamp: 1700000000,
              action: "edit",
              title: "Old",
              username: "ada",
              has_password: true,
              password: "leaked-secret",
              sections: [{ password: "leaked-secret" }],
            },
          ],
        };
    },
  });
  await ready(h);
  const reply = await h.send({
    type: "item-history",
    id: "b".repeat(32),
    revision: "c".repeat(64),
  });
  assert.ok(reply.history, JSON.stringify(reply));
  assert.equal(reply.history.entries.length, 1);
  assert.equal(JSON.stringify(reply).includes("leaked-secret"), false);
  assert.equal(reply.history.entries[0].has_password, true);
  assert.equal(reply.history.entries[0].title, "Old");
  const native = h.sent.find((r) => r.type === "item-history");
  assert.equal(native.item_id, "b".repeat(32));
  const unsupported = harness();
  await ready(unsupported);
  const refused = await unsupported.send({
    type: "item-history",
    id: "b".repeat(32),
    revision: "c".repeat(64),
  });
  assert.equal(refused.history, undefined);
});

test("history restore sends the index and rejects out-of-bound values", async () => {
  const h = harness({
    capabilities: ["history-v1"],
    onRequest: (r) => {
      if (r.type === "item-restore-history")
        return {
          v: 1,
          id: r.id,
          type: "item-saved",
          item_id: r.item_id,
          revision: "e".repeat(64),
        };
    },
  });
  await ready(h);
  const reply = await h.send({
    type: "item-restore-history",
    id: "b".repeat(32),
    revision: "c".repeat(64),
    historyIndex: 2,
  });
  assert.equal(reply.saved.item_id, "b".repeat(32));
  assert.equal(reply.saved.revision, "e".repeat(64));
  const native = h.sent.find((r) => r.type === "item-restore-history");
  assert.equal(native.history_index, 2);
  const bad = await h.send({
    type: "item-restore-history",
    id: "b".repeat(32),
    revision: "c".repeat(64),
    historyIndex: 20,
  });
  assert.equal(bad.saved, undefined);
});

test("vault search forwards only a valid archived state filter", async () => {
  const h = harness({
    onRequest: (r) => {
      if (r.type === "vault-search")
        return { v: 1, id: r.id, type: "vault-items", items: [] };
    },
  });
  await ready(h);
  await h.send({
    type: "vault-search",
    query: "",
    category: "archived",
    stateFilter: "archived",
  });
  const archived = h.sent.filter((r) => r.type === "vault-search").at(-1);
  assert.equal(archived.state, "archived");
  assert.equal(archived.category, "");
  await h.send({
    type: "vault-search",
    query: "",
    category: "all",
    stateFilter: "bogus",
  });
  const invalid = h.sent.filter((r) => r.type === "vault-search").at(-1);
  assert.equal("state" in invalid, false);
  await h.send({ type: "vault-search", query: "", category: "all" });
  const plain = h.sent.filter((r) => r.type === "vault-search").at(-1);
  assert.equal("state" in plain, false);
});

test("conditional request does not block ordinary match or fill state", async () => {
  const h = await conditionalReady([conditionalEntry(1)]);
  await h.send(
    {
      type: "passkey-conditional-open",
      id: conditionalID(1),
      options: conditionalOptions(1),
    },
    contentSender(),
  );
  const match = await h.send({ type: "inline-match" }, contentSender());
  assert.equal(match.candidates.length, 1);
  assert.equal((await h.send({ type: "state" })).pending, false);
  await h.send(
    { type: "inline-fill", id: "b".repeat(32), revision: "c".repeat(64) },
    contentSender(),
  );
  assert.equal(h.sent.some((r) => r.type === "fill"), true);
});

test("conditional selection rebinds the original challenge, exact credential and sender context", async () => {
  const entry = conditionalEntry(3);
  const h = await conditionalReady([entry]);
  const options = conditionalOptions(3);
  const reply = await h.send(
    { type: "passkey-conditional-open", id: conditionalID(1), options },
    contentSender(),
  );
  assert.equal(reply.passkeys.length, 1);
  const selected = await h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalID(1),
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
    },
    contentSender(),
  );
  assert.equal(selected.credential.id, "native-credential");
  const gets = h.sent.filter((r) => r.type === "passkey-get");
  assert.equal(gets.length, 1);
  assert.deepEqual(Object.keys(gets[0]).sort(), [
    "capability",
    "credential_id",
    "document_id",
    "id",
    "item_id",
    "options",
    "origin",
    "revision",
    "tab_id",
    "type",
    "v",
  ]);
  assert.equal(gets[0].credential_id, entry.credential_id);
  assert.equal(Object.hasOwn(gets[0], "credential_revision"), false);
  assert.equal(gets[0].origin, "https://example.test");
  assert.equal(gets[0].tab_id, 1);
  assert.equal(gets[0].document_id, "doc-1");
  assert.equal(gets[0].item_id, entry.item_id);
  assert.equal(gets[0].revision, entry.revision);
  const native = JSON.parse(gets[0].options);
  assert.equal(native.challenge, JSON.parse(options).challenge);
  assert.deepEqual(native.allowCredentials, [
    { type: "public-key", id: entry.credential_id },
  ]);
  assert.notEqual(gets[0].options, options);
});

test("conditional selection refuses new options, foreign revisions and unknown keys", async () => {
  const entry = conditionalEntry(4);
  const h = await conditionalReady([entry]);
  await h.send(
    {
      type: "passkey-conditional-open",
      id: conditionalID(1),
      options: conditionalOptions(4),
    },
    contentSender(),
  );
  const cases = [
    {
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
      options: JSON.stringify({ challenge: "evil" }),
    },
    {
      item_id: entry.item_id,
      revision: "d".repeat(64),
      credential_id: entry.credential_id,
    },
    {
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: core.base64URLEncode(new Uint8Array(32).fill(77)),
    },
    {
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
      native: true,
    },
  ];
  for (const selection of cases) {
    const before = h.sent.filter((r) => r.type === "passkey-get").length;
    const reply = await h.send(
      {
        type: "passkey-conditional-select",
        id: conditionalID(1),
        ...selection,
      },
      contentSender(),
    );
    assert.equal(reply.fallback, true);
    assert.equal(h.sent.filter((r) => r.type === "passkey-get").length, before);
  }
  const accepted = await h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalID(1),
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
    },
    contentSender(),
  );
  assert.equal(accepted.credential.id, "native-credential");
});

test("a stale conditional list reply cannot revive a navigated document", async () => {
  const entries = [conditionalEntry(5)];
  const h = await conditionalReady(entries, { holdList: true });
  const pending = h.send(
    {
      type: "passkey-conditional-open",
      id: conditionalID(1),
      options: conditionalOptions(5),
    },
    contentSender(),
  );
  await tick();
  const list = h.sent.find((r) => r.type === "passkey-list");
  assert.ok(list);
  h.setDoc("doc-2");
  h.listeners.updated(1, { status: "loading" });
  h.deliver({
    v: 1,
    id: list.id,
    type: "passkey-candidates",
    passkeys: entries,
    truncated: false,
  });
  const reply = await pending;
  assert.equal(reply.fallback, true);
  const after = await h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalID(1),
      item_id: entries[0].item_id,
      revision: entries[0].revision,
      credential_id: entries[0].credential_id,
    },
    contentSender("doc-2"),
  );
  assert.equal(after.fallback, true);
  assert.equal(h.sent.some((r) => r.type === "passkey-get"), false);
});

test("navigation, cancel and lock invalidate unused conditional intents", async () => {
  const entry = conditionalEntry(6);
  const h = await conditionalReady([entry]);
  const open = () =>
    h.send(
      {
        type: "passkey-conditional-open",
        id: conditionalID(1),
        options: conditionalOptions(6),
      },
      contentSender(),
    );
  await open();
  await h.send({ type: "passkey-cancel", id: conditionalID(1) }, contentSender());
  let reply = await h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalID(1),
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
    },
    contentSender(),
  );
  assert.equal(reply.fallback, true);
  await open();
  h.listeners.updated(1, { url: "https://example.test/other" });
  reply = await h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalID(1),
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
    },
    contentSender(),
  );
  assert.equal(reply.fallback, true);
  assert.equal(h.sent.some((r) => r.type === "passkey-get"), false);
});

test("old host and disabled settings expose no conditional wire", async () => {
  for (const h of [
    harness(),
    await conditionalReady([conditionalEntry(7)], {
      settings: { offerUsePasskeys: false },
    }),
  ]) {
    if (!h.sent.some((r) => r.type === "hello")) await ready(h);
    const before = h.sent.filter((r) => r.type === "passkey-list").length;
    const reply = await h.send(
      {
        type: "passkey-conditional-open",
        id: conditionalID(1),
        options: conditionalOptions(7),
      },
      contentSender(),
    );
    assert.equal(reply.fallback, true);
    assert.equal(h.sent.filter((r) => r.type === "passkey-list").length, before);
    assert.equal((await h.send({ type: "state" })).passkeyConditionalSupported, false);
    assert.equal((await h.send({ type: "inline-state" }, contentSender())).passkeyConditionalSupported, false);
  }
});

test("conditional intents are one per document and bounded at 64 entries", async () => {
  const entry = conditionalEntry(8);
  const h = await conditionalReady([entry]);
  const open = (doc, n) => {
    h.setDoc(doc);
    return h.send(
      {
        type: "passkey-conditional-open",
        id: conditionalID(n),
        options: conditionalOptions(8),
      },
      contentSender(doc),
    );
  };
  const select = (doc, n) => {
    h.setDoc(doc);
    return h.send(
      {
        type: "passkey-conditional-select",
        id: conditionalID(n),
        item_id: entry.item_id,
        revision: entry.revision,
        credential_id: entry.credential_id,
      },
      contentSender(doc),
    );
  };
  await open("doc-a", 1);
  await open("doc-a", 2);
  assert.equal((await select("doc-a", 1)).fallback, true);
  assert.equal((await select("doc-a", 2)).credential.id, "native-credential");
  for (let index = 0; index < 70; index++)
    await open("bulk-" + index, index);
  assert.equal((await select("bulk-0", 0)).fallback, true);
  assert.equal(
    (await select("bulk-69", 69)).credential.id,
    "native-credential",
  );
});

test("a truncated conditional list allows the native picker without selectors", async () => {
  const entry = conditionalEntry(9);
  const options = conditionalOptions(9);
  const h = await conditionalReady([entry], { truncated: true });
  const reply = await h.send(
    { type: "passkey-conditional-open", id: conditionalID(1), options },
    contentSender(),
  );
  assert.equal(reply.truncated, true);
  const selected = await h.send(
    { type: "passkey-conditional-select", id: conditionalID(1), native: true },
    contentSender(),
  );
  assert.equal(selected.credential.id, "native-credential");
  const get = h.sent.find((r) => r.type === "passkey-get");
  assert.equal(get.item_id, undefined);
  assert.equal(get.revision, undefined);
  assert.equal(get.options, options);
  const second = await h.send(
    { type: "passkey-conditional-select", id: conditionalID(1), native: true },
    contentSender(),
  );
  assert.equal(second.fallback, true);
  const plain = await conditionalReady([entry], { truncated: false });
  await plain.send(
    { type: "passkey-conditional-open", id: conditionalID(1), options },
    contentSender(),
  );
  assert.equal(
    (
      await plain.send(
        {
          type: "passkey-conditional-select",
          id: conditionalID(1),
          native: true,
        },
        contentSender(),
      )
    ).fallback,
    true,
  );
});

// ---- Conditional intent invalidation notifications ---------------------------
const conditionalUUID = (n) =>
  "aaaaaaaa-bbbb-cccc-dddd-" + String(n).padStart(12, "0");
const conditionalCancels = (h) =>
  h.tabMessages.filter(
    (sent) => sent.message.type === "locklark:conditional-passkey-cancel",
  );
const openConditional = (h, n, doc = "doc-1") => {
  h.setDoc(doc);
  return h.send(
    {
      type: "passkey-conditional-open",
      id: conditionalUUID(n),
      options: conditionalOptions(1),
    },
    contentSender(doc),
  );
};

test("lock and disconnect notify the exact waiting tab and document with a bare id", async () => {
  const h = await conditionalReady([conditionalEntry(1)]);
  await openConditional(h, 1);
  await h.send({ type: "lock" });
  let cancellations = conditionalCancels(h);
  assert.equal(cancellations.length, 1);
  assert.equal(cancellations[0].tabId, 1);
  assert.equal(cancellations[0].options.documentId, "doc-1");
  assert.deepEqual(Object.keys(cancellations[0].message).sort(), ["id", "type"]);
  assert.equal(cancellations[0].message.id, conditionalUUID(1));
  assert.equal(
    JSON.stringify(cancellations[0].message).includes("Item 1"),
    false,
  );

  const second = await conditionalReady([conditionalEntry(2)]);
  await openConditional(second, 2);
  second.losePort();
  await tick();
  await tick();
  cancellations = conditionalCancels(second);
  assert.equal(cancellations.length, 1);
  assert.equal(cancellations[0].message.id, conditionalUUID(2));
  assert.equal(cancellations[0].options.documentId, "doc-1");
});

test("navigation and tab removal notify the affected document only", async () => {
  const h = await conditionalReady([conditionalEntry(3)]);
  await openConditional(h, 3);
  h.listeners.updated(1, { url: "https://example.test/other" });
  let cancellations = conditionalCancels(h);
  assert.equal(cancellations.length, 1);
  assert.equal(cancellations[0].message.id, conditionalUUID(3));
  assert.equal(cancellations[0].options.documentId, "doc-1");
  await openConditional(h, 4);
  h.listeners.removed(1);
  cancellations = conditionalCancels(h);
  assert.equal(cancellations.length, 2);
  assert.equal(cancellations[1].message.id, conditionalUUID(4));
  assert.deepEqual(Object.keys(cancellations[1].message).sort(), ["id", "type"]);
});

test("a successful selection never sends an invalidation notification", async () => {
  const entry = conditionalEntry(5);
  const h = await conditionalReady([entry]);
  await openConditional(h, 5);
  const selected = await h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalUUID(5),
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
    },
    contentSender(),
  );
  assert.equal(selected.credential.id, "native-credential");
  assert.equal(h.sent.some((r) => r.type === "passkey-get"), true);
  assert.equal(conditionalCancels(h).length, 0);
});

test("eviction notifies the dropped intent without changing status", async () => {
  const h = await conditionalReady([conditionalEntry(6)]);
  const before = (await h.send({ type: "state" })).status;
  for (let index = 0; index < 65; index++)
    await openConditional(h, index, "evict-" + index);
  const cancellations = conditionalCancels(h);
  assert.equal(cancellations.length, 1);
  assert.equal(cancellations[0].message.id, conditionalUUID(0));
  assert.equal(cancellations[0].options.documentId, "evict-0");
  assert.equal((await h.send({ type: "state" })).status, before);
});

test("disabling Passkey settings notifies waiting intents and keeps status", async () => {
  const h = await conditionalReady([conditionalEntry(7)]);
  await openConditional(h, 7);
  const before = (await h.send({ type: "state" })).status;
  h.listeners.storage({ offerUsePasskeys: { newValue: false } }, "local");
  await tick();
  const cancellations = conditionalCancels(h);
  assert.equal(cancellations.length, 1);
  assert.equal(cancellations[0].message.id, conditionalUUID(7));
  assert.equal((await h.send({ type: "state" })).status, before);
  assert.equal((await h.send({ type: "state" })).passkeyConditionalSupported, false);
});

// ---- Conditional selection: one approval slot, atomic revalidation -----------
const nextProbe = async (h) => {
  let timer;
  try {
    await Promise.race([
      h.waitProbe(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error("probe was never deferred")), 2000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
};
const settle = async (rounds = 10) => {
  for (let index = 0; index < rounds; index++) await tick();
};

test("conditional selection preserves an ordinary pending approval and fill slot", async () => {
  const entry = conditionalEntry(10);
  const h = await conditionalReady([entry], { holdGet: true });
  const open = (n) =>
    h.send(
      {
        type: "passkey-conditional-open",
        id: conditionalID(n),
        options: conditionalOptions(10),
      },
      contentSender(),
    );
  const select = (n) =>
    h.send(
      {
        type: "passkey-conditional-select",
        id: conditionalID(n),
        item_id: entry.item_id,
        revision: entry.revision,
        credential_id: entry.credential_id,
      },
      contentSender(),
    );
  const gets = () => h.sent.filter((r) => r.type === "passkey-get");
  const deliver = (id) =>
    h.deliver({
      v: 1,
      id: gets().at(-1).id,
      type: "passkey-result",
      credential: JSON.stringify({ id, rawId: "AQID" }),
    });
  const state = () => h.send({ type: "state" });

  await open(1);
  const ordinary = h.send(
    {
      type: "passkey",
      operation: "get",
      id: conditionalID(2),
      options: conditionalOptions(10),
    },
    contentSender(),
  );
  await settle();
  assert.equal(gets().length, 1);
  assert.equal((await state()).pending, true);
  assert.equal((await select(1)).fallback, true, "ordinary approval owns the slot");
  assert.equal(gets().length, 1, "no second native get");
  assert.equal((await state()).pending, true, "ordinary approval is untouched");
  deliver("ordinary-credential");
  assert.equal((await ordinary).credential.id, "ordinary-credential");
  assert.equal((await state()).pending, false);
  const accepted = select(1);
  await settle();
  assert.equal(gets().length, 2, "the refused selection never consumed the intent");
  deliver("native-credential");
  assert.equal((await accepted).credential.id, "native-credential");

  await h.send({ type: "match" });
  await open(3);
  let releaseFill;
  h.holdFill(new Promise((resolve) => (releaseFill = resolve)));
  const filling = h.send({
    type: "fill",
    id: "b".repeat(32),
    revision: "c".repeat(64),
  });
  await settle();
  assert.equal((await state()).pending, true);
  assert.equal((await select(3)).fallback, true, "ordinary fill owns the slot");
  assert.equal(gets().length, 2, "no native get during an ordinary fill");
  releaseFill();
  await filling;

  await h.send({ type: "disconnect" });
});

test("two racing conditional selections share one approval slot", async () => {
  const entry = conditionalEntry(11);
  const h = await conditionalReady([entry], { holdGet: true });
  await h.send(
    {
      type: "passkey-conditional-open",
      id: conditionalID(1),
      options: conditionalOptions(11),
    },
    contentSender(),
  );
  const select = () =>
    h.send(
      {
        type: "passkey-conditional-select",
        id: conditionalID(1),
        item_id: entry.item_id,
        revision: entry.revision,
        credential_id: entry.credential_id,
      },
      contentSender(),
    );
  const gets = () => h.sent.filter((r) => r.type === "passkey-get");
  const first = select(),
    second = select();
  await settle();
  assert.equal(gets().length, 1, "one shared native get");
  assert.equal((await h.send({ type: "state" })).pending, true);
  h.deliver({
    v: 1,
    id: gets()[0].id,
    type: "passkey-result",
    credential: JSON.stringify({ id: "native-credential", rawId: "AQID" }),
  });
  const replies = [await first, await second];
  assert.equal(
    replies.filter((reply) => reply.credential?.id === "native-credential").length,
    1,
    "exactly one selection wins the challenge",
  );
  assert.equal(replies.filter((reply) => reply.fallback === true).length, 1);
  assert.equal(gets().length, 1, "the loser never asks the host again");
  assert.equal((await h.send({ type: "state" })).pending, false);
  assert.equal((await select()).fallback, true, "the intent was consumed once");
});

test("a deferred conditional context recheck cannot resurrect canceled, replaced or locked intents", async () => {
  const entry = conditionalEntry(12);
  for (const scenario of ["cancel", "replace", "navigate", "lock"]) {
    const h = await conditionalReady([entry], { holdGet: true });
    const open = (n) =>
      h.send(
        {
          type: "passkey-conditional-open",
          id: conditionalID(n),
          options: conditionalOptions(12),
        },
        contentSender(),
      );
    const select = (n) =>
      h.send(
        {
          type: "passkey-conditional-select",
          id: conditionalID(n),
          item_id: entry.item_id,
          revision: entry.revision,
          credential_id: entry.credential_id,
        },
        contentSender(),
      );
    const gets = () => h.sent.filter((r) => r.type === "passkey-get");
    await open(1);
    const release = h.deferProbe(1);
    const selection = select(1);
    await nextProbe(h);
    if (scenario === "cancel")
      await h.send({ type: "passkey-cancel", id: conditionalID(1) }, contentSender());
    else if (scenario === "replace") await open(2);
    else if (scenario === "navigate")
      h.listeners.updated(1, { url: "https://example.test/other" });
    else await h.send({ type: "lock" });
    release();
    await settle();
    assert.equal(gets().length, 0, scenario + ": no stale native get");
    assert.equal(
      (await selection).fallback,
      true,
      scenario + ": the stale selection is refused",
    );
    assert.equal(gets().length, 0, scenario + ": still no stale native get");
    if (scenario === "replace") {
      const newer = select(2);
      await settle();
      assert.equal(gets().length, 1, "the newer intent survives the stale selection");
      h.deliver({
        v: 1,
        id: gets()[0].id,
        type: "passkey-result",
        credential: JSON.stringify({ id: "native-credential", rawId: "AQID" }),
      });
      assert.equal((await newer).credential.id, "native-credential");
    } else {
      assert.equal((await select(1)).fallback, true, scenario + ": intent stays invalid");
      assert.equal(gets().length, 0, scenario);
    }
  }
});

test("a late native reply cannot escape invalidation of its conditional approval", async () => {
  const entry = conditionalEntry(13);
  const h = await conditionalReady([entry], { holdGet: true });
  await h.send(
    {
      type: "passkey-conditional-open",
      id: conditionalID(1),
      options: conditionalOptions(13),
    },
    contentSender(),
  );
  const selection = h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalID(1),
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
    },
    contentSender(),
  );
  await settle();
  const get = h.sent.find((r) => r.type === "passkey-get");
  assert.ok(get, "the approval is in flight");
  assert.equal((await h.send({ type: "state" })).pending, true);
  h.listeners.storage({ offerUsePasskeys: { newValue: false } }, "local");
  await settle();
  assert.equal((await h.send({ type: "state" })).passkeyConditionalSupported, false);
  h.deliver({
    v: 1,
    id: get.id,
    type: "passkey-result",
    credential: JSON.stringify({ id: "late-credential", rawId: "AQID" }),
  });
  const reply = await selection;
  assert.equal(reply.fallback, true, "a late credential is never delivered");
  assert.equal(reply.credential, undefined);
  assert.equal((await h.send({ type: "state" })).pending, false);
  assert.doesNotMatch((await h.send({ type: "state" })).status, /\u5df2\u4ea4\u4ed8/);
});

// --- WebAuthn Signal API hints (issue39) -----------------------------------
const SIGNAL_CAP = "passkey-signal-v1";
const signalID = (n) => core.base64URLEncode(new Uint8Array(32).fill(n));
const signalUserID = (n) => core.base64URLEncode(new Uint8Array(16).fill(n));
const unknownSignalOptions = (extra = {}) =>
  JSON.stringify({
    kind: "unknown",
    rpId: "example.test",
    credentialId: signalID(1),
    ...extra,
  });
const acceptedSignalOptions = () =>
  JSON.stringify({
    kind: "accepted",
    rpId: "example.test",
    userId: signalUserID(2),
    allAcceptedCredentialIds: [signalID(3), signalID(4)],
  });
const userSignalOptions = () =>
  JSON.stringify({
    kind: "user",
    rpId: "example.test",
    userId: signalUserID(2),
    name: "User Name",
    displayName: "User Display",
  });
const signalHarness = (options = {}) =>
  harness({
    ...options,
    capabilities: options.capabilities ?? [SIGNAL_CAP],
    onRequest: (r) => {
      const reply = options.onRequest ? options.onRequest(r) : undefined;
      if (reply !== undefined) return reply;
      if (r.type === "passkey-signal" && options.holdSignal !== true)
        return { v: 1, id: r.id, type: "passkey-signal-accepted" };
      if (r.type === "fill")
        return {
          v: 1,
          id: r.id,
          type: "fill",
          username: "fill-user",
          password: "fill-password",
        };
      return undefined;
    },
  });
const signalWires = (h) => h.sent.filter((r) => r.type === "passkey-signal");

test("signal: a content hint reaches the exact native frame and nothing else", async () => {
  const h = signalHarness();
  await ready(h);
  const before = await h.send({ type: "state" });
  const options = unknownSignalOptions();
  const reply = await h.send(
    { type: "passkey-signal", options },
    contentSender(),
  );
  assert.deepEqual(JSON.parse(JSON.stringify(reply)), {});
  const wires = signalWires(h);
  assert.equal(wires.length, 1);
  assert.deepEqual(Object.keys(wires[0]).sort(), [
    "capability",
    "document_id",
    "id",
    "options",
    "origin",
    "tab_id",
    "type",
    "v",
  ]);
  assert.equal(wires[0].v, 1);
  assert.equal(wires[0].options, options, "the bounded hint is forwarded verbatim");
  assert.equal(wires[0].origin, "https://example.test");
  assert.equal(wires[0].tab_id, 1);
  assert.equal(wires[0].document_id, "doc-1");
  assert.equal(wires[0].capability, "a".repeat(32));
  const after = await h.send({ type: "state" });
  assert.equal(after.pending, false, "no approval slot is claimed");
  assert.equal(after.status, before.status, "a hint changes no status");
  assert.deepEqual(after.candidates, before.candidates);
});

test("signal: the three strict dictionaries reach the host unchanged and stay answerless", async () => {
  const h = signalHarness();
  await ready(h);
  for (const options of [
    unknownSignalOptions(),
    acceptedSignalOptions(),
    userSignalOptions(),
  ]) {
    const reply = await h.send(
      { type: "passkey-signal", options },
      contentSender(),
    );
    assert.deepEqual(JSON.parse(JSON.stringify(reply)), {});
  }
  assert.deepEqual(
    signalWires(h).map((r) => JSON.parse(r.options).kind),
    ["unknown", "accepted", "user"],
  );
  assert.equal(
    h.sent.some((r) => r.type === "passkey-list" || r.type === "passkey-get"),
    false,
    "a hint never lists or asserts credentials",
  );
});

test("signal: an acknowledgement with a private or unknown field is refused", async () => {
  const h = signalHarness({
    onRequest: (r) =>
      r.type === "passkey-signal"
        ? { v: 1, id: r.id, type: "passkey-signal-accepted", count: 1 }
        : undefined,
  });
  await ready(h);
  const reply = await h.send(
    { type: "passkey-signal", options: unknownSignalOptions() },
    contentSender(),
  );
  assert.equal(reply.fallback, true, "a malformed ack is never accepted");
  assert.equal(reply.credential, undefined);
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, false, "the protocol error is fail-closed");
});

test("signal: core accepts only the exact acceptance frame", () => {
  const id = "a".repeat(32);
  assert.equal(
    core.validPasskeySignalAck({ v: 1, id, type: "passkey-signal-accepted" }, id),
    true,
  );
  for (const value of [
    { v: 1, type: "passkey-signal-accepted" },
    { v: 1, id, type: "passkey-signal-accepted", count: 1 },
    { v: 1, id, type: "passkey-signal-accepted", item_id: "b".repeat(32) },
    { v: 1, id, type: "passkey-signal-accepted", credential_id: signalID(1) },
    { v: 1, id, type: "passkey-signal-accepted", user_name: "u" },
    { v: 2, id, type: "passkey-signal-accepted" },
    { v: 1, id, type: "passkey-result" },
  ])
    assert.equal(core.validPasskeySignalAck(value, id), false, JSON.stringify(value));
  assert.equal(
    core.validPasskeySignalAck({ v: 1, id, type: "passkey-signal-accepted" }, "c".repeat(32)),
    false,
    "the ack must answer this exact request",
  );
  assert.equal(
    core.validResponse({ v: 1, id, type: "passkey-signal-accepted" }),
    true,
  );
  assert.equal(
    core.validResponse({ v: 1, id, type: "passkey-signal-accepted", count: 1 }),
    false,
  );
});

test("signal: an old host without passkey-signal-v1 gets no wire and no prompt", async () => {
  const h = signalHarness({ capabilities: [] });
  await ready(h);
  const reply = await h.send(
    { type: "passkey-signal", options: unknownSignalOptions() },
    contentSender(),
  );
  assert.equal(reply.fallback, true);
  assert.equal(signalWires(h).length, 0);
  const state = await h.send({ type: "state" });
  assert.equal(state.connected, true, "the hint never disconnects the vault");
});

test("signal: a disconnected worker neither auto-connects nor sends a hint", async () => {
  const h = signalHarness();
  const reply = await h.send(
    { type: "passkey-signal", options: unknownSignalOptions() },
    contentSender(),
  );
  assert.equal(reply.fallback, true);
  assert.deepEqual(h.sent, [], "no hello and no hint are sent");
});

test("signal: the Passkey use setting gates the hint without prompting", async () => {
  const h = signalHarness({ settings: { offerUsePasskeys: false } });
  await ready(h);
  const reply = await h.send(
    { type: "passkey-signal", options: unknownSignalOptions() },
    contentSender(),
  );
  assert.equal(reply.fallback, true);
  assert.equal(signalWires(h).length, 0);
  assert.equal((await h.send({ type: "state" })).connected, true);
});

test("signal: only the actual content sender may forward a hint", async () => {
  const h = signalHarness();
  await ready(h);
  const before = signalWires(h).length;
  // Popup, options page, an extension page and a mismatched document are all
  // refused without producing a wire frame.
  await h.send({ type: "passkey-signal", options: unknownSignalOptions() });
  const escapes = [
    { id: "fixed", url: "chrome-extension://fixed/options.html" },
    { id: "fixed", url: "https://example.test/login", tab: { id: 1 } },
    contentSender("doc-other"),
  ];
  for (const sender of escapes)
    await h.send({ type: "passkey-signal", options: unknownSignalOptions() }, sender);
  assert.equal(signalWires(h).length, before);
});

test("signal: caller-supplied origin, selectors and page fields are refused", async () => {
  const h = signalHarness();
  await ready(h);
  const options = unknownSignalOptions();
  for (const extra of [
    { origin: "https://evil.test" },
    { tab_id: 9 },
    { document_id: "doc-9" },
    { capability: "f".repeat(32) },
    { item_id: "b".repeat(32) },
    { credential_id: signalID(1) },
    { kind: "unknown" },
    { count: 1 },
  ]) {
    const reply = await h.send(
      { type: "passkey-signal", options, ...extra },
      contentSender(),
    );
    assert.equal(reply.fallback, true, JSON.stringify(extra));
  }
  assert.equal(signalWires(h).length, 0);
});

test("signal: malformed, unknown-member, unbounded and oversize hints are refused", async () => {
  const h = signalHarness();
  await ready(h);
  const cases = [
    "",
    "{",
    "null",
    "[]",
    JSON.stringify({ kind: "other", rpId: "example.test" }),
    JSON.stringify({ kind: "unknown", rpId: "example.test" }),
    unknownSignalOptions({ credentialId: "AAAA=" }),
    unknownSignalOptions({ rpId: "Example.test" }),
    unknownSignalOptions({ extra: true }),
    JSON.stringify({
      kind: "accepted",
      rpId: "example.test",
      userId: signalUserID(2),
      allAcceptedCredentialIds: Array.from({ length: 65 }, (_, i) =>
        signalID(i + 1),
      ),
    }),
    "x".repeat(32769),
  ];
  for (const options of cases) {
    const reply = await h.send(
      { type: "passkey-signal", options },
      contentSender(),
    );
    assert.equal(reply.fallback, true, String(options).slice(0, 80));
  }
  assert.equal(signalWires(h).length, 0);
});

test("signal: a hint is dropped when settings change while the context recheck is in flight", async () => {
  const h = signalHarness();
  await ready(h);
  const release = h.deferProbe(1);
  const pending = h.send(
    { type: "passkey-signal", options: unknownSignalOptions() },
    contentSender(),
  );
  await h.waitProbe();
  h.listeners.storage({ offerUsePasskeys: { newValue: false } }, "local");
  release();
  const reply = await pending;
  assert.equal(reply.fallback, true);
  assert.equal(signalWires(h).length, 0, "the stale hint is never wired");
});

test("signal: a hint is dropped when the connection is lost while the recheck is in flight", async () => {
  const h = signalHarness();
  await ready(h);
  const release = h.deferProbe(1);
  const pending = h.send(
    { type: "passkey-signal", options: unknownSignalOptions() },
    contentSender(),
  );
  await h.waitProbe();
  h.losePort();
  release();
  const reply = await pending;
  assert.equal(reply.fallback, true);
  assert.equal(signalWires(h).length, 0);
  assert.equal((await h.send({ type: "state" })).connected, false);
});

test("signal: a hint never occupies the ordinary fill slot", async () => {
  const h = signalHarness();
  await ready(h);
  await h.send(
    { type: "passkey-signal", options: userSignalOptions() },
    contentSender(),
  );
  assert.equal(signalWires(h).length, 1);
  const match = await h.send({ type: "inline-match" }, contentSender());
  assert.equal(match.candidates.length, 1, "candidates still load");
  assert.equal((await h.send({ type: "state" })).pending, false);
});

// Private native-clipboard port regressions (capability
// native-clipboard-lease-v1). Only the popup may open "native-clipboard".
const CLIPBOARD_CAP = "native-clipboard-lease-v1";
const COPY_TICKET = "f".repeat(64);
const hexId = (n) => n.toString(16).padStart(32, "0");
const SELECTOR = {
  item_id: "b".repeat(32),
  revision: "c".repeat(64),
  field: "password",
};
async function clipboardPort(options = {}, name, sender) {
  const h = harness({ capabilities: [CLIPBOARD_CAP], ...options });
  await ready(h);
  return { h, port: h.emitPort(name, sender) };
}
test("private clipboard port: a disconnect cancels the exact prepared ticket", async () => {
  const { h, port } = await clipboardPort();
  assert.equal((await port.waitReady()).native, true);
  port.post({ type: "prepare", request_id: hexId(1), ...SELECTOR });
  const prepared = await port.waitFor((m) => m.type === "prepared");
  assert.equal(prepared.copy_ticket, COPY_TICKET);
  assert.equal(prepared.request_id, hexId(1));
  const prepare = h.sent.find((x) => x.type === "prepare-copy-field");
  assert.deepEqual(
    [prepare.item_id, prepare.revision, prepare.field],
    [SELECTOR.item_id, SELECTOR.revision, "password"],
  );
  port.post({
    type: "commit",
    request_id: hexId(2),
    ...SELECTOR,
    copy_ticket: COPY_TICKET,
  });
  const commit = await waitFor(
    () => h.sent.find((x) => x.type === "commit-copy-field"),
    "commit forward",
  );
  assert.deepEqual(Object.keys(commit).sort(), [
    "capability",
    "copy_ticket",
    "id",
    "type",
    "v",
  ]);
  assert.equal(commit.copy_ticket, COPY_TICKET);
  assert.equal(commit.capability, prepare.capability);
  // No native response ever arrives: the popup closing must still revoke the
  // pending desktop job with the one exact ticket it was given.
  port.disconnect();
  const cancel = await waitFor(
    () => h.sent.find((x) => x.type === "cancel-copy-field"),
    "cancel after disconnect",
  );
  assert.equal(cancel.copy_ticket, COPY_TICKET);
  assert.equal(cancel.capability, prepare.capability);
  assert.deepEqual(
    h.sent.filter(
      (x) => x.type === "item-copy-field" || x.type === "copy-field",
    ),
    [],
  );
  assert.deepEqual(
    h.sent.filter((x) => x.type === "cancel-copy-field").length,
    1,
  );
  h.deliver({
    v: 1,
    id: commit.id,
    type: "copy-result",
    copy_mode: "native",
    copied: true,
    copy_ticket: COPY_TICKET,
    state: "confirmed",
  });
  await tick();
  assert.equal(
    h.sent.filter((x) => x.type === "commit-copy-field").length,
    1,
    "an unknown outcome is never retried",
  );
});
test("private clipboard port: one preparation in flight, late ticket cancelled", async () => {
  const { h, port } = await clipboardPort({ holdCopyPrepare: true });
  await port.waitReady();
  port.post({ type: "prepare", request_id: hexId(1), ...SELECTOR });
  const prepare = await waitFor(
    () => h.sent.find((x) => x.type === "prepare-copy-field"),
    "prepare forward",
  );
  port.post({ type: "prepare", request_id: hexId(2), ...SELECTOR });
  const refusal = await port.waitFor((m) => m.type === "refused");
  assert.equal(refusal.request_id, "");
  assert.equal(refusal.unknown, false);
  assert.equal(
    h.sent.filter((x) => x.type === "prepare-copy-field").length,
    1,
    "the second prepare never reaches the host",
  );
  port.disconnect();
  h.deliver({
    v: 1,
    id: prepare.id,
    type: "copy-prepared",
    copy_mode: "native",
    ...SELECTOR,
    copy_ticket: COPY_TICKET,
    expires_in_seconds: 10,
    cleanup_ttl_seconds: 30,
  });
  const cancel = await waitFor(
    () => h.sent.find((x) => x.type === "cancel-copy-field"),
    "late cancel",
  );
  assert.equal(cancel.copy_ticket, COPY_TICKET);
  assert.equal(
    port.received.filter((m) => m.type === "prepared").length,
    0,
    "a closed port never receives a grant",
  );
});
test("private clipboard port: wrong senders are dropped and IDs are bounded", async () => {
  for (const [name, sender] of [
    ["native-clipboard", { tab: { id: 1 } }],
    ["native-clipboard", { url: "https://example.test" }],
    ["other-port", {}],
  ]) {
    const { h, port } = await clipboardPort({}, name, sender);
    assert.equal(port.disconnected, true, "the port is closed");
    assert.deepEqual(port.received, []);
    port.post({ type: "prepare", request_id: hexId(1), ...SELECTOR });
    await tick();
    assert.deepEqual(h.sent.filter((x) => x.type === "prepare-copy-field"), []);
  }
  const { h, port } = await clipboardPort();
  await port.waitReady();
  const refused = async (n) => {
    await waitFor(
      () => port.received.filter((m) => m.type === "refused").length >= n,
      "refusal " + n,
    );
    return port.received.filter((m) => m.type === "refused").at(-1);
  };
  for (let n = 0; n < 32; n++) {
    port.post({
      type: "cancel",
      request_id: hexId(n + 1),
      copy_ticket: "0".repeat(64),
    });
    await port.waitFor(
      (m) => m.type === "cancelled" && m.request_id === hexId(n + 1),
    );
  }
  assert.equal(port.received.filter((m) => m.type === "cancelled").length, 32);
  // The 33rd fresh id is refused, and a replayed old id is never accepted.
  port.post({ type: "prepare", request_id: hexId(33), ...SELECTOR });
  assert.equal((await refused(1)).request_id, "");
  port.post({ type: "cancel", request_id: hexId(1), copy_ticket: "0".repeat(64) });
  port.post({ type: "prepare", request_id: hexId(1), ...SELECTOR });
  assert.equal((await refused(2)).request_id, "");
  assert.equal(port.received.filter((m) => m.type === "cancelled").length, 32);
  assert.deepEqual(h.sent.filter((x) => x.type === "prepare-copy-field"), []);
  // A fresh port starts with its own full budget of 32 request ids.
  const next = h.emitPort();
  await next.waitReady();
  for (let n = 0; n < 32; n++) {
    next.post({
      type: "cancel",
      request_id: hexId(n + 33),
      copy_ticket: "0".repeat(64),
    });
    await next.waitFor(
      (m) => m.type === "cancelled" && m.request_id === hexId(n + 33),
    );
  }
  assert.equal(next.received.filter((m) => m.type === "cancelled").length, 32);
});

// ---- Multi-credential conditional selection (exact child revision) ----------
const MULTI_ITEM = "a".repeat(32);
const MULTI_PARENT = "b".repeat(64);
const MULTI_CRED_A = core.base64URLEncode(new Uint8Array(32).fill(7));
const MULTI_CRED_B = core.base64URLEncode(new Uint8Array(32).fill(8));
const MULTI_CHILD_A = "1".repeat(64);
const MULTI_CHILD_B = "2".repeat(64);
const multiEntry = (credential, child) => ({
  item_id: MULTI_ITEM,
  revision: MULTI_PARENT,
  title: "Multi",
  credential_id: credential,
  credential_revision: child,
  rp_id: "example.test",
  user_name: "multi@example.test",
  display_name: "Multi User",
});

async function multiReady() {
  const h = await conditionalReady([
    multiEntry(MULTI_CRED_A, MULTI_CHILD_A),
    multiEntry(MULTI_CRED_B, MULTI_CHILD_B),
  ]);
  const reply = await h.send(
    { type: "passkey-conditional-open", id: conditionalID(1), options: conditionalOptions(7) },
    contentSender(),
  );
  assert.equal(reply.passkeys.length, 2);
  return h;
}

function multiSelect(extra = {}) {
  return {
    type: "passkey-conditional-select",
    id: conditionalID(1),
    item_id: MULTI_ITEM,
    revision: MULTI_PARENT,
    credential_id: MULTI_CRED_B,
    credential_revision: MULTI_CHILD_B,
    ...extra,
  };
}

test("two siblings under one parent select the SECOND by its exact child revision", async () => {
  const h = await multiReady();
  const selected = await h.send(multiSelect(), contentSender());
  assert.equal(selected.credential.id, "native-credential");
  const gets = h.sent.filter((r) => r.type === "passkey-get");
  assert.equal(gets.length, 1);
  assert.deepEqual(Object.keys(gets[0]).sort(), [
    "capability",
    "credential_id",
    "credential_revision",
    "document_id",
    "id",
    "item_id",
    "options",
    "origin",
    "revision",
    "tab_id",
    "type",
    "v",
  ]);
  assert.equal(gets[0].item_id, MULTI_ITEM);
  assert.equal(gets[0].revision, MULTI_PARENT);
  assert.equal(gets[0].credential_id, MULTI_CRED_B);
  assert.equal(gets[0].credential_revision, MULTI_CHILD_B);
  assert.notEqual(gets[0].credential_id, MULTI_CRED_A);
  const pinned = JSON.parse(gets[0].options);
  assert.deepEqual(pinned.allowCredentials, [
    { type: "public-key", id: MULTI_CRED_B },
  ]);
  assert.equal(h.sent.some((r) => r.raw_item_id || r.raw_record || r.private_key), false);
});

test("stale, missing or invented child selectors are refused without a first-credential fallback", async () => {
  for (const extra of [
    { credential_revision: MULTI_CHILD_A },
    { credential_revision: "3".repeat(64) },
    { credential_revision: MULTI_CHILD_B.slice(1) },
  ]) {
    const h = await multiReady();
    const reply = await h.send(multiSelect(extra), contentSender());
    assert.equal(reply.fallback, true, "stale child selector must refuse");
    assert.equal(h.sent.some((r) => r.type === "passkey-get"), false);
  }
  const h = await multiReady();
  const missing = multiSelect();
  delete missing.credential_revision;
  const reply = await h.send(missing, contentSender());
  assert.equal(reply.fallback, true, "missing child selector must refuse");
  assert.equal(h.sent.some((r) => r.type === "passkey-get"), false);
  const extraField = await h.send(
    multiSelect({ raw_record: "x" }),
    contentSender(),
  );
  assert.equal(extraField.fallback, true, "unknown field must refuse");
  assert.equal(h.sent.some((r) => r.type === "passkey-get"), false);
});

test("legacy seven-key candidates keep the singleton selector without a child revision", async () => {
  const entry = conditionalEntry(2);
  const h = await conditionalReady([entry]);
  const opened = await h.send(
    { type: "passkey-conditional-open", id: conditionalID(1), options: conditionalOptions(2) },
    contentSender(),
  );
  assert.equal(Object.hasOwn(opened.passkeys[0], "credential_revision"), false);
  const selected = await h.send(
    {
      type: "passkey-conditional-select",
      id: conditionalID(1),
      item_id: entry.item_id,
      revision: entry.revision,
      credential_id: entry.credential_id,
    },
    contentSender(),
  );
  assert.equal(selected.credential.id, "native-credential");
  const get = h.sent.find((r) => r.type === "passkey-get");
  assert.equal(get.credential_id, entry.credential_id);
  assert.equal(Object.hasOwn(get, "credential_revision"), false);
});

const PASSKEY_CRED2 = core.base64URLEncode(new Uint8Array(32).fill(8));
const PASSKEY_CHILD1 = "1".repeat(64);
const PASSKEY_CHILD2 = "2".repeat(64);

function managedPasskey(credentialId, revision, userName, displayName, extra = {}) {
  return {
    credential_id: credentialId,
    credential_revision: revision,
    rp_id: "example.test",
    user_name: userName,
    display_name: displayName,
    ...extra,
  };
}

function multiDetailItem(passkeys, overrides = {}) {
  return {
    id: PASSKEY_ID, revision: PASSKEY_REV, category: "login",
    title: "Example", username: "ada", has_passkey: true,
    passkey_count: passkeys.length,
    passkeys,
    ...overrides,
  };
}

test("multi passkey detail projects bounded child revisions and list rows carry only count", async () => {
  const h = harness({
    capabilities: [PASSKEY_CAP],
    onRequest: (r) => {
      if (r.type === "item-get")
        return {
          v: 1, id: r.id, type: "item-detail",
          item: multiDetailItem([
            managedPasskey(PASSKEY_CRED, PASSKEY_CHILD1, "ada", "Ada", {
              user_handle: "private-handle",
            }),
          ].map((entry) => {
            const { user_handle, ...publicEntry } = entry;
            return publicEntry;
          }).concat([
            managedPasskey(PASSKEY_CRED2, PASSKEY_CHILD2, "grace", "Grace"),
          ])),
        };
      if (r.type === "vault-search")
        return {
          v: 1, id: r.id, type: "vault-items",
          items: [{
            id: PASSKEY_ID, revision: PASSKEY_REV, category: "login",
            title: "Example", has_passkey: true, passkey_count: 2,
          }],
        };
    },
  });
  await ready(h);
  const detail = await h.send({ type: "item-get", id: PASSKEY_ID, revision: PASSKEY_REV });
  assert.equal(detail.detail.passkey_count, 2);
  assert.equal(detail.detail.has_passkey, true);
  assert.equal(detail.detail.passkey, undefined, "multi detail has no legacy singleton");
  assert.deepEqual(
    detail.detail.passkeys.map((entry) => [
      entry.credential_id, entry.credential_revision, entry.user_name,
    ]),
    [
      [PASSKEY_CRED, PASSKEY_CHILD1, "ada"],
      [PASSKEY_CRED2, PASSKEY_CHILD2, "grace"],
    ],
  );
  assert.deepEqual(
    Object.keys(detail.detail.passkeys[0]).sort(),
    ["credential_id", "credential_revision", "display_name", "rp_id", "user_name"],
  );
  assert.equal(JSON.stringify(detail).includes("private-handle"), false);

  const search = await h.send({ type: "vault-search", query: "", category: "all" });
  assert.equal(search.vaultItems.length, 1);
  assert.equal(search.vaultItems[0].passkey_count, 2);
  assert.equal(search.vaultItems[0].has_passkey, true);
  assert.equal(search.vaultItems[0].passkey, undefined);
  assert.equal(Object.hasOwn(search.vaultItems[0], "passkeys"), false);
  await h.send({ type: "disconnect" });
});

test("malformed, duplicated, private or excessive passkey arrays are refused not filtered", async () => {
  const cases = [
    [managedPasskey(PASSKEY_CRED, PASSKEY_CHILD1, "ada", "Ada")], // count says two
    [
      managedPasskey(PASSKEY_CRED, PASSKEY_CHILD1, "ada", "Ada"),
      managedPasskey(PASSKEY_CRED, PASSKEY_CHILD2, "ada", "Ada"),
    ],
    [managedPasskey(PASSKEY_CRED, PASSKEY_CHILD1, "ada", "Ada", { user_handle: "secret" })],
  ];
  const missingRevision = managedPasskey(PASSKEY_CRED, PASSKEY_CHILD1, "ada", "Ada");
  delete missingRevision.credential_revision;
  cases.push([missingRevision], [
    managedPasskey(PASSKEY_CRED, "short", "ada", "Ada"),
  ]);
  cases.push(
    Array.from({ length: 17 }, (_, index) =>
      managedPasskey(
        core.base64URLEncode(new Uint8Array(32).fill(index)),
        (index + 1).toString(16).padStart(2, "0").repeat(32),
        "user" + index, "User " + index,
      ),
    ),
  );
  // The first case deliberately supplies two entries but a conflicting count.
  cases[0] = [
    managedPasskey(PASSKEY_CRED, PASSKEY_CHILD1, "ada", "Ada"),
    managedPasskey(PASSKEY_CRED2, PASSKEY_CHILD2, "grace", "Grace"),
  ];
  for (const passkeys of cases) {
    const h = harness({
      capabilities: [PASSKEY_CAP],
      onRequest: (r) =>
        r.type === "item-get"
          ? {
              v: 1, id: r.id, type: "item-detail",
              item: multiDetailItem(passkeys, { passkey_count: 1 }),
            }
          : undefined,
    });
    await ready(h);
    const reply = await h.send({ type: "item-get", id: PASSKEY_ID, revision: PASSKEY_REV });
    assert.equal(reply?.detail?.passkeys, undefined, "invalid array must never be filtered to a first entry");
    assert.equal(reply?.detail?.has_passkey, false);
    assert.equal(JSON.stringify(reply).includes(PASSKEY_CRED), false);
    await h.send({ type: "disconnect" });
  }

  const list = harness({
    capabilities: [PASSKEY_CAP],
    onRequest: (r) =>
      r.type === "vault-search"
        ? {
            v: 1, id: r.id, type: "vault-items",
            items: [{
              id: PASSKEY_ID, revision: PASSKEY_REV, category: "login",
              title: "Example", has_passkey: true, passkey_count: 1,
              passkeys: [managedPasskey(PASSKEY_CRED, PASSKEY_CHILD1, "ada", "Ada")],
            }],
          }
        : undefined,
  });
  await ready(list);
  const search = await list.send({ type: "vault-search", query: "", category: "all" });
  assert.deepEqual(Array.from(search.vaultItems), [], "list rows never carry arrays");
  await list.send({ type: "disconnect" });
});

test("legacy singleton detail is unchanged and an exact child revision is forwarded", async () => {
  const removals = [];
  const h = harness({
    capabilities: [PASSKEY_CAP],
    onRequest: (r) => {
      if (r.type === "item-get")
        return {
          v: 1, id: r.id, type: "item-detail",
          item: {
            id: PASSKEY_ID, revision: PASSKEY_REV, category: "login",
            title: "Example", username: "ada", has_passkey: true,
            passkey: passkeyMeta(),
          },
        };
      if (r.type === "passkey-remove") {
        removals.push(r);
        return {
          v: 1, id: r.id, type: "passkey-removed", item_id: r.item_id,
          revision: PASSKEY_NEXT, credential_id: r.credential_id,
        };
      }
    },
  });
  await ready(h);
  const detail = await h.send({ type: "item-get", id: PASSKEY_ID, revision: PASSKEY_REV });
  assert.equal(detail.detail.has_passkey, true);
  assert.equal(detail.detail.passkey.user_name, "ada");
  assert.equal(detail.detail.passkey_count, undefined, "legacy frames keep their shape");
  assert.equal(Object.hasOwn(detail.detail, "passkeys"), false);

  const removed = await h.send({
    type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV,
    credential_id: PASSKEY_CRED, credential_revision: PASSKEY_CHILD1,
  });
  assert.equal(removed.passkeyRemoved.credential_id, PASSKEY_CRED);
  assert.equal(removals.length, 1);
  assert.equal(removals[0].credential_revision, PASSKEY_CHILD1);
  const refused = await h.send({
    type: "passkey-remove", id: PASSKEY_ID, revision: PASSKEY_REV,
    credential_id: PASSKEY_CRED, credential_revision: "short",
  });
  assert.equal(refused.passkeyRemoved, undefined);
  assert.equal(removals.length, 1, "a malformed child revision never reaches the host");
  await h.send({ type: "disconnect" });
});

test("credit card vault filter forwards the canonical native category and keeps the exact row", async () => {
  const CARD_ID = "a1".repeat(16);
  const CARD_REV = "b2".repeat(32);
  const h = harness({
    onRequest: (r) =>
      r.type === "vault-search"
        ? {
            v: 1,
            id: r.id,
            type: "vault-items",
            items: [
              {
                id: CARD_ID,
                revision: CARD_REV,
                category: "credit_card",
                title: "Browser acceptance card",
                subtitle: "Visa 0000",
                state: "active",
              },
            ],
          }
        : undefined,
  });
  await ready(h);
  const reply = await h.send({
    type: "vault-search",
    query: "",
    category: "credit_card",
  });
  const request = h.sent.filter((r) => r.type === "vault-search").at(-1);
  assert.equal(request.query, "");
  assert.equal(request.category, "credit_card");
  assert.equal(reply.vaultItems.length, 1);
  assert.equal(reply.vaultItems[0].id, CARD_ID);
  assert.equal(reply.vaultItems[0].revision, CARD_REV);

  // The popup row contract keeps the exact id/revision and still selects the
  // card through the public credit_card filter after internal normalization.
  const rows = core.filterVaultItems(reply.vaultItems, {
    query: "",
    category: "credit_card",
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].id, CARD_ID);
  assert.equal(rows[0].revision, CARD_REV);
  await h.send({ type: "disconnect" });
});

test("generated history expires by TTL and is pruned on read", async () => {
  const h = harness({
    clock: 1_700_000_000_000,
    capabilities: ["generate-v1"],
  });
  await ready(h);
  const generated = await h.send({
    type: "generate",
    recordHistory: true,
    length: 20,
    digits: true,
    symbols: true,
  });
  assert.equal(typeof generated.historyId, "string");
  assert.match(generated.historyId, /^[a-f0-9]{32}$/);
  let state = await h.send({ type: "state" });
  assert.equal(state.generatedHistory.length, 1);
  assert.equal(state.generatedHistory[0].id, generated.historyId);

  // The plaintext generated password must not outlive the bounded TTL.
  h.advanceClock(5 * 60 * 1000 + 1);
  state = await h.send({ type: "state" });
  assert.equal(state.generatedHistory.length, 0);
  await h.send({ type: "disconnect" });
});

test("credit-card fill refuses a missing or stale explicit gesture", async () => {
  const h = harness({ clock: 1_700_000_000_000 });
  await ready(h);
  const before = h.sent.filter((request) => request.type === "fill").length;
  const id = "b".repeat(32);
  const revision = "c".repeat(64);

  const missing = await h.send({
    type: "fill",
    id,
    revision,
    category: "credit_card",
  });
  assert.match(missing.status, /拒绝/);
  assert.equal(
    h.sent.filter((request) => request.type === "fill").length,
    before,
    "no native card fill without a gesture",
  );

  const stale = await h.send({
    type: "fill",
    id,
    revision,
    category: "credit_card",
    userGesture: {
      v: 1,
      scope: "credit_card",
      at: 1_700_000_000_000 - 10 * 1000 - 1,
    },
  });
  assert.match(stale.status, /拒绝/);
  assert.equal(
    h.sent.filter((request) => request.type === "fill").length,
    before,
    "no native card fill from an expired gesture",
  );
  await h.send({ type: "disconnect" });
});

function generatedHistoryLength(state) {
  return state.generatedHistory.length;
}

test("generated history is released by its timer without a later visit", async () => {
  const TTL = 5 * 60 * 1000;
  const h = harness({ clock: 1_700_000_000_000, capabilities: ["generate-v1"] });
  await ready(h);
  const generated = await h.send({
    type: "generate",
    recordHistory: true,
    length: 20,
    digits: true,
    symbols: true,
  });
  assert.equal(generatedHistoryLength(await h.send({ type: "state" })), 1);
  // No user access after this point: only the deadline timer runs.
  const armed = h.timerFor(TTL);
  assert.ok(armed, "a deadline timer is armed for the generated entry");
  h.advanceClock(TTL);
  clearTimeout(armed[0]);
  armed[1].fn();
  assert.equal(generatedHistoryLength(await h.send({ type: "state" })), 0);
  const stale = await h.send({
    type: "generator-history-fill",
    historyId: generated.historyId,
  });
  assert.match(stale.status, /拒绝/);
  await h.send({ type: "disconnect" });
});

test("regenerate, lock and disconnect clear the deadline timer", async () => {
  const TTL = 5 * 60 * 1000;
  const h = harness({ clock: 1_700_000_000_000, capabilities: ["generate-v1"] });
  await ready(h);
  await h.send({ type: "generate", recordHistory: true, length: 20 });
  assert.ok(h.timerFor(TTL));
  await h.send({ type: "lock" });
  assert.equal(h.timerFor(TTL), undefined, "lock clears the timer");
  assert.equal(generatedHistoryLength(await h.send({ type: "state" })), 0);

  await ready(h);
  await h.send({ type: "generate", recordHistory: true, length: 20 });
  assert.ok(h.timerFor(TTL));
  await h.send({ type: "disconnect" });
  assert.equal(h.timerFor(TTL), undefined, "disconnect clears the timer");
  assert.equal(generatedHistoryLength(await h.send({ type: "state" })), 0);
});

test("a resumed worker neither revives old entries nor keeps a stale deadline", async () => {
  const TTL = 5 * 60 * 1000;
  const h = harness({ clock: 1_700_000_000_000, capabilities: ["generate-v1"] });
  await ready(h);
  await h.send({ type: "generate", recordHistory: true, length: 20 });
  assert.ok(h.timerFor(TTL));
  // The worker is suspended and resumes late: it starts with an empty heap
  // and no carried-over timer, so nothing is revived.
  h.advanceClock(TTL + 1);
  const resumed = harness({ clock: 1_700_000_000_000 + TTL + 1 });
  assert.equal(generatedHistoryLength(await resumed.send({ type: "state" })), 0);
  assert.deepEqual(resumed.pendingDelays().filter((ms) => ms === TTL), []);
  await h.send({ type: "disconnect" });
  await resumed.send({ type: "disconnect" });
});

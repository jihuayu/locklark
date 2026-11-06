const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");
const tick = () => new Promise((resolve) => setImmediate(resolve));
function harness(options = {}) {
  const timers = new Map();
  const listeners = {},
    sent = [],
    injected = [];
  const messageListeners = [];
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
    },
  };
  const api = {
    storage: {
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
      connectNative: () => port,
      onMessage: { addListener: (f) => messageListeners.push(f) },
    },
    tabs: {
      query: async () => [{ id: tabId, url: tabUrl, windowId }],
      onActivated: { addListener: (f) => (listeners.active = f) },
      onUpdated: { addListener: (f) => (listeners.updated = f) },
    },
    windows: {
      WINDOW_ID_NONE: -1,
      onFocusChanged: { addListener: (f) => (listeners.focus = f) },
    },
    scripting: {
      executeScript: async (options) => {
        if (options.target.frameIds && options.target.documentIds)
          throw Error("Cannot specify both 'frameIds' and 'documentIds'.");
        if (options.func === core.probe && hangProbe)
          return new Promise(() => {});
        if (options.func === core.probe)
          return [
            {
              frameId: 0,
              documentId: doc,
              result: { top: true, origin: "https://example.test" },
            },
          ];
        if (options.func === core.otpDocument && options.args[1] === "probe") {
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
    setTimeout: (fn, ms) => {
      const h = setTimeout(fn, ms);
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
    sent,
    holdFill: (promise) => (fillWait = promise),
    injected,
    listeners,
    hangProbe: () => (hangProbe = true),
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
    setTab: (x) => (tabId = x),
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
  assert.equal(
    (await h.send({ type: "inline-match" }, contentSender())).candidates.length,
    1,
  );
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

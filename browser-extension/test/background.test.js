const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");
const core = require("../core.js");
const tick = () => new Promise((resolve) => setImmediate(resolve));
function harness() {
  const timers = new Map();
  const listeners = {},
    sent = [],
    injected = [];
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
    autoCommit = true;
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
      if (r.type === "cancel")
        queueMicrotask(() =>
          portMessage({ v: 1, id: r.id, type: "cancelled" }),
        );
    },
  };
  const api = {
    runtime: {
      id: "fixed",
      getURL: (p) => "chrome-extension://fixed/" + p,
      connectNative: () => port,
      onMessage: { addListener: (f) => (messageListener = f) },
    },
    tabs: {
      query: async () => [
        { id: tabId, url: "https://example.test/login", windowId },
      ],
      onActivated: { addListener: (f) => (listeners.active = f) },
      onUpdated: { addListener: (f) => (listeners.updated = f) },
    },
    windows: {
      WINDOW_ID_NONE: -1,
      onFocusChanged: { addListener: (f) => (listeners.focus = f) },
    },
    scripting: {
      executeScript: async (options) => {
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
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../background.js"), "utf8"),
    context,
  );
  const sender = { id: "fixed", url: "chrome-extension://fixed/popup.html" };
  return {
    sent,
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
    setWindow: (x) => (windowId = x),
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
        const handled = messageListener(m, s, resolve);
        if (handled === false) resolve(undefined);
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

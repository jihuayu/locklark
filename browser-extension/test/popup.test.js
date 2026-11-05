const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// These are DOM primitives only. Every render and event handler under test is
// loaded from the real popup.js; the runtime boundary is deliberately deferred.
function harness() {
  function element() {
    return {
      textContent: "",
      disabled: false,
      dataset: {},
      children: [],
      listeners: new Map(),
      addEventListener(type, callback) {
        this.listeners.set(type, callback);
      },
      replaceChildren(...children) {
        this.children = children;
      },
      append(...children) {
        this.children.push(...children);
      },
    };
  }
  const elements = Object.fromEntries(
    [
      "status",
      "origin",
      "save-warning",
      "connect",
      "refresh",
      "save-new",
      "disconnect",
      "candidates",
    ].map((id) => ["#" + id, element()]),
  );
  const requests = [];
  let poll;
  const context = {
    document: {
      querySelector(selector) {
        assert.ok(elements[selector], "unexpected product selector");
        return elements[selector];
      },
      createElement: element,
    },
    chrome: {
      runtime: {
        sendMessage(message) {
          return new Promise((resolve, reject) =>
            requests.push({ message, resolve, reject, taken: false }),
          );
        },
      },
    },
    setInterval(callback) {
      poll = callback;
    },
  };
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8"),
    context,
  );
  return {
    elements,
    requests,
    poll: () => poll(),
    take(type) {
      const call = requests.find((r) => !r.taken && r.message.type === type);
      assert.ok(call, "missing " + type + " request");
      call.taken = true;
      return call;
    },
    click(selector) {
      const target =
        typeof selector === "string" ? elements[selector] : selector;
      assert.equal(target.disabled, false, "control is disabled");
      target.listeners.get("click")();
    },
    row: () => elements["#candidates"].children[0],
  };
}
const flush = () => new Promise((resolve) => setImmediate(resolve));
function state(revision = "a", overrides = {}) {
  return {
    connected: true,
    status: "ready-" + revision,
    origin: "https://example.test",
    pending: false,
    saveBlocked: false,
    candidates: [
      { id: "1".repeat(32), title: "Login", revision: revision.repeat(64) },
    ],
    ...overrides,
  };
}
async function ready() {
  const h = harness();
  h.take("state").resolve(state());
  await flush();
  return h;
}

test("refresh disables existing actions before its deferred RPC completes", async () => {
  const h = await ready();
  const [oldFill, oldUpdate] = h.row().children;
  h.click("#refresh");
  h.take("match");
  for (const control of ["#refresh", "#save-new"])
    assert.equal(h.elements[control].disabled, true);
  assert.ok(h.row().children.every((button) => button.disabled));
  // A queued click can retain an old listener even after nodes are disabled.
  oldFill.listeners.get("click")();
  oldUpdate.listeners.get("click")();
  h.elements["#save-new"].listeners.get("click")();
  assert.deepEqual(
    h.requests.map((r) => r.message.type),
    ["state", "match"],
  );
});

test("late polling replies and errors cannot replace a newer action result", async () => {
  for (const lateError of [false, true]) {
    const h = await ready();
    h.poll();
    const old = h.take("state");
    h.click("#refresh");
    h.take("match").resolve(state("b"));
    await flush();
    h.take("state").resolve(state("b"));
    await flush();
    const currentRow = h.row();
    if (lateError) old.reject(Error("synthetic old runtime failure"));
    else old.resolve(state("a"));
    await flush();
    assert.equal(h.elements["#status"].textContent, "ready-b");
    assert.equal(h.row(), currentRow);
    h.click(h.row().children[1]);
    assert.equal(h.take("save-update").message.revision, "b".repeat(64));
  }
});

test("out-of-order polls in one action generation retain the newest revision", async () => {
  for (const lateError of [false, true]) {
    const h = await ready();
    h.poll();
    const old = h.take("state");
    h.poll();
    h.take("state").resolve(state("b"));
    await flush();
    const currentRow = h.row();
    if (lateError) old.reject(Error("synthetic old polling failure"));
    else old.resolve(state("a"));
    await flush();
    assert.equal(h.elements["#status"].textContent, "ready-b");
    assert.equal(h.row(), currentRow);
    h.click(h.row().children[1]);
    assert.equal(h.take("save-update").message.revision, "b".repeat(64));
  }
});

test("polls still show native pending while a business RPC is deferred", async () => {
  const h = await ready();
  h.click("#refresh");
  h.take("match");
  h.poll();
  h.take("state").resolve(
    state("a", { pending: true, status: "native approval pending" }),
  );
  await flush();
  assert.equal(h.elements["#status"].textContent, "native approval pending");
  assert.equal(h.elements["#refresh"].disabled, true);
  assert.equal(h.elements["#save-new"].disabled, true);
  assert.equal(h.elements["#disconnect"].disabled, false);
});

test("disconnect interrupts an action and its old completion cannot affect the next action", async () => {
  for (const lateError of [false, true]) {
    const h = await ready();
    h.click("#refresh");
    const old = h.take("match");
    h.click("#disconnect");
    const disconnected = state("a", {
      connected: false,
      candidates: [],
      status: "disconnected",
    });
    h.take("disconnect").resolve(disconnected);
    await flush();
    h.take("state").resolve(disconnected);
    await flush();
    h.click("#connect");
    const next = h.take("connect");
    const count = h.requests.length;
    if (lateError) old.reject(Error("synthetic old action failure"));
    else old.resolve(state("a"));
    await flush();
    assert.equal(h.requests.length, count, "old action launched a state query");
    assert.equal(
      h.elements["#connect"].disabled,
      true,
      "old action reset the new busy state",
    );
    assert.equal(h.elements["#status"].textContent, "disconnected");
    next.resolve(state("b"));
    await flush();
    h.take("state").resolve(state("b"));
    await flush();
    assert.equal(h.elements["#status"].textContent, "ready-b");
    assert.equal(h.elements["#refresh"].disabled, false);
  }
});

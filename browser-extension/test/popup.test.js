const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// These are DOM primitives only. Every render and event handler under test is
// loaded from the real popup.js; the runtime boundary is deliberately deferred.
function element() {
  return {
    textContent: "",
    disabled: false,
    hidden: false,
    checked: false,
    className: "",
    type: "",
    dataset: {},
    style: {},
    attributes: {},
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
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.hasOwn(this.attributes, name)
        ? this.attributes[name]
        : null;
    },
    removeAttribute(name) {
      delete this.attributes[name];
    },
  };
}
const CATEGORIES = [
  "vulnerable",
  "reused",
  "weak",
  "unsecured_http",
  "totp_not_stored",
  "expiring",
];
function harness() {
  const ids = [
    "status",
    "auto-login",
    "passkey-save",
    "passkey-use",
    "origin",
    "save-warning",
    "connect",
    "refresh",
    "save-new",
    "cancel-otp",
    "disconnect",
    "candidates",
    "pending-save-banner",
    "pending-save-mode",
    "pending-save-origin",
    "pending-save-username",
    "pending-save-title",
    "commit-staged-save",
    "dismiss-staged-save",
    "never-save-origin",
    "generator-section",
    "gen-mode",
    "gen-length",
    "gen-length-value",
    "gen-random-options",
    "gen-digits",
    "gen-symbols",
    "gen-memorable-options",
    "gen-capitalize",
    "gen-separator",
    "gen-regenerate",
    "gen-fill",
    "gen-copy",
    "gen-preview",
    "gen-entropy",
    "gen-history",
    "gen-status",
    "offer-save-logins",
    "clear-never-save",
    "watchtower-site-banner",
    "watchtower-site-badge",
    "watchtower-site-text",
    "watchtower-site-action",
    "watchtower-panel",
    "watchtower-score-bar",
    "watchtower-score",
    "watchtower-summary",
    "watchtower-empty",
    "watchtower-refresh",
    "watchtower-hibp-optin",
    "watchtower-run-hibp",
    "watchtower-hibp-note",
    "watchtower-findings",
    "watchtower-card-",
    "watchtower-count-",
  ];
  for (const category of CATEGORIES)
    ids.push(
      "watchtower-card-" + category,
      "watchtower-count-" + category,
    );
  const elements = Object.fromEntries(
    ids.map((id) => ["#" + id, element()]),
  );
  elements["#gen-mode"].value = "random";
  elements["#gen-length"].value = "24";
  elements["#gen-length"].min = "16";
  elements["#gen-length"].max = "64";
  elements["#gen-length-value"].textContent = "24";
  elements["#gen-separator"].value = "hyphens";
  elements["#gen-digits"].checked = true;
  elements["#gen-symbols"].checked = true;
  elements["#gen-capitalize"].checked = true;
  const requests = [];
  const clipboardWrites = [];
  let poll;
  const context = {
    navigator: {
      clipboard: {
        writeText(value) {
          clipboardWrites.push(value);
          return Promise.resolve();
        },
      },
    },
    document: {
      querySelector(selector) {
        assert.ok(elements[selector], "unexpected product selector");
        return elements[selector];
      },
      createElement: element,
      createTextNode: (text) => ({ textContent: text }),
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
    URL,
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
    clipboardWrites,
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
    fire(selector, type, value) {
      const target =
        typeof selector === "string" ? elements[selector] : selector;
      assert.ok(target.listeners.get(type), "missing " + type + " listener");
      if (value !== undefined) target.value = value;
      target.listeners.get(type)({ target });
    },
    change(selector, checked) {
      const target = elements[selector];
      target.checked = checked;
      target.listeners.get("change")({ target });
    },
    row: () => elements["#candidates"].children[0],
    badges(row = elements["#candidates"].children[0]) {
      return (row.children || []).filter((child) => child.dataset?.wtFlag);
    },
    findings: () => elements["#watchtower-findings"].children,
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
    pendingSave: null,
    generatedHistory: [],
    neverSaveOrigins: [],
    offerSaveLogins: true,
    generatorDefaults: {
      mode: "random",
      length: 24,
      digits: true,
      symbols: true,
      wordCount: 4,
      separator: "hyphens",
      capitalize: true,
      pinLength: 6,
    },
    site: { origin: "https://example.test", unsecured: false },
    watchtower: null,
    watchtowerHIBP: false,
    candidates: [
      { id: "1".repeat(32), title: "Login", revision: revision.repeat(64) },
    ],
    ...overrides,
  };
}
function finding(overrides = {}) {
  return {
    id: "a".repeat(32),
    revision: "b".repeat(64),
    title: "Example",
    origin: "https://example.test",
    flags: ["weak"],
    strength_score: 32,
    strength_category: "weak",
    reuse_count: 0,
    breach_count: 0,
    ...overrides,
  };
}
function report(overrides = {}) {
  return {
    profile: "watchtower-v2",
    hibp_checked: false,
    overall_score: 42,
    checked: 4,
    counts: {
      vulnerable: 1,
      reused: 1,
      weak: 2,
      unsecured_http: 1,
      totp_not_stored: 3,
      expiring: 1,
      passkey_not_stored: 2,
    },
    site: { origin: "https://example.test", unsecured_http: false },
    site_findings: [],
    findings: [
      finding({
        id: "a".repeat(32),
        title: "Vulnerable",
        flags: ["vulnerable", "weak"],
        strength_score: 10,
        strength_category: "terrible",
      }),
      finding({
        id: "b".repeat(32),
        title: "Reused",
        flags: ["reused"],
        strength_score: 40,
        strength_category: "fair",
        reuse_count: 2,
      }),
      finding({
        id: "c".repeat(32),
        title: "Expiring",
        flags: ["expiring-soon"],
        strength_score: 90,
        strength_category: "fantastic",
      }),
    ],
    ...overrides,
  };
}
function findAction(node, action) {
  for (const child of node.children || []) {
    if (child.dataset?.action === action) return child;
    const nested = findAction(child, action);
    if (nested) return nested;
  }
  return null;
}
async function ready(overrides = {}) {
  const h = harness();
  h.take("state").resolve(state("a", overrides));
  await flush();
  return h;
}
async function settle(h, pending) {
  const call = typeof pending === "string" ? h.take(pending) : pending;
  call.resolve(state());
  await flush();
  h.take("state").resolve(state());
  await flush();
  return call;
}

test("refresh disables existing actions before its deferred RPC completes", async () => {
  const h = await ready();
  const [oldFill, oldUpdate] = h.row().children;
  h.click("#refresh");
  h.take("match");
  for (const control of ["#refresh", "#save-new"])
    assert.equal(h.elements[control].disabled, true);
  assert.ok(
    h
      .row()
      .children.slice(0, 3)
      .every((button) => button.disabled),
  );
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

test("OTP action sends only candidate metadata and cancellation stays available while pending", async () => {
  const h = harness();
  h.take("state").resolve(state());
  await flush();
  const otp = h.row().children[2];
  assert.equal(otp.dataset.action, "otp");
  h.click(otp);
  const request = h.take("otp");
  assert.equal(
    Object.keys(request.message).sort().join(","),
    "id,revision,type",
  );
  assert.equal(h.row().children[2].disabled, true);
  h.poll();
  h.take("state").resolve(state("a", { pending: true, otpPending: true }));
  await flush();
  assert.equal(h.elements["#cancel-otp"].disabled, false);
  h.click("#cancel-otp");
  const cancel = h.take("cancel-otp");
  assert.equal(Object.keys(cancel.message).join(","), "type");
  cancel.resolve(state("a", { pending: false, otpPending: false }));
  await flush();
  h.take("state").resolve(state());
  await flush();
  assert.equal(h.elements["#cancel-otp"].disabled, true);
  request.resolve(state("old", { pending: true, otpPending: true }));
  await flush();
  assert.equal(h.elements["#cancel-otp"].disabled, true);
});

function pendingSave(overrides = {}) {
  return {
    stageId: "f".repeat(32),
    origin: "https://example.test",
    username: "alice",
    title: "Example",
    mode: "new",
    existingItemId: "",
    existingRevision: "",
    expiresAt: Date.now() + 60000,
    connected: true,
    candidates: [],
    ...overrides,
  };
}
async function pendingReady(overrides = {}) {
  const h = harness();
  h.take("state").resolve(
    state("a", { pendingSave: pendingSave(overrides) }),
  );
  await flush();
  return h;
}
async function settleAction(h, request, response) {
  request.resolve(response);
  await flush();
  h.take("state").resolve(response);
  await flush();
}
async function finishAction(h, type, response) {
  await settleAction(h, h.take(type), response);
}
function generatedState(password, revision = "b", extra = {}) {
  return {
    ...state(revision),
    password,
    profile: {
      mode: "random",
      length: password.length,
      alphabet_size: 84,
      entropy_bits_floor: 100,
    },
    ...extra,
  };
}
async function previewPassword(h, password = "Preview-123!") {
  h.click("#gen-regenerate");
  const response = generatedState(password);
  await finishAction(h, "generate", response);
}

test("pending save banner renders title and commits the staged update", async () => {
  const h = await pendingReady({
    mode: "update",
    existingItemId: "a".repeat(32),
    existingRevision: "b".repeat(64),
  });
  assert.equal(h.elements["#pending-save-banner"].hidden, false);
  assert.equal(
    h.elements["#pending-save-mode"].textContent,
    "检测到待更新的登录密码",
  );
  assert.equal(
    h.elements["#pending-save-origin"].textContent,
    "https://example.test",
  );
  assert.equal(
    h.elements["#pending-save-username"].textContent,
    "用户名：alice",
  );
  assert.equal(h.elements["#pending-save-title"].value, "Example");
  assert.equal(h.elements["#commit-staged-save"].textContent, "更新密码");
  h.elements["#pending-save-title"].value = "Edited title";
  h.click("#commit-staged-save");
  const request = h.take("commit-staged-save");
  assert.deepEqual(
    {
      stageId: request.message.stageId,
      mode: request.message.mode,
      itemId: request.message.itemId,
      revision: request.message.revision,
      title: request.message.title,
    },
    {
      stageId: "f".repeat(32),
      mode: "update",
      itemId: "a".repeat(32),
      revision: "b".repeat(64),
      title: "Edited title",
    },
  );
  const response = state("b", { pendingSave: null });
  request.resolve(response);
  await flush();
  h.take("state").resolve(response);
  await flush();
  assert.equal(h.elements["#pending-save-banner"].hidden, true);
});

for (const [selector, type, never] of [
  ["#dismiss-staged-save", "dismiss-staged-save", false],
  ["#never-save-origin", "never-save-origin", true],
]) {
  test("pending save " + type + " clears the banner", async () => {
    const h = await pendingReady();
    h.click(selector);
    const request = h.take(type);
    assert.equal(request.message.stageId, "f".repeat(32));
    if (never) assert.equal(request.message.neverForOrigin, undefined);
    const response = state("b", { pendingSave: null });
    request.resolve(response);
    await flush();
    h.take("state").resolve(response);
    await flush();
    assert.equal(h.elements["#pending-save-banner"].hidden, true);
  });
}

test("generator mode switching updates length controls and requests matching params", async () => {
  const h = await ready();
  assert.equal(h.elements["#gen-random-options"].hidden, false);
  assert.equal(h.elements["#gen-memorable-options"].hidden, true);
  h.fire("#gen-mode", "change", "memorable");
  const request = h.take("generate");
  assert.equal(request.message.mode, "memorable");
  assert.equal(request.message.length, 4);
  assert.equal(request.message.capitalize, true);
  assert.equal(request.message.separator, "hyphens");
  assert.equal(h.elements["#gen-random-options"].hidden, true);
  assert.equal(h.elements["#gen-memorable-options"].hidden, false);
  assert.equal(h.elements["#gen-length"].min, "3");
  assert.equal(h.elements["#gen-length"].max, "8");
  assert.equal(h.elements["#gen-length"].value, "4");
  await settleAction(h, request, state("b", { password: "word-word-word-word" }));
  h.fire("#gen-mode", "change", "pin");
  const pin = h.take("generate");
  assert.equal(pin.message.mode, "pin");
  assert.equal(pin.message.length, 6);
  assert.equal(h.elements["#gen-length"].min, "4");
  assert.equal(h.elements["#gen-length"].max, "12");
  await settleAction(h, pin, state("c", { password: "123456" }));
});

test("regenerate requests a fresh password and shows preview with entropy", async () => {
  const h = await ready();
  h.click("#gen-regenerate");
  const request = h.take("generate");
  assert.equal(request.message.mode, "random");
  assert.equal(request.message.length, 24);
  assert.equal(request.message.digits, true);
  assert.equal(request.message.symbols, true);
  assert.equal(request.message.recordHistory, false);
  const response = generatedState("Abc-123-xyz");
  request.resolve(response);
  await flush();
  assert.equal(h.elements["#gen-preview"].textContent, "Abc-123-xyz");
  assert.equal(h.elements["#gen-entropy"].textContent, "100 bits");
  h.take("state").resolve(response);
  await flush();
  assert.equal(h.elements["#gen-copy"].disabled, false);
});

test("generator fill sends the previewed password, not a fresh one", async () => {
  const h = await ready();
  await previewPassword(h);
  assert.equal(h.elements["#gen-fill"].disabled, false);
  h.click("#gen-fill");
  const request = h.take("generator-fill");
  assert.equal(request.message.password, "Preview-123!");
  assert.equal(request.message.mode, "random");
  assert.equal(request.message.recordHistory, undefined);
  const before = h.requests.filter(
    (item) => !item.taken && item.message.type === "generate",
  ).length;
  assert.equal(before, 0);
  await settleAction(h, request, generatedState("Preview-123!", "c"));
  assert.equal(h.elements["#gen-status"].textContent, "正在填充…");
});

test("generator copy uses the clipboard without throwing", async () => {
  const h = await ready();
  await previewPassword(h);
  assert.equal(h.elements["#gen-copy"].disabled, false);
  h.click("#gen-copy");
  await flush();
  await flush();
  assert.deepEqual(h.clipboardWrites, ["Preview-123!"]);
  assert.equal(h.elements["#gen-status"].textContent, "已复制");
});

test("generated history skips malformed entries and fills the selected password", async () => {
  const entry = {
    id: "9".repeat(32),
    origin: "https://example.test",
    username: "alice",
    password: "History-123!",
    profile: {
      mode: "random",
      length: 12,
      alphabet_size: 84,
      entropy_bits_floor: 100,
    },
    createdAt: Date.now(),
  };
  const h = harness();
  h.take("state").resolve(
    state("a", {
      generatedHistory: [
        entry,
        { id: "bad", password: "x" },
        null,
        { id: "8".repeat(32), origin: "https://example.test" },
      ],
    }),
  );
  await flush();
  assert.equal(h.elements["#gen-history"].children.length, 1);
  const row = h.elements["#gen-history"].children[0];
  assert.equal(row.dataset.entryId, entry.id);
  const actions = row.children[2];
  assert.equal(actions.children[0].dataset.action, "fill");
  assert.equal(actions.children[1].dataset.action, "save");
  h.click(actions.children[0]);
  const request = h.take("generator-history-fill");
  assert.equal(request.message.historyId, entry.id);
  const response = state("b", {
    generatedHistory: [entry],
    password: entry.password,
    profile: entry.profile,
  });
  request.resolve(response);
  await flush();
  assert.equal(h.elements["#gen-preview"].textContent, entry.password);
  h.take("state").resolve(response);
  await flush();
  assert.equal(h.elements["#gen-history"].children.length, 1);
});

test("never-save clearing and offer-save setting use dedicated commands", async () => {
  const h = harness();
  const initial = state("a", {
    neverSaveOrigins: ["https://example.test"],
    origin: "https://example.test",
  });
  h.take("state").resolve(initial);
  await flush();
  assert.equal(h.elements["#offer-save-logins"].checked, true);
  assert.equal(h.elements["#clear-never-save"].hidden, false);
  h.click("#clear-never-save");
  const clearRequest = h.take("clear-never-save-origin");
  assert.equal(clearRequest.message.type, "clear-never-save-origin");
  const cleared = state("b", {
    neverSaveOrigins: [],
    origin: "https://example.test",
  });
  clearRequest.resolve(cleared);
  await flush();
  h.take("state").resolve(cleared);
  await flush();
  assert.equal(h.elements["#clear-never-save"].hidden, true);
  h.elements["#offer-save-logins"].checked = false;
  h.fire("#offer-save-logins", "change");
  const settings = h.take("settings");
  assert.equal(settings.message.offerSaveLogins, false);
  const disabled = state("c", {
    neverSaveOrigins: [],
    offerSaveLogins: false,
  });
  settings.resolve(disabled);
  await flush();
  h.take("state").resolve(disabled);
  await flush();
  assert.equal(h.elements["#offer-save-logins"].checked, false);
});

test("generated history save action stages the selected entry", async () => {
  const entry = {
    id: "7".repeat(32),
    origin: "https://example.test",
    username: "alice",
    password: "History-Save-1!",
    profile: {
      mode: "random",
      length: 15,
      alphabet_size: 84,
      entropy_bits_floor: 95,
    },
  };
  const h = harness();
  h.take("state").resolve(state("a", { generatedHistory: [entry] }));
  await flush();
  const actions = h.elements["#gen-history"].children[0].children[2];
  h.click(actions.children[1]);
  const request = h.take("generator-history-save");
  assert.equal(request.message.historyId, entry.id);
  const response = state("b", {
    generatedHistory: [entry],
    pendingSave: pendingSave(),
  });
  request.resolve(response);
  await flush();
  assert.equal(h.elements["#pending-save-banner"].hidden, false);
  h.take("state").resolve(response);
  await flush();
  assert.equal(h.elements["#pending-save-mode"].textContent, "检测到待保存的新登录");
});
test("current-site banner warns for HTTP, vulnerable, weak and reused logins", async () => {
  let h = await ready({
    origin: "",
    site: { origin: "http://example.test/login", unsecured: true },
  });
  let banner = h.elements["#watchtower-site-banner"];
  assert.equal(banner.hidden, false);
  assert.equal(banner.dataset.level, "warning");
  assert.match(
    h.elements["#watchtower-site-badge"].textContent,
    /不安全的 HTTP/,
  );
  assert.match(h.elements["#watchtower-site-text"].textContent, /不建议/);
  assert.equal(h.elements["#watchtower-site-action"].hidden, true);

  h = await ready({
    candidates: [
      {
        id: "1".repeat(32),
        title: "Login",
        revision: "a".repeat(64),
        watchtower_flags: ["vulnerable", "weak"],
      },
    ],
  });
  banner = h.elements["#watchtower-site-banner"];
  assert.equal(banner.hidden, false);
  assert.equal(banner.dataset.level, "critical");
  assert.match(h.elements["#watchtower-site-badge"].textContent, /泄露/);
  assert.equal(h.elements["#watchtower-site-action"].hidden, false);

  for (const flag of ["weak", "reused"]) {
    h = await ready({
      watchtower: report({
        findings: [],
        site_findings: [finding({ flags: [flag] })],
      }),
    });
    banner = h.elements["#watchtower-site-banner"];
    assert.equal(banner.hidden, false, flag);
    assert.equal(banner.dataset.level, "warning", flag);
    assert.match(
      h.elements["#watchtower-site-badge"].textContent,
      /弱密码/,
      flag,
    );
  }

  h = await ready();
  assert.equal(h.elements["#watchtower-site-banner"].hidden, true);
});

test("candidate rows keep fill/update/otp first and append compact health badges", async () => {
  const h = await ready({
    candidates: [
      {
        id: "1".repeat(32),
        title: "Login",
        revision: "a".repeat(64),
        watchtower_flags: [
          "vulnerable",
          "weak",
          "reused",
          "unsecured-http",
          "totp-not-stored",
        ],
        strength_score: 10,
        strength_category: "terrible",
        reuse_count: 2,
        breach_count: 3,
      },
    ],
  });
  const row = h.row();
  assert.deepEqual(
    row.children.slice(0, 3).map((child) => child.dataset.action),
    ["fill", "update", "otp"],
  );
  assert.deepEqual(
    h.badges(row).map((badge) => badge.dataset.wtFlag),
    ["vulnerable", "weak", "reused", "unsecured-http", "totp-not-stored"],
  );
  assert.deepEqual(
    h.badges(row).map((badge) => badge.textContent),
    ["已泄露", "弱密码", "重复密码", "HTTP 不安全", "未设 2FA"],
  );
  assert.equal(h.badges(row)[0].className.includes("wt-red"), true);
  assert.equal(h.badges(row)[1].className.includes("wt-amber"), true);
  assert.equal(h.badges(row)[4].className.includes("wt-neutral"), true);
  assert.equal(
    row.children.filter((child) => child.dataset?.wtFlag === undefined)
      .length,
    4,
    "existing controls remain intact",
  );
});

test("vault panel renders score, six category cards and filtered findings", async () => {
  const h = await ready({ watchtower: report() });
  assert.equal(h.elements["#watchtower-score"].textContent, "42/100");
  assert.equal(h.elements["#watchtower-score-bar"].style.width, "42%");
  assert.equal(h.elements["#watchtower-score-bar"].dataset.level, "red");
  assert.match(h.elements["#watchtower-summary"].textContent, /已检查 4 项/);
  for (const [category, count] of [
    ["vulnerable", "1"],
    ["reused", "1"],
    ["weak", "2"],
    ["unsecured_http", "1"],
    ["totp_not_stored", "3"],
    ["expiring", "1"],
  ])
    assert.equal(
      h.elements[`#watchtower-count-${category}`].textContent,
      count,
      category,
    );
  assert.equal(h.findings().length, 3);

  h.click("#watchtower-card-weak");
  assert.equal(h.findings().length, 1);
  assert.equal(h.findings()[0].children[0].textContent, "Vulnerable");
  assert.equal(
    h.elements["#watchtower-card-weak"].dataset.active,
    "true",
  );
  h.click("#watchtower-card-weak");
  assert.equal(h.findings().length, 3);
  assert.equal(
    h.elements["#watchtower-card-weak"].dataset.active,
    "false",
  );

  h.click("#watchtower-card-vulnerable");
  assert.equal(h.findings().length, 1);
  assert.equal(h.findings()[0].children[0].textContent, "Vulnerable");
  h.click("#watchtower-card-expiring");
  assert.equal(h.findings().length, 1);
  assert.equal(h.findings()[0].children[0].textContent, "Expiring");
});

test("vault panel uses green/amber/red score bands and a clear empty state", async () => {
  for (const [score, level] of [
    [80, "green"],
    [79, "amber"],
    [49, "red"],
  ]) {
    const h = await ready({ watchtower: report({ overall_score: score }) });
    assert.equal(
      h.elements["#watchtower-score-bar"].dataset.level,
      level,
      String(score),
    );
  }

  let h = await ready({
    watchtower: report({ findings: [], site_findings: [] }),
  });
  assert.equal(h.elements["#watchtower-empty"].hidden, false);
  assert.match(h.elements["#watchtower-empty"].textContent, /未发现/);
  assert.equal(h.findings().length, 0);

  h = await ready();
  assert.equal(h.elements["#watchtower-empty"].hidden, false);
  assert.match(h.elements["#watchtower-empty"].textContent, /尚未运行/);
  assert.equal(h.elements["#watchtower-score"].textContent, "—");
});

test("HIBP run is a no-op without opt-in and local refresh always excludes HIBP", async () => {
  const h = await ready({ watchtower: report() });
  const before = h.requests.length;
  h.click("#watchtower-run-hibp");
  assert.equal(h.requests.length, before, "unchecked HIBP run sent a request");
  assert.match(
    h.elements["#watchtower-hibp-note"].textContent,
    /请先勾选/,
  );

  h.elements["#watchtower-hibp-optin"].checked = true;
  h.click("#watchtower-run-hibp");
  const hibp = h.take("watchtower");
  assert.equal(hibp.message.type, "watchtower");
  assert.equal(hibp.message.includeHibp, true);
  await settle(h, hibp);

  h.elements["#watchtower-hibp-optin"].checked = true;
  h.click("#watchtower-refresh");
  const local = h.take("watchtower");
  assert.equal(local.message.includeHibp, false);
  await settle(h, local);
});

test("HIBP opt-in persists through settings and background remains the final gate", async () => {
  const h = await ready();
  h.change("#watchtower-hibp-optin", true);
  const settings = h.take("settings");
  assert.equal(settings.message.type, "settings");
  assert.equal(settings.message.watchtowerHIBP, true);
  settings.resolve(state("a", { watchtowerHIBP: true }));
  await flush();
  h.take("state").resolve(state("a", { watchtowerHIBP: true }));
  await flush();
  assert.equal(h.elements["#watchtower-hibp-optin"].checked, true);
});

test("open-and-change opens only validated HTTPS origins through the background", async () => {
  let h = await ready({
    watchtower: report({
      findings: [finding({ origin: "https://example.test" })],
      site_findings: [finding({ origin: "https://example.test" })],
    }),
  });
  const action = findAction(h.findings()[0], "watchtower-open");
  assert.ok(action);
  assert.equal(action.textContent, "打开并修改");
  h.click(action);
  const findingOpen = h.take("watchtower-open");
  assert.equal(findingOpen.message.type, "watchtower-open");
  assert.equal(findingOpen.message.origin, "https://example.test");
  await settle(h, findingOpen);

  h = await ready({
    candidates: [
      {
        id: "1".repeat(32),
        title: "Login",
        revision: "a".repeat(64),
        watchtower_flags: ["weak"],
      },
    ],
  });
  assert.equal(h.elements["#watchtower-site-action"].hidden, false);
  h.click("#watchtower-site-action");
  const bannerOpen = h.take("watchtower-open");
  assert.equal(bannerOpen.message.type, "watchtower-open");
  assert.equal(bannerOpen.message.origin, "https://example.test");
  await settle(h, bannerOpen);

  h = await ready({
    watchtower: report({
      findings: [finding({ origin: "http://example.test" })],
      site_findings: [],
    }),
  });
  assert.equal(findAction(h.findings()[0], "watchtower-open"), null);
});


test("editor textarea never assigns getter-only type in strict mode", () => {
  const source = fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8");
  const match = source.match(
    /  function addEditorInput\(descriptor, value\) \{[\s\S]*?\n  \}\n  function addCustomField/,
  );
  assert.ok(match, "addEditorInput source not found");
  const functionSource = match[0].replace(/\n  function addCustomField[\s\S]*$/, "");
  const editorFields = { children: [], append(child) { this.children.push(child); } };
  const sandbox = {
    document: {
      createElement(tag) {
        const node = {
          className: "",
          textContent: "",
          dataset: {},
          children: [],
          append(...children) { this.children.push(...children); },
        };
        if (tag === "textarea") {
          node.rows = 0;
          node.value = "";
          Object.defineProperty(node, "type", {
            get() { return "textarea"; },
          });
        } else {
          node.type = "";
        }
        return node;
      },
    },
    els: { editorFields },
    editorInputs: [],
  };
  vm.runInNewContext(
    '"use strict";\n' + functionSource + "\nglobalThis.addEditorInput = addEditorInput;",
    sandbox,
  );
  assert.doesNotThrow(() =>
    sandbox.addEditorInput(
      { name: "urls", label: "网站", type: "textarea" },
      "https://example.test/login",
    ),
  );
  assert.equal(sandbox.editorInputs.length, 1);
  assert.equal(sandbox.editorInputs[0].input.type, "textarea");
  assert.equal(sandbox.editorInputs[0].input.rows, 3);
  assert.equal(sandbox.editorInputs[0].input.value, "https://example.test/login");
});

test("popup CSS always hides hidden menus despite display rules", () => {
  const css = fs.readFileSync(path.join(__dirname, "../popup.css"), "utf8");
  assert.match(css, /\[hidden\]\s*\{\s*display:\s*none\s*!important;?\s*\}/);
});


async function saveEditorHarness(mode) {
  const source = fs.readFileSync(path.join(__dirname, "../popup.js"), "utf8");
  const match = source.match(
    /  async function saveEditor\(\) \{[\s\S]*?\n  \}\n  async function generateEditorPassword/,
  );
  assert.ok(match, "saveEditor source not found");
  const functionSource = match[0].replace(
    /\n  async function generateEditorPassword[\s\S]*$/,
    "",
  );
  const calls = [];
  const sandbox = {
    mode,
    vaultBusy: false,
    editorMode: mode === "edit" ? "edit" : "create",
    lastDetail: { id: "a".repeat(32), revision: "b".repeat(64) },
    lastState: { connected: true },
    vaultLoaded: true,
    els: { editorSave: { disabled: false } },
    api: {
      runtime: {
        async sendMessage(message) {
          assert.equal(sandbox.vaultBusy, true, "busy held during save RPC");
          calls.push(["save", message.mode]);
          return { saved: { item_id: "c".repeat(32), revision: "d".repeat(64) } };
        },
      },
    },
    collectEditorItem: () => ({ title: "Example" }),
    toast: (message) => calls.push(["toast", message]),
    wipeEditor: () => calls.push(["wipeEditor"]),
    wipeDetail: () => calls.push(["wipeDetail"]),
    showView: (name) => calls.push(["showView", name]),
    async openDetail(item) {
      assert.equal(sandbox.vaultBusy, false, "openDetail must not see save busy");
      calls.push(["openDetail", item]);
    },
    async refreshVault(silent) {
      assert.equal(sandbox.vaultBusy, false, "refreshVault must not see save busy");
      calls.push(["refreshVault", silent]);
    },
  };
  vm.runInNewContext(
    '"use strict";\n' + functionSource + "\nglobalThis.saveEditor = saveEditor;",
    sandbox,
  );
  await sandbox.saveEditor();
  return { sandbox, calls };
}

test("saveEditor releases its own busy before edit detail handoff", async () => {
  const { sandbox, calls } = await saveEditorHarness("edit");
  assert.equal(sandbox.vaultBusy, false);
  assert.equal(sandbox.els.editorSave.disabled, false);
  assert.deepEqual(calls.map((call) => call[0]), [
    "save",
    "wipeEditor",
    "toast",
    "openDetail",
  ]);
  const opened = calls.find((call) => call[0] === "openDetail")[1];
  assert.equal(opened.id, "c".repeat(32));
  assert.equal(opened.revision, "d".repeat(64));
  assert.equal(calls.find((call) => call[0] === "toast")[1], "已保存");
});

test("saveEditor releases its own busy before create vault refresh", async () => {
  const { sandbox, calls } = await saveEditorHarness("create");
  assert.equal(sandbox.vaultBusy, false);
  assert.equal(sandbox.els.editorSave.disabled, false);
  assert.deepEqual(calls.map((call) => call[0]), [
    "save",
    "wipeEditor",
    "toast",
    "wipeDetail",
    "showView",
    "refreshVault",
  ]);
  assert.deepEqual(calls.find((call) => call[0] === "showView"), [
    "showView",
    "vault",
  ]);
  assert.deepEqual(calls.find((call) => call[0] === "refreshVault"), [
    "refreshVault",
    true,
  ]);
});

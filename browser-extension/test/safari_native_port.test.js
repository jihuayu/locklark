"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const shim = require("../safari-native-port.js");
const {
  createPort,
  install,
  isSafariRuntime,
  NATIVE_HOST_NAME,
  PROTOCOL_VERSION,
  MAX_FRAME_BYTES,
  MAX_FRAMES_PER_POLL,
} = shim;

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function success(envelope, frames = []) {
  return { v: PROTOCOL_VERSION, token: envelope.token, ok: true, frames };
}

function makeBridge(handler) {
  const calls = [];
  const bridge = (envelope) => {
    calls.push(envelope);
    return Promise.resolve(handler(envelope, calls.length, calls));
  };
  bridge.calls = calls;
  bridge.byOp = (op) => calls.filter((call) => call.op === op);
  return bridge;
}

function openPort(handler, options = {}) {
  const bridge = makeBridge(handler);
  const port = createPort(bridge, {
    pollIntervalMs: 60000,
    callTimeoutMs: 500,
    ...options,
  });
  return { bridge, port };
}

async function closePort(port) {
  try {
    port.disconnect();
  } catch {
    // already closed
  }
  await wait(5);
}

function safariApi(overrides = {}) {
  const runtime = {
    connectNative() {
      throw Error("original connectNative");
    },
    sendNativeMessage() {
      return Promise.resolve({});
    },
    getURL() {
      return "safari-web-extension://4D4C0CC4-1111-2222-3333-444455556666/";
    },
    getManifest() {
      return { manifest_version: 3, background: { scripts: ["background.js"] } };
    },
    ...overrides,
  };
  return { runtime };
}

test("one native send frame per postMessage and no replay", async () => {
  const { bridge, port } = openPort((envelope) => success(envelope));
  await wait(5);
  const first = { v: 1, id: "a".repeat(32), type: "hello" };
  port.postMessage(first);
  first.id = "mutated-after-post";
  port.postMessage({ v: 1, id: "b".repeat(32), type: "match" });
  port.postMessage({ v: 1, id: "c".repeat(32), type: "fill" });
  await wait(20);
  const sends = bridge.byOp("send");
  assert.equal(sends.length, 3);
  assert.equal(sends[0].frame.id, "a".repeat(32));
  for (const send of sends) {
    assert.deepEqual(Object.keys(send).sort(), ["frame", "op", "token", "v"]);
    assert.equal(send.v, PROTOCOL_VERSION);
    assert.equal(send.op, "send");
    assert.match(send.token, /^[a-f0-9]{32}$/);
  }
  assert.equal(bridge.byOp("close").length, 0);
  await closePort(port);
});

test("postMessage after close never reaches native", async () => {
  const { bridge, port } = openPort((envelope) => success(envelope));
  await wait(5);
  port.disconnect();
  assert.equal(port.closed, true);
  assert.throws(() => port.postMessage({ v: 1, id: "x", type: "hello" }));
  await wait(20);
  assert.equal(bridge.byOp("send").length, 0);
  assert.equal(bridge.byOp("close").length, 1);
  assert.equal(port.reason, "disconnected");
});

test("stale response from a closed epoch is ignored", async () => {
  let resolveSend;
  const { bridge, port } = openPort((envelope) => {
    if (envelope.op === "send")
      return new Promise((resolve) => {
        resolveSend = resolve;
      });
    return success(envelope);
  });
  await wait(5);
  const messages = [];
  let disconnects = 0;
  port.onMessage.addListener((message) => messages.push(message));
  port.onDisconnect.addListener(() => disconnects++);
  port.postMessage({ v: 1, id: "d".repeat(32), type: "hello" });
  await wait(5);
  const staleEpoch = port.epoch;
  port.disconnect();
  resolveSend({
    v: PROTOCOL_VERSION,
    token: bridge.byOp("send")[0].token,
    ok: true,
    frames: [{ v: 1, id: "e".repeat(32), type: "locked" }],
  });
  await wait(20);
  assert.notEqual(staleEpoch, port.epoch);
  assert.equal(messages.length, 0);
  assert.equal(disconnects, 1);
  assert.equal(bridge.byOp("send").length, 1);
});

test("bad token reply closes the port without retry", async () => {
  const { bridge, port } = openPort((envelope) => {
    if (envelope.op === "send")
      return { v: PROTOCOL_VERSION, token: "f".repeat(32), ok: true, frames: [] };
    return success(envelope);
  });
  await wait(5);
  port.postMessage({ v: 1, id: "1".repeat(32), type: "hello" });
  await wait(10);
  assert.equal(port.closed, true);
  assert.equal(port.reason, "protocol");
  assert.equal(bridge.byOp("send").length, 1);
  await wait(20);
  assert.equal(bridge.byOp("send").length, 1);
});

test("oversized outgoing frame is refused before any native call", async () => {
  const { bridge, port } = openPort((envelope) => success(envelope));
  await wait(5);
  assert.throws(() =>
    port.postMessage({
      v: 1,
      id: "2".repeat(32),
      type: "hello",
      pad: "x".repeat(MAX_FRAME_BYTES + 1),
    }),
  );
  assert.equal(bridge.byOp("send").length, 0);
  await closePort(port);
});

test("oversized native frame closes the port", async () => {
  const { port } = openPort((envelope) => {
    if (envelope.op === "send")
      return success(envelope, [
        {
          v: 1,
          id: "3".repeat(32),
          type: "locked",
          pad: "x".repeat(MAX_FRAME_BYTES + 1),
        },
      ]);
    return success(envelope);
  });
  await wait(5);
  port.postMessage({ v: 1, id: "4".repeat(32), type: "hello" });
  await wait(10);
  assert.equal(port.closed, true);
  assert.equal(port.reason, "protocol");
});

test("unknown reply keys and non-object frames close the port", async () => {
  for (const reply of [
    (envelope) => ({
      v: PROTOCOL_VERSION,
      token: envelope.token,
      ok: true,
      frames: [],
      error: "raw native detail",
    }),
    (envelope) => ({
      v: PROTOCOL_VERSION,
      token: envelope.token,
      ok: true,
      frames: ["not-an-object"],
    }),
    (envelope) => ({
      v: PROTOCOL_VERSION,
      token: envelope.token,
      ok: true,
      frames: Array.from({ length: MAX_FRAMES_PER_POLL + 1 }, (_, index) => ({
        v: 1,
        id: String(index),
        type: "locked",
      })),
    }),
    (envelope) => ({
      v: 2,
      token: envelope.token,
      ok: true,
      frames: [],
    }),
  ]) {
    const { port } = openPort((envelope) => {
      if (envelope.op === "send") return reply(envelope);
      return success(envelope);
    });
    await wait(5);
    port.postMessage({ v: 1, id: "5".repeat(32), type: "hello" });
    await wait(10);
    assert.equal(port.closed, true);
    assert.equal(port.reason, "protocol");
  }
});

test("native failure reply closes the port and is never retried", async () => {
  const { bridge, port } = openPort((envelope) => {
    if (envelope.op === "send")
      return { v: PROTOCOL_VERSION, token: envelope.token, ok: false };
    return success(envelope);
  });
  await wait(5);
  port.postMessage({ v: 1, id: "6".repeat(32), type: "save-new" });
  await wait(10);
  assert.equal(port.closed, true);
  assert.equal(port.reason, "native-failure");
  assert.equal(bridge.byOp("send").length, 1);
  await wait(30);
  assert.equal(bridge.byOp("send").length, 1);
});

test("rejected native call closes the port as unavailable, no retry", async () => {
  const { bridge, port } = openPort((envelope) => {
    if (envelope.op === "send") throw Error("/private/raw/path");
    return success(envelope);
  });
  await wait(5);
  port.postMessage({ v: 1, id: "7".repeat(32), type: "commit-ready" });
  await wait(10);
  assert.equal(port.closed, true);
  assert.equal(port.reason, "native-unavailable");
  assert.doesNotMatch(port.reason, /private|path/);
  assert.equal(bridge.byOp("send").length, 1);
  await wait(20);
  assert.equal(bridge.byOp("send").length, 1);
});

test("timed out native call closes the port and late replies are ignored", async () => {
  let resolveSend;
  const { bridge, port } = openPort(
    (envelope) => {
      if (envelope.op === "send")
        return new Promise((resolve) => {
          resolveSend = resolve;
        });
      return success(envelope);
    },
    { callTimeoutMs: 25 },
  );
  await wait(5);
  const messages = [];
  port.onMessage.addListener((message) => messages.push(message));
  port.postMessage({ v: 1, id: "8".repeat(32), type: "hello" });
  await wait(70);
  assert.equal(port.closed, true);
  assert.equal(port.reason, "timeout");
  assert.equal(bridge.byOp("send").length, 1);
  resolveSend(success(bridge.byOp("send")[0], [{ v: 1, type: "locked" }]));
  await wait(20);
  assert.equal(messages.length, 0);
  assert.equal(bridge.byOp("send").length, 1);
});

test("polling is bounded to one outstanding request", async () => {
  let active = 0;
  let maxActive = 0;
  const { bridge, port } = openPort(
    (envelope) => {
      if (envelope.op !== "poll") return success(envelope);
      active++;
      maxActive = Math.max(maxActive, active);
      return new Promise((resolve) =>
        setTimeout(() => {
          active--;
          resolve(success(envelope));
        }, 25),
      );
    },
    { pollIntervalMs: 2 },
  );
  await wait(120);
  assert.equal(maxActive, 1);
  const pollsBeforeClose = bridge.byOp("poll").length;
  assert.ok(pollsBeforeClose >= 1);
  assert.ok(pollsBeforeClose <= 6, `poll count ${pollsBeforeClose}`);
  await closePort(port);
  await wait(40);
  assert.equal(bridge.byOp("poll").length, pollsBeforeClose);
});

test("unsolicited poll frames are delivered once and stop after close", async () => {
  let pollCount = 0;
  const { bridge, port } = openPort(
    (envelope) => {
      if (envelope.op !== "poll") return success(envelope);
      pollCount++;
      if (pollCount === 1)
        return success(envelope, [
          { v: 1, id: "9".repeat(32), type: "locked" },
        ]);
      return success(envelope);
    },
    { pollIntervalMs: 5 },
  );
  const messages = [];
  let disconnects = 0;
  port.onMessage.addListener((message) => messages.push(message));
  port.onDisconnect.addListener(() => disconnects++);
  await wait(30);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].type, "locked");
  await wait(30);
  assert.equal(messages.length, 1);
  port.disconnect();
  const pollsAtClose = bridge.byOp("poll").length;
  await wait(40);
  assert.equal(bridge.byOp("poll").length, pollsAtClose);
  assert.equal(disconnects, 1);
});

test("listener exceptions do not cause native retries and do not stop other listeners", async () => {
  const { bridge, port } = openPort((envelope) => {
    if (envelope.op === "send")
      return success(envelope, [{ v: 1, type: "locked" }]);
    return success(envelope);
  });
  await wait(5);
  const received = [];
  port.onMessage.addListener(() => {
    throw Error("listener failure");
  });
  port.onMessage.addListener((message) => received.push(message));
  port.postMessage({ v: 1, id: "a".repeat(31) + "b", type: "hello" });
  await wait(15);
  assert.equal(received.length, 1);
  assert.equal(bridge.byOp("send").length, 1);
  await closePort(port);
});

test("connection tokens are 32 lowercase hex characters and unique", async () => {
  const first = openPort((envelope) => success(envelope));
  const second = openPort((envelope) => success(envelope));
  await wait(5);
  const firstToken = first.bridge.calls[0].token;
  const secondToken = second.bridge.calls[0].token;
  assert.match(firstToken, /^[a-f0-9]{32}$/);
  assert.match(secondToken, /^[a-f0-9]{32}$/);
  assert.notEqual(firstToken, secondToken);
  await closePort(first.port);
  await closePort(second.port);
});

test("explicit token injection is validated", () => {
  assert.throws(() =>
    createPort(() => Promise.resolve({}), { token: "NOT-A-TOKEN" }),
  );
  assert.throws(() =>
    createPort(() => Promise.resolve({}), { token: "a".repeat(31) }),
  );
});

test("install never patches non-Safari runtimes", () => {
  for (const api of [
    safariApi({ getURL: () => "chrome-extension://abc/" }),
    safariApi({ getURL: () => "moz-extension://abc/" }),
    safariApi({
      getURL: () => "safari-web-extension://abc/",
      getManifest: () => ({ manifest_version: 3, key: "chromium-key" }),
    }),
    safariApi({
      getURL: () => "safari-web-extension://abc/",
      getManifest: () => ({
        manifest_version: 3,
        browser_specific_settings: { gecko: { id: "x" } },
      }),
    }),
  ]) {
    const original = api.runtime.connectNative;
    assert.equal(isSafariRuntime(api), false);
    assert.equal(install(api), false);
    assert.equal(api.runtime.connectNative, original);
  }
  assert.equal(
    isSafariRuntime({
      runtime: { getURL: () => "safari-web-extension://abc/" },
    }),
    false,
  );
});

test("install only replaces runtime.connectNative on Safari", async () => {
  const api = safariApi();
  const originalGlobal = globalThis.chrome;
  const runtime = api.runtime;
  const originalSend = runtime.sendNativeMessage;
  const originalConnect = runtime.connectNative;
  assert.equal(install(api), true);
  assert.notEqual(runtime.connectNative, originalConnect);
  assert.equal(runtime.sendNativeMessage, originalSend);
  assert.equal(globalThis.chrome, originalGlobal);
  assert.throws(() => runtime.connectNative("other.host"));
  const port = runtime.connectNative(NATIVE_HOST_NAME);
  assert.equal(typeof port.postMessage, "function");
  assert.equal(port.name, "locklark-native");
  await wait(5);
  await closePort(port);
  assert.equal(install(api), true);
});

test("module exports no mutation, process or file primitives", () => {
  const allowed = [
    "NATIVE_HOST_NAME",
    "PROTOCOL_VERSION",
    "MAX_FRAME_BYTES",
    "MAX_FRAMES_PER_POLL",
    "MAX_REPLY_BYTES",
    "DEFAULT_POLL_INTERVAL_MS",
    "DEFAULT_CALL_TIMEOUT_MS",
    "createPort",
    "install",
    "isSafariRuntime",
  ];
  assert.deepEqual(Object.keys(shim).sort(), allowed.sort());
  for (const name of Object.keys(shim))
    assert.doesNotMatch(
      name,
      /exec|spawn|launch|write|mutate|evaluate|scripting|process/i,
    );
  assert.equal(globalThis.chrome, undefined);
  assert.equal(globalThis.browser, undefined);
});

test("loading in a page-like VM creates only the namespace, no browser patch", () => {
  const source = fs.readFileSync(
    path.join(__dirname, "..", "safari-native-port.js"),
    "utf8",
  );
  const sandbox = {
    TextEncoder,
    crypto: webcrypto,
    setTimeout,
    clearTimeout,
    console,
  };
  vm.runInNewContext(source, sandbox);
  assert.equal(sandbox.chrome, undefined);
  assert.equal(sandbox.browser, undefined);
  assert.equal(typeof sandbox.LocklarkSafariNativePort.createPort, "function");
  assert.equal(Object.keys(sandbox).includes("LocklarkSafariNativePort"), false);
});

test("VM auto-install happens only for a Safari-shaped runtime", async () => {
  const source = fs.readFileSync(
    path.join(__dirname, "..", "safari-native-port.js"),
    "utf8",
  );
  const safari = safariApi();
  const sandbox = {
    TextEncoder,
    crypto: webcrypto,
    setTimeout,
    clearTimeout,
    console,
    chrome: safari,
  };
  vm.runInNewContext(source, sandbox);
  assert.equal(sandbox.browser, undefined);
  assert.notEqual(safari.runtime.connectNative.toString().includes("original"), true);
  const port = safari.runtime.connectNative(NATIVE_HOST_NAME);
  await wait(5);
  port.disconnect();
  assert.equal(port.closed, true);
});

const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

const ORIGIN = "https://example.test";
const SIGNAL_METHODS = [
  ["signalUnknownCredential", "unknown"],
  ["signalAllAcceptedCredentials", "accepted"],
  ["signalCurrentUserDetails", "user"],
];
const flush = async (count = 8) => {
  for (let index = 0; index < count; index++)
    await new Promise((resolve) => setImmediate(resolve));
};
const b64 = (bytes) =>
  Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const credentialId = (fill = 1, size = 32) => b64(new Uint8Array(size).fill(fill));
const userId = (fill = 2, size = 16) => b64(new Uint8Array(size).fill(fill));

const unknownSignal = (extra = {}) => ({
  rpId: "example.test",
  credentialId: credentialId(1),
  ...extra,
});
const acceptedSignal = (extra = {}) => ({
  rpId: "example.test",
  userId: userId(),
  allAcceptedCredentialIds: [credentialId(3), credentialId(4)],
  ...extra,
});
const userSignal = (extra = {}) => ({
  rpId: "example.test",
  userId: userId(),
  name: "User Name",
  displayName: "User Display",
  ...extra,
});

// MAIN-world harness. Every native static signal method, when present, records
// its receiver and arguments and returns a real deferred promise so a test can
// decide whether (and when) the native call settles.
function makeHarness(options = {}) {
  const messages = [];
  const windowListeners = {};
  const timers = new Map();
  const calls = [];
  let timerSerial = 0;
  function PublicKeyCredential() {}
  PublicKeyCredential.prototype = {};
  const methods = options.methods || {};
  const present = options.present || SIGNAL_METHODS.map(([name]) => name);
  for (const [name] of SIGNAL_METHODS) {
    if (!present.includes(name)) continue;
    const custom = methods[name];
    const native = function (...args) {
      const record = { name, self: this, args };
      calls.push(record);
      if (custom) return custom.apply(this, args);
      const promise = new Promise((resolve, reject) => {
        record.resolve = resolve;
        record.reject = reject;
      });
      record.promise = promise;
      return promise;
    };
    Object.defineProperty(PublicKeyCredential, name, {
      configurable: true,
      writable: true,
      value: native,
    });
  }
  if (options.nativeCapabilities)
    PublicKeyCredential.getClientCapabilities = function () {
      return Promise.resolve({ ...options.nativeCapabilities });
    };
  const windowObject = {
    addEventListener(type, listener) {
      (windowListeners[type] = windowListeners[type] || []).push(listener);
    },
    removeEventListener(type, listener) {
      const list = windowListeners[type];
      if (!list) return;
      const index = list.indexOf(listener);
      if (index >= 0) list.splice(index, 1);
    },
    postMessage(data) {
      messages.push(data);
      if (
        data &&
        data.source === "locklark-capability-v1" &&
        typeof data.conditional !== "boolean"
      )
        // Answer the capability handshake so availability probes stay bounded.
        queueMicrotask(() =>
          deliver({
            source: "locklark-capability-v1",
            id: data.id,
            conditional: options.extensionConditional === true,
          }),
        );
    },
  };
  windowObject.top = windowObject;
  windowObject.location = { origin: ORIGIN };
  const context = {
    window: windowObject,
    top: windowObject,
    location: { origin: ORIGIN, protocol: "https:" },
    isSecureContext: true,
    navigator: { credentials: { create: () => {}, get: () => {} } },
    PublicKeyCredential,
    AuthenticatorAttestationResponse: function () {},
    AuthenticatorAssertionResponse: function () {},
    DOMException,
    structuredClone,
    Uint8Array,
    ArrayBuffer,
    crypto: require("node:crypto").webcrypto,
    btoa: (raw) => Buffer.from(raw, "binary").toString("base64"),
    atob: (raw) => Buffer.from(raw, "base64").toString("binary"),
    setTimeout: (fn, ms) => {
      const id = ++timerSerial;
      timers.set(id, { fn, ms });
      return id;
    },
    clearTimeout: (id) => timers.delete(id),
    console: {},
  };
  context.self = context;
  context.globalThis = context;
  context.document = {
    visibilityState: "visible",
    permissionsPolicy: { allowsFeature: () => true },
    featurePolicy: { allowsFeature: () => true },
  };
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../webauthn.js"), "utf8"),
    context,
  );
  function deliver(data) {
    for (const listener of windowListeners.message || [])
      listener({ source: windowObject, origin: ORIGIN, data });
  }
  return {
    PublicKeyCredential,
    calls,
    messages,
    hints: () =>
      messages.filter((message) => message?.source === "locklark-signal-v1"),
    requestPosts: () =>
      messages.filter((message) => message?.source === "locklark-request-v1"),
    resolve: (index, value) => calls[index].resolve(value),
    reject: (index, error) => calls[index].reject(error),
  };
}

test("signalUnknownCredential returns the exact native promise and posts one hint after fulfilment", async () => {
  const h = makeHarness();
  const options = unknownSignal();
  const promise = h.PublicKeyCredential.signalUnknownCredential(options);
  assert.equal(h.calls.length, 1, "the native method is called first");
  assert.equal(h.calls[0].self, h.PublicKeyCredential, "correct receiver");
  assert.equal(h.calls[0].args[0], options, "options identity preserved");
  assert.equal(promise, h.calls[0].promise, "the exact native promise is returned");
  await flush();
  assert.equal(h.hints().length, 0, "no hint before the native promise fulfils");
  h.resolve(0, undefined);
  assert.equal(await promise, undefined);
  await flush();
  const hints = h.hints();
  assert.equal(hints.length, 1, "exactly one hint per fulfilment");
  assert.deepEqual(Object.keys(hints[0]).sort(), ["id", "options", "source"]);
  assert.equal(hints[0].source, "locklark-signal-v1");
  assert.match(hints[0].id, /^[a-f0-9-]{36}$/);
  assert.deepEqual(JSON.parse(hints[0].options), {
    kind: "unknown",
    rpId: "example.test",
    credentialId: credentialId(1),
  });
  assert.equal(h.requestPosts().length, 0, "a hint is not a credential request");
});

test("all three WebAuthn3 dictionaries are wrapped with their exact members", async () => {
  const h = makeHarness();
  const accepted = h.PublicKeyCredential.signalAllAcceptedCredentials(
    acceptedSignal(),
  );
  const user = h.PublicKeyCredential.signalCurrentUserDetails(userSignal());
  h.resolve(0);
  h.resolve(1);
  assert.equal(await accepted, undefined);
  assert.equal(await user, undefined);
  await flush();
  const [first, second] = h.hints().map((hint) => JSON.parse(hint.options));
  assert.deepEqual(first, {
    kind: "accepted",
    rpId: "example.test",
    userId: userId(),
    allAcceptedCredentialIds: [credentialId(3), credentialId(4)],
  });
  assert.deepEqual(second, {
    kind: "user",
    rpId: "example.test",
    userId: userId(),
    name: "User Name",
    displayName: "User Display",
  });
});

test("a rejected native promise is handled and never produces a hint", async () => {
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on("unhandledRejection", onUnhandled);
  try {
    const h = makeHarness();
    const options = unknownSignal();
    const promise = h.PublicKeyCredential.signalUnknownCredential(options);
    h.reject(0, new DOMException("NotAllowedError", "NotAllowedError"));
    await assert.rejects(promise);
    await flush();
    assert.equal(h.hints().length, 0, "a native rejection never yields a hint");
    assert.equal(unhandled.length, 0, "the observer swallows its own rejection");
  } finally {
    process.removeListener("unhandledRejection", onUnhandled);
  }
});

test("a native synchronous throw is rethrown unchanged and posts no hint", async () => {
  const boom = new TypeError("native refused synchronously");
  const h = makeHarness({
    methods: {
      signalUnknownCredential: () => {
        throw boom;
      },
    },
  });
  assert.throws(
    () => h.PublicKeyCredential.signalUnknownCredential(unknownSignal()),
    (error) => error === boom,
  );
  await flush();
  assert.equal(h.hints().length, 0);
});

test("an absent native signal method stays absent and nothing is advertised", async () => {
  const h = makeHarness({
    present: [],
    nativeCapabilities: { hybridTransport: true, conditionalCreate: true },
  });
  for (const [name] of SIGNAL_METHODS)
    assert.equal(
      Object.prototype.hasOwnProperty.call(h.PublicKeyCredential, name),
      false,
      name + " must not be created by the extension",
    );
  const capabilities = await h.PublicKeyCredential.getClientCapabilities.call(
    h.PublicKeyCredential,
  );
  assert.deepEqual(Object.keys(capabilities).sort(), [
    "conditionalCreate",
    "hybridTransport",
  ]);
  assert.equal(
    Object.keys(capabilities).some((key) => /signal/i.test(key)),
    false,
    "no signal capability is invented",
  );
  assert.equal(h.hints().length, 0);
});

test("one present native method is wrapped while the missing ones stay missing", async () => {
  const h = makeHarness({ present: ["signalUnknownCredential"] });
  assert.equal(
    typeof h.PublicKeyCredential.signalUnknownCredential,
    "function",
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      h.PublicKeyCredential,
      "signalAllAcceptedCredentials",
    ),
    false,
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(
      h.PublicKeyCredential,
      "signalCurrentUserDetails",
    ),
    false,
  );
});

test("the hint snapshot is taken before the page can mutate options during the async call", async () => {
  const h = makeHarness();
  const options = unknownSignal();
  const promise = h.PublicKeyCredential.signalUnknownCredential(options);
  options.rpId = "evil.test";
  options.credentialId = credentialId(9);
  options.extra = "private";
  h.resolve(0);
  await promise;
  await flush();
  const [hint] = h.hints();
  assert.ok(hint);
  assert.deepEqual(JSON.parse(hint.options), {
    kind: "unknown",
    rpId: "example.test",
    credentialId: credentialId(1),
  });
  assert.equal(hint.options.includes("evil.test"), false);
  assert.equal(hint.options.includes("private"), false);
});

test("malformed, oversize and unknown-member hints are ignored without changing the native outcome", async () => {
  const cases = [
    unknownSignal({ rpId: "Example.test" }),
    unknownSignal({ rpId: "example.test/login" }),
    unknownSignal({ credentialId: "AAAA" + "=" }),
    unknownSignal({ credentialId: b64(new Uint8Array(1025)) }),
    unknownSignal({ credentialId: "" }),
    acceptedSignal({
      allAcceptedCredentialIds: Array.from({ length: 65 }, (_, i) =>
        credentialId(i + 1),
      ),
    }),
    acceptedSignal({ userId: b64(new Uint8Array(65)) }),
    userSignal({ name: "line\nbreak" }),
    userSignal({ displayName: "null\u0000byte" }),
    userSignal({ name: "\ud800" }),
    userSignal({ name: "x".repeat(1025) }),
    // 64 accepted ids of 1024 bytes exceed the 32 KiB options bound.
    acceptedSignal({
      allAcceptedCredentialIds: Array.from({ length: 64 }, () =>
        b64(new Uint8Array(1024).fill(7)),
      ),
    }),
  ];
  for (const options of cases) {
    const h = makeHarness();
    const promise = h.PublicKeyCredential.signalUnknownCredential(options);
    assert.equal(promise, h.calls[0].promise, "the native promise is returned");
    h.resolve(0, "value");
    assert.equal(await promise, "value");
    await flush();
    assert.equal(h.hints().length, 0, JSON.stringify(options).slice(0, 120));
  }
});

test("page members outside the allowlist are dropped from the hint", async () => {
  const h = makeHarness();
  const options = unknownSignal({ extra: "member", nested: { private: 1 } });
  const promise = h.PublicKeyCredential.signalUnknownCredential(options);
  h.resolve(0);
  await promise;
  await flush();
  const [hint] = h.hints();
  assert.ok(hint);
  assert.deepEqual(Object.keys(JSON.parse(hint.options)).sort(), [
    "credentialId",
    "kind",
    "rpId",
  ]);
  assert.equal(hint.options.includes("nested"), false);
});

test("a throwing member getter is ignored and the native call keeps its outcome", async () => {
  const h = makeHarness();
  const options = {
    get rpId() {
      throw new Error("hostile getter");
    },
    credentialId: credentialId(1),
  };
  const promise = h.PublicKeyCredential.signalUnknownCredential(options);
  assert.equal(promise, h.calls[0].promise);
  h.resolve(0, "ok");
  assert.equal(await promise, "ok");
  await flush();
  assert.equal(h.hints().length, 0);
  assert.equal(h.messages.some((m) => m?.source === "locklark-signal-v1"), false);
});

test("a non-thenable native return value is returned as-is and posts no hint", async () => {
  const marker = { value: 1 };
  const h = makeHarness({
    methods: {
      signalUnknownCredential: () => marker,
    },
  });
  const result = h.PublicKeyCredential.signalUnknownCredential(unknownSignal());
  assert.equal(result, marker, "the exact returned object is preserved");
  await flush();
  assert.equal(h.hints().length, 0, "only a fulfilled promise may hint");
});

test("the wrapper preserves a caller-supplied receiver", async () => {
  const h = makeHarness();
  const receiver = { custom: true };
  const promise = h.PublicKeyCredential.signalCurrentUserDetails.call(
    receiver,
    userSignal(),
  );
  assert.equal(h.calls[0].self, receiver, "this is forwarded unchanged");
  h.resolve(0);
  await promise;
  await flush();
  assert.equal(h.hints().length, 1);
});

test("a hint never carries candidate or private bytes beyond the allowlisted members", async () => {
  const h = makeHarness();
  const options = {
    ...userSignal(),
    userHandle: b64(new Uint8Array(8).fill(1)),
    privateKey: "secret",
  };
  const promise = h.PublicKeyCredential.signalCurrentUserDetails(options);
  h.resolve(0);
  await promise;
  await flush();
  const [hint] = h.hints();
  assert.deepEqual(Object.keys(JSON.parse(hint.options)).sort(), [
    "displayName",
    "kind",
    "name",
    "rpId",
    "userId",
  ]);
  const wire = JSON.stringify(h.messages);
  assert.equal(wire.includes("privateKey"), false);
  assert.equal(wire.includes("secret"), false);
  assert.equal(hint.options.includes("userHandle"), false);
});

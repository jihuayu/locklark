const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

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

// Deterministic stand-in for an AbortSignal: lets a test abort at an exact
// point and observe whether the MAIN-world code released its listener.
function makeAbortSignal() {
  let aborted = false;
  const listeners = new Map();
  const signal = {
    get aborted() {
      return aborted;
    },
    addEventListener(type, listener, listenerOptions) {
      if (type !== "abort") return;
      listeners.set(listener, listenerOptions?.once === true);
    },
    removeEventListener(type, listener) {
      if (type === "abort") listeners.delete(listener);
    },
  };
  return {
    signal,
    get listenerCount() {
      return listeners.size;
    },
    abort() {
      if (aborted) return;
      aborted = true;
      for (const [listener, once] of [...listeners]) {
        if (once) listeners.delete(listener);
        listener({ type: "abort" });
      }
    },
  };
}

function makeHarness(options = {}) {
  const messages = [];
  const windowListeners = {};
  const timers = new Map();
  const nativeGet = [];
  const nativeCreate = [];
  const nativeConditionalCalls = [];
  const extensionConditional = options.extensionConditional === true;
  const deferCapabilityReplies = options.deferCapabilityReplies === true;
  const heldCapabilityQueries = [];
  let replyCapability = options.replyCapability !== false;
  let timerSerial = 0;
  function PublicKeyCredential() {}
  function AuthenticatorAttestationResponse() {}
  function AuthenticatorAssertionResponse() {}
  PublicKeyCredential.prototype = {};
  AuthenticatorAttestationResponse.prototype = {};
  AuthenticatorAssertionResponse.prototype = {};
  const nativeConditional = function () {
    nativeConditionalCalls.push(this);
    return Promise.resolve(options.nativeConditional === true);
  };
  PublicKeyCredential.isConditionalMediationAvailable = nativeConditional;
  if (options.nativeCapabilities)
    PublicKeyCredential.getClientCapabilities = function () {
      nativeConditionalCalls.push(this);
      return Promise.resolve({ ...options.nativeCapabilities });
    };
  const windowObject = {
    listeners: windowListeners,
    addEventListener(type, listener) {
      (windowListeners[type] = windowListeners[type] || []).push(listener);
    },
    removeEventListener(type, listener) {
      const list = windowListeners[type];
      if (!list) return;
      const index = list.indexOf(listener);
      if (index >= 0) list.splice(index, 1);
    },
    postMessage(data, origin) {
      messages.push(data);
      // A real browser delivers window.postMessage back to every same-window
      // listener, including the MAIN listener that just posted it.
      queueMicrotask(() => deliver(data));
      if (
        data &&
        data.source === "locklark-capability-v1" &&
        typeof data.conditional !== "boolean"
      ) {
        // Deferred mode holds the handshake open so a test can cancel while the
        // capability reply is still outstanding.
        if (deferCapabilityReplies) {
          heldCapabilityQueries.push(data);
          return;
        }
        if (replyCapability)
          queueMicrotask(() =>
            deliver({
              source: "locklark-capability-v1",
              id: data.id,
              conditional: extensionConditional,
            }),
          );
      }
    },
  };
  windowObject.top = windowObject;
  windowObject.location = { origin: "https://example.test" };
  const context = {
    window: windowObject,
    top: windowObject,
    self: windowObject,
    location: { origin: "https://example.test", protocol: "https:" },
    isSecureContext: true,
    navigator: {
      credentials: {
        create: (opts) => {
          nativeCreate.push(opts);
          return Promise.resolve("native-create");
        },
        get: (opts) => {
          nativeGet.push(opts);
          return Promise.resolve("native-get");
        },
      },
    },
    PublicKeyCredential,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
    DOMException,
    structuredClone,
    Uint8Array,
    ArrayBuffer,
    TextEncoder,
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
  context.document = {
    visibilityState: options.visibilityState || "visible",
    permissionsPolicy: { allowsFeature: () => true },
    featurePolicy: { allowsFeature: () => true },
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../webauthn.js"), "utf8"),
    context,
  );
  function deliver(data) {
    for (const listener of windowListeners.message || [])
      listener({ source: windowObject, origin: "https://example.test", data });
  }
  function fireTimer(predicate) {
    const found = [...timers].find(([, timer]) => predicate(timer.ms));
    assert.ok(found, "expected timer");
    timers.delete(found[0]);
    found[1].fn();
    return found[1].ms;
  }
  return {
    messages,
    timers,
    nativeGet,
    nativeCreate,
    nativeConditionalCalls,
    PublicKeyCredential,
    navigator: context.navigator,
    window: windowObject,
    deliver,
    fireTimer,
    disableCapabilityReplies: () => (replyCapability = false),
    capabilityQueries: () =>
      messages.filter(
        (m) =>
          m &&
          m.source === "locklark-capability-v1" &&
          typeof m.conditional !== "boolean",
      ),
    replyCapabilities: (value = extensionConditional) => {
      const held = heldCapabilityQueries.splice(0);
      for (const data of held)
        deliver({
          source: "locklark-capability-v1",
          id: data.id,
          conditional: value,
        });
    },
    listenerCount: (type) => (windowListeners[type] || []).length,
    requests: (type) =>
      messages.filter((m) => m.source === "locklark-request-v1" && m.type === type),
    pagehide: () => {
      for (const listener of windowListeners.pagehide || []) listener({});
    },
  };
}

const credentialPayload = (id) => ({
  id: "credential-id",
  rawId: b64(Uint8Array.from([1, 2, 3, 4])),
  authenticatorAttachment: "platform",
  response: {
    clientDataJSON: b64(Uint8Array.from([5, 6, 7])),
    authenticatorData: b64(Uint8Array.from([8])),
    signature: b64(Uint8Array.from([9])),
  },
  clientExtensionResults: {},
});

const createOptions = (extra = {}) => ({
  publicKey: {
    challenge: Uint8Array.from([1, 2, 3, 4]),
    rp: { id: "example.test", name: "Example" },
    user: {
      id: Uint8Array.from([7, 7]),
      name: "user@example.test",
      displayName: "User",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -257 }],
    ...extra,
  },
});

const conditionalOptions = (extra = {}) => ({
  mediation: "conditional",
  publicKey: {
    challenge: Uint8Array.from([1, 2, 3, 4]),
    rpId: "example.test",
    timeout: 300000,
    userVerification: "required",
    ...extra,
  },
});

test("conditional get never arms the 120s timer and ignores publicKey.timeout", async () => {
  const h = makeHarness({ extensionConditional: true });
  const promise = h.navigator.credentials.get(conditionalOptions());
  await flush();
  const request = h.requests("get")[0];
  assert.ok(request, "request posted to the isolated bridge");
  assert.equal(request.conditional, true);
  const serialized = JSON.parse(request.options);
  assert.equal(serialized.timeout, undefined);
  assert.equal(serialized.challenge, b64(Uint8Array.from([1, 2, 3, 4])));
  assert.equal(h.timers.size, 0, "no conditional timeout timer is armed");
  h.deliver({
    source: "locklark-result-v1",
    id: request.id,
    credential: credentialPayload(),
  });
  const result = await promise;
  assert.equal(result.id, "credential-id");
  assert.equal(result.type, "public-key");
  assert.equal(h.nativeGet.length, 0);
  assert.equal(h.messages.some((m) => "passkeys" in m), false);
});

test("normal get keeps the baseline 120s timeout behaviour", async () => {
  const h = makeHarness({ extensionConditional: true });
  const pending = h.navigator.credentials.get({
    publicKey: {
      challenge: Uint8Array.from([1]),
      rpId: "example.test",
      timeout: 5000,
    },
  });
  await flush();
  const request = h.requests("get")[0];
  assert.ok(request);
  assert.equal(request.conditional, false);
  assert.equal(JSON.parse(request.options).timeout, 5000);
  assert.equal(h.timers.size, 1);
  assert.equal([...h.timers.values()][0].ms, 5000);
  h.deliver({ source: "locklark-result-v1", id: request.id, fallback: true });
  assert.equal(await pending, "native-get");
});

test("old host without the capability falls back to the browser conditional UI", async () => {
  const h = makeHarness({ extensionConditional: false });
  const result = await h.navigator.credentials.get(conditionalOptions());
  assert.equal(result, "native-get");
  assert.equal(h.nativeGet.length, 1);
  assert.equal(h.requests("get").length, 0);
  assert.equal(h.timers.size, 0);
});

test("a silent isolated bridge is bounded by the <=1s capability handshake", async () => {
  const h = makeHarness({ extensionConditional: true });
  h.disableCapabilityReplies();
  const promise = h.navigator.credentials.get(conditionalOptions());
  await flush();
  assert.equal(h.requests("get").length, 0);
  const ms = h.fireTimer((value) => value > 0);
  assert.ok(ms <= 1000, "handshake timeout is bounded to one second");
  await flush();
  assert.equal(await promise, "native-get");
  assert.equal(h.nativeGet.length, 1);
});

test("abort posts cancel, rejects AbortError and leaves no pending call", async () => {
  const h = makeHarness({ extensionConditional: true });
  const controller = new AbortController();
  const promise = h.navigator.credentials.get({
    ...conditionalOptions(),
    signal: controller.signal,
  });
  await flush();
  const request = h.requests("get")[0];
  assert.ok(request);
  controller.abort();
  await assert.rejects(promise, /aborted|Abort/i);
  const cancel = h.messages.find(
    (m) => m.source === "locklark-request-v1" && m.type === "cancel",
  );
  assert.ok(cancel);
  assert.equal(cancel.id, request.id);
  h.deliver({
    source: "locklark-result-v1",
    id: request.id,
    credential: credentialPayload(),
  });
  assert.equal(h.timers.size, 0);
});

test("pagehide aborts the conditional wait and clears the pending call", async () => {
  const h = makeHarness({ extensionConditional: true });
  const promise = h.navigator.credentials.get(conditionalOptions());
  await flush();
  const request = h.requests("get")[0];
  h.pagehide();
  await assert.rejects(promise, /aborted|Abort/i);
  h.deliver({
    source: "locklark-result-v1",
    id: request.id,
    credential: credentialPayload(),
  });
  assert.equal(h.nativeGet.length, 0);
});

test("unsupported extensions still delegate to the native browser call", async () => {
  const h = makeHarness({ extensionConditional: true });
  const result = await h.navigator.credentials.get(
    conditionalOptions({ extensions: { largeBlob: { support: "required" } } }),
  );
  assert.equal(result, "native-get");
  assert.equal(h.requests("get").length, 0);
  const crossPlatform = makeHarness({ extensionConditional: true });
  const second = await crossPlatform.navigator.credentials.get({
    ...conditionalOptions(),
    publicKey: {
      ...conditionalOptions().publicKey,
      authenticatorSelection: { authenticatorAttachment: "cross-platform" },
    },
  });
  assert.equal(second, "native-get");
  assert.equal(crossPlatform.requests("get").length, 0);
});

test("isConditionalMediationAvailable ORs the native answer with the extension boolean", async () => {
  const h = makeHarness({ extensionConditional: true, nativeConditional: false });
  const value = await h.PublicKeyCredential.isConditionalMediationAvailable.call(
    h.PublicKeyCredential,
  );
  assert.equal(value, true);
  assert.equal(h.nativeConditionalCalls.length >= 1, true);
  assert.equal(h.nativeConditionalCalls.at(-1), h.PublicKeyCredential);
  const plain = makeHarness({
    extensionConditional: false,
    nativeConditional: false,
  });
  assert.equal(
    await plain.PublicKeyCredential.isConditionalMediationAvailable(),
    false,
  );
  const nativeOnly = makeHarness({
    extensionConditional: false,
    nativeConditional: true,
  });
  assert.equal(
    await nativeOnly.PublicKeyCredential.isConditionalMediationAvailable(),
    true,
  );
});

test("getClientCapabilities preserves native keys sorted and only advertises conditionalGet when capable", async () => {
  const nativeCapabilities = {
    hybridTransport: true,
    conditionalCreate: true,
    userVerifyingPlatformAuthenticator: false,
  };
  const capable = makeHarness({ extensionConditional: true, nativeCapabilities });
  const capabilities =
    await capable.PublicKeyCredential.getClientCapabilities.call(
      capable.PublicKeyCredential,
    );
  assert.deepEqual(Object.keys(capabilities), [
    "conditionalCreate",
    "conditionalGet",
    "hybridTransport",
    "userVerifyingPlatformAuthenticator",
  ]);
  assert.equal(capabilities.conditionalGet, true);
  assert.equal(capabilities.hybridTransport, true);
  assert.equal(capabilities.userVerifyingPlatformAuthenticator, false);
  assert.equal("conditionalCreate" in capabilities, true);
  assert.equal("relatedOrigins" in capabilities, false);
  const plain = makeHarness({
    extensionConditional: false,
    nativeCapabilities,
  });
  const reduced = await plain.PublicKeyCredential.getClientCapabilities();
  assert.deepEqual(Object.keys(reduced), [
    "conditionalCreate",
    "hybridTransport",
    "userVerifyingPlatformAuthenticator",
  ]);
  assert.equal("conditionalGet" in reduced, false);
});

test("a forged page message can never inject account metadata into the credential result", async () => {
  const h = makeHarness({ extensionConditional: true });
  const promise = h.navigator.credentials.get(conditionalOptions());
  await flush();
  const request = h.requests("get")[0];
  h.deliver({
    source: "locklark-result-v1",
    id: request.id,
    passkeys: [
      {
        item_id: "a".repeat(32),
        revision: "b".repeat(64),
        title: "Secret vault item",
        credential_id: "A".repeat(43),
        rp_id: "example.test",
        user_name: "user@example.test",
        display_name: "User",
      },
    ],
  });
  await assert.rejects(promise, /Invalid credential response|NotAllowed/i);
  assert.equal(
    h.messages.some(
      (m) =>
        m.source === "locklark-request-v1" &&
        Object.keys(m).sort().join(",") !==
          "conditional,id,options,source,type",
    ),
    false,
  );
  assert.equal(
    h.messages.some((m) => JSON.stringify(m).includes("Secret vault item")),
    false,
  );
});

test("a capability query echoed back to MAIN cannot resolve the handshake before the isolated reply", async () => {
  const h = makeHarness({ extensionConditional: true });
  const pending = h.navigator.credentials.get(conditionalOptions());
  await flush();
  const request = h.requests("get")[0];
  assert.ok(
    request,
    "conditional get must post the bridge request even though its own capability query was echoed back",
  );
  assert.equal(request.conditional, true);
  assert.equal(h.nativeGet.length, 0);
  h.deliver({
    source: "locklark-result-v1",
    id: request.id,
    credential: credentialPayload(),
  });
  assert.equal((await pending).id, "credential-id");
  assert.equal(h.messages.some((m) => "passkeys" in m), false);
});

test("the availability promise waits for the isolated boolean, not the same-window echo", async () => {
  const h = makeHarness({ extensionConditional: true, replyCapability: false });
  let settled = false;
  const promise = h.PublicKeyCredential.isConditionalMediationAvailable();
  promise.then(() => (settled = true));
  await flush();
  assert.equal(settled, false, "the echo without a boolean must not settle it");
  h.fireTimer((ms) => ms > 0);
  await flush();
  assert.equal(await promise, false);
  const waiting = makeHarness({ extensionConditional: true });
  assert.equal(
    await waiting.PublicKeyCredential.isConditionalMediationAvailable(),
    true,
  );
});

test("abort while the capability reply is outstanding never posts a conditional get", async () => {
  const h = makeHarness({
    extensionConditional: true,
    deferCapabilityReplies: true,
  });
  const controller = makeAbortSignal();
  const promise = h.navigator.credentials.get({
    ...conditionalOptions(),
    signal: controller.signal,
  });
  await flush();
  assert.equal(h.capabilityQueries().length, 1, "handshake is still in flight");
  assert.equal(h.requests("get").length, 0);
  assert.equal(h.listenerCount("pagehide"), 1);
  controller.abort();
  await assert.rejects(promise, /aborted|Abort/i);
  assert.equal(controller.listenerCount, 0, "abort listener released");
  assert.equal(h.listenerCount("pagehide"), 0, "pagehide listener released");
  assert.equal(h.timers.size, 0, "capability waiter timer cleared");
  assert.equal(
    h.messages.some((m) => m.type === "cancel"),
    false,
    "nothing was posted, so nothing needs cancelling",
  );
  // The late capability reply must not resurrect the cancelled request.
  h.replyCapabilities(true);
  await flush();
  assert.equal(h.requests("get").length, 0);
  assert.equal(h.nativeGet.length, 0);
});

test("abort while an unavailable capability is outstanding never invokes native get", async () => {
  const h = makeHarness({
    extensionConditional: false,
    deferCapabilityReplies: true,
  });
  const controller = makeAbortSignal();
  const promise = h.navigator.credentials.get({
    ...conditionalOptions(),
    signal: controller.signal,
  });
  await flush();
  assert.equal(h.capabilityQueries().length, 1);
  controller.abort();
  await assert.rejects(promise, /aborted|Abort/i);
  h.replyCapabilities(false);
  await flush();
  assert.equal(
    h.nativeGet.length,
    0,
    "an aborted call must not reach the native browser operation after the handshake",
  );
  assert.equal(h.requests("get").length, 0);
  assert.equal(h.timers.size, 0);
  assert.equal(controller.listenerCount, 0);
  assert.equal(h.listenerCount("pagehide"), 0);
});

test("pagehide while the capability reply is outstanding does not revive the request", async () => {
  const h = makeHarness({
    extensionConditional: true,
    deferCapabilityReplies: true,
  });
  const promise = h.navigator.credentials.get(conditionalOptions());
  await flush();
  assert.equal(h.capabilityQueries().length, 1);
  assert.equal(h.listenerCount("pagehide"), 1);
  h.pagehide();
  await assert.rejects(promise, /aborted|Abort/i);
  assert.equal(h.listenerCount("pagehide"), 0);
  assert.equal(h.timers.size, 0, "capability waiter timer cleared");
  h.replyCapabilities(true);
  await flush();
  assert.equal(h.requests("get").length, 0);
  assert.equal(h.nativeGet.length, 0);
});

test("a legitimate unavailable fallback keeps the original options and leaks no listeners", async () => {
  const h = makeHarness({
    extensionConditional: false,
    deferCapabilityReplies: true,
  });
  const controller = makeAbortSignal();
  const options = { ...conditionalOptions(), signal: controller.signal };
  const promise = h.navigator.credentials.get(options);
  await flush();
  assert.equal(h.capabilityQueries().length, 1);
  h.replyCapabilities(false);
  assert.equal(await promise, "native-get");
  assert.equal(h.nativeGet.length, 1);
  assert.equal(h.nativeGet[0], options, "native receives the original options object");
  assert.equal(h.nativeGet[0].mediation, "conditional");
  assert.equal(h.nativeGet[0].publicKey, options.publicKey);
  assert.equal(h.nativeGet[0].publicKey.timeout, 300000);
  assert.deepEqual([...h.nativeGet[0].publicKey.challenge], [1, 2, 3, 4]);
  assert.equal(h.nativeGet[0].signal, controller.signal);
  assert.equal(controller.listenerCount, 0, "abort listener released");
  assert.equal(h.listenerCount("pagehide"), 0, "pagehide listener released");
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests("get").length, 0);
});

test("a settled conditional get releases its listeners and ignores later aborts", async () => {
  const h = makeHarness({ extensionConditional: true });
  const controller = makeAbortSignal();
  const promise = h.navigator.credentials.get({
    ...conditionalOptions(),
    signal: controller.signal,
  });
  await flush();
  const request = h.requests("get")[0];
  assert.ok(request);
  assert.equal(controller.listenerCount, 1);
  assert.equal(h.listenerCount("pagehide"), 1);
  h.deliver({
    source: "locklark-result-v1",
    id: request.id,
    credential: credentialPayload(),
  });
  assert.equal((await promise).id, "credential-id");
  assert.equal(controller.listenerCount, 0, "abort listener released");
  assert.equal(h.listenerCount("pagehide"), 0, "pagehide listener released");
  controller.abort();
  await flush();
  assert.equal(
    h.messages.some((m) => m.type === "cancel"),
    false,
    "a late abort must not post a cancel for a settled call",
  );
  assert.equal(h.timers.size, 0);
});

test("an abort that lands between the fallback decision and the native call still wins", async () => {
  const h = makeHarness({
    extensionConditional: false,
    deferCapabilityReplies: true,
  });
  const controller = makeAbortSignal();
  const promise = h.navigator.credentials.get({
    ...conditionalOptions(),
    signal: controller.signal,
  });
  await flush();
  assert.equal(h.capabilityQueries().length, 1);
  // Resolving the handshake synchronously queues the fallback decision first;
  // the abort then lands while the decision is still being processed, after the
  // abort listener has already been removed.
  h.replyCapabilities(false);
  queueMicrotask(() => controller.abort());
  await assert.rejects(promise, /aborted|Abort/i);
  await flush();
  assert.equal(
    h.nativeGet.length,
    0,
    "the native conditional call must not start after cancellation",
  );
  assert.equal(h.requests("get").length, 0);
});

test("RS256-only create falls back to the browser's authenticator untouched", async () => {
  const h = makeHarness({ extensionConditional: true });
  const options = createOptions();
  assert.equal(await h.navigator.credentials.create(options), "native-create");
  assert.equal(h.nativeCreate.length, 1);
  assert.equal(h.nativeCreate[0], options, "native receives the original options");
  assert.equal(h.nativeCreate[0].publicKey.pubKeyCredParams[0].alg, -257);
  assert.equal(h.requests("create").length, 0);
  assert.equal(h.timers.size, 0);
});

test("an over-long create list with ES256 first still falls back to the browser", async () => {
  const h = makeHarness({ extensionConditional: true });
  const pubKeyCredParams = [{ type: "public-key", alg: -7 }];
  for (let index = 0; index < 32; index++)
    pubKeyCredParams.push({ type: "public-key", alg: -257 });
  assert.equal(pubKeyCredParams.length, 33);
  const options = createOptions({ pubKeyCredParams });
  assert.equal(await h.navigator.credentials.create(options), "native-create");
  assert.equal(h.nativeCreate.length, 1);
  assert.equal(h.nativeCreate[0], options, "native receives the original options");
  assert.equal(h.nativeCreate[0].publicKey.pubKeyCredParams.length, 33);
  assert.equal(h.requests("create").length, 0, "no bridge request for a list the host refuses");
  assert.equal(h.timers.size, 0);
});

test("EdDSA-only create falls back to the browser's authenticator untouched", async () => {
  const h = makeHarness({ extensionConditional: true });
  const options = createOptions({
    pubKeyCredParams: [
      { type: "public-key", alg: -8 },
      { type: "public-key", alg: -257 },
    ],
  });
  assert.equal(await h.navigator.credentials.create(options), "native-create");
  assert.equal(h.nativeCreate.length, 1);
  assert.equal(h.nativeCreate[0], options);
  assert.equal(h.requests("create").length, 0);
  assert.equal(h.timers.size, 0);
});

test("a create list mixing ES256 with other algorithms stays with the extension and aborts cleanly", async () => {
  const h = makeHarness({ extensionConditional: true });
  const controller = makeAbortSignal();
  const options = createOptions({
    pubKeyCredParams: [
      { type: "public-key", alg: -257 },
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -8 },
    ],
  });
  options.signal = controller.signal;
  const promise = h.navigator.credentials.create(options);
  await flush();
  const request = h.requests("create")[0];
  assert.ok(request, "ES256-capable list is intercepted by the extension");
  assert.equal(JSON.parse(request.options).pubKeyCredParams.length, 3);
  assert.equal(controller.listenerCount, 1);
  controller.abort();
  await assert.rejects(promise, /aborted|Abort/i);
  assert.equal(
    h.messages.filter((m) => m.source === "locklark-request-v1" && m.type === "cancel")[0].id,
    request.id,
  );
  assert.equal(h.nativeCreate.length, 0);
  assert.equal(controller.listenerCount, 0, "abort listener released");
  assert.equal(h.listenerCount("pagehide"), 0);
  assert.equal(h.timers.size, 0, "create timer cleared");
});

test("enterprise or unknown attestation create delegates to the browser", async () => {
  for (const attestation of ["enterprise", "vendor-specific"]) {
    const h = makeHarness({ extensionConditional: true });
    const options = createOptions({ attestation });
    assert.equal(await h.navigator.credentials.create(options), "native-create");
    assert.equal(h.nativeCreate.length, 1, attestation + " must reach the native authenticator");
    assert.equal(h.nativeCreate[0], options);
    assert.equal(h.nativeCreate[0].publicKey.attestation, attestation);
    assert.equal(h.requests("create").length, 0);
    assert.equal(h.timers.size, 0);
  }
  const direct = makeHarness({ extensionConditional: true });
  const supported = createOptions({
    attestation: "direct",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  });
  const promise = direct.navigator.credentials.create(supported);
  await flush();
  const request = direct.requests("create")[0];
  assert.ok(request, "standard attestation values stay with the extension");
  direct.deliver({ source: "locklark-result-v1", id: request.id, fallback: true });
  assert.equal(await promise, "native-create");
  assert.equal(direct.nativeCreate[0], supported);
});

test("unsupported create extensions and cross-platform selection still delegate natively", async () => {
  const h = makeHarness({ extensionConditional: true });
  const prf = createOptions({ extensions: { prf: {} } });
  assert.equal(await h.navigator.credentials.create(prf), "native-create");
  const crossPlatform = createOptions({
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { authenticatorAttachment: "cross-platform" },
  });
  assert.equal(await h.navigator.credentials.create(crossPlatform), "native-create");
  assert.equal(h.nativeCreate.length, 2);
  assert.equal(h.nativeCreate[0], prf);
  assert.equal(h.nativeCreate[1], crossPlatform);
  assert.equal(h.requests("create").length, 0);
  assert.equal(h.timers.size, 0);
});

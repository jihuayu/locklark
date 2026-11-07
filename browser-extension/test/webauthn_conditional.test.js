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
  const nativeGetError = options.nativeGetError;
  const nativeCreateError = options.nativeCreateError;
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
  windowObject.location = {
    origin: "https://example.test",
    hostname: options.hostname || "example.test",
  };
  const context = {
    window: windowObject,
    top: windowObject,
    self: windowObject,
    location: {
      origin: "https://example.test",
      hostname: options.hostname || "example.test",
      protocol: "https:",
    },
    isSecureContext: true,
    navigator: {
      credentials: {
        create: (opts) => {
          nativeCreate.push(opts);
          return nativeCreateError
            ? Promise.reject(nativeCreateError)
            : Promise.resolve("native-create");
        },
        get: (opts) => {
          nativeGet.push(opts);
          return nativeGetError
            ? Promise.reject(nativeGetError)
            : Promise.resolve("native-get");
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

// Issue 39 routing contract: the MAIN-world shim only routes. A page-supplied
// RP hint that is plainly outside this document's host belongs to the browser,
// which alone owns related-origin and ".well-known" resolution. Nothing local
// normalizes hints, queries the network or claims related-origin support.
const es256Create = (rp) =>
  createOptions({
    rp: { id: rp, name: "Example" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  });

test("a plainly foreign rp.id delegates create to the original call once", async () => {
  const h = makeHarness({ extensionConditional: true });
  const options = es256Create("foreign.test");
  assert.equal(await h.navigator.credentials.create(options), "native-create");
  assert.equal(h.nativeCreate.length, 1, "the original call runs exactly once");
  assert.equal(h.nativeCreate[0], options, "original options identity");
  assert.equal(h.nativeCreate[0].publicKey.rp.id, "foreign.test");
  assert.equal(h.requests("create").length, 0, "no bridge request");
  assert.equal(h.messages.length, 0, "nothing posted to the page bridge");
  assert.equal(h.timers.size, 0);
  for (const rp of ["foreign.test", "example.test.evil", "notexample.test"]) {
    const other = makeHarness({ extensionConditional: true });
    const opts = es256Create(rp);
    assert.equal(await other.navigator.credentials.create(opts), "native-create");
    assert.equal(other.nativeCreate[0], opts);
    assert.equal(other.requests("create").length, 0);
  }
});

test("a plainly foreign rpId delegates get with no capability handshake", async () => {
  const h = makeHarness({
    extensionConditional: true,
    deferCapabilityReplies: true,
  });
  const options = {
    mediation: "conditional",
    publicKey: {
      challenge: Uint8Array.from([1, 2, 3, 4]),
      rpId: "foreign.test",
      timeout: 300000,
    },
  };
  assert.equal(await h.navigator.credentials.get(options), "native-get");
  assert.equal(h.nativeGet.length, 1);
  assert.equal(h.nativeGet[0], options, "original options identity");
  assert.equal(h.nativeGet[0].publicKey.rpId, "foreign.test");
  assert.equal(h.nativeGet[0].mediation, "conditional");
  assert.equal(h.nativeGet[0].publicKey.timeout, 300000, "no local rewrite");
  assert.equal(h.capabilityQueries().length, 0);
  assert.equal(h.requests("get").length, 0);
  assert.equal(h.messages.length, 0);
  assert.equal(h.listenerCount("pagehide"), 0);
  assert.equal(h.timers.size, 0);
});

test("a foreign RP keeps the browser's own rejection untouched", async () => {
  const message =
    "The relying party ID is not a registrable domain suffix of, nor equal to, the current domain.";
  const getError = new DOMException(message, "SecurityError");
  const createError = new DOMException(message, "SecurityError");
  const h = makeHarness({
    extensionConditional: true,
    nativeGetError: getError,
    nativeCreateError: createError,
  });
  const getOptions = {
    publicKey: {
      challenge: Uint8Array.from([1]),
      rpId: "foreign.test",
      timeout: 9000,
    },
  };
  await assert.rejects(
    h.navigator.credentials.get(getOptions),
    (error) => error === getError,
  );
  assert.equal(h.nativeGet.length, 1);
  assert.equal(h.nativeGet[0], getOptions);
  const created = es256Create("foreign.test");
  await assert.rejects(
    h.navigator.credentials.create(created),
    (error) => error === createError,
  );
  assert.equal(h.nativeCreate.length, 1);
  assert.equal(h.nativeCreate[0], created);
  assert.equal(h.requests("get").length + h.requests("create").length, 0);
  assert.equal(h.messages.length, 0);
});

test("non-canonical or non-string RP hints fall back instead of being normalized", async () => {
  for (const rpId of [
    "Example.test",
    "exämple.test",
    "example.test.",
    "example.test/login",
    42,
    null,
    { id: "example.test" },
  ]) {
    const h = makeHarness({ extensionConditional: true });
    const options = {
      mediation: "conditional",
      publicKey: { challenge: Uint8Array.from([1]), rpId, timeout: 300000 },
    };
    assert.equal(
      await h.navigator.credentials.get(options),
      "native-get",
      "rpId " + JSON.stringify(rpId) + " is not a canonical local hint",
    );
    assert.equal(h.nativeGet.length, 1);
    assert.equal(h.nativeGet[0], options);
    assert.equal(h.requests("get").length, 0);
    assert.equal(h.messages.length, 0);
    assert.equal(h.timers.size, 0);
  }
  for (const rp of [
    { id: "Example.test" },
    { id: "exämple.test" },
    { id: 42 },
    { id: null },
    "example.test",
    7,
  ]) {
    const h = makeHarness({ extensionConditional: true });
    const options = createOptions({
      rp,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    });
    assert.equal(
      await h.navigator.credentials.create(options),
      "native-create",
      "rp " + JSON.stringify(rp) + " is not a canonical local hint",
    );
    assert.equal(h.nativeCreate.length, 1);
    assert.equal(h.nativeCreate[0], options);
    assert.equal(h.requests("create").length, 0);
    assert.equal(h.messages.length, 0);
    assert.equal(h.timers.size, 0);
  }
});

test("an absent RP hint defaults to the current host and stays eligible", async () => {
  const h = makeHarness({ extensionConditional: true });
  const getOptions = {
    publicKey: { challenge: Uint8Array.from([1, 2]), timeout: 5000 },
  };
  const pending = h.navigator.credentials.get(getOptions);
  await flush();
  const request = h.requests("get")[0];
  assert.ok(request, "an absent rpId means this host, so it stays local");
  assert.equal(JSON.parse(request.options).rpId, undefined);
  h.deliver({ source: "locklark-result-v1", id: request.id, fallback: true });
  assert.equal(await pending, "native-get");
  assert.equal(h.nativeGet[0], getOptions);
  const created = makeHarness({ extensionConditional: true });
  const createOpts = createOptions({
    rp: { name: "Example" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  });
  const createPending = created.navigator.credentials.create(createOpts);
  await flush();
  const createRequest = created.requests("create")[0];
  assert.ok(createRequest, "an absent rp.id means this host, so it stays local");
  assert.deepEqual(JSON.parse(createRequest.options).rp, { name: "Example" });
  created.deliver({
    source: "locklark-result-v1",
    id: createRequest.id,
    fallback: true,
  });
  assert.equal(await createPending, "native-create");
  assert.equal(created.nativeCreate[0], createOpts);
});

test("canonical exact and parent-suffix RP hints stay local and abort cleanly", async () => {
  const suffix = makeHarness({
    extensionConditional: true,
    hostname: "app.example.test",
  });
  const controller = makeAbortSignal();
  const options = {
    mediation: "conditional",
    publicKey: {
      challenge: Uint8Array.from([1]),
      rpId: "example.test",
      timeout: 300000,
    },
    signal: controller.signal,
  };
  const promise = suffix.navigator.credentials.get(options);
  await flush();
  const request = suffix.requests("get")[0];
  assert.ok(request, "app.example.test may use the example.test RP");
  assert.equal(JSON.parse(request.options).rpId, "example.test");
  assert.equal(controller.listenerCount, 1);
  controller.abort();
  await assert.rejects(promise, /aborted|Abort/i);
  assert.equal(
    suffix.messages.filter((m) => m.type === "cancel")[0].id,
    request.id,
  );
  assert.equal(controller.listenerCount, 0, "abort listener released");
  assert.equal(suffix.listenerCount("pagehide"), 0, "pagehide listener released");
  assert.equal(suffix.timers.size, 0);
  assert.equal(suffix.nativeGet.length, 0);
  const exact = makeHarness({ extensionConditional: true });
  const exactOptions = es256Create("example.test");
  const pending = exact.navigator.credentials.create(exactOptions);
  await flush();
  const created = exact.requests("create")[0];
  assert.ok(created, "the exact host stays interceptable");
  exact.deliver({ source: "locklark-result-v1", id: created.id, fallback: true });
  assert.equal(await pending, "native-create");
  assert.equal(exact.nativeCreate[0], exactOptions);
});

test("foreign RP routing invents no related-origin capability or wire payload", async () => {
  const h = makeHarness({
    extensionConditional: true,
    nativeCapabilities: { hybridTransport: true },
  });
  const options = {
    publicKey: { challenge: Uint8Array.from([1]), rpId: "foreign.test" },
  };
  assert.equal(await h.navigator.credentials.get(options), "native-get");
  assert.equal(h.nativeGet[0], options);
  const capabilities = await h.PublicKeyCredential.getClientCapabilities();
  assert.deepEqual(Object.keys(capabilities), [
    "conditionalGet",
    "hybridTransport",
  ]);
  assert.equal("relatedOrigins" in capabilities, false);
  assert.equal(
    h.messages.some((m) => JSON.stringify(m).includes("foreign.test")),
    false,
    "the page's RP hint never reaches the bridge",
  );
  assert.deepEqual(
    [...new Set(h.messages.map((m) => m.source))],
    ["locklark-capability-v1"],
    "the only traffic is the capability handshake",
  );
});

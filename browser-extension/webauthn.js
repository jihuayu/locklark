/* MAIN world: standard WebAuthn data only. Never contains vault keys/passwords.
 * The isolated bridge and native host authenticate the actual browser origin. */
(() => {
  "use strict";
  if (!isSecureContext || window !== window.top || !navigator.credentials)
    return;
  const create = navigator.credentials.create.bind(navigator.credentials);
  const get = navigator.credentials.get.bind(navigator.credentials);
  const pending = new Map();
  // Extension capability probe. The isolated content script answers with one
  // boolean; account metadata never crosses this bridge.
  const CAPABILITY_SOURCE = "locklark-capability-v1";
  const capabilityWaiters = new Map();
  function extensionConditionalAvailable(timeout = 800, registerCancel) {
    return new Promise((resolve) => {
      const requestId = crypto.randomUUID();
      let done = false;
      const finish = (value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        capabilityWaiters.delete(requestId);
        resolve(value === true);
      };
      const timer = setTimeout(() => finish(false), Math.min(timeout, 1000));
      capabilityWaiters.set(requestId, finish);
      // Callers that can be cancelled mid-handshake register a release hook so
      // the waiter, its timer and its closure are dropped immediately instead
      // of lingering until the bounded timeout.
      if (typeof registerCancel === "function")
        registerCancel(() => finish(false));
      window.postMessage(
        { source: CAPABILITY_SOURCE, id: requestId },
        location.origin,
      );
    });
  }
  const b64 = (value) => {
    const bytes =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : ArrayBuffer.isView(value)
          ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
          : null;
    if (!bytes || bytes.length > 32768)
      throw new TypeError("Invalid WebAuthn buffer");
    let raw = "";
    for (const byte of bytes) raw += String.fromCharCode(byte);
    return btoa(raw)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  };
  const buffer = (raw) =>
    Uint8Array.from(atob(raw.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
      c.charCodeAt(0),
    ).buffer;
  function serialize(value, conditional) {
    const p = { ...value, challenge: b64(value.challenge) };
    // Conditional requests never carry a caller-supplied timeout: the browser
    // (or this bridge) keeps them pending for the page lifetime instead.
    if (conditional) delete p.timeout;
    if (value.user) p.user = { ...value.user, id: b64(value.user.id) };
    for (const key of ["allowCredentials", "excludeCredentials"])
      if (value[key]) p[key] = value[key].map((d) => ({ ...d, id: b64(d.id) }));
    return JSON.stringify(p);
  }
  function credential(data) {
    const created = !!data.response.attestationObject;
    const response = Object.create(
      (created
        ? AuthenticatorAttestationResponse
        : AuthenticatorAssertionResponse
      ).prototype,
    );
    for (const field of [
      "clientDataJSON",
      "attestationObject",
      "authenticatorData",
      "signature",
      "userHandle",
    ])
      if (data.response[field] !== undefined)
        Object.defineProperty(response, field, {
          enumerable: true,
          value: buffer(data.response[field]),
        });
    if (!created && data.response.userHandle === undefined)
      Object.defineProperty(response, "userHandle", {
        value: null,
        enumerable: true,
      });
    if (created)
      Object.defineProperties(response, {
        getTransports: { value: () => [...(data.response.transports || [])] },
        getPublicKey: { value: () => buffer(data.response.publicKey) },
        getPublicKeyAlgorithm: {
          value: () => data.response.publicKeyAlgorithm,
        },
        getAuthenticatorData: {
          value: () => buffer(data.response.authenticatorData),
        },
      });
    const result = Object.create(PublicKeyCredential.prototype);
    Object.defineProperties(result, {
      id: { value: data.id, enumerable: true },
      rawId: { value: buffer(data.rawId), enumerable: true },
      type: { value: "public-key", enumerable: true },
      authenticatorAttachment: {
        value: data.authenticatorAttachment,
        enumerable: true,
      },
      response: { value: response, enumerable: true },
      getClientExtensionResults: {
        value: () => structuredClone(data.clientExtensionResults || {}),
      },
      toJSON: { value: () => structuredClone(data) },
    });
    return result;
  }
  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin) return;
    if (event.data?.source === CAPABILITY_SOURCE) {
      // window.postMessage also delivers our own outgoing query back to this
      // listener. Only a real isolated-world reply carries a boolean; an echo
      // without one must never resolve the handshake early.
      if (typeof event.data.conditional !== "boolean") return;
      const waiter = capabilityWaiters.get(event.data.id);
      if (waiter) waiter(event.data.conditional);
      return;
    }
    if (event.data?.source !== "locklark-result-v1") return;
    const call = pending.get(event.data.id);
    if (!call) return;
    call.finish(event.data);
  });
  // Keep in step with the native host's create parser: ES256 (-7) is the only
  // credential algorithm it can produce, and it only understands the standard
  // attestation values, so enterprise/unknown forms must reach a real
  // authenticator. false always means "delegate to the browser".
  const HOST_ALGORITHM = -7;
  const HOST_ATTESTATION = new Set(["", "none", "indirect", "direct"]);
  const HOST_PARAMETER_SCAN = 32;
  function nativeCompatibleCreate(publicKey) {
    const parameters = publicKey.pubKeyCredParams;
    if (!Array.isArray(parameters)) return false;
    // The host refuses any list longer than 32 entries outright, so such a
    // request must reach a real authenticator even when it lists ES256 first.
    if (parameters.length > HOST_PARAMETER_SCAN) return false;
    let supported = false;
    for (let i = 0; i < Math.min(parameters.length, HOST_PARAMETER_SCAN); i++) {
      const parameter = parameters[i];
      if (parameter?.type === "public-key" && parameter.alg === HOST_ALGORITHM) {
        supported = true;
        break;
      }
    }
    if (!supported) return false;
    const attestation = publicKey.attestation;
    return attestation === undefined || HOST_ATTESTATION.has(attestation);
  }
  function intercept(original, kind, options) {
    const conditional = kind === "get" && options?.mediation === "conditional";
    if (
      !options?.publicKey ||
      options.mediation === "silent" ||
      document.visibilityState !== "visible"
    )
      return original(options);
    const feature =
      kind === "create"
        ? "publickey-credentials-create"
        : "publickey-credentials-get";
    if (
      (document.permissionsPolicy || document.featurePolicy)?.allowsFeature(
        feature,
      ) === false
    )
      return original(options);
    const abortedError = () =>
      new DOMException("Operation aborted", "AbortError");
    if (options.signal?.aborted) return Promise.reject(abortedError());
    let raw;
    try {
      raw = serialize(options.publicKey, conditional);
    } catch {
      return original(options);
    }
    if (raw.length > 32768) return original(options);
    // Unsupported extension algorithms stay with the browser's authenticator.
    if (
      Object.keys(options.publicKey.extensions || {}).some(
        (k) => k !== "credProps",
      ) ||
      options.publicKey.authenticatorSelection?.authenticatorAttachment ===
        "cross-platform"
    )
      return original(options);
    // Never let a create request the host cannot parse (non-ES256 algorithms or
    // enterprise/unknown attestation) turn into a NotAllowed refusal: hand the
    // untouched original options back to the browser's authenticator instead.
    if (kind === "create" && !nativeCompatibleCreate(options.publicKey))
      return original(options);
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      let done = false;
      let posted = false;
      let timer = null;
      let releaseHandshake = null;
      const cleanup = () => {
        done = true;
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        pending.delete(id);
        options.signal?.removeEventListener("abort", abort);
        if (conditional) window.removeEventListener("pagehide", pagehide);
        // Drop any in-flight capability handshake now rather than leaving its
        // waiter and timer alive until the bounded timeout.
        if (releaseHandshake) {
          const release = releaseHandshake;
          releaseHandshake = null;
          release();
        }
      };
      const cancel = (error) => {
        if (done) return;
        const wasPosted = posted;
        cleanup();
        if (wasPosted)
          window.postMessage(
            { source: "locklark-request-v1", type: "cancel", id },
            location.origin,
          );
        reject(error);
      };
      const abort = () => cancel(abortedError());
      const pagehide = () => cancel(abortedError());
      const fallback = () => {
        if (done) return;
        cleanup();
        Promise.resolve()
          .then(() => {
            // Recheck inside the deferred step: an abort that lands after the
            // listener was removed but before the native call starts must still
            // win over handing the request back to the browser.
            if (options.signal?.aborted) throw abortedError();
            return original(options);
          })
          .then(resolve, reject);
      };
      const start = () => {
        if (done) return;
        // A conditional request waits for the page lifecycle: no 120s timer is
        // armed and publicKey.timeout is ignored, matching native autofill UI.
        if (!conditional)
          timer = setTimeout(
            () => {
              if (done) return;
              cleanup();
              window.postMessage(
                { source: "locklark-request-v1", type: "cancel", id },
                location.origin,
              );
              reject(
                new DOMException("Operation timed out", "NotAllowedError"),
              );
            },
            Math.min(options.publicKey.timeout || 120000, 120000),
          );
        posted = true;
        pending.set(id, {
          finish: (message) => {
            if (done) return;
            if (message.error) {
              cleanup();
              reject(
                new DOMException(
                  "Passkey result not confirmed",
                  "NotAllowedError",
                ),
              );
              return;
            }
            if (message.fallback) {
              fallback();
              return;
            }
            cleanup();
            try {
              resolve(credential(message.credential));
            } catch {
              reject(
                new DOMException(
                  "Invalid credential response",
                  "NotAllowedError",
                ),
              );
            }
          },
        });
        window.postMessage(
          {
            source: "locklark-request-v1",
            type: kind,
            id,
            options: raw,
            conditional,
          },
          location.origin,
        );
      };
      // Register cancellation handling before any await boundary, including
      // the capability handshake, so an abort or pagehide that lands while the
      // bridge is being probed can never resurrect the request afterwards.
      options.signal?.addEventListener("abort", abort, { once: true });
      if (conditional)
        window.addEventListener("pagehide", pagehide, { once: true });
      if (!conditional) {
        start();
        return;
      }
      // Old host or disabled settings must fall back to the browser's own
      // conditional UI; never fabricate a credential and never run it for a
      // call the page already cancelled.
      extensionConditionalAvailable(800, (release) => {
        releaseHandshake = release;
      }).then((supported) => {
        releaseHandshake = null;
        if (done) return;
        if (options.signal?.aborted) {
          cancel(abortedError());
          return;
        }
        if (supported) start();
        else fallback();
      });
    });
  }
  navigator.credentials.create = (options) =>
    intercept(create, "create", options);
  navigator.credentials.get = (options) => intercept(get, "get", options);
  try {
    const nativeConditional = PublicKeyCredential.isConditionalMediationAvailable;
    Object.defineProperty(
      PublicKeyCredential,
      "isConditionalMediationAvailable",
      {
        configurable: true,
        writable: true,
        value: function isConditionalMediationAvailable() {
          const native =
            typeof nativeConditional === "function"
              ? Promise.resolve(nativeConditional.call(this)).catch(() => false)
              : Promise.resolve(false);
          return Promise.all([native, extensionConditionalAvailable()]).then(
            ([available, extension]) => available === true || extension === true,
          );
        },
      },
    );
  } catch {}
  try {
    const nativeClientCapabilities = PublicKeyCredential.getClientCapabilities;
    if (typeof nativeClientCapabilities === "function")
      Object.defineProperty(
        PublicKeyCredential,
        "getClientCapabilities",
        {
          configurable: true,
          writable: true,
          value: function getClientCapabilities() {
            return Promise.resolve(nativeClientCapabilities.call(this)).then(
              (capabilities) =>
                extensionConditionalAvailable().then((supported) => {
                  const native =
                    capabilities && typeof capabilities === "object"
                      ? capabilities
                      : {};
                  const merged = {};
                  for (const key of Object.keys(native))
                    merged[key] = native[key];
                  if (supported === true) merged.conditionalGet = true;
                  const result = {};
                  for (const key of Object.keys(merged).sort())
                    result[key] = merged[key];
                  return result;
                }),
            );
          },
        },
      );
  } catch {}
})();

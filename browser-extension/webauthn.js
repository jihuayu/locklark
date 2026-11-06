/* MAIN world: standard WebAuthn data only. Never contains vault keys/passwords.
 * The isolated bridge and native host authenticate the actual browser origin. */
(() => {
  "use strict";
  if (!isSecureContext || window !== window.top || !navigator.credentials)
    return;
  const create = navigator.credentials.create.bind(navigator.credentials);
  const get = navigator.credentials.get.bind(navigator.credentials);
  const pending = new Map();
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
  function serialize(value) {
    const p = { ...value, challenge: b64(value.challenge) };
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
    if (
      event.source !== window ||
      event.origin !== location.origin ||
      event.data?.source !== "locklark-result-v1"
    )
      return;
    const call = pending.get(event.data.id);
    if (!call) return;
    call.finish(event.data);
  });
  function intercept(original, kind, options) {
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
    if (options.signal?.aborted)
      return Promise.reject(
        new DOMException("Operation aborted", "AbortError"),
      );
    let raw;
    try {
      raw = serialize(options.publicKey);
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
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      let done = false;
      const cleanup = () => {
        done = true;
        clearTimeout(timer);
        pending.delete(id);
        options.signal?.removeEventListener("abort", abort);
      };
      const abort = () => {
        if (done) return;
        cleanup();
        window.postMessage(
          { source: "locklark-request-v1", type: "cancel", id },
          location.origin,
        );
        reject(new DOMException("Operation aborted", "AbortError"));
      };
      const fallback = () => {
        if (done) return;
        cleanup();
        Promise.resolve()
          .then(() => original(options))
          .then(resolve, reject);
      };
      const timer = setTimeout(
        () => {
          if (done) return;
          cleanup();
          window.postMessage(
            { source: "locklark-request-v1", type: "cancel", id },
            location.origin,
          );
          reject(new DOMException("Operation timed out", "NotAllowedError"));
        },
        Math.min(options.publicKey.timeout || 120000, 120000),
      );
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
      options.signal?.addEventListener("abort", abort, { once: true });
      window.postMessage(
        {
          source: "locklark-request-v1",
          type: kind,
          id,
          options: raw,
          conditional: options.mediation === "conditional",
        },
        location.origin,
      );
    });
  }
  navigator.credentials.create = (options) =>
    intercept(create, "create", options);
  navigator.credentials.get = (options) => intercept(get, "get", options);
})();

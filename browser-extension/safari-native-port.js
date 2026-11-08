/*
 * Locklark Safari native transport boundary.
 *
 * Safari's standard `runtime.sendNativeMessage` reaches the Safari web
 * extension handler; its `connectNative` does not provide the Chromium-style
 * duplex stdio Port used by the desktop helper. This file adapts the native
 * handler endpoint into the small Port surface that background.js expects:
 * postMessage / disconnect / onMessage / onDisconnect.
 *
 * Design constraints:
 *  - loaded only in the Safari background context, before background.js;
 *  - never replaces globalThis.chrome/browser and never patches the browser
 *    API; the explicit connectNative export is used only for a
 *    safari-web-extension:// runtime;
 *  - exactly one sendNativeMessage envelope per postMessage, no retries;
 *  - at most one outstanding poll request and a bounded number of frames;
 *  - any failed, ambiguous, oversized, mistyped, mistokened or timed-out
 *    native call closes the Port and reports a safe reason, never a protocol
 *    reply and never a mutating retry.
 */
(function (root) {
  "use strict";

  const NATIVE_HOST_NAME = "org.locklark.browser";
  const PROTOCOL_VERSION = 1;
  const MAX_FRAME_BYTES = 256 * 1024;
  const MAX_FRAMES_PER_POLL = 64;
  const MAX_REPLY_BYTES = 1024 * 1024;
  const DEFAULT_POLL_INTERVAL_MS = 200;
  const DEFAULT_CALL_TIMEOUT_MS = 15000;
  const TOKEN_PATTERN = /^[a-f0-9]{32}$/;
  const REPLY_KEYS = ["v", "token", "ok", "frames"];
  const ENVELOPE_KEYS = {
    open: ["v", "op", "token"],
    send: ["v", "op", "token", "frame"],
    poll: ["v", "op", "token"],
    close: ["v", "op", "token"],
  };

  const textEncoder =
    typeof TextEncoder === "function" ? new TextEncoder() : null;

  function utf8Length(text) {
    if (typeof text !== "string") return Infinity;
    if (textEncoder) return textEncoder.encode(text).length;
    if (typeof Buffer === "function" && Buffer.byteLength)
      return Buffer.byteLength(text, "utf8");
    return Infinity;
  }

  function isPlainObject(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  function hasExactKeys(value, expected) {
    if (!isPlainObject(value)) return false;
    const keys = Object.keys(value);
    if (keys.length !== expected.length) return false;
    for (const key of keys) if (!expected.includes(key)) return false;
    return true;
  }

  function snapshotFrame(value) {
    if (!isPlainObject(value)) throw Error("invalid frame");
    let text;
    try {
      text = JSON.stringify(value);
    } catch {
      throw Error("invalid frame");
    }
    if (typeof text !== "string") throw Error("invalid frame");
    if (utf8Length(text) > MAX_FRAME_BYTES) throw Error("invalid frame");
    let copy;
    try {
      copy = JSON.parse(text);
    } catch {
      throw Error("invalid frame");
    }
    if (!isPlainObject(copy)) throw Error("invalid frame");
    return copy;
  }

  function validateToken(value) {
    if (typeof value !== "string" || !TOKEN_PATTERN.test(value))
      throw Error("invalid token");
    return value;
  }

  function secureCrypto() {
    if (root && root.crypto && typeof root.crypto.getRandomValues === "function")
      return root.crypto;
    return null;
  }

  function makeToken() {
    const cryptoObject = secureCrypto();
    if (!cryptoObject) throw Error("secure random unavailable");
    const bytes = new Uint8Array(16);
    cryptoObject.getRandomValues(bytes);
    let token = "";
    for (const byte of bytes) token += byte.toString(16).padStart(2, "0");
    return validateToken(token);
  }

  function positiveInteger(value, fallback) {
    return Number.isSafeInteger(value) && value > 0 ? value : fallback;
  }

  /*
   * Returns null for any reply that is not exactly the bounded success or
   * failure envelope. On success, frame objects are already JSON-safe copies.
   */
  function validateReply(reply, token) {
    try {
      if (!isPlainObject(reply)) return null;
      for (const key of Object.keys(reply))
        if (!REPLY_KEYS.includes(key)) return null;
      if (reply.v !== PROTOCOL_VERSION) return null;
      if (reply.token !== token) return null;
      if (typeof reply.ok !== "boolean") return null;
      if (reply.ok === false) {
        if (Object.hasOwn(reply, "frames")) return null;
        return { ok: false, frames: [] };
      }
      if (!Object.hasOwn(reply, "frames")) return null;
      if (!Array.isArray(reply.frames)) return null;
      if (reply.frames.length > MAX_FRAMES_PER_POLL) return null;
      const frames = [];
      for (const frame of reply.frames) {
        if (!isPlainObject(frame)) return null;
        const frameText = JSON.stringify(frame);
        if (typeof frameText !== "string") return null;
        if (utf8Length(frameText) > MAX_FRAME_BYTES) return null;
        frames.push(frame);
      }
      const replyText = JSON.stringify(reply);
      if (typeof replyText !== "string") return null;
      if (utf8Length(replyText) > MAX_REPLY_BYTES) return null;
      return { ok: true, frames };
    } catch {
      return null;
    }
  }

  function isSafariRuntime(api) {
    try {
      if (!api || typeof api !== "object" || !api.runtime) return false;
      const runtime = api.runtime;
      if (typeof runtime.sendNativeMessage !== "function") return false;
      if (typeof runtime.connectNative !== "function") return false;
      const baseURL =
        typeof runtime.getURL === "function" ? String(runtime.getURL("")) : "";
      if (!baseURL.startsWith("safari-web-extension://")) return false;
      const manifest =
        typeof runtime.getManifest === "function"
          ? runtime.getManifest()
          : null;
      if (manifest && typeof manifest === "object") {
        if (manifest.key) return false;
        if (manifest.browser_specific_settings) return false;
        if (manifest.background && manifest.background.service_worker)
          return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  let epochCounter = 0;

  function createPort(bridge, options = {}) {
    const sendNativeMessage =
      typeof bridge === "function"
        ? bridge
        : bridge && typeof bridge.sendNativeMessage === "function"
          ? bridge.sendNativeMessage.bind(bridge)
          : null;
    if (!sendNativeMessage) throw Error("native bridge unavailable");

    const token =
      options.token === undefined ? makeToken() : validateToken(options.token);
    const pollIntervalMs = positiveInteger(
      options.pollIntervalMs,
      DEFAULT_POLL_INTERVAL_MS,
    );
    const callTimeoutMs = positiveInteger(
      options.callTimeoutMs,
      DEFAULT_CALL_TIMEOUT_MS,
    );
    const schedule = options.setTimeout || setTimeout;
    const cancel = options.clearTimeout || clearTimeout;

    const messageListeners = [];
    const disconnectListeners = [];
    let epoch = ++epochCounter;
    let closed = false;
    let closeReason = "";
    let chain = Promise.resolve();
    let pollTimer = null;
    let pollInFlight = false;
    let closeSent = false;

    const onMessage = Object.freeze({
      addListener(listener) {
        if (typeof listener === "function" && !messageListeners.includes(listener))
          messageListeners.push(listener);
      },
      removeListener(listener) {
        const index = messageListeners.indexOf(listener);
        if (index >= 0) messageListeners.splice(index, 1);
      },
      hasListener(listener) {
        return messageListeners.includes(listener);
      },
    });

    const onDisconnect = Object.freeze({
      addListener(listener) {
        if (
          typeof listener === "function" &&
          !disconnectListeners.includes(listener)
        )
          disconnectListeners.push(listener);
      },
      removeListener(listener) {
        const index = disconnectListeners.indexOf(listener);
        if (index >= 0) disconnectListeners.splice(index, 1);
      },
      hasListener(listener) {
        return disconnectListeners.includes(listener);
      },
    });

    function deliver(frame) {
      for (const listener of messageListeners.slice()) {
        if (closed) return;
        try {
          listener(frame);
        } catch {
          // A listener failure must not turn into a native retry.
        }
      }
    }

    function finish(reason, sendCloseOperation) {
      if (closed) return;
      closed = true;
      epoch = -1;
      closeReason = reason;
      if (pollTimer !== null) {
        cancel(pollTimer);
        pollTimer = null;
      }
      pollInFlight = false;
      if (sendCloseOperation && !closeSent) {
        closeSent = true;
        try {
          const pending = sendNativeMessage({
            v: PROTOCOL_VERSION,
            op: "close",
            token,
          });
          if (pending && typeof pending.catch === "function")
            pending.catch(() => {});
        } catch {
          // The Port is already closed; a failed close is not retried.
        }
      }
      for (const listener of disconnectListeners.slice()) {
        try {
          listener(port);
        } catch {
          // onDisconnect notification is best-effort and exactly once.
        }
      }
    }

    function schedulePoll(delay) {
      if (closed || pollTimer !== null || pollInFlight) return;
      pollTimer = schedule(() => {
        pollTimer = null;
        if (closed || pollInFlight) return;
        pollInFlight = true;
        enqueue(
          { v: PROTOCOL_VERSION, op: "poll", token },
          "poll",
        );
      }, delay);
    }

    function invoke(envelope, kind) {
      const requestEpoch = epoch;
      let settled = false;
      const timer = schedule(() => {
        if (settled || closed || requestEpoch !== epoch) return;
        settled = true;
        finish("timeout", false);
      }, callTimeoutMs);

      return Promise.resolve()
        .then(() => sendNativeMessage(envelope))
        .then((reply) => {
          if (settled || closed || requestEpoch !== epoch) return;
          settled = true;
          cancel(timer);
          const result = validateReply(reply, token);
          if (!result) {
            finish("protocol", false);
            return;
          }
          if (!result.ok) {
            finish("native-failure", false);
            return;
          }
          for (const frame of result.frames) {
            if (closed || requestEpoch !== epoch) return;
            deliver(frame);
          }
          if (!closed && (kind === "open" || kind === "send"))
            schedulePoll(0);
        })
        .catch(() => {
          if (settled || closed || requestEpoch !== epoch) return;
          settled = true;
          cancel(timer);
          finish("native-unavailable", false);
        })
        .finally(() => {
          cancel(timer);
          if (kind === "poll") {
            pollInFlight = false;
            if (!closed && requestEpoch === epoch)
              schedulePoll(pollIntervalMs);
          }
        });
    }

    function enqueue(envelope, kind) {
      const requestEpoch = epoch;
      chain = chain
        .then(() => {
          if (closed || requestEpoch !== epoch) return;
          return invoke(envelope, kind);
        })
        .catch(() => {
          // invoke converts native failures into a closed Port; nothing is
          // replayed and no caller-controlled mutation is retried.
        });
      return chain;
    }

    function postMessage(message) {
      if (closed) throw Error("disconnected");
      const frame = snapshotFrame(message);
      enqueue(
        { v: PROTOCOL_VERSION, op: "send", token, frame },
        "send",
      );
    }

    function disconnect() {
      if (closed) return;
      finish("disconnected", true);
    }

    const port = Object.freeze({
      name: "locklark-native",
      postMessage,
      disconnect,
      onMessage,
      onDisconnect,
      get closed() {
        return closed;
      },
      get epoch() {
        return epoch;
      },
      get reason() {
        return closeReason;
      },
    });

    enqueue({ v: PROTOCOL_VERSION, op: "open", token }, "open");
    schedulePoll(pollIntervalMs);
    return port;
  }

  /*
   * Explicit connector. The caller (background.js) decides, from its own
   * Safari runtime detection, whether to use this; nothing here mutates the
   * browser API, replaces a global or patches runtime.connectNative. The host
   * name is the only accepted one and every call is re-validated internally.
   */
  function connectNative(api, name, options = {}) {
    if (!isSafariRuntime(api)) throw Error("not a safari runtime");
    if (name !== NATIVE_HOST_NAME) throw Error("unknown native host");
    const runtime = api.runtime;
    const sendNativeMessage = runtime.sendNativeMessage.bind(runtime);
    const bridge = (envelope) => sendNativeMessage(NATIVE_HOST_NAME, envelope);
    return createPort(bridge, options);
  }

  const namespace = Object.freeze({
    NATIVE_HOST_NAME,
    PROTOCOL_VERSION,
    MAX_FRAME_BYTES,
    MAX_FRAMES_PER_POLL,
    MAX_REPLY_BYTES,
    DEFAULT_POLL_INTERVAL_MS,
    DEFAULT_CALL_TIMEOUT_MS,
    connectNative,
    createPort,
    isSafariRuntime,
  });

  if (typeof module === "object" && module.exports) module.exports = namespace;
  if (root && typeof root === "object") {
    try {
      Object.defineProperty(root, "LocklarkSafariNativePort", {
        value: namespace,
        writable: false,
        configurable: true,
        enumerable: false,
      });
    } catch {
      // A frozen global scope leaves the CommonJS export in place.
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : undefined);

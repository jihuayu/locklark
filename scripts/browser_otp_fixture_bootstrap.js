// Test-only content-script bootstrap for the real extension storage cases.
// It is prepended before production core.js/content.js in the copied bundle.
// It provides a synthetic BarcodeDetector that always reports no match, a
// delegated MutationObserver counter for the one OTP callback, and a delegated
// body.innerText read counter. It never reads or publishes text, touches
// runtime/storage/approvals, changes permissions, or adds product hooks.
(() => {
  "use strict";
  const root = document.documentElement;
  let decodes = 0;
  let observed = 0;
  let disconnected = 0;
  let active = 0;
  let target = "missing";
  let bodyRead = 0;
  let bodyReady = "pending";
  const pendingDecodes = [];
  function publish() {
    root.dataset.locklarkOtpFixtureDecode = String(decodes);
    root.dataset.locklarkOtpFixtureObserved = String(observed);
    root.dataset.locklarkOtpFixtureDisconnected = String(disconnected);
    root.dataset.locklarkOtpFixtureActive = String(active);
    root.dataset.locklarkOtpFixtureTarget = target;
    root.dataset.locklarkOtpFixtureBodyRead = String(bodyRead);
    root.dataset.locklarkOtpFixtureBodyReady = bodyReady;
    root.dataset.locklarkOtpFixturePending = String(pendingDecodes.length);
  }
  function installBodyRead() {
    if (bodyReady !== "pending") return;
    if (!document.body) return;
    const native = Object.getOwnPropertyDescriptor(
      HTMLElement.prototype,
      "innerText",
    );
    if (!native || typeof native.get !== "function") {
      bodyReady = "unavailable";
      publish();
      return;
    }
    try {
      Object.defineProperty(document.body, "innerText", {
        configurable: true,
        enumerable: false,
        get() {
          bodyRead++;
          publish();
          return native.get.call(this);
        },
        set(value) {
          if (typeof native.set !== "function")
            throw TypeError("innerText setter unavailable");
          native.set.call(this, value);
        },
      });
      bodyReady = "ready";
    } catch {
      bodyReady = "unavailable";
    }
    publish();
  }
  if (!installBodyRead()) {
    if (document.readyState === "loading")
      document.addEventListener("DOMContentLoaded", installBodyRead, {
        once: true,
      });
    else installBodyRead();
  }
  class FixtureBarcodeDetector {
    static async getSupportedFormats() {
      return ["qr_code"];
    }
    async detect() {
      decodes++;
      publish();
      if (root.dataset.locklarkOtpFixtureDefer === "1") {
        return await new Promise((resolve) => {
          pendingDecodes.push(resolve);
          publish();
        });
      }
      return [];
    }
  }
  document.addEventListener("locklark-otp-fixture-release", () => {
    for (const resolve of pendingDecodes.splice(0)) resolve([]);
    publish();
  });
  globalThis.BarcodeDetector = FixtureBarcodeDetector;
  const NativeMutationObserver = globalThis.MutationObserver;
  if (typeof NativeMutationObserver === "function") {
    class FixtureMutationObserver extends NativeMutationObserver {
      constructor(callback) {
        super(callback);
        let source = "";
        try {
          source = Function.prototype.toString.call(callback);
        } catch {}
        this.__otpFixture = source.includes("scheduleOTPScan");
        if (this.__otpFixture && active !== 0) target = "ambiguous";
        else if (this.__otpFixture && target === "missing") target = "identified";
        this.__otpFixtureDisconnected = false;
        publish();
      }
      observe(targetNode, options) {
        super.observe(targetNode, options);
        if (!this.__otpFixture) return;
        if (active !== 0) target = "ambiguous";
        active++;
        observed++;
        publish();
      }
      disconnect() {
        if (this.__otpFixture && !this.__otpFixtureDisconnected) {
          this.__otpFixtureDisconnected = true;
          if (active > 0) active--;
          disconnected++;
        }
        super.disconnect();
        if (this.__otpFixture) publish();
      }
    }
    globalThis.MutationObserver = FixtureMutationObserver;
  }
  publish();
})();

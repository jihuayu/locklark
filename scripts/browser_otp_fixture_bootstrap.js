// Test-only content-script bootstrap for the real extension storage smoke.
// It is prepended before production core.js/content.js in the copied bundle.
// It provides only a synthetic BarcodeDetector that always reports no match and
// a delegating MutationObserver wrapper. The OTP observer is identified from
// the callback's unique scheduleOTPScan reference, never from observe options.
// All other observers are delegated without counting. No runtime, storage,
// approval, permission, or product hook is touched.
(() => {
  "use strict";
  const root = document.documentElement;
  let decodes = 0;
  let observed = 0;
  let disconnected = 0;
  let active = 0;
  let target = "missing";
  function publish() {
    root.dataset.locklarkOtpFixtureDecode = String(decodes);
    root.dataset.locklarkOtpFixtureObserved = String(observed);
    root.dataset.locklarkOtpFixtureDisconnected = String(disconnected);
    root.dataset.locklarkOtpFixtureActive = String(active);
    root.dataset.locklarkOtpFixtureTarget = target;
  }
  class FixtureBarcodeDetector {
    static async getSupportedFormats() {
      return ["qr_code"];
    }
    async detect() {
      decodes++;
      publish();
      return [];
    }
  }
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

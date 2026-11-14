// Test-only content-script bootstrap for the real extension storage smoke.
// It is prepended before production core.js/content.js in the copied bundle.
// It provides only a synthetic BarcodeDetector that always reports no match and
// a delegating MutationObserver wrapper that counts the OTP observer lifecycle.
// It never touches runtime messaging, chrome.storage, approvals, or permissions.
(() => {
  "use strict";
  const root = document.documentElement;
  let decodes = 0;
  let observed = 0;
  let disconnected = 0;
  function publish() {
    root.dataset.locklarkOtpFixtureDecode = String(decodes);
    root.dataset.locklarkOtpFixtureObserved = String(observed);
    root.dataset.locklarkOtpFixtureDisconnected = String(disconnected);
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
        this.__otpFixture = false;
        this.__otpFixtureDisconnected = false;
      }
      observe(target, options) {
        super.observe(target, options);
        if (
          options &&
          options.childList === true &&
          options.subtree === true &&
          options.attributes !== true
        ) {
          this.__otpFixture = true;
          observed++;
          publish();
        }
      }
      disconnect() {
        if (this.__otpFixture && !this.__otpFixtureDisconnected) {
          this.__otpFixtureDisconnected = true;
          disconnected++;
          publish();
        }
        super.disconnect();
      }
    }
    globalThis.MutationObserver = FixtureMutationObserver;
  }
  publish();
})();

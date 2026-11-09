import { AXE_VERSION, fail, keyboardSummary, validateAxeVersion } from "./browser_accessibility_receipt.mjs";

export const AXE_RUN_OPTIONS = {
  runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
};

export const CONTROL_SELECTOR = [
  "button", 'input:not([type="hidden"])', "select", "textarea", "a[href]",
  '[role="button"]', '[role="tab"]', '[role="checkbox"]', '[role="switch"]', "summary",
].join(",");

// Serialized into an extension page or the real action popup. Keep it
// self-contained: only document, getComputedStyle and element methods are used.
// A control counts only when it is a real Tab stop: not disabled, not inside a
// hidden/inert/closed-<details> ancestor, and visible per CSS/content visibility.
export function focusSnapshot(selector) {
  const doc = globalThis.document;
  const styleOf = (element) => {
    try { return globalThis.getComputedStyle(element); } catch { return null; }
  };
  const blockedByAncestor = (element) => {
    for (let node = element; node; node = node.parentElement) {
      if (node.hidden === true || node.hasAttribute?.("hidden")) return true;
      if (node.inert === true || node.hasAttribute?.("inert")) return true;
      if (node.localName === "details" && node.open !== true) {
        const summary = [...(node.children || [])].find((child) => child.localName === "summary");
        if (!summary || typeof summary.contains !== "function" || !summary.contains(element)) return true;
      }
    }
    return false;
  };
  const focusable = (element) => {
    if (!element || !(element.tabIndex >= 0)) return false;
    if (element.disabled === true ||
      (typeof element.matches === "function" && element.matches(":disabled"))) return false;
    if (blockedByAncestor(element)) return false;
    const style = styleOf(element);
    if (style && (style.display === "none" || style.visibility === "hidden" ||
      style.visibility === "collapse" || style.contentVisibility === "hidden")) return false;
    if (typeof element.checkVisibility === "function" &&
      !element.checkVisibility({ checkOpacity: false, checkVisibilityCSS: true })) return false;
    const rect = element.getBoundingClientRect?.();
    return !!rect && rect.width > 0 && rect.height > 0;
  };
  if (!doc || typeof doc.querySelectorAll !== "function") return { total: 0, activeIndex: -1 };
  const visible = [...doc.querySelectorAll(selector)].filter(focusable);
  return { total: visible.length, activeIndex: visible.indexOf(doc.activeElement) };
}

export async function injectAxe(target, source) {
  const session = await target.context().newCDPSession();
  const result = await session.send("Runtime.evaluate", {
    expression: source, awaitPromise: false, returnByValue: true,
  });
  if (result.exceptionDetails) fail("axe-injection-failed");
  const version = await target.evaluate(() => globalThis.axe?.version || "");
  if (!validateAxeVersion(version)) fail("axe-version-mismatch");
  return version;
}

export async function runAxe(target) {
  return await target.evaluate(async (options) => {
    const result = await globalThis.axe.run(document, options);
    return {
      violations: result.violations.map((rule) => ({
        id: String(rule.id || ""), impact: String(rule.impact || ""), nodes: (rule.nodes || []).length,
      })),
      incomplete: result.incomplete.map((rule) => ({
        id: String(rule.id || ""), impact: String(rule.impact || ""), nodes: (rule.nodes || []).length,
      })),
    };
  }, AXE_RUN_OPTIONS);
}

export async function horizontalOverflow(target) {
  return await target.evaluate(() =>
    document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
}

export async function lockedPopup(target) {
  return await target.evaluate(() => {
    const view = document.querySelector("#locked-view");
    if (!view || view.hidden !== false) return false;
    if (view.hasAttribute("hidden") || view.closest("[hidden]")) return false;
    if (typeof view.checkVisibility === "function" &&
      !view.checkVisibility({ checkOpacity: false, checkVisibilityCSS: true })) return false;
    return true;
  });
}

// Native background state/readiness proof, kept in addition to the platform
// context guard above: the real action popup only reaches this state after
// background.js accepted a state message from a tabless (popup) sender. A
// regular tab never passes core.validSender, so this probe would keep timing
// out there; it never replaces the context guard.
export async function popupReady(target) {
  return await target.evaluate(() => {
    const view = document.querySelector("#locked-view");
    const status = document.querySelector("#status");
    if (document.readyState !== "complete" || !view || view.hidden !== false) return false;
    if (view.hasAttribute("hidden")) return false;
    if (typeof view.checkVisibility === "function" &&
      !view.checkVisibility({ checkOpacity: false, checkVisibilityCSS: true })) return false;
    return !!status && (status.textContent || "").trim().length > 0;
  });
}

// Read-only platform proof that the attached target is the actual extension
// action popup and not a regular tab that happens to load popup.html:
//  * chrome.extension.getViews({type:"popup"}) must contain the real window;
//  * chrome.tabs.getCurrent must call back with undefined (tabless);
//  * the actual document must be visible at the exact fixed popup URL.
// It never sends runtime/auth/state/approval messages and never opens the popup.
export async function assertActionPopupContext(target, expectedURL) {
  if (typeof expectedURL !== "string" || expectedURL.length === 0) {
    fail("popup-context-not-action");
  }
  let proof;
  try {
    proof = await target.evaluate(async (expected) => {
      try {
        const api = globalThis.chrome;
        if (!api || !api.extension || typeof api.extension.getViews !== "function" ||
          !api.tabs || typeof api.tabs.getCurrent !== "function") {
          return { ok: false, platform: true };
        }
        let views;
        try { views = api.extension.getViews({ type: "popup" }); }
        catch { return { ok: false, platform: true }; }
        if (!Array.isArray(views)) return { ok: false, platform: true };
        if (!views.includes(window)) return { ok: false, reason: "view" };
        const current = await new Promise((resolve) => {
          let settled = false;
          let timer = 0;
          const finish = (result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            resolve(result);
          };
          timer = setTimeout(() => finish({ reception: "timeout" }), 3000);
          try { api.tabs.getCurrent((tab) => finish({ reception: "callback", tab })); }
          catch { finish({ reception: "error" }); }
        });
        if (current.reception !== "callback") return { ok: false, platform: true };
        if (current.tab !== undefined) return { ok: false, reason: "tab" };
        if (document.visibilityState !== "visible" || document.hidden !== false) return { ok: false, reason: "visibility" };
        if (String(location.href) !== expected) return { ok: false, reason: "url" };
        return { ok: true };
      } catch { return { ok: false, platform: true }; }
    }, expectedURL);
  } catch {
    fail("popup-context-unavailable");
  }
  if (!proof || proof.ok !== true) {
    const reason = ["view", "tab", "visibility", "url"].includes(proof?.reason)
      ? proof.reason : "platform";
    console.log("Action popup context check failed: " + reason);
    if (proof?.platform === true) fail("popup-context-unavailable");
    fail("popup-context-not-action");
  }
  return true;
}

export async function tabReachability(target) {
  const initial = await target.evaluate(focusSnapshot, CONTROL_SELECTOR);
  const total = Number.isSafeInteger(initial?.total) ? initial.total : 0;
  const seen = new Set();
  if (Number.isSafeInteger(initial?.activeIndex) && initial.activeIndex >= 0 && initial.activeIndex < total) {
    seen.add(initial.activeIndex);
  }
  let steps = 0;
  const maxSteps = Math.min(total + 10, 200);
  for (let index = 0; index < maxSteps && seen.size < total; index += 1) {
    await target.keyboard.press("Tab");
    steps += 1;
    const snapshot = await target.evaluate(focusSnapshot, CONTROL_SELECTOR);
    if (Number.isSafeInteger(snapshot?.activeIndex) && snapshot.activeIndex >= 0 &&
      snapshot.activeIndex < total) seen.add(snapshot.activeIndex);
  }
  return keyboardSummary({ total, reached: seen.size, tabSteps: steps });
}

export const probes = {
  AXE_RUN_OPTIONS, CONTROL_SELECTOR, focusSnapshot, injectAxe, runAxe,
  assertActionPopupContext, horizontalOverflow, lockedPopup, popupReady, tabReachability,
};

export { AXE_VERSION };

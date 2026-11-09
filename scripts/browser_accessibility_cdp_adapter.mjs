import { readFileSync } from "node:fs";
import { join } from "node:path";
import { AccessibilityError, fail } from "./browser_accessibility_receipt.mjs";

const LOCAL_WS = /^ws:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d+\//;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function popupURL(extensionId) {
  return `chrome-extension://${extensionId}/popup.html`;
}

export function parseDevToolsPort(text) {
  const first = String(text || "").split(/\r?\n/)[0].trim();
  if (!/^\d+$/.test(first)) fail("devtools-port-timeout");
  const port = Number(first);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) fail("devtools-port-timeout");
  return port;
}

export async function readDevToolsPort(profile, { timeoutMs = 15000, intervalMs = 50 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return parseDevToolsPort(readFileSync(join(profile, "DevToolsActivePort"), "utf8"));
    } catch {
      await sleep(intervalMs);
    }
  }
  fail("devtools-port-timeout");
}

export function browserEndpoint(port) {
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) fail("devtools-port-timeout");
  return `http://127.0.0.1:${port}`;
}

export async function browserVersion(port, { timeoutMs = 3000 } = {}) {
  try {
    const response = await fetch(`${browserEndpoint(port)}/json/version`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) return "unknown";
    const info = await response.json();
    const value = typeof info?.Browser === "string" ? info.Browser : "";
    return /^[A-Za-z0-9 .()/_-]{1,120}$/.test(value) ? value : "unknown";
  } catch {
    return "unknown";
  }
}

export async function listTargets(port, { timeoutMs = 3000 } = {}) {
  let response;
  try {
    response = await fetch(`${browserEndpoint(port)}/json/list`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    fail("devtools-list-failed");
  }
  if (!response.ok) fail("devtools-list-failed");
  const targets = await response.json().catch(() => fail("devtools-targets-invalid"));
  if (!Array.isArray(targets)) fail("devtools-targets-invalid");
  return targets;
}

export function selectActionPopupTarget(targets, extensionId, previousIds = []) {
  if (!Array.isArray(targets)) fail("devtools-targets-invalid");
  const url = popupURL(extensionId);
  const previous = new Set(previousIds);
  const fresh = targets.filter((target) =>
    target && target.url === url && typeof target.id === "string" && !previous.has(target.id));
  if (!fresh.length) fail("popup-not-opened");
  // CDP target type alone cannot prove the action popup: Edge has reported the
  // real popup as both "other" and "page". Accept either type only as a fresh,
  // unique, exact-URL, local-WebSocket candidate; the attached page must then
  // prove its action-popup context through the platform read-only guard.
  const candidates = fresh.filter((target) =>
    (target.type === "page" || target.type === "other") &&
    typeof target.webSocketDebuggerUrl === "string" &&
    LOCAL_WS.test(target.webSocketDebuggerUrl));
  if (candidates.length > 1) fail("popup-target-ambiguous");
  if (candidates.length !== 1) fail("popup-target-not-action");
  return candidates[0];
}

export async function waitForActionPopup(port, extensionId, previousIds, {
  timeoutMs = 15000, intervalMs = 100,
} = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      return selectActionPopupTarget(await listTargets(port), extensionId, previousIds);
    } catch (error) {
      if (error?.code !== "popup-not-opened") throw error;
    }
    await sleep(intervalMs);
  }
  fail("popup-open-timeout");
}

export async function waitForTargetGone(port, targetId, { timeoutMs = 5000, intervalMs = 100 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const targets = await listTargets(port);
    if (!targets.some((target) => target?.id === targetId)) return true;
    await sleep(intervalMs);
  }
  fail("popup-close-timeout");
}

// The real action popup may be exposed by Chromium as an "other" or "page"
// target and Playwright does not reliably expose it as a Page. This adapter
// provides only the surface the read-only probes and Tab traversal need. It
// never sends product runtime messages, never disables CSP and never injects
// state. Target metadata alone is only a candidate; the caller must prove the
// attached popup context through the platform read-only guard before auditing.
export async function attachActionPopup(target, { port = 0, timeoutMs = 5000 } = {}) {
  if (!target || typeof target.webSocketDebuggerUrl !== "string" ||
    !LOCAL_WS.test(target.webSocketDebuggerUrl)) fail("popup-attach-failed");
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  const calls = new Map();
  let seq = 0;
  let closed = false;
  const rejectAll = () => {
    for (const call of calls.values()) {
      clearTimeout(call.timer);
      call.reject(new AccessibilityError("cdp-closed"));
    }
    calls.clear();
  };
  const abort = () => {
    closed = true;
    rejectAll();
  };
  ws.addEventListener("message", (event) => {
    let response;
    try { response = JSON.parse(event.data); } catch { return; }
    const call = calls.get(response.id);
    if (!call) return;
    calls.delete(response.id);
    clearTimeout(call.timer);
    if (response.error) call.reject(new AccessibilityError("cdp-closed"));
    else call.resolve(response.result || {});
  });
  // Post-open transport errors and closes must reject pending calls, never
  // throw from an event listener (a legitimate popup close can arrive later).
  ws.addEventListener("close", abort);
  ws.addEventListener("error", abort);
  await new Promise((resolve, reject) => {
    let settled = false;
    let timer = 0;
    const onOpen = () => settle(null);
    const onError = () => settle(new AccessibilityError("popup-attach-failed"));
    const onClose = () => settle(new AccessibilityError("popup-attach-failed"));
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onError);
      ws.removeEventListener("close", onClose);
    };
    const settle = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve();
    };
    timer = setTimeout(() => {
      try { ws.close(); } catch {}
      settle(new AccessibilityError("popup-attach-failed"));
    }, timeoutMs);
    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onError);
    ws.addEventListener("close", onClose);
  });
  const send = (method, params = {}, callTimeoutMs = 5000) => new Promise((resolve, reject) => {
    if (closed || ws.readyState !== WebSocket.OPEN) {
      reject(new AccessibilityError("cdp-closed"));
      return;
    }
    const id = ++seq;
    const timer = setTimeout(() => {
      calls.delete(id);
      reject(new AccessibilityError("cdp-timeout"));
    }, callTimeoutMs);
    calls.set(id, { resolve, reject, timer });
    ws.send(JSON.stringify({ id, method, params }));
  });
  const evaluate = async (fn, arg) => {
    const expression = `(${String(fn)})(${JSON.stringify(arg === undefined ? null : arg)})`;
    const result = await send("Runtime.evaluate", {
      expression, awaitPromise: true, returnByValue: true, userGesture: false,
    });
    if (result.exceptionDetails) fail("evaluation-failed");
    return result.result?.value;
  };
  await send("Runtime.enable").catch(() => fail("popup-attach-failed"));
  return {
    targetId: target.id,
    evaluate,
    context: () => ({ newCDPSession: () => ({ send: (method, params) => send(method, params) }) }),
    keyboard: {
      async press(key) {
        if (key !== "Tab") fail("unsupported-key");
        const params = {
          key: "Tab", code: "Tab", windowsVirtualKeyCode: 9, nativeVirtualKeyCode: 9,
        };
        await send("Input.dispatchKeyEvent", { type: "rawKeyDown", ...params });
        await send("Input.dispatchKeyEvent", { type: "keyUp", ...params });
      },
    },
    async setViewportSize({ width, height }) {
      if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) ||
        width < 1 || height < 1 || width > 10000 || height > 10000) fail("evaluation-failed");
      await send("Emulation.setDeviceMetricsOverride", {
        width, height, deviceScaleFactor: 1, mobile: false, screenWidth: width, screenHeight: height,
      });
    },
    async emulateMedia({ forcedColors, reducedMotion }) {
      if (!["none", "active"].includes(forcedColors) ||
        !["no-preference", "reduce"].includes(reducedMotion)) fail("evaluation-failed");
      await send("Emulation.setEmulatedMedia", {
        media: "",
        features: [
          { name: "forced-colors", value: forcedColors },
          { name: "prefers-reduced-motion", value: reducedMotion },
        ],
      });
    },
    wait: sleep,
    async poll(fn, arg, { timeoutMs: pollTimeoutMs = 10000, intervalMs = 100, errorCode = "poll-timeout" } = {}) {
      const deadline = Date.now() + pollTimeoutMs;
      while (Date.now() < deadline) {
        if (await evaluate(fn, arg)) return true;
        await sleep(intervalMs);
      }
      fail(errorCode);
    },
    async close() {
      try { await send("Page.close", {}, 1500); } catch {}
      try { ws.close(); } catch {}
      if (port) {
        try { await fetch(`${browserEndpoint(port)}/json/close/${encodeURIComponent(target.id)}`); } catch {}
      }
    },
  };
}

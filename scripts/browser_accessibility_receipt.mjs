import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";

export const SCHEMA = "locklark.browser-accessibility-receipt.v1";
export const AXE_VERSION = "4.10.3";
export const EXTENSION_ID = "geldnhjapnackobgknocomedmjgphnpe";
export const VIEWPORTS = [
  { id: "desktop", width: 1280, height: 800 },
  { id: "narrow-200pct-equivalent", width: 640, height: 800 },
];
export const MODES = [
  { id: "default", forcedColors: "none", reducedMotion: "no-preference" },
  { id: "forced-colors", forcedColors: "active", reducedMotion: "no-preference" },
  { id: "reduced-motion", forcedColors: "none", reducedMotion: "reduce" },
];
export const LIMITATIONS = [
  "No real screen reader (NVDA, VoiceOver or JAWS) was run.",
  "forced-colors and reduced-motion are browser emulation, not actual OS high contrast or motion settings.",
  "The narrow viewport is equivalent layout coverage, not real browser 200% zoom.",
  "The action popup is audited at its actual native dimensions; responsive viewport emulation is limited to the options page.",
  "Media emulation is CDP emulation, not real OS zoom, high contrast or reader output.",
  "The action popup was opened by the physical Ctrl+Shift+Y shortcut; no product state, unlock, approval or auth message was injected.",
  "No native host, vault, unlock, approval or authentication fixture was used.",
];
export const FAILURE_CODES = new Set([
  "axe-unavailable", "axe-version-mismatch", "axe-injection-failed", "source-dirty",
  "source-unavailable", "build-failed", "extension-identity", "browser-launch-failed",
  "devtools-port-timeout", "devtools-targets-invalid", "devtools-list-failed",
  "popup-not-opened", "popup-open-timeout", "popup-target-ambiguous",
  "popup-target-not-action", "popup-context-not-action", "popup-context-unavailable",
  "popup-attach-failed", "popup-ready-timeout",
  "popup-not-locked", "popup-close-timeout", "native-shortcut-failed",
  "window-manager-unavailable",
  "options-open-failed", "evaluation-failed", "cdp-timeout", "cdp-closed",
  "unsupported-key", "poll-timeout", "receipt-invalid", "receipt-failure-code",
  "output-required", "output-exists", "axe-source-not-absolute",
  "axe-source-unavailable", "unknown-argument", "driver-error",
]);
const FORBIDDEN_KEYS = new Set([
  "html", "text", "nodehtml", "nodetext", "textcontent", "innerhtml", "value", "values",
  "fields", "field_values", "password", "secret", "token", "screenshot", "screenshots",
  "target", "targets", "selector", "selectors", "url", "urls", "path", "paths", "profile",
  "profile_path", "body", "request", "response", "cookie", "cookies", "headers",
]);
const PRIVATE_FRAGMENTS = ["/workspace/", "/tmp/", "file://", "data:image", "chrome-extension://"];

export class AccessibilityError extends Error {
  constructor(code) {
    if (!FAILURE_CODES.has(code)) code = "driver-error";
    super(code);
    this.code = code;
  }
}

export function fail(code) { throw new AccessibilityError(code); }
export function errorCode(error) { return error instanceof AccessibilityError ? error.code : "driver-error"; }
export function validateAxeVersion(version) { return version === AXE_VERSION; }

export function resolveAxeSource(explicit, env = process.env) {
  const source = explicit || env.LOCKLARK_TEST_AXE_SOURCE || "";
  if (!source || !isAbsolute(source)) fail("axe-source-not-absolute");
  const path = resolve(source);
  if (!existsSync(path) || !statSync(path).isFile()) fail("axe-source-unavailable");
  return path;
}

export function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function extensionIdFromKey(base64Key) {
  const digest = createHash("sha256").update(Buffer.from(base64Key, "base64")).digest();
  const alphabet = "abcdefghijklmnop";
  return [...digest.subarray(0, 16)].flatMap((byte) => [alphabet[byte >> 4], alphabet[byte & 15]]).join("");
}

export function minimizeAxeResult(raw) {
  const clean = (items) => (Array.isArray(items) ? items : []).map((rule) => ({
    id: String(rule?.id || "unknown"),
    impact: String(rule?.impact || "unknown"),
    nodes: Array.isArray(rule?.nodes) ? rule.nodes.length : 0,
  }));
  return { violations: clean(raw?.violations), incomplete: clean(raw?.incomplete) };
}

export function keyboardSummary({ total, reached, tabSteps }) {
  const ok = Number.isSafeInteger(total) && total > 0 && reached === total &&
    Number.isSafeInteger(tabSteps) && tabSteps >= 0;
  return { total, reached, tab_steps: tabSteps, status: ok ? "PASS" : "FAIL" };
}

export function auditStatus({ page, violations, overflow, keyboard, locked }) {
  if (!Array.isArray(violations) || violations.length > 0) return "FAIL";
  if (overflow !== false) return "FAIL";
  if (keyboard?.status !== "PASS") return "FAIL";
  if (page === "popup.html" && locked !== true) return "FAIL";
  return "PASS";
}

export function buildReceipt({
  head = "", sourceClean = true, sourceSha256 = "", axeStatus = "available",
  axeVersion = AXE_VERSION, axeSourceSha256 = "", browserVersion = "",
  audits = [], failure = "", unavailable = false,
}) {
  if (failure && !FAILURE_CODES.has(failure)) fail("receipt-failure-code");
  const unavailableState = unavailable === true || axeStatus !== "available";
  const publicAudits = unavailableState ? [] : audits;
  const effectiveFailure = failure || (sourceClean !== true ? "source-dirty" : "");
  const failed = effectiveFailure || publicAudits.some((audit) => audit.status !== "PASS");
  const summary = {
    audits: publicAudits.length,
    violations: publicAudits.reduce((sum, audit) => sum + audit.violations.length, 0),
    incomplete: publicAudits.reduce((sum, audit) => sum + audit.incomplete.length, 0),
    failed_audits: publicAudits.filter((audit) => audit.status !== "PASS").length,
  };
  return {
    schema: SCHEMA,
    state: unavailableState ? "UNAVAILABLE" : failed ? "FAIL" : "PASS",
    head,
    source_clean: sourceClean === true,
    ...(sourceSha256 ? { source_sha256: sourceSha256 } : {}),
    browser: "edge",
    browser_version: browserVersion,
    extension_id: EXTENSION_ID,
    axe: { status: axeStatus === "available" ? "available" : "UNAVAILABLE", version: axeVersion, source_sha256: axeSourceSha256 },
    ...(effectiveFailure ? { failure: effectiveFailure } : {}),
    audits: publicAudits,
    summary,
    not_claimed: [...LIMITATIONS],
  };
}

function scan(value) {
  if (Array.isArray(value)) { value.forEach(scan); return; }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(key.toLowerCase())) fail("receipt-invalid");
      scan(child);
    }
    return;
  }
  if (typeof value !== "string") return;
  for (const fragment of PRIVATE_FRAGMENTS) {
    if (value.toLowerCase().includes(fragment)) fail("receipt-invalid");
  }
}

export function assertPublicReceipt(receipt) {
  scan(receipt);
  if (!["PASS", "FAIL", "UNAVAILABLE"].includes(receipt.state)) fail("receipt-invalid");
  if (receipt.failure && !FAILURE_CODES.has(receipt.failure)) fail("receipt-failure-code");
  if (receipt.state === "UNAVAILABLE" && receipt.audits.length !== 0) fail("receipt-invalid");
  if (receipt.state === "PASS") {
    if (receipt.source_clean !== true) fail("receipt-invalid");
    if (receipt.audits.length === 0) fail("receipt-invalid");
    if (receipt.audits.some((audit) => audit.status !== "PASS" || audit.violations.length > 0)) {
      fail("receipt-invalid");
    }
  }
  return true;
}

export function ensureNewOutput(out) {
  if (!out) fail("output-required");
  const path = resolve(out);
  if (existsSync(path)) fail("output-exists");
  return path;
}

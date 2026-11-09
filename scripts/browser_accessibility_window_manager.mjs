// Read-only native window-manager preflight for the real action-popup audit.
//
// The physical Ctrl+Shift+Y popup is a transient X11 window: without a real
// EWMH window manager, Chromium can lose focus or tear the popup down while a
// CDP session is attaching, which used to surface as a sporadic cdp-closed.
// This guard only reads the standard EWMH _NET_SUPPORTING_WM_CHECK property
// (root window plus the manager's self-reference). It never starts, replaces,
// installs or configures a window manager, display, desktop setting or user
// preference. A missing DISPLAY/property/tool is a fixed, explicit
// window-manager-unavailable result rather than a later random CDP failure.
import { execFileSync } from "node:child_process";
import { fail } from "./browser_accessibility_receipt.mjs";

export const WINDOW_MANAGER_READY = "ready";
export const WINDOW_MANAGER_UNAVAILABLE = "window-manager-unavailable";

const PROPERTY = "_NET_SUPPORTING_WM_CHECK";
const PROPERTY_LINE = /^_NET_SUPPORTING_WM_CHECK\(WINDOW\):\s*window id #\s*(0x[0-9a-fA-F]{1,16})\s*$/m;

function parseWindowId(stdout) {
  const match = String(stdout || "").match(PROPERTY_LINE);
  return match ? match[1].toLowerCase() : "";
}

// xprop is a fixed, read-only host dependency. Any spawn error, timeout or
// non-zero exit means "cannot prove a window manager is present" and must not
// leak a raw exception or a later CDP error into the receipt.
function runXprop(args, { env }) {
  try {
    const stdout = execFileSync("xprop", args, {
      env,
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return { ok: true, stdout };
  } catch {
    return { ok: false, stdout: "" };
  }
}

// Public protocol guard: return the strict ready enum, or fail with exactly the
// fixed window-manager-unavailable code. Callers must run this before opening
// Edge or sending the action shortcut.
export function assertNativeWindowManager({ env = process.env, run = runXprop } = {}) {
  if (typeof env?.DISPLAY !== "string" || env.DISPLAY.trim() === "") {
    fail(WINDOW_MANAGER_UNAVAILABLE);
  }
  let root;
  try {
    root = run(["-root", PROPERTY], { env });
  } catch {
    fail(WINDOW_MANAGER_UNAVAILABLE);
  }
  if (!root || root.ok !== true) fail(WINDOW_MANAGER_UNAVAILABLE);
  const rootWindow = parseWindowId(root.stdout);
  if (!rootWindow) fail(WINDOW_MANAGER_UNAVAILABLE);

  // EWMH requires the manager's check window to carry the same property and
  // point to itself. This distinguishes a real manager from a stale root atom.
  let manager;
  try {
    manager = run(["-id", rootWindow, PROPERTY], { env });
  } catch {
    fail(WINDOW_MANAGER_UNAVAILABLE);
  }
  if (!manager || manager.ok !== true) fail(WINDOW_MANAGER_UNAVAILABLE);
  if (parseWindowId(manager.stdout) !== rootWindow) fail(WINDOW_MANAGER_UNAVAILABLE);

  return { status: WINDOW_MANAGER_READY };
}

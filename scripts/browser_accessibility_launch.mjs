// Launch helpers for the read-only action-popup accessibility audit.
// Runs the real Edge binary as a normal process with a private throwaway
// profile and a local, credential-free fixture page (never auth, vault or
// native host). The action popup is opened only by a physical Ctrl+Shift+Y
// through the existing guarded XTest driver.
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { fail } from "./browser_accessibility_receipt.mjs";
import { listTargets, readDevToolsPort } from "./browser_accessibility_cdp_adapter.mjs";
import { popupReady } from "./browser_accessibility_probes.mjs";

export const FIXTURE_TITLE = "Locklark accessibility acceptance";
export const ACTION_SHORTCUT = "Control_L+Shift_L+y";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function gitHead(root) {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root }).toString().trim();
  } catch {
    fail("source-unavailable");
  }
}

function digestTree(root) {
  if (!existsSync(root)) return "";
  const hash = createHash("sha256");
  const walk = (directory) => {
    for (const entry of readdirSync(directory).sort()) {
      const path = join(directory, entry);
      if (statSync(path).isDirectory()) walk(path);
      else {
        hash.update(entry);
        hash.update(readFileSync(path));
      }
    }
  };
  walk(root);
  return hash.digest("hex");
}

// Refuse to claim git HEAD as evidence when the product sources are dirty, and
// always bind the receipt to the exact built extension bytes that were audited.
export function sourceState(root) {
  let status = "";
  try {
    status = execFileSync("git", ["status", "--porcelain", "--untracked-files=no", "--", "browser-extension"], {
      cwd: root,
    }).toString();
  } catch {
    fail("source-unavailable");
  }
  return { clean: status.trim() === "", sha256: digestTree(join(root, "browser-extension/dist/chromium")) };
}

export function startFixturePage() {
  return new Promise((resolve, reject) => {
    const server = createServer((request, response) => {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'",
      });
      response.end(`<!doctype html><html lang="en"><head><title>${FIXTURE_TITLE}</title></head>` +
        `<body><h1>${FIXTURE_TITLE}</h1><p>Credential-free focus page; no product data.</p></body></html>`);
    });
    server.once("error", () => reject(Object.assign(new Error("browser-launch-failed"), { code: "browser-launch-failed" })));
    server.listen(0, "127.0.0.1", () => {
      resolve({ url: `http://127.0.0.1:${server.address().port}/`, close: () => server.close() });
    });
  });
}

export function launchEdge({ executable, profile, extension, url }) {
  const child = spawn(executable, [
    `--user-data-dir=${profile}`,
    "--remote-debugging-port=0",
    "--no-sandbox",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-sync",
    "--no-proxy-server",
    "--window-size=1200,850",
    `--disable-extensions-except=${extension}`,
    `--load-extension=${extension}`,
    url,
  ], { stdio: "ignore" });
  child.launchError = null;
  child.once("error", () => { child.launchError = "browser-launch-failed"; });
  return child;
}

export async function waitForFixturePage(port, url, { timeoutMs = 15000, intervalMs = 100 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const targets = await listTargets(port).catch(() => []);
    if (targets.some((target) => target?.type === "page" && target.url === url)) return true;
    await sleep(intervalMs);
  }
  fail("browser-launch-failed");
}

export function sendActionShortcut(root) {
  let output;
  try {
    output = execFileSync("python3", [join(root, "scripts/browser_native_x11.py")], {
      input: JSON.stringify({ title_prefix: FIXTURE_TITLE, actions: [{ key: ACTION_SHORTCUT }] }),
      env: process.env,
      timeout: 20000,
      stdio: ["pipe", "pipe", "ignore"],
    }).toString();
  } catch {
    fail("native-shortcut-failed");
  }
  let result;
  try { result = JSON.parse(output); } catch { fail("native-shortcut-failed"); }
  if (!validNativeWindowResult(result)) fail("native-shortcut-failed");
  return result;
}

// browser_native_x11.py serializes the X11 Window integer as a JSON number.
// Refuse malformed acknowledgements without rejecting a successful XTest call.
export function validNativeWindowResult(result) {
  return !!result && Number.isSafeInteger(result.window) &&
    result.window > 0 && result.window <= 0xffffffff;
}

// A readiness timeout is a hard failure: it is exactly how a regular-tab
// popup.html (sender.tab set, state message refused) reveals itself.
export async function waitForPopupReady(popup, { timeoutMs = 15000, intervalMs = 100 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await popupReady(popup)) return true;
    await sleep(intervalMs);
  }
  fail("popup-ready-timeout");
}

export async function stopBrowser(child) {
  if (!child || child.exitCode !== null) return;
  try { child.kill("SIGTERM"); } catch {}
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline && child.exitCode === null) await sleep(100);
  if (child.exitCode === null) {
    try { child.kill("SIGKILL"); } catch {}
  }
}

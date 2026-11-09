#!/usr/bin/env node
// External, read-only accessibility audit of the real Locklark extension.
// The action popup is opened by a physical Ctrl+Shift+Y on a normal Edge
// process; no regular-tab popup.html is accepted as popup evidence. CDP target
// metadata only selects a unique candidate; the attached document must prove
// its tabless popup view and fixed visible URL before any audit. No product
// state, unlock, approval, auth or native-host message is injected.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  AXE_VERSION, EXTENSION_ID, SCHEMA, assertPublicReceipt, buildReceipt, ensureNewOutput,
  errorCode, extensionIdFromKey, fail, resolveAxeSource, sha256File,
} from "./browser_accessibility_receipt.mjs";
import { auditTarget, openOptionsTarget, pageTarget } from "./browser_accessibility_audit.mjs";
import {
  attachActionPopup, browserEndpoint, browserVersion as edgeVersion, listTargets, popupURL,
  readDevToolsPort, waitForActionPopup, waitForTargetGone,
} from "./browser_accessibility_cdp_adapter.mjs";
import {
  FIXTURE_TITLE, gitHead, launchEdge, sendActionShortcut, sourceState,
  startFixturePage, stopBrowser, waitForFixturePage, waitForPopupReady,
} from "./browser_accessibility_launch.mjs";
import { assertActionPopupContext, lockedPopup } from "./browser_accessibility_probes.mjs";
import { WINDOW_MANAGER_UNAVAILABLE, assertNativeWindowManager } from "./browser_accessibility_window_manager.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PLAYWRIGHT = process.env.LOCKLARK_TEST_PLAYWRIGHT || "/workspace/locklark/web/node_modules/playwright";
const EDGE = process.env.LOCKLARK_TEST_EDGE || "/workspace/toolchains/edge/opt/microsoft/msedge/msedge";
const EXTENSION = join(ROOT, "browser-extension/dist/chromium");
const USAGE = `Usage: node scripts/browser_accessibility_acceptance.mjs --out <new-public.json> [--axe-source <absolute path>]

LOCKLARK_TEST_AXE_SOURCE may supply the pinned axe-core ${AXE_VERSION} axe.min.js path.
Requires a visible GUI session with a real EWMH window manager on DISPLAY: a
read-only _NET_SUPPORTING_WM_CHECK preflight runs before Edge/action. The parent
then opens the real action popup with a physical Ctrl+Shift+Y through
scripts/browser_native_x11.py.` + "\n";

function parseArgs(argv) {
  const args = { out: "", axeSource: "", help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--help" || value === "-h") args.help = true;
    else if (value === "--out") args.out = argv[++index] || "";
    else if (value === "--axe-source") args.axeSource = argv[++index] || "";
    else fail("unknown-argument");
  }
  return args;
}

function writeReceipt(path, receipt) {
  assertPublicReceipt(receipt);
  writeFileSync(path, JSON.stringify(receipt, null, 2) + "\n", { flag: "wx" });
  console.log(`wrote ${path}: state=${receipt.state} audits=${receipt.summary.audits} ` +
    `violations=${receipt.summary.violations}`);
}

function buildExtension() {
  try {
    execFileSync(process.execPath, [join("browser-extension", "build.js"), "chromium"], { cwd: ROOT, stdio: "inherit" });
  } catch {
    fail("build-failed");
  }
  const manifest = JSON.parse(readFileSync(join(EXTENSION, "manifest.json"), "utf8"));
  if (extensionIdFromKey(manifest.key || "") !== EXTENSION_ID) fail("extension-identity");
}

async function disconnect(browser) {
  await Promise.race([
    browser.close().catch(() => {}),
    new Promise((resolve) => { const timer = setTimeout(resolve, 5000); timer.unref?.(); }),
  ]);
}

async function auditRealPages({ chromium, profile, fixture, axeSource }) {
  const edge = launchEdge({ executable: EDGE, profile, extension: EXTENSION, url: fixture.url });
  let port = 0;
  let browser = null;
  let popup = null;
  try {
    port = await readDevToolsPort(profile);
    const version = await edgeVersion(port);
    if (edge.launchError) fail("browser-launch-failed");
    await waitForFixturePage(port, fixture.url);
    const previousIds = (await listTargets(port)).map((target) => target.id);
    sendActionShortcut(ROOT);
    const target = await waitForActionPopup(port, EXTENSION_ID, previousIds);
    popup = await attachActionPopup(target, { port });
    await assertActionPopupContext(popup, popupURL(EXTENSION_ID));
    await waitForPopupReady(popup, { timeoutMs: 15000 });
    if (!(await lockedPopup(popup))) fail("popup-not-locked");
    const popupAudits = await auditTarget(popup, { pageName: "popup.html", axeSource });
    console.log("audited real action popup (native sender path, locked state)");
    await popup.close();
    popup = null;
    await waitForTargetGone(port, target.id);
    console.log("closed action popup before options audit");
    browser = await chromium.connectOverCDP(browserEndpoint(port));
    const context = browser.contexts()[0] || (await browser.newContext());
    const options = await openOptionsTarget(context, EXTENSION_ID, pageTarget);
    try {
      const optionsAudits = await auditTarget(options, { pageName: "options.html", axeSource });
      return { audits: [...popupAudits, ...optionsAudits], browserVersion: version };
    } finally {
      await options.close().catch(() => {});
    }
  } finally {
    if (popup) await popup.close().catch(() => {});
    if (browser) await disconnect(browser);
    await stopBrowser(edge);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) { console.log(USAGE); return 0; }
  const out = ensureNewOutput(args.out);
  const head = gitHead(ROOT);
  const before = sourceState(ROOT);
  if (!before.clean) {
    writeReceipt(out, buildReceipt({ head, sourceClean: false, failure: "source-dirty" }));
    return 1;
  }
  let axePath;
  try { axePath = resolveAxeSource(args.axeSource); } catch (error) {
    if (!String(errorCode(error)).startsWith("axe-source-")) throw error;
    writeReceipt(out, buildReceipt({ head, sourceClean: true, axeStatus: "UNAVAILABLE", failure: "axe-unavailable" }));
    return 3;
  }
  const axeSourceSha256 = sha256File(axePath);
  const axeSource = readFileSync(axePath, "utf8");
  const profile = mkdtempSync(join(tmpdir(), "locklark-a11y-"));
  let audited = { clean: before.clean, sha256: "" };
  let fixture = null;
  let audits = [];
  let failure = "";
  let axeUnavailable = false;
  let environmentUnavailable = false;
  let browserVersion = "";
  try {
    buildExtension();
    audited = sourceState(ROOT);
    assertNativeWindowManager();
    const { chromium } = createRequire(import.meta.url)(PLAYWRIGHT);
    fixture = await startFixturePage();
    const result = await auditRealPages({ chromium, profile, fixture, axeSource });
    audits = result.audits;
    browserVersion = result.browserVersion;
  } catch (error) {
    const code = errorCode(error);
    if (code === "axe-version-mismatch") {
      axeUnavailable = true;
      failure = "axe-version-mismatch";
    } else if (code === WINDOW_MANAGER_UNAVAILABLE) {
      environmentUnavailable = true;
      failure = WINDOW_MANAGER_UNAVAILABLE;
    } else {
      failure = code;
    }
    audits = [];
  } finally {
    fixture?.close();
    rmSync(profile, { recursive: true, force: true });
  }
  const receipt = buildReceipt({
    head, sourceClean: audited.clean, sourceSha256: audited.sha256,
    axeStatus: axeUnavailable ? "UNAVAILABLE" : "available", axeVersion: AXE_VERSION,
    axeSourceSha256, browserVersion, audits, failure, unavailable: environmentUnavailable,
  });
  writeReceipt(out, receipt);
  return receipt.state === "PASS" ? 0 : receipt.state === "FAIL" ? 1 : 3;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((code) => { process.exitCode = code; }).catch((error) => {
    console.error(`accessibility driver failed [${errorCode(error)}]`);
    process.exitCode = 2;
  });
}

export { main, parseArgs, SCHEMA, USAGE, FIXTURE_TITLE };

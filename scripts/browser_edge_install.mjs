// Real Microsoft Edge extension install through the visible edge://extensions
// manager. Edge ignores the deprecated --load-extension /
// --disable-extensions-except switches, so the built package is installed only
// through the real manager UI and the native GTK directory chooser.
//
// The manager's controls live in shadow roots. document.querySelectorAll
// cannot see them, so every control is found with Playwright's standard
// locator visibility and clicked only at its measured box, through real CDP
// mouse input:
//
//   1. the unique visible Developer mode switch (fluent-switch); its real
//      boolean checked property is read, and it is clicked only when it is
//      false, then the same visible switch must report true. Browser-chrome
//      Extensions menu state is never required.
//   2. the unique visible Load unpacked control (fluent-button[title=...]);
//      physically clicked at its measured box.
//   3. the native chooser, driven by scripts/browser_native_x11.py with the
//      exact owner request: the actual ASCII page title as the manager prefix,
//      the exact private --user-data-dir, the real Edge image and owner: true.
//      The driver derives the owner PID from the unique real manager window
//      and proves the chooser's ownership before any XTest input.
//   4. the fixed extension target and exactly the expected background.js
//      service worker.
//
// No preload, addInitScript, init script, Extensions.loadUnpacked, extension
// load switch, direct extension storage/preference write, setInputFiles,
// filechooser.setFiles or hidden UI state is used.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Fixed identity derived from the manifest "key".
export const EDGE_EXTENSION_ID = "geldnhjapnackobgknocomedmjgphnpe";
export const EDGE_BACKGROUND_URL =
  "chrome-extension://" + EDGE_EXTENSION_ID + "/background.js";

// Manifest public key -> Chrome extension id: the first 16 SHA-256 bytes as
// hex, with each hex digit mapped into a lowercase letter (0-9 -> a-j,
// a-f -> k-p).
export function manifestExtensionId(extensionDir) {
  const manifest = JSON.parse(
    readFileSync(join(extensionDir, "manifest.json"), "utf8"),
  );
  assert.equal(manifest.manifest_version, 3, "Chromium package required");
  assert.equal(typeof manifest.key, "string", "extension key required");
  assert.equal(
    manifest.background?.service_worker,
    "background.js",
    "service worker required",
  );
  return [...createHash("sha256")
    .update(Buffer.from(manifest.key, "base64"))
    .digest("hex")
    .slice(0, 32)]
    .map((digit) => String.fromCharCode(97 + parseInt(digit, 16)))
    .join("");
}

export const EDGE_MANAGER_URL = "edge://extensions/";
// Install-only PASS label: the manifest-derived ID and its background.js
// service worker were proven through the real manager UI. No pairing ran.
export const EDGE_INSTALL_PASS =
  "PASS: real Edge extension installed through the visible edge://extensions " +
  "Developer mode switch and Load unpacked chooser; manifest-derived extension " +
  "ID " + EDGE_EXTENSION_ID + " with exactly " + EDGE_BACKGROUND_URL +
  " service worker";
export const EDGE_DEVELOPER_SWITCH_SELECTOR =
  'fluent-switch[aria-label="Developer mode"]';
export const EDGE_LOAD_UNPACKED_SELECTOR = 'fluent-button[title="Load unpacked"]';
// Title copied by the manager's own Load unpacked dialog (Edge 157 amd64).
export const EDGE_CHOOSER_TITLE_PREFIX = "Select the extension directory.";
// The prefix the manager page always carries. The actual page title must be
// an ASCII extension of this prefix; it is never manufactured here. The
// browser-chrome "Extensions menu" is not required: the Developer mode switch
// is already visible on edge://extensions.
export const EDGE_PAGE_TITLE_PREFIX = "Extensions";
export const EDGE_FORBIDDEN_FLAGS = [
  "--load-extension",
  "--disable-extensions-except",
];

// Stage labels are printed only after the step they name. A failing stage and
// its fixed classification are reported by runEdgeInstallStage, never by
// echoing selector errors, window titles, paths or driver output.
export const EDGE_INSTALL_REASONS = Object.freeze({
  "edge-page": "edge-manager-unavailable",
  "edge-developer-mode": "edge-developer-mode-failed",
  "edge-load-unpacked": "edge-load-unpacked-unavailable",
  "edge-chooser": "chooser-not-owned",
  "edge-installed": "edge-extension-not-installed",
  "edge-service-worker": "edge-service-worker-missing",
});

export class EdgeInstallError extends Error {
  constructor(stage) {
    super(EDGE_INSTALL_REASONS[stage] || "edge-install-unclassified");
    this.name = "EdgeInstallError";
  }
}

export function assertEdgeLaunchArguments(args) {
  for (const arg of args)
    assert(
      !EDGE_FORBIDDEN_FLAGS.includes(String(arg).split("=", 1)[0]),
      "Edge launch must not use extension load switches",
    );
}

function printableAsciiLine(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    [...value].every((character) => {
      const code = character.codePointAt(0);
      return code >= 32 && code <= 126;
    })
  );
}

// The watchdog matches the page title by prefix, so only a real manager title
// is accepted: trimmed printable ASCII that starts with the Extensions prefix
// (which keeps it out of every browser-chrome "<page> - <profile> - Microsoft
// Edge" title). The request must carry exactly that title.
export function assertChooserRequest(request, actualTitle) {
  assert(
    printableAsciiLine(actualTitle) && !/^\s|\s$/.test(actualTitle),
    "actual page title must be trimmed ASCII",
  );
  // The manager page itself starts with the fixed prefix and is not one of
  // the browser-chrome "<page> - <profile> - Microsoft Edge" titles.
  assert(
    actualTitle.startsWith(EDGE_PAGE_TITLE_PREFIX),
    "actual page title must name the Extensions manager",
  );
  assert.deepEqual(request.title, actualTitle);
  assert.equal(request.title_prefix, actualTitle);
  assert.equal(request.owner_title_prefix, actualTitle);
  assert.equal(request.chooser_title_prefix, EDGE_CHOOSER_TITLE_PREFIX);
  assert.equal(request.owner, true);
  assert.equal(request.preserve_focus, true);
  return request;
}

// The X11 helper request for the native GTK directory chooser. `title` is the
// observed actual page.title() and is required: the helper re-locates the
// unique manager window by that exact ASCII prefix, derives its PID from it,
// proves the exact executable image, the single exact private --user-data-dir
// switch and the chooser's ownership, then sends Ctrl+L, the absolute package
// directory and Return. The caller PID is never supplied.
export function edgeChooserX11Request({ extensionDir, executable, profile, title }) {
  assert(typeof title === "string" && title !== "", "actual page title required");
  assert(extensionDir.startsWith("/"), "absolute extension directory required");
  assert(executable.startsWith("/"), "absolute Edge executable required");
  assert(profile.startsWith("/"), "absolute profile required");
  assert(!profile.endsWith("/"), "profile must not end with a slash");
  for (const value of [extensionDir, executable, profile])
    assert(printableAsciiLine(value), "chooser input must be printable ASCII");
  return assertChooserRequest({
    owner: true,
    title,
    title_prefix: title,
    chooser_title_prefix: EDGE_CHOOSER_TITLE_PREFIX,
    owner_title_prefix: title,
    user_data_dir: profile,
    executable,
    preserve_focus: true,
    actions: [{ key: "Control_L+l" }, { text: extensionDir }, { key: "Return" }],
  }, title);
}

// Exactly one visible copy, judged only by Playwright's visibility filter; no
// DOM count, shadow-root traversal or hidden element is consulted.
async function uniqueVisible(locator, eventually) {
  let match = null;
  await eventually(async () => {
    if ((await locator.count()) !== 1) return false;
    const box = await locator.first().boundingBox();
    match = box && box.width > 0 && box.height > 0 ? { locator, box } : null;
    return match !== null;
  }, "unique-visible");
  return match;
}

// One real pointer click (motion, press, release) at the control's measured box
// through CDP. No page-side listener, instrumentation or DOM click is used;
// the effect is verified through the control's own real state.
async function realClick(page, box) {
  const x = box.x + box.width / 2;
  const y = box.y + box.height / 2;
  const client = await page.context().newCDPSession(page);
  try {
    await client.send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
    for (const type of ["mousePressed", "mouseReleased"])
      await client.send("Input.dispatchMouseEvent", {
        type,
        x,
        y,
        button: "left",
        clickCount: 1,
      });
  } finally {
    await client.detach().catch(() => {});
  }
}

// The real checked state of the unique visible switch, read from the exact
// element handle Playwright's visible locator resolved (a document lookup
// cannot see open shadow roots, and another copy is never consulted). The real
// Edge fluent-switch exposes no aria-checked and no accessible checked state;
// its visible component itself publishes a boolean `checked` property. Only
// that strict boolean is accepted: a missing, null or non-boolean value fails
// closed and is never treated as unchecked.
async function visibleSwitchState(locator) {
  const handle = await locator.first().elementHandle({ timeout: 5000 });
  if (!handle) throw Error("developer-switch");
  try {
    const checked = await handle.evaluate((element) => element.checked);
    if (typeof checked !== "boolean") throw Error("developer-switch");
    return checked ? "checked" : "unchecked";
  } finally {
    await handle.dispose();
  }
}

// Manager-UI install of the built package. Nothing here pairs, unlocks or
// starts any later journey.
export async function installEdgeExtensionThroughManager({
  browser,
  page,
  extensionDir,
  edgeExecutable,
  profile,
  inputRequest,
  eventually,
  phase,
}) {
  const failed = (stage, error) =>
    error instanceof EdgeInstallError ? error : new EdgeInstallError(stage);
  const step = async (stage, action) => {
    try {
      return await action();
    } catch (error) {
      throw failed(stage, error);
    }
  };
  await page.bringToFront();
  await step("edge-page", async () => {
    phase("edge-manager");
    await page.goto(EDGE_MANAGER_URL);
    await eventually(
      async () => (await page.title()).startsWith(EDGE_PAGE_TITLE_PREFIX),
      "edge-page",
    );
  });
  // The Developer mode switch is already visible on edge://extensions/, so no
  // browser-chrome Extensions menu step is required. Competing manager windows
  // are refused inside the driver: it needs one unique viewable window for the
  // manager prefix and derives the owner PID from that window alone.
  await step("edge-developer-mode", async () => {
    phase("edge-developer-mode");
    const switchLocator = page
      .locator(EDGE_DEVELOPER_SWITCH_SELECTOR)
      .filter({ visible: true });
    const { box } = await uniqueVisible(switchLocator, eventually);
    // Toggle only when this same visible switch reports checked=false, then
    // require the same switch to report true.
    if ((await visibleSwitchState(switchLocator)) !== "checked")
      await realClick(page, box);
    await eventually(
      async () => (await visibleSwitchState(switchLocator)) === "checked",
      "edge-developer-mode",
    );
  });
  await step("edge-load-unpacked", async () => {
    phase("edge-load-unpacked");
    const { box } = await uniqueVisible(
      page.locator(EDGE_LOAD_UNPACKED_SELECTOR).filter({ visible: true }),
      eventually,
    );
    await realClick(page, box);
  });
  // The reviewed helper waits for the chooser itself before any XTest input,
  // so exactly one guarded request is issued. A failed child never reaches the
  // fixed proof check, and nothing is replayed after possible input.
  await step("edge-chooser", async () => {
    phase("edge-chooser");
    const title = await page.title();
    const chosen = inputRequest(edgeChooserX11Request({
      extensionDir,
      executable: edgeExecutable,
      profile,
      title,
    }));
    if (chosen?.ownership?.owned !== true)
      throw new EdgeInstallError("edge-chooser");
  });
  await step("edge-installed", async () => {
    // The explicit directory selection commits asynchronously; observe the
    // real fixed extension target only after the owned chooser proof.
    phase("edge-installed");
    await eventually(
      async () =>
        (await extensionTargets(browser)).some(
          (target) => target.url === EDGE_BACKGROUND_URL,
        ),
      "edge-installed",
    );
  });
  await step("edge-service-worker", async () => {
    phase("edge-service-worker");
    // The worker starts asynchronously after the extension target exists.
    await eventually(
      async () =>
        browser.serviceWorkers().length > 0 ||
        (await new Promise((resolve) => {
          const timer = setTimeout(() => resolve(false), 1000);
          browser.waitForEvent("serviceworker").then(
            () => (clearTimeout(timer), resolve(true)),
            () => (clearTimeout(timer), resolve(false)),
          );
        })),
      "edge-service-worker",
    );
  });
  // The manifest-derived ID must be the fixed ID, and exactly one service
  // worker must carry exactly its background.js URL.
  if (manifestExtensionId(extensionDir) !== EDGE_EXTENSION_ID)
    throw new EdgeInstallError("edge-installed");
  const identity = extensionWorkerIdentity(browser.serviceWorkers());
  if (identity === null) throw new EdgeInstallError("edge-service-worker");
  phase("continue");
  return identity;
}

// Exactly one service worker and exactly the expected background.js URL of the
// manifest-derived extension; anything else is null, never a partial match.
export function extensionWorkerIdentity(workers) {
  const urls = workers.map((worker) => worker.url());
  if (urls.length !== 1 || urls[0] !== EDGE_BACKGROUND_URL) return null;
  return { extensionId: EDGE_EXTENSION_ID, workerUrl: urls[0] };
}

// Real CDP target list; used to prove the manager finished installing the
// fixed extension origin before any product journey starts. Attached to a
// regular page when one exists (the extension's own pages are not targets of
// this context session).
export async function extensionTargets(browser) {
  const context = browser.contexts()[0];
  const pages = context?.pages() || [];
  const page = pages.find((candidate) => candidate.url().startsWith("http")) ||
    pages[0];
  if (!page) throw Error("edge-targets");
  const client = await context.newCDPSession(page);
  try {
    const { targetInfos } = await client.send("Target.getTargets");
    return targetInfos;
  } finally {
    await client.detach().catch(() => {});
  }
}

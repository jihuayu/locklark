// Static contract for the real Edge manager install: the fixed manifest-derived
// identity and the exact guarded X11 chooser request. No browser, X server,
// window titles or private paths are used or printed here.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  EDGE_BACKGROUND_URL,
  EDGE_CHOOSER_TITLE_PREFIX,
  EDGE_DEVELOPER_SWITCH_SELECTOR,
  EDGE_EXTENSION_ID,
  EDGE_LOAD_UNPACKED_SELECTOR,
  EDGE_MANAGER_URL,
  EDGE_INSTALL_REASONS,
  EdgeInstallError,
  assertChooserRequest,
  assertEdgeLaunchArguments,
  edgeChooserX11Request,
  extensionWorkerIdentity,
  manifestExtensionId,
} from "./browser_edge_install.mjs";

const FIXED_ID = "geldnhjapnackobgknocomedmjgphnpe";
const PRIVATE = {
  profile: "/tmp/locklark-private-profile",
  executable: "/opt/microsoft/msedge/msedge",
  extensionDir: "/tmp/locklark-private-extension/chromium",
  title: "Extensions",
};

function packageWith(manifest) {
  const directory = mkdtempSync(join(tmpdir(), "locklark-edge-contract-"));
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, "manifest.json"), JSON.stringify(manifest));
  return directory;
}

test("fixed manifest-derived identity and service worker", () => {
  assert.equal(EDGE_EXTENSION_ID, FIXED_ID);
  assert.equal(EDGE_BACKGROUND_URL, "chrome-extension://" + FIXED_ID + "/background.js");
  assert.equal(EDGE_MANAGER_URL, "edge://extensions/");
  const real = fileURLToPath(new URL("../browser-extension/dist/chromium", import.meta.url));
  assert.equal(manifestExtensionId(real), FIXED_ID);
});

test("the id is derived from the manifest key, not hard-coded", () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("synthetic-not-the-locklark-key").toString("base64"),
    background: { service_worker: "background.js" },
  });
  try {
    const derived = manifestExtensionId(directory);
    assert.match(derived, /^[a-p]{32}$/);
    assert.notEqual(derived, FIXED_ID);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  for (const manifest of [
    { manifest_version: 2, key: "AA==", background: { service_worker: "background.js" } },
    { manifest_version: 3, background: { service_worker: "background.js" } },
    { manifest_version: 3, key: "AA==", background: { service_worker: "other.js" } },
    { manifest_version: 3, key: "AA==" },
  ]) {
    const invalid = packageWith(manifest);
    try {
      assert.throws(() => manifestExtensionId(invalid));
    } finally {
      rmSync(invalid, { recursive: true, force: true });
    }
  }
});

test("Edge launch never carries extension load switches", () => {
  assertEdgeLaunchArguments(["--no-sandbox", "--remote-debugging-port=0"]);
  for (const flag of [
    "--load-extension=/tmp/x",
    "--disable-extensions-except=/tmp/x",
  ])
    assert.throws(() => assertEdgeLaunchArguments(["--no-sandbox", flag]));
});

test("chooser request is the exact owner input shape without a caller PID", () => {
  const request = edgeChooserX11Request(PRIVATE);
  assert.deepEqual(request, {
    owner: true,
    title: "Extensions",
    title_prefix: "Extensions",
    chooser_title_prefix: EDGE_CHOOSER_TITLE_PREFIX,
    owner_title_prefix: "Extensions",
    user_data_dir: PRIVATE.profile,
    executable: "/opt/microsoft/msedge/msedge",
    preserve_focus: true,
    actions: [
      { key: "Control_L+l" },
      { text: PRIVATE.extensionDir },
      { key: "Return" },
    ],
  });
  assert.equal(Object.hasOwn(request, "owner_pid"), false);
  // The actual observed page title is required; no title is manufactured.
  assert.throws(() => edgeChooserX11Request({ ...PRIVATE, title: undefined }));
  for (const title of [null, "", "edge://extensions", "\u6269\u5c55\u7a0b\u5e8f"])
    assert.throws(() => edgeChooserX11Request({ ...PRIVATE, title }));
  // The request carries exactly the title its caller observed.
  const manager = "Extensions";
  assert.equal(edgeChooserX11Request({ ...PRIVATE, title: manager }).title, manager);
  assert.throws(() =>
    edgeChooserX11Request({ ...PRIVATE, executable: "msedge" }));
  assert.throws(() =>
    edgeChooserX11Request({ ...PRIVATE, profile: PRIVATE.profile + "/" }));
  assert.throws(() =>
    edgeChooserX11Request({ ...PRIVATE, extensionDir: "relative/dir" }));
});

test("the page title is an ASCII manager prefix, never the chrome title", () => {
  const extensions = edgeChooserX11Request(PRIVATE);
  // Titles observed from the real Edge chrome and other private markers.
  for (const title of [
    "edge://extensions",
    "Extensions - Microsoft\u200b Edge",
    "Locklark Edge install 0123456789ab",
    "  ",
    "",
    "Extensions\n",
    "Extensions\u0000",
    "Extensions\t",
    "\u6269\u5c55\u7a0b\u5e8f",
    "Extensions \u6269\u5c55\u7a0b\u5e8f",
  ]) {
    assert.throws(() => edgeChooserX11Request({ ...PRIVATE, title }), undefined, title);
    assert.throws(() => assertChooserRequest(extensions, title));
  }
  // A strict prefix of the manager title is refused by the watchdog.
  assert.throws(() => edgeChooserX11Request({ ...PRIVATE, title: "Exten" }));
  assert.throws(() => assertChooserRequest(extensions, "Exten"));
});

test("chooser request values stay one printable-ASCII line", () => {
  for (const overrides of [
    { extensionDir: "/tmp/a\nb" },
    { extensionDir: "/tmp/\u8def\u5f84" },
    { profile: "/tmp/a\rb" },
    { executable: "/opt/edge\n" },
  ])
    assert.throws(() => edgeChooserX11Request({ ...PRIVATE, ...overrides }));
});

test("exactly the expected background.js worker is accepted", () => {
  const worker = (url) => ({ url: () => url });
  assert.deepEqual(extensionWorkerIdentity([worker(EDGE_BACKGROUND_URL)]), {
    extensionId: FIXED_ID,
    workerUrl: EDGE_BACKGROUND_URL,
  });
  for (const workers of [
    [],
    [worker(EDGE_BACKGROUND_URL), worker(EDGE_BACKGROUND_URL)],
    [worker("chrome-extension://" + FIXED_ID + "/other.js")],
    [worker("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/background.js")],
    [worker("chrome-extension://" + FIXED_ID + "/background.js/extra")],
  ])
    assert.equal(extensionWorkerIdentity(workers), null);
});

test("install failures are fixed classifications, never raw errors", () => {
  const reasons = {
    "edge-page": "edge-manager-unavailable",
    "edge-developer-mode": "edge-developer-mode-failed",
    "edge-load-unpacked": "edge-load-unpacked-unavailable",
    "edge-chooser": "chooser-not-owned",
    "edge-installed": "edge-extension-not-installed",
    "edge-service-worker": "edge-service-worker-missing",
    unexpected: "edge-install-unclassified",
  };
  for (const [stage, message] of Object.entries(reasons))
    assert.equal(new EdgeInstallError(stage).message, message);
  assert.deepEqual(Object.keys(EDGE_INSTALL_REASONS), Object.keys(reasons).slice(0, -1));
});


// Static contract for the real Edge manager install: the fixed manifest-derived
// identity, the exact guarded folder action, the exact guarded X11 keyboard
// request and their folder-action-before-keyboard sequencing. No browser, X
// server, window titles or private paths are used or printed here.
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
  EDGE_MANAGER_TITLE,
  EDGE_MANAGER_URL,
  EDGE_INSTALL_REASONS,
  EdgeInstallError,
  assertChooserRequest,
  assertEdgeLaunchArguments,
  edgeChooserX11Request,
  edgeFolderActionRequest,
  extensionWorkerIdentity,
  installEdgeExtensionThroughManager,
  isEdgeFolderActionOutput,
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
test("folder request is exactly the fixed select_folder action", () => {
  const request = edgeFolderActionRequest(PRIVATE);
  assert.deepEqual(request, {
    owner: true,
    title: "Extensions",
    title_prefix: "Extensions",
    chooser_title_prefix: EDGE_CHOOSER_TITLE_PREFIX,
    owner_title_prefix: "Extensions",
    user_data_dir: PRIVATE.profile,
    executable: "/opt/microsoft/msedge/msedge",
    chooser_action: { select_folder: true },
  });
  // Exactly these keys, and none of the keyboard/path shape.
  assert.deepEqual(Object.keys(request).sort(), [
    "chooser_action",
    "chooser_title_prefix",
    "executable",
    "owner",
    "owner_title_prefix",
    "title",
    "title_prefix",
    "user_data_dir",
  ]);
  for (const absent of [
    "actions",
    "preserve_focus",
    "extension_dir",
    "owner_pid",
    "chooser_title",
    "click",
  ])
    assert.equal(Object.hasOwn(request, absent), false, absent);
  assert.deepEqual(Object.keys(request.chooser_action), ["select_folder"]);
  assert.equal(request.chooser_action.select_folder, true);
  // The existing keyboard/path request keeps its shape and no folder action.
  const keyboard = edgeChooserX11Request(PRIVATE);
  assert.deepEqual(Object.keys(keyboard).sort(), [
    "actions",
    "chooser_title_prefix",
    "executable",
    "owner",
    "owner_title_prefix",
    "preserve_focus",
    "title",
    "title_prefix",
    "user_data_dir",
  ]);
  assert.deepEqual(keyboard.actions, [
    { key: "Control_L+l" },
    { text: PRIVATE.extensionDir },
    { key: "Return" },
  ]);
  assert.equal(Object.hasOwn(keyboard, "chooser_action"), false);
});

test("folder output is exactly one select_folder click", () => {
  assert.equal(
    isEdgeFolderActionOutput({ chooser_action: "select_folder", clicks: 1 }),
    true,
  );
  for (const output of [
    undefined,
    null,
    true,
    "select_folder",
    [],
    {},
    { chooser_action: "select_folder", clicks: 0 },
    { chooser_action: "select_folder", clicks: 2 },
    { chooser_action: "select_folder", clicks: "1" },
    { chooser_action: "select_directory", clicks: 1 },
    { chooser_action: "select_folder", clicks: 1, focus: true },
    { chooser_action: { select_folder: true }, clicks: 1 },
    { ownership: { owned: true } },
    Object.assign(Object.create(null), { chooser_action: "select_folder", clicks: 1 }),
  ])
    assert.equal(isEdgeFolderActionOutput(output), false, String(JSON.stringify(output)));
});

test("folder request carries the actual observed title, never a partial", () => {
  // The observed page.title() the request carries is exactly the real title.
  assert.equal(EDGE_MANAGER_TITLE, "Extensions");
  assert.equal(edgeFolderActionRequest(PRIVATE).title, EDGE_MANAGER_TITLE);
  for (const title of [
    undefined,
    null,
    "",
    "Exten",
    "Extensions ",
    " Extensions",
    "Extensions - Microsoft Edge",
    "Extensions - Microsoft\u200b Edge",
    "edge://extensions",
    "  ",
    "Extensions\n",
    "Extensions\u0000",
    "Extensions\t",
    "\u6269\u5c55\u7a0b\u5e8f",
    "Extensions \u6269\u5c55\u7a0b\u5e8f",
    "Extensions - real observed manager title",
    1,
  ])
    assert.throws(() => edgeFolderActionRequest({ ...PRIVATE, title }), undefined, String(title));
  // A missing title is refused even when every other field is present.
  const { title: _omitted, ...untitled } = PRIVATE;
  assert.throws(() => edgeFolderActionRequest(untitled));
});

test("folder request refuses altered profile or executable", () => {
  const request = edgeFolderActionRequest(PRIVATE);
  assert.equal(request.user_data_dir, PRIVATE.profile);
  assert.equal(request.executable, PRIVATE.executable);
  for (const overrides of [
    { executable: "msedge" },
    { executable: "" },
    { executable: "/opt/edge\n" },
    { executable: "/opt/\u8def\u5f84" },
    { executable: undefined },
    { profile: "relative/profile" },
    { profile: PRIVATE.profile + "/" },
    { profile: "" },
    { profile: "/tmp/a\rb" },
    { profile: "/tmp/\u8def\u5f84" },
    { profile: undefined },
  ])
    assert.throws(() => edgeFolderActionRequest({ ...PRIVATE, ...overrides }));
});

// Synthetic manager page and browser for the sequencing contract: the
// Developer mode switch already reports true, the Load unpacked click needs no
// state and the page title is the exact observed manager title. No browser, X
// server or UI is started.
function installHarness() {
  const shown = [];
  const locator = {
    filter: () => locator,
    count: async () => 1,
    first: () => locator,
    boundingBox: async () => ({ x: 10, y: 10, width: 20, height: 20 }),
    elementHandle: async () => ({
      evaluate: async () => true,
      dispose: async () => {},
    }),
  };
  return {
    shown,
    page: {
      bringToFront: async () => {},
      goto: async () => {},
      title: async () => (shown.push(true), EDGE_MANAGER_TITLE),
      locator: () => locator,
      context: () => ({
        newCDPSession: async () => ({ send: async () => {}, detach: async () => {} }),
      }),
    },
    // No extension target and no worker: installation is never assumed.
    browser: {
      contexts: () => [{
        pages: () => [{ url: () => "http://127.0.0.1/" }],
        newCDPSession: async () => ({
          send: async () => ({ targetInfos: [] }),
          detach: async () => {},
        }),
      }],
      serviceWorkers: () => [],
      waitForEvent: async () => {},
    },
    eventually: async (predicate) => {
      assert.equal(await predicate(), true);
    },
  };
}

const isFolder = (value) => Object.hasOwn(value, "chooser_action");

test("install sends the folder action before the keyboard request", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("synthetic-not-the-locklark-key").toString("base64"),
    background: { service_worker: "background.js" },
  });
  const calls = [];
  const phases = [];
  const harness = installHarness();
  try {
    // No extension target ever appears, so the final install gate still fails
    // after both requests ran exactly once, in that order.
    await assert.rejects(
      installEdgeExtensionThroughManager({
        ...harness,
        extensionDir: directory,
        edgeExecutable: PRIVATE.executable,
        profile: PRIVATE.profile,
        inputRequest: (value) => {
          calls.push(isFolder(value) ? "folder" : "keyboard");
          return isFolder(value)
            ? { chooser_action: "select_folder", clicks: 1 }
            : { ownership: { owned: true } };
        },
        phase: (label) => phases.push(label),
      }),
      (error) => error instanceof EdgeInstallError &&
        error.message === "edge-extension-not-installed",
    );
    assert.deepEqual(calls, ["folder", "keyboard"]);
    // The title was observed at the manager page and once after the Load
    // unpacked click; both requests carried that exact observed title.
    assert.equal(harness.shown.length, 2);
    assert(phases.indexOf("edge-load-unpacked") < phases.indexOf("edge-chooser-folder"));
    assert(phases.indexOf("edge-chooser-folder") < phases.indexOf("edge-chooser"));
    assert(phases.indexOf("edge-chooser") < phases.indexOf("edge-installed"));
    assert.equal(phases.includes("continue"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the sequencing requests carry the exact observed manager title", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("AA==").toString("base64"),
    background: { service_worker: "background.js" },
  });
  const harness = installHarness();
  const seen = [];
  try {
    await assert.rejects(
      installEdgeExtensionThroughManager({
        ...harness,
        extensionDir: directory,
        edgeExecutable: PRIVATE.executable,
        profile: PRIVATE.profile,
        inputRequest: (value) => {
          seen.push(value);
          return isFolder(value)
            ? { chooser_action: "select_folder", clicks: 1 }
            : { ownership: { owned: true } };
        },
        phase: () => {},
      }),
      (error) => error instanceof EdgeInstallError,
    );
    assert.equal(seen.length, 2);
    for (const value of seen) {
      assert.equal(value.title, EDGE_MANAGER_TITLE);
      assert.equal(value.title_prefix, EDGE_MANAGER_TITLE);
      assert.equal(value.owner_title_prefix, EDGE_MANAGER_TITLE);
      assert.equal(value.chooser_title_prefix, EDGE_CHOOSER_TITLE_PREFIX);
      assert.equal(value.user_data_dir, PRIVATE.profile);
      assert.equal(value.executable, PRIVATE.executable);
    }
    // The unchanged keyboard/path request and the fixed folder request.
    assert.deepEqual(seen[0], edgeFolderActionRequest(PRIVATE));
    assert.deepEqual(seen[1], edgeChooserX11Request({ ...PRIVATE, extensionDir: directory }));
    assert.deepEqual(seen[0].chooser_action, { select_folder: true });
    assert.equal(Object.hasOwn(seen[0], "actions"), false);
    assert.equal(Object.hasOwn(seen[1], "chooser_action"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a folder response that is not one select_folder click stops the flow", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("AA==").toString("base64"),
    background: { service_worker: "background.js" },
  });
  try {
    for (const folderOutput of [
      { chooser_action: "select_folder", clicks: 0 },
      { chooser_action: "select_folder", clicks: 2 },
      { chooser_action: "select_folder", clicks: 1, owned: true },
      { ownership: { owned: true } },
      undefined,
    ]) {
      const calls = [];
      const harness = installHarness();
      await assert.rejects(
        installEdgeExtensionThroughManager({
          ...harness,
          extensionDir: directory,
          edgeExecutable: PRIVATE.executable,
          profile: PRIVATE.profile,
          inputRequest: (value) => {
            calls.push(isFolder(value) ? "folder" : "keyboard");
            return isFolder(value) ? folderOutput : { ownership: { owned: true } };
          },
          phase: () => {},
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "chooser-not-owned",
        String(JSON.stringify(folderOutput)),
      );
      // No retry and no keyboard request after the refused folder answer.
      assert.deepEqual(calls, ["folder"]);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a keyboard result that is not owned stops the flow", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("AA==").toString("base64"),
    background: { service_worker: "background.js" },
  });
  try {
    for (const keyboardOutput of [
      undefined,
      {},
      { ownership: null },
      { ownership: { owned: false } },
    ]) {
      const calls = [];
      const harness = installHarness();
      await assert.rejects(
        installEdgeExtensionThroughManager({
          ...harness,
          extensionDir: directory,
          edgeExecutable: PRIVATE.executable,
          profile: PRIVATE.profile,
          inputRequest: (value) => {
            calls.push(isFolder(value) ? "folder" : "keyboard");
            return isFolder(value)
              ? { chooser_action: "select_folder", clicks: 1 }
              : keyboardOutput;
          },
          phase: () => {},
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "chooser-not-owned",
      );
      // One folder request, one keyboard request and no retry.
      assert.deepEqual(calls, ["folder", "keyboard"]);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
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


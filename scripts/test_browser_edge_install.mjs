// Static contract for the real Edge manager install: the fixed manifest-derived
// identity, the two closed chooser actions (navigate, then Open), no caller
// coordinate, the measured internal Open point and their navigate-before-Open
// sequencing. No browser, X server, window titles or private paths are used or
// printed here.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  EDGE_BACKGROUND_URL,
  EDGE_CHOOSER_ACTION_KEYS,
  EDGE_CHOOSER_NAVIGATE,
  EDGE_CHOOSER_NAVIGATE_KEYS,
  EDGE_CHOOSER_OPEN,
  EDGE_CHOOSER_OPEN_LOCAL,
  EDGE_CHOOSER_OPEN_SCREEN,
  EDGE_CHOOSER_ORIGIN,
  EDGE_CHOOSER_SIZE,
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
  edgeChooserNavigateRequest,
  edgeChooserOpenRequest,
  edgeChooserX11Request,
  extensionTargets,
  extensionWorkerIdentity,
  installEdgeExtensionThroughManager,
  isEdgeChooserActionOutput,
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
test("chooser actions are exactly navigate then open, no select_folder", () => {
  const navigate = edgeChooserNavigateRequest(PRIVATE);
  assert.deepEqual(navigate, {
    owner: true,
    title: "Extensions",
    title_prefix: "Extensions",
    chooser_title_prefix: EDGE_CHOOSER_TITLE_PREFIX,
    owner_title_prefix: "Extensions",
    user_data_dir: PRIVATE.profile,
    executable: "/opt/microsoft/msedge/msedge",
    chooser_action: { chooser_navigate: true },
    extension_dir: PRIVATE.extensionDir,
  });
  assert.deepEqual(Object.keys(navigate).sort(), [...EDGE_CHOOSER_NAVIGATE_KEYS].sort());
  assert.deepEqual(navigate.chooser_action, EDGE_CHOOSER_NAVIGATE);
  // The navigate plan carries exactly the one validated package directory and
  // no key, Return included; the X11 driver itself sends the true Ctrl+L
  // chord and types that path only.
  assert.deepEqual(Object.keys(navigate.chooser_action), ["chooser_navigate"]);
  assert.equal(navigate.chooser_action.chooser_navigate, true);
  assert.equal(navigate.extension_dir, PRIVATE.extensionDir);
  const open = edgeChooserOpenRequest(PRIVATE);
  assert.deepEqual(open, {
    owner: true,
    title: "Extensions",
    title_prefix: "Extensions",
    chooser_title_prefix: EDGE_CHOOSER_TITLE_PREFIX,
    owner_title_prefix: "Extensions",
    user_data_dir: PRIVATE.profile,
    executable: "/opt/microsoft/msedge/msedge",
    chooser_action: { chooser_open: true },
  });
  assert.deepEqual(Object.keys(open).sort(), [...EDGE_CHOOSER_ACTION_KEYS].sort());
  assert.deepEqual(open.chooser_action, EDGE_CHOOSER_OPEN);
  // Neither action has the generic keyboard shape, a focus flag, a label, a
  // caller coordinate or the removed select_folder behaviour.
  for (const request of [navigate, open]) {
    for (const absent of [
      "actions", "preserve_focus", "owner_pid", "chooser_title", "click",
      "click_label", "wait_label", "label", "x", "y", "point", "width",
      "height", "window", "target", "select_folder",
    ])
      assert.equal(Object.hasOwn(request, absent), false, absent);
  }
  // The Open action never carries the package directory: an extra input is
  // never forwarded into it.
  assert.equal(Object.hasOwn(open, "extension_dir"), false);
  assert.deepEqual(
    edgeChooserOpenRequest({ ...PRIVATE, extensionDir: PRIVATE.extensionDir }),
    open,
  );
  // The builders destructure exactly the four named values: a caller
  // coordinate, label, action list, focus flag, PID or attribution override is
  // not a parameter and can never be forwarded into the request.
  const signature = (fn) =>
    fn.toString().match(/^[^(]*(\(\{[^}]*\}\))/)[1];
  const navigateShape = signature(edgeChooserNavigateRequest);
  const openShape = signature(edgeChooserOpenRequest);
  assert.equal(navigateShape, "({ extensionDir, executable, profile, title })");
  assert.equal(openShape, "({ executable, profile, title })");
  for (const forbidden of [
    "click", "actions", "preserve_focus", "owner_pid", "x", "y", "point",
    "label", "select_folder", "chooser_action",
  ]) {
    assert.doesNotMatch(navigateShape, new RegExp("\\b" + forbidden + "\\b"), forbidden);
    assert.doesNotMatch(openShape, new RegExp("\\b" + forbidden + "\\b"), forbidden);
  }
  // A caller's coordinate is never forwarded, even inside the accepted shape.
  assert.deepEqual(
    edgeChooserOpenRequest({ ...PRIVATE, x: 1076, y: 799, click: [1076, 799] }),
    open,
  );
  // The navigate path is the existing absolute printable-ASCII directory.
  for (const extensionDir of [
    undefined, null, "", "relative/dir", "/", PRIVATE.extensionDir + "/",
    PRIVATE.extensionDir + "\n", "/tmp/\u8def\u5f84", "/tmp/a\u0000b", 1,
  ])
    assert.throws(() => {
      edgeChooserNavigateRequest({ ...PRIVATE, extensionDir });
    });
  // The reviewed generic owner/keyboard request keeps its shape and is not a
  // chooser action.
  const keyboard = edgeChooserX11Request(PRIVATE);
  assert.deepEqual(keyboard.actions, [
    { key: "Control_L+l" },
    { text: PRIVATE.extensionDir },
    { key: "Return" },
  ]);
  assert.equal(Object.hasOwn(keyboard, "chooser_action"), false);
  assert.equal(
    Object.hasOwn(edgeChooserNavigateRequest(PRIVATE), "actions"),
    false,
  );
});

test("chooser acknowledgement is fixed per action and never success", () => {
  assert.equal(
    isEdgeChooserActionOutput({ chooser_action: "chooser_navigate", clicks: 0 }, "navigate"),
    true,
  );
  assert.equal(
    isEdgeChooserActionOutput({ chooser_action: "chooser_open", clicks: 1 }, "open"),
    true,
  );
  // Crossed actions, counts, expansions and the removed select_folder answer
  // are all refused.
  for (const [output, action] of [
    [{ chooser_action: "chooser_navigate", clicks: 0 }, "open"],
    [{ chooser_action: "chooser_open", clicks: 1 }, "navigate"],
    [{ chooser_action: "chooser_navigate", clicks: 1 }, "navigate"],
    [{ chooser_action: "chooser_open", clicks: 0 }, "open"],
    [{ chooser_action: "chooser_open", clicks: 2 }, "open"],
    [{ chooser_action: "chooser_open", clicks: "1" }, "open"],
    [{ chooser_action: "chooser_open", clicks: true }, "open"],
    [{ chooser_action: "select_folder", clicks: 1 }, "open"],
    [{ chooser_action: "chooser_open", clicks: 1, installed: true }, "open"],
    [{ chooser_action: "chooser_open", clicks: 1, ownership: { owned: true } }, "open"],
    [{ ownership: { owned: true } }, "open"],
    [undefined, "open"],
    [null, "navigate"],
    [true, "open"],
    [[], "navigate"],
    [{}, "navigate"],
    [Object.assign(Object.create(null), { chooser_action: "chooser_open", clicks: 1 }), "open"],
    [{ chooser_action: "chooser_open", clicks: 1 }, "select_folder"],
    [{ chooser_action: "chooser_open", clicks: 1 }, undefined],
  ])
    assert.equal(isEdgeChooserActionOutput(output, action), false,
      String(action) + " " + String(JSON.stringify(output)));
});

test("chooser requests carry exactly the observed Edge manager title", () => {
  assert.equal(EDGE_MANAGER_TITLE, "Extensions");
  for (const build of [edgeChooserNavigateRequest, edgeChooserOpenRequest]) {
    assert.equal(build(PRIVATE).title, EDGE_MANAGER_TITLE);
    for (const title of [
      undefined,
      null,
      "",
      "Exten",
      "Ext",
      "Extension",
      "Extensions ",
      " Extensions",
      "Extensions - Profile 1",
      "Extensions - Microsoft Edge",
      "Extensions - Microsoft\u200b Edge",
      "edge://extensions",
      "  ",
      "Extensions\n",
      "Extensions\u0000",
      "Extensions\t",
      "\u6269\u5c55\u7a0b\u5e8f",
      "Extensions \u6269\u5c55\u7a0b\u5e8f",
      1,
    ])
      assert.throws(() => build({ ...PRIVATE, title }), undefined, String(title));
    const { title: _omitted, ...untitled } = PRIVATE;
    assert.throws(() => build(untitled));
  }
  // The generic title watchdog keeps its own strict check, and the strict
  // chooser contract refuses a generic prefix the watchdog would accept.
  assert.throws(() => assertChooserRequest(edgeChooserOpenRequest(PRIVATE), "Ext"));
  assert.throws(() => edgeChooserOpenRequest({ ...PRIVATE, title: "Extensions manager" }));
});

test("chooser requests refuse altered profile or executable", () => {
  const open = edgeChooserOpenRequest(PRIVATE);
  assert.equal(open.user_data_dir, PRIVATE.profile);
  assert.equal(open.executable, PRIVATE.executable);
  const OMIT = Symbol("omit");
  for (const build of [edgeChooserNavigateRequest, edgeChooserOpenRequest])
    for (const overrides of [
      { executable: "msedge" },
      { executable: "" },
      { executable: "/opt/edge\n" },
      { executable: "/opt/\u8def\u5f84" },
      { executable: OMIT },
      { profile: "relative/profile" },
      { profile: PRIVATE.profile + "/" },
      { profile: "" },
      { profile: "/tmp/a\rb" },
      { profile: "/tmp/\u8def\u5f84" },
      { profile: OMIT },
    ]) {
      const input = { ...PRIVATE, ...overrides };
      for (const key of Object.keys(overrides))
        if (input[key] === OMIT) delete input[key];
      assert.throws(() => {
        build(input);
      }, undefined, build.name + " " + Object.keys(overrides).join(","));
    }
});

test("both actions carry exactly the caller's one profile and Edge image", () => {
  // The profile and executable are not a driver constant: each request carries
  // the caller's exact install values unchanged, and neither action derives or
  // substitutes a different private profile or Edge image.
  const other = {
    profile: "/tmp/another-private-profile",
    executable: "/opt/microsoft/msedge-beta/msedge",
  };
  for (const build of [edgeChooserNavigateRequest, edgeChooserOpenRequest]) {
    const request = build({ ...PRIVATE, ...other });
    assert.equal(request.user_data_dir, other.profile);
    assert.equal(request.executable, other.executable);
    assert.equal(Object.hasOwn(request, "profile"), false);
    assert.equal(Object.hasOwn(request, "user-data-dir"), false);
  }
  assert.deepEqual(
    edgeChooserOpenRequest({ ...PRIVATE, ...other }),
    edgeChooserOpenRequest({ ...PRIVATE, ...other, title: "Extensions" }),
  );
  assert.notDeepEqual(
    edgeChooserOpenRequest({ ...PRIVATE, ...other }).user_data_dir,
    edgeChooserOpenRequest(PRIVATE).user_data_dir,
  );
});

// Synthetic manager page and BrowserContext for the sequencing contract: the
// Developer mode switch already reports true, the Load unpacked click needs no
// state and the page title is the exact observed manager title. `browser` is
// the Playwright BrowserContext returned by chromium.launchPersistentContext(),
// not a Browser: it has pages()/newCDPSession()/serviceWorkers() and no
// contexts(). No browser, X server or UI is started.
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
    // `contexts()` throws: a Browser shape must never be queried here.
    browser: {
      contexts: () => {
        throw Error("edge-targets: supplied BrowserContext has no contexts()");
      },
      pages: () => [{ url: () => "http://127.0.0.1/" }],
      newCDPSession: async () => ({
        send: async () => ({ targetInfos: [] }),
        detach: async () => {},
      }),
      serviceWorkers: () => [],
      waitForEvent: async () => {},
    },
    eventually: async (predicate) => {
      assert.equal(await predicate(), true);
    },
  };
}

const chooserStep = (value) =>
  value?.chooser_action?.chooser_navigate === true
    ? "navigate"
    : value?.chooser_action?.chooser_open === true
      ? "open"
      : "keyboard";
const answer = (step) => ({
  navigate: { chooser_action: "chooser_navigate", clicks: 0 },
  open: { chooser_action: "chooser_open", clicks: 1 },
  keyboard: { ownership: { owned: true } },
})[step];

test("install navigates, then opens, then waits for the real target", async () => {
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
    // after both actions ran exactly once, in that order.
    await assert.rejects(
      installEdgeExtensionThroughManager({
        ...harness,
        extensionDir: directory,
        edgeExecutable: PRIVATE.executable,
        profile: PRIVATE.profile,
        inputRequest: (value) => {
          const step = chooserStep(value);
          calls.push(step);
          return answer(step);
        },
        phase: (label) => phases.push(label),
      }),
      (error) => error instanceof EdgeInstallError &&
        error.message === "edge-extension-not-installed",
    );
    assert.deepEqual(calls, ["navigate", "open"]);
    // The title was observed at the manager page and once after the Load
    // unpacked click; both actions carried that exact observed title.
    assert.equal(harness.shown.length, 2);
    assert(phases.indexOf("edge-load-unpacked") < phases.indexOf("edge-chooser-navigate"));
    assert(phases.indexOf("edge-chooser-navigate") < phases.indexOf("edge-chooser-open"));
    assert(phases.indexOf("edge-chooser-open") < phases.indexOf("edge-installed"));
    assert.equal(phases.includes("continue"), false);
    // No menu or dropdown stage remains anywhere in the flow.
    for (const label of phases)
      assert.doesNotMatch(label, /menu|dropdown|folder/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the sequencing actions carry the exact observed manager title", async () => {
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
          return answer(chooserStep(value));
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
      assert.equal(value.owner, true);
    }
    assert.deepEqual(seen[0], edgeChooserNavigateRequest({ ...PRIVATE, extensionDir: directory }));
    assert.deepEqual(seen[1], edgeChooserOpenRequest(PRIVATE));
    assert.deepEqual(seen[0].chooser_action, { chooser_navigate: true });
    assert.equal(seen[0].extension_dir, directory);
    assert.equal(Object.hasOwn(seen[0], "actions"), false);
    assert.equal(Object.hasOwn(seen[1], "extension_dir"), false);
    assert.deepEqual(seen[1].chooser_action, { chooser_open: true });
    for (const value of seen) {
      for (const absent of ["click", "x", "y", "point", "click_label", "wait_label", "preserve_focus"])
        assert.equal(Object.hasOwn(value, absent), false, absent);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the Open action clicks only the measured internal point", () => {
  // Measured on the owned Edge 157 screenshots: the point is never a caller
  // value and never a generic label lookup.
  assert.deepEqual(EDGE_CHOOSER_SIZE, { width: 1124, height: 822 });
  assert.deepEqual(EDGE_CHOOSER_ORIGIN, { x: 82, y: 33 });
  assert.deepEqual(EDGE_CHOOSER_OPEN_LOCAL, { x: 1076, y: 799 });
  assert.deepEqual(EDGE_CHOOSER_OPEN_LOCAL, {
    x: EDGE_CHOOSER_SIZE.width - 48,
    y: EDGE_CHOOSER_SIZE.height - 23,
  });
  assert.deepEqual(EDGE_CHOOSER_OPEN_SCREEN, { x: 1158, y: 832 });
  // The removed width-62,height-69 point hit the Select folder filter.
  assert.notDeepEqual(
    { x: EDGE_CHOOSER_SIZE.width - 62, y: EDGE_CHOOSER_SIZE.height - 69 },
    EDGE_CHOOSER_OPEN_LOCAL,
  );
  // No chooser request builder has a coordinate or label parameter; an
  // injected one is not forwarded into the closed action.
  for (const injected of [
    { x: 1076, y: 799 },
    { point: { x: 1076, y: 799 } },
    { click: [1076, 799] },
    { click_label: "Open" },
    { actions: [{ click: [1076, 799] }] },
  ]) {
    assert.deepEqual(edgeChooserNavigateRequest({ ...PRIVATE, ...injected }),
      edgeChooserNavigateRequest(PRIVATE));
    assert.deepEqual(edgeChooserOpenRequest({ ...PRIVATE, ...injected }),
      edgeChooserOpenRequest(PRIVATE));
  }
  // The driver's measured constants are the only source of the Open point.
  const measured = {
    x: EDGE_CHOOSER_SIZE.width - 48,
    y: EDGE_CHOOSER_SIZE.height - 23,
  };
  assert.deepEqual(EDGE_CHOOSER_OPEN_LOCAL, measured);
});

test("a navigate answer that is not its fixed acknowledgement stops the flow", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("AA==").toString("base64"),
    background: { service_worker: "background.js" },
  });
  try {
    for (const navigateOutput of [
      { chooser_action: "chooser_navigate", clicks: 1 },
      { chooser_action: "chooser_navigate", clicks: 0, owned: true },
      { chooser_action: "chooser_open", clicks: 1 },
      { chooser_action: "select_folder", clicks: 1 },
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
            const step = chooserStep(value);
            calls.push(step);
            return step === "navigate" ? navigateOutput : answer(step);
          },
          phase: () => {},
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "chooser-not-owned",
        String(JSON.stringify(navigateOutput)),
      );
      // No retry and no Open click after the refused navigate answer.
      assert.deepEqual(calls, ["navigate"]);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an Open answer that is not its fixed acknowledgement stops the flow", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("AA==").toString("base64"),
    background: { service_worker: "background.js" },
  });
  try {
    for (const openOutput of [
      { chooser_action: "chooser_open", clicks: 0 },
      { chooser_action: "chooser_open", clicks: 2 },
      { chooser_action: "chooser_open", clicks: 1, owned: true },
      { chooser_action: "chooser_navigate", clicks: 0 },
      { chooser_action: "select_folder", clicks: 1 },
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
            const step = chooserStep(value);
            calls.push(step);
            return step === "open" ? openOutput : answer(step);
          },
          phase: () => {},
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "chooser-not-owned",
        String(JSON.stringify(openOutput)),
      );
      // One navigate, one Open and no retry.
      assert.deepEqual(calls, ["navigate", "open"]);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("extension targets are queried from the supplied BrowserContext", async () => {
  const targetInfos = [{
    targetId: "synthetic-target",
    type: "service_worker",
    url: EDGE_BACKGROUND_URL,
  }];
  const calls = [];
  const context = {
    // A real BrowserContext has no contexts(); calling it must fail the test.
    contexts: () => {
      calls.push("contexts");
      throw Error("BrowserContext has no contexts()");
    },
    pages: () => {
      calls.push("pages");
      return [
        { url: () => "edge://extensions/" },
        { url: () => "http://127.0.0.1/" },
      ];
    },
    newCDPSession: async (page) => {
      calls.push("newCDPSession");
      return {
        send: async (method) => {
          calls.push(method);
          assert.equal(method, "Target.getTargets");
          return { targetInfos };
        },
        detach: async () => {
          calls.push("detach");
        },
      };
    },
  };
  // The attached page is the regular http page, not the manager page.
  const sessionPage = [];
  context.newCDPSession = async (page) => {
    calls.push("newCDPSession");
    sessionPage.push(page.url());
    return {
      send: async () => ({ targetInfos }),
      detach: async () => {},
    };
  };
  assert.deepEqual(await extensionTargets(context), targetInfos);
  assert.deepEqual(sessionPage, ["http://127.0.0.1/"]);
  assert.equal(calls.includes("contexts"), false);
  // The returned data is exactly what CDP reported, never synthesized.
  assert.deepEqual(calls.slice(0, 2), ["pages", "newCDPSession"]);
  // No page in the context is a fixed failure, not fabricated targets.
  await assert.rejects(
    extensionTargets({
      pages: () => [],
      newCDPSession: async () => {
        throw Error("unexpected newCDPSession");
      },
    }),
    (error) => error.message === "edge-targets",
  );
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


// Static contract for the real Edge manager install: the fixed manifest-derived
// identity, the two closed chooser actions (navigate, then Open), no caller
// coordinate, the measured internal Open point and their navigate-before-Open
// sequencing. No browser, X server, window titles or private paths are used or
// printed here.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  EDGE_INSTALL_PASS,
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
// The existing synthetic login origin the official harness already serves.
const SYNTHETIC_ORIGIN = "https://login.locklark.test:8443";

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
  const goto = [];
  const popup = { ready: async () => true };
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
    goto,
    popup,
    page: {
      bringToFront: async () => {},
      goto: async (url) => {
        goto.push(url);
      },
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
  let popups = 0;
  try {
    // No extension target ever appears, so the final install gate still fails
    // after both actions ran exactly once, in that order.
    await assert.rejects(
      installEdgeExtensionThroughManager({
        ...harness,
        extensionDir: directory,
        edgeExecutable: PRIVATE.executable,
        profile: PRIVATE.profile,
        origin: SYNTHETIC_ORIGIN,
        inputRequest: (value) => {
          const step = chooserStep(value);
          calls.push(step);
          return answer(step);
        },
        openPopup: async () => {
          calls.push("popup");
          popups += 1;
          return harness.popup;
        },
        phase: (label) => phases.push(label),
      }),
      (error) => error instanceof EdgeInstallError &&
        error.message === "edge-extension-not-installed",
    );
    assert.deepEqual(calls, ["navigate", "open", "popup"]);
    assert.equal(popups, 1);
    assert.deepEqual(harness.goto, [EDGE_MANAGER_URL, SYNTHETIC_ORIGIN + "/login"]);
    // The title was observed at the manager page and once after the Load
    // unpacked click; both actions carried that exact observed title.
    assert.equal(harness.shown.length, 2);
    assert(phases.indexOf("edge-load-unpacked") < phases.indexOf("edge-chooser-navigate"));
    assert(phases.indexOf("edge-chooser-navigate") < phases.indexOf("edge-chooser-open"));
    assert(phases.indexOf("edge-chooser-open") < phases.indexOf("edge-activate"));
    assert(phases.indexOf("edge-activate") < phases.indexOf("edge-installed"));
    assert.equal(phases.includes("continue"), false);
    // No menu or dropdown stage remains anywhere in the flow.
    for (const label of phases)
      assert.doesNotMatch(label, /menu|dropdown|folder/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// One shared order log across every observable step of the synthetic harness:
// chooser requests, title observations, tab navigations, the popup action and
// the real CDP target query. Only synthetic values are logged.
function orderedHarness(order) {
  const harness = installHarness();
  const bringToFront = harness.page.bringToFront;
  const title = harness.page.title;
  const goto = harness.page.goto;
  harness.page.bringToFront = async () => {
    order.push("bringToFront");
    return bringToFront();
  };
  harness.page.title = async () => {
    order.push("title");
    return title();
  };
  harness.page.goto = async (url) => {
    order.push("goto:" + url);
    return goto(url);
  };
  const send = harness.browser.newCDPSession;
  harness.browser.newCDPSession = async (...args) => {
    order.push("targets");
    return send(...args);
  };
  return harness;
}

function interactiveHooks(harness, order, { extensionDir, popup } = {}) {
  return {
    extensionDir,
    edgeExecutable: PRIVATE.executable,
    profile: PRIVATE.profile,
    origin: SYNTHETIC_ORIGIN,
    inputRequest: (value) => {
      const step = chooserStep(value);
      order.push(step);
      return answer(step);
    },
    openPopup: async () => {
      order.push("popup");
      return popup === undefined ? harness.popup : popup;
    },
    phase: (label) => order.push("phase:" + label),
  };
}

test("popup activation runs after chooser_open and before the target proof", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("AA==").toString("base64"),
    background: { service_worker: "background.js" },
  });
  try {
    const order = [];
    const harness = orderedHarness(order);
    // No extension target ever appears: the popup action itself never stands
    // in for the target or worker proof, so the flow still rejects after it.
    await assert.rejects(
      installEdgeExtensionThroughManager({
        ...harness,
        ...interactiveHooks(harness, order, { extensionDir: directory }),
      }),
      (error) => error instanceof EdgeInstallError &&
        error.message === "edge-extension-not-installed",
    );
    const first = (step) => order.indexOf(step);
    const only = (step) => order.filter((value) => value === step).length === 1;
    // The separate physical Open action ran exactly once before activation.
    const openedAt = first("open");
    assert(openedAt > first("navigate"), order.join(","));
    // Activation: exactly one navigation to the synthetic login origin and
    // exactly one user-facing popup action, both after chooser_open.
    const popupAt = first("popup");
    const loginAt = first("goto:" + SYNTHETIC_ORIGIN + "/login");
    assert(only("popup"), order.join(","));
    assert(only("goto:" + SYNTHETIC_ORIGIN + "/login"), order.join(","));
    assert(openedAt < loginAt, order.join(","));
    assert(openedAt < popupAt, order.join(","));
    assert(loginAt < popupAt, order.join(","));
    // The manager was still the only page before activation.
    const managerAt = first("goto:" + EDGE_MANAGER_URL);
    assert.equal(order.filter((value) => value.startsWith("goto:")).length, 2);
    assert(managerAt < openedAt);
    // Target proof happens strictly after activation, through the real
    // BrowserContext CDP session.
    assert(popupAt < first("targets"), order.join(","));
    assert(first("phase:edge-activate") < first("phase:edge-installed"));
    assert(first("phase:edge-chooser-open") < first("phase:edge-activate"));
    assert.equal(order.includes("phase:continue"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a refused Open answer never activates, navigates or proves a target", async () => {
  const directory = packageWith({
    manifest_version: 3,
    key: Buffer.from("AA==").toString("base64"),
    background: { service_worker: "background.js" },
  });
  try {
    const order = [];
    const harness = orderedHarness(order);
    const hooks = interactiveHooks(harness, order, { extensionDir: directory });
    await assert.rejects(
      installEdgeExtensionThroughManager({
        ...harness,
        ...hooks,
        inputRequest: (value) => {
          const step = chooserStep(value);
          order.push(step);
          return step === "open"
            ? { chooser_action: "chooser_open", clicks: 0 }
            : answer(step);
        },
      }),
      (error) => error instanceof EdgeInstallError &&
        error.message === "chooser-not-owned",
    );
    assert.equal(order.includes("popup"), false);
    assert.equal(order.includes("goto:" + SYNTHETIC_ORIGIN + "/login"), false);
    assert.equal(order.includes("targets"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// A harness context that logs the real BrowserContext CDP target query (through
// the ordered wrapper) and then answers it with the fixed extension target, and
// itself reports exactly one background.js worker, so the positive path and the
// negative controls differ only in the activation step.
function workerHarness(order) {
  const harness = orderedHarness(order);
  const original = harness.browser.newCDPSession;
  harness.browser.newCDPSession = async (...args) => {
    await original(...args);
    return {
      send: async (method) => {
        assert.equal(method, "Target.getTargets");
        return {
          targetInfos: [{
            targetId: "synthetic-target",
            type: "service_worker",
            url: EDGE_BACKGROUND_URL,
          }],
        };
      },
      detach: async () => {},
    };
  };
  harness.browser.serviceWorkers = () => [{ url: () => EDGE_BACKGROUND_URL }];
  harness.browser.waitForEvent = async () => {};
  return harness;
}

// The real package is fixed-identity; the synthetic key would be refused by the
// manifest-derived ID check, so this copies the fixed real manifest only.
function fixedPackage() {
  const directory = mkdtempSync(join(tmpdir(), "locklark-edge-contract-"));
  mkdirSync(directory, { recursive: true });
  writeFileSync(
    join(directory, "manifest.json"),
    readFileSync(
      fileURLToPath(new URL("../browser-extension/dist/chromium/manifest.json", import.meta.url)),
    ),
  );
  return directory;
}

test("popup action, target and exactly one worker complete the install", async () => {
  const directory = fixedPackage();
  try {
    const order = [];
    const harness = workerHarness(order);
    const identity = await installEdgeExtensionThroughManager({
      ...harness,
      ...interactiveHooks(harness, order, { extensionDir: directory }),
    });
    assert.deepEqual(identity, {
      extensionId: FIXED_ID,
      workerUrl: EDGE_BACKGROUND_URL,
    });
    // The popup stayed open (one reference, never re-opened) from activation
    // through both proofs.
    assert.equal(order.filter((value) => value === "popup").length, 1);
    assert(order.indexOf("popup") < order.indexOf("phase:edge-installed"));
    assert(order.indexOf("popup") < order.indexOf("targets"));
    assert(order.indexOf("phase:edge-installed") < order.indexOf("phase:edge-service-worker"));
    assert.equal(order[order.length - 1], "phase:continue");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a missing target is still rejected after popup activation", async () => {
  const directory = fixedPackage();
  try {
    // Worker present but no extension target: never a PASS.
    for (const context of [
      // No target list at all.
      () => ({
        send: async () => ({ targetInfos: [] }),
      }),
      // The manager page target only, never the extension target.
      () => ({
        send: async () => ({
          targetInfos: [{
            targetId: "synthetic-manager",
            type: "page",
            url: EDGE_MANAGER_URL,
          }],
        }),
      }),
    ]) {
      const order = [];
      const harness = workerHarness(order);
      harness.browser.newCDPSession = async () => {
        order.push("targets");
        return { ...context(), detach: async () => {} };
      };
      await assert.rejects(
        installEdgeExtensionThroughManager({
          ...harness,
          ...interactiveHooks(harness, order, { extensionDir: directory }),
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "edge-extension-not-installed",
      );
      assert.equal(order.includes("popup"), true);
      assert.equal(order.includes("phase:continue"), false);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a missing background.js worker is still rejected after popup activation", async () => {
  const directory = fixedPackage();
  try {
    for (const workers of [
      // (Inactive) card: the worker never comes back.
      () => [],
      // A different worker is not the fixed background.js worker.
      () => [{ url: () => "chrome-extension://" + FIXED_ID + "/other.js" }],
      // A different extension's background.js is not this one.
      () => [{ url: () => "chrome-extension://" + "a".repeat(32) + "/background.js" }],
      // More than one worker is never a partial match.
      () => [
        { url: () => EDGE_BACKGROUND_URL },
        { url: () => EDGE_BACKGROUND_URL },
      ],
    ]) {
      const order = [];
      const harness = workerHarness(order);
      harness.browser.serviceWorkers = workers;
      await assert.rejects(
        installEdgeExtensionThroughManager({
          ...harness,
          ...interactiveHooks(harness, order, { extensionDir: directory }),
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "edge-service-worker-missing",
      );
      assert.equal(order.includes("popup"), true);
      assert.equal(order.includes("targets"), true);
      assert.equal(order.includes("phase:continue"), false);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a failed or missing popup activation fails closed without a target proof", async () => {
  const directory = fixedPackage();
  try {
    for (const popup of [
      async () => {
        throw Error("Action popup did not open");
      },
      async () => null,
      async () => undefined,
    ]) {
      const order = [];
      const harness = workerHarness(order);
      const hooks = interactiveHooks(harness, order, { extensionDir: directory });
      await assert.rejects(
        installEdgeExtensionThroughManager({
          ...harness,
          ...hooks,
          openPopup: popup,
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "edge-worker-not-activated",
      );
      assert.equal(order.includes("phase:edge-installed"), false);
      assert.equal(order.includes("targets"), false);
    }
    // A missing helper or synthetic origin is refused before any manager step.
    for (const overrides of [
      { openPopup: undefined },
      { origin: undefined },
      { origin: "login.locklark.test" },
      { origin: "" },
    ]) {
      const order = [];
      const harness = workerHarness(order);
      await assert.rejects(
        installEdgeExtensionThroughManager({
          ...harness,
          ...interactiveHooks(harness, order, { extensionDir: directory }),
          ...overrides,
        }),
        (error) => error instanceof EdgeInstallError &&
          error.message === "edge-worker-not-activated",
      );
      assert.deepEqual(order, []);
    }
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
        origin: SYNTHETIC_ORIGIN,
        openPopup: async () => harness.popup,
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
          origin: SYNTHETIC_ORIGIN,
          openPopup: async () => harness.popup,
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
          origin: SYNTHETIC_ORIGIN,
          openPopup: async () => harness.popup,
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
  const pages = [
    { url: () => "edge://extensions/" },
    { url: () => "http://127.0.0.1/" },
  ];
  // One implementation of the CDP stub: it records the attached page and the
  // actual Target.getTargets method, and its detach.
  const context = {
    // A real BrowserContext has no contexts(); calling it must fail the test.
    contexts: () => {
      calls.push("contexts");
      throw Error("BrowserContext has no contexts()");
    },
    pages: () => {
      calls.push("pages");
      return pages;
    },
    newCDPSession: async (page) => {
      assert.equal(pages.includes(page), true);
      calls.push("newCDPSession:" + page.url());
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
  assert.deepEqual(await extensionTargets(context), targetInfos);
  // The returned data is exactly what CDP reported, never synthesized.
  assert.deepEqual(calls, [
    "pages",
    "newCDPSession:http://127.0.0.1/",
    "Target.getTargets",
    "detach",
  ]);
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
    "edge-activate": "edge-worker-not-activated",
    "edge-installed": "edge-extension-not-installed",
    "edge-service-worker": "edge-service-worker-missing",
    unexpected: "edge-install-unclassified",
  };
  for (const [stage, message] of Object.entries(reasons))
    assert.equal(new EdgeInstallError(stage).message, message);
  assert.deepEqual(Object.keys(EDGE_INSTALL_REASONS), Object.keys(reasons).slice(0, -1));
});

// The opt-in pair/disconnect checkpoint is defined in the official acceptance
// script itself. That script starts a browser at import time, so these tests
// inspect only its reviewed source blocks; they never launch Edge, open a
// popup, read the X server or print a path/title/fixture value.
const NATIVE_ACCEPTANCE = fileURLToPath(
  new URL("./browser_native_acceptance.mjs", import.meta.url),
);
const nativeSource = readFileSync(NATIVE_ACCEPTANCE, "utf8");

// The literal block that starts at `marker`, including its balanced braces.
// A missing or unterminated block is a test failure, never an empty match.
function sourceBlock(source, marker) {
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, marker);
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let index = open; index < source.length; index++) {
    if (source[index] === "{") depth += 1;
    else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
  }
  throw Error("unterminated source block: " + marker);
}

const PAIR_GUARD = sourceBlock(nativeSource, "if (edgePairDisconnect) {");
const PAIR_FUNCTION = sourceBlock(
  nativeSource,
  "async function acceptEdgePairDisconnect(driver) {",
);
const MANAGED_BRANCH = nativeSource.slice(
  nativeSource.indexOf("    // Visible manager UI only."),
  nativeSource.indexOf('  await page.goto(origin + "/login");'),
);
const PAIR_STAGES = nativeSource.slice(
  nativeSource.indexOf("const EDGE_PAIR_STAGES ="),
  nativeSource.indexOf("]);", nativeSource.indexOf("const EDGE_PAIR_STAGES =")) + 3,
);
const SAFE_REASONS = nativeSource.slice(
  nativeSource.indexOf("    const safeReasons = ["),
  nativeSource.indexOf("    ];", nativeSource.indexOf("    const safeReasons = [")),
);

test("pair/disconnect mode is opt-in, Edge-only, absolute and mutually exclusive", () => {
  assert.match(
    nativeSource,
    /const edgePairDisconnect = process\.env\.LOCKLARK_TEST_EDGE_PAIR_DISCONNECT === "1";/,
  );
  // The route checkpoint refuses this mode exactly like every other journey
  // that would change what pairing, fill or checkout mean.
  const routeFunction =
    "function routeModeCompatible() " +
    sourceBlock(nativeSource, "function routeModeCompatible()");
  const compatible = (env) =>
    new Function("process", routeFunction + "; return routeModeCompatible;")({
      env,
    })();
  assert.equal(compatible({}), true);
  assert.equal(
    compatible({ LOCKLARK_TEST_EDGE_PAIR_DISCONNECT: "1" }),
    false,
  );
  assert.equal(compatible({ LOCKLARK_TEST_EDGE_INSTALL_ONLY: "1" }), false);
  // Execute the actual guard block with a synthetic Edge launch context and
  // the same assert implementation it uses in production.
  const guard = (env, browser, executable) =>
    new Function(
      "assert",
      "process",
      "browserName",
      "browserExecutable",
      "edgePairDisconnect",
      PAIR_GUARD,
    )(assert, { env }, browser, executable, true);
  const absolute = "/opt/microsoft/msedge/msedge";
  guard({ LOCKLARK_TEST_EDGE_PAIR_DISCONNECT: "1" }, "edge", absolute);
  assert.throws(
    () => guard({ LOCKLARK_TEST_EDGE_PAIR_DISCONNECT: "1" }, "chromium", absolute),
    /requires LOCKLARK_TEST_BROWSER=edge/,
  );
  assert.throws(
    () => guard({ LOCKLARK_TEST_EDGE_PAIR_DISCONNECT: "1" }, "edge", "msedge"),
    /requires an explicit absolute executable path/,
  );
  const forbidden = [
    "LOCKLARK_TEST_EDGE_INSTALL_ONLY",
    "LOCKLARK_TEST_CHECKOUT_FRAMES",
    "LOCKLARK_TEST_SHARED_CLIPBOARD",
    "LOCKLARK_TEST_POPUP_VAULT",
    "LOCKLARK_TEST_ROUTE_DETAIL_READ",
    "LOCKLARK_TEST_ROUTE_IDLE_TTL",
    "LOCKLARK_TEST_FAILURE_STAGE",
    "LOCKLARK_TEST_BROWSER_PARITY",
    "LOCKLARK_TEST_PASSKEY_MANAGEMENT",
    "LOCKLARK_TEST_PASSKEY_CONDITIONAL",
    "LOCKLARK_TEST_OTHER_PROVIDER",
    "LOCKLARK_TEST_PASSKEY_SIGNALS",
  ];
  for (const name of forbidden)
    assert.throws(
      () =>
        guard(
          { ...{ [name]: "1" } },
          "edge",
          absolute,
        ),
      /cannot be combined with another acceptance mode/,
      name,
    );
  // Empty workflow-materialized values and explicit 0 never select a mode.
  const inert = Object.fromEntries(forbidden.map((name) => [name, "0"]));
  inert.LOCKLARK_TEST_EDGE_PAIR_DISCONNECT = "1";
  guard(inert, "edge", absolute);
  const empty = Object.fromEntries(forbidden.map((name) => [name, ""]));
  empty.LOCKLARK_TEST_EDGE_PAIR_DISCONNECT = "1";
  guard(empty, "edge", absolute);
  // Install-only's own list gained exactly this mutual-exclusion name.
  const installGuard = sourceBlock(nativeSource, "if (edgeInstallOnly) {");
  assert.match(installGuard, /"LOCKLARK_TEST_EDGE_PAIR_DISCONNECT"/);
  guard({ LOCKLARK_TEST_EDGE_PAIR_DISCONNECT: "1" }, "edge", absolute);
  // Both guards run before launch: no browser can start for a refused pair.
  assert.ok(
    nativeSource.indexOf("if (edgePairDisconnect) {") <
      nativeSource.indexOf("chromium.launchPersistentContext("),
  );
});

test("the strict install identity and worker proofs run before any pair action", () => {
  const order = [
    "installEdgeExtensionThroughManager({",
    "assert.deepEqual(identity,",
    "assert.equal(browser.serviceWorkers().length, 1",
    "if (edgeInstallOnly) {",
    "throw EDGE_INSTALL_COMPLETE;",
    "await acceptEdgePairDisconnect({",
    "throw EDGE_PAIR_COMPLETE;",
  ];
  let previous = -1;
  for (const marker of order) {
    const index = MANAGED_BRANCH.indexOf(marker);
    assert.ok(index > previous, marker);
    previous = index;
  }
  // The install-only fork is unchanged and never reaches the pair journey.
  const pairAt = MANAGED_BRANCH.indexOf("await acceptEdgePairDisconnect({");
  const installOnlyAt = MANAGED_BRANCH.indexOf("if (edgeInstallOnly) {");
  const installCompleteAt = MANAGED_BRANCH.indexOf("throw EDGE_INSTALL_COMPLETE;");
  assert.ok(installOnlyAt < installCompleteAt);
  assert.ok(installCompleteAt < pairAt);
  // The same real visible manager helper is called with exactly its existing
  // options; no pair-only preload, extension flag, storage write or second
  // harness is introduced.
  const helperCall = sourceBlock(MANAGED_BRANCH, "installEdgeExtensionThroughManager({");
  for (const option of [
    "browser",
    "page",
    "extensionDir: extension",
    "edgeExecutable: browserExecutable",
    "profile",
    "origin",
    "inputRequest:",
    "openPopup",
    "eventually",
    "phase",
  ])
    assert.match(helperCall, new RegExp("\\b" + option.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  // Pair mode shares the install-only launch exactly: the one existing
  // non-managed branch keeps the load switches, while the managed branch
  // selects no switches and no pair-only launch hook is added.
  assert.match(
    managedLaunchSource(),
    /\.\.\.\(edgeManagerInstall\s*\? \[\]\s*:\s*\["--disable-extensions-except=" \+ extension, "--load-extension=" \+ extension\]\)/,
  );
  assert.doesNotMatch(
    MANAGED_BRANCH + PAIR_FUNCTION,
    /--load-extension|--disable-extensions-except|addInitScript|setInputFiles|filechooser/,
  );
});

// The shared managed-install launch block, from the launch arguments through
// the persistent context options. Only its reviewed shape is inspected.
function managedLaunchSource() {
  return nativeSource.slice(
    nativeSource.indexOf("  const launchArguments = ["),
    nativeSource.indexOf("  browser = await chromium.launchPersistentContext("),
  ) + nativeSource.slice(
    nativeSource.indexOf("  browser = await chromium.launchPersistentContext("),
    nativeSource.indexOf("  browser.on(\"console\""),
  );
}

test("pair/disconnect uses the exact physical popup and native X11 controls", () => {
  // The real install-helper popup is what gets clicked; #connect is the
  // popup's actual control, never a synthetic event or a second popup.
  assert.equal(
    PAIR_FUNCTION.match(/installedPopup\.click\("#connect"\)/g)?.length,
    1,
  );
  assert.match(PAIR_FUNCTION, /await installedPopup\.count\("#connect"\)/);
  // Only the generated synthetic fixture vault path, password and Secret Key
  // reach the existing native X11 helper before the exact approval. No quick
  // pairing control is ever chosen.
  const native = [
    '{ click_label: "金库文件" }',
    "{ text: fixture.Path }",
    '{ click_label: "主密码" }',
    "{ text: fixture.Password }",
    '{ click_label: "Secret Key" }',
    "{ text: fixture.Secret }",
    '{ click_label: "解锁" }',
    '{ click_label: "确认连接此扩展" }',
  ];
  let previous = -1;
  for (const marker of native) {
    const index = PAIR_FUNCTION.indexOf(marker);
    assert.ok(index > previous, marker);
    previous = index;
  }
  assert.doesNotMatch(PAIR_FUNCTION, /连接并启用快捷填充/);
  assert.deepEqual(
    [...PAIR_FUNCTION.matchAll(/fixture\.([A-Za-z]+)/g)].map((match) => match[1]),
    ["Path", "Password", "Secret"],
  );
  // No page fill, clipboard, credential-value inspection or added journey.
  assert.doesNotMatch(
    PAIR_FUNCTION,
    /\.fill\(|inputValue|textContent|innerText|clipboard|Clipboard|localStorage|sessionStorage|setInputFiles|filechooser|fill-value|approve-fill/i,
  );
  // The exact disconnect control and the existing wait_absent contract.
  assert.equal(PAIR_FUNCTION.match(/popup\.click\("#disconnect"\)/g)?.length, 1);
  assert.match(PAIR_FUNCTION, /input\(\[\], true, \{ wait_absent: true \}\)/);
});

test("pair proof is followed by disconnect and a fresh disconnected popup proof", () => {
  const compact = PAIR_FUNCTION.replace(/\s+/g, " ");
  const steps = [
    'popupStatusKind(await popup.text("#status")) === "paired"',
    '(await popup.disabled("#refresh")) === false',
    '(await popup.disabled("#connect")) === true',
    'popup.click("#disconnect")',
    "input([], true, { wait_absent: true })",
    'popupStatusKind(await popup.text("#status")) === "disconnected"',
    '(await popup.disabled("#connect")) === false',
    '(await popup.disabled("#refresh")) === true',
  ];
  let previous = -1;
  for (const marker of steps) {
    const index = compact.indexOf(marker);
    assert.ok(index > previous, marker);
    previous = index;
  }
  // Exactly two fresh physical popup opens: one for the paired proof and one
  // after the exact native window disappeared for the disconnected proof.
  assert.equal(PAIR_FUNCTION.match(/await openPopup\(\)/g)?.length, 2);
  assert.match(
    PAIR_FUNCTION,
    /input\(\[\], true, \{ wait_absent: true \}\);\s*mark\("edge-pair-disconnected"\);\s*popup = await openPopup\(\);/,
  );
});

test("pair/disconnect has separate success labels and fixed failure text", () => {
  const labelStart = nativeSource.indexOf("const EDGE_PAIR_DISCONNECT_PASS =");
  const labelEnd = nativeSource.indexOf(";", labelStart) + 1;
  const pairLabel = new Function(
    nativeSource.slice(labelStart, labelEnd) +
      "; return EDGE_PAIR_DISCONNECT_PASS;",
  )();
  assert.equal(typeof pairLabel, "string");
  assert.ok(pairLabel.startsWith("PASS: real Edge extension installed"));
  assert.match(pairLabel, /physically disconnected and re-proven disconnected/);
  assert.notEqual(pairLabel, EDGE_INSTALL_PASS);
  // The final dispatch has install-only, then pair/disconnect, then the
  // general browser journey; pair mode never prints the other two labels.
  const labelsAt = nativeSource.indexOf("if (edgeInstallOnly) {\n  console.log(EDGE_INSTALL_PASS);");
  assert.ok(labelsAt > 0);
  assert.match(
    nativeSource.slice(labelsAt),
    /if \(edgeInstallOnly\) \{\n  console\.log\(EDGE_INSTALL_PASS\);\n\} else if \(edgePairDisconnect\) \{\n  console\.log\(EDGE_PAIR_DISCONNECT_PASS\);\n\} else \{/,
  );
  assert.match(nativeSource, /const EDGE_PAIR_COMPLETE = Object\.freeze/);
  assert.doesNotMatch(nativeSource, /const EDGE_PAIR_COMPLETE = EDGE_INSTALL_COMPLETE/);
  // Both fixed success sentinels are swallowed by the failure handler; pair
  // success never writes a diagnostic.
  assert.match(
    nativeSource,
    /!\(edgeInstallOnly && error === EDGE_INSTALL_COMPLETE\) &&\s*!\(edgePairDisconnect && error === EDGE_PAIR_COMPLETE\)/,
  );
  // Every pair stage is from the fixed allowlist and is masked otherwise.
  for (const match of PAIR_FUNCTION.matchAll(/mark\("([^"]+)"\)/g))
    assert.match(PAIR_STAGES, new RegExp('"' + match[1] + '"'), match[1]);
  assert.match(
    nativeSource,
    /edgePairDisconnect && !EDGE_PAIR_STAGES\.has\(value\) && "edge-pair"/,
  );
  // Pair failures classify only through fixed literals and allowlisted text.
  const pairReasons = [
    "Edge pair popup unavailable",
    "Edge pair connect control unavailable",
    "Edge pair status not paired",
    "Edge pair refresh unavailable",
    "Edge pair disconnect control unavailable",
    "Edge pair connect control remained enabled",
    "Edge pair status not disconnected",
    "Edge pair refresh remained enabled after disconnect",
  ];
  for (const reason of pairReasons) assert.ok(SAFE_REASONS.includes(reason), reason);
  assert.match(nativeSource, /edgePairDisconnect\s*\n?\s*\? "edge-pair-unclassified"/);
  assert.doesNotMatch(PAIR_GUARD, /\$\{/);
  assert.doesNotMatch(PAIR_FUNCTION, /error\.|\.stack|\.message/);
});

// External shared desktop<->extension clipboard acceptance.
//
// This is test tooling only: the actual desktop app binary is started as a
// plain process in the same isolated environment as the browser, unlocked
// through genuine native UI input, and the extension copies through its normal
// native-messaging port. No product test switch, approval hook, runtime grant
// or JS/DOM state injection exists here. Clipboard bytes and the independent
// foreign-owner marker travel only through private JSON stdin pipes; logs carry
// fixed phase names and booleans.
import { execFileSync, spawn } from "node:child_process";
import {
  chmodSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  statSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import assert from "node:assert/strict";

const DESKTOP_TITLE = "Locklark · 本地金库";
// Product default: security.clipboard.clearAfterSeconds = 30.
const CLIPBOARD_TTL_MS = 30000;
const TTL_MARGIN_MS = 4000;
const OWNER_SETTLE_MS = 2500;
const COPY_CONFIRM_SELECTOR =
  '[data-field-id="password"] [data-action="copy-field"]';

function failure(message) {
  return Error(message);
}

// One private JSON line channel per external helper process. Responses never
// echo request payloads; callers decide which fixed fields are inspected.
class LineWorker {
  constructor(child, name) {
    this.child = child;
    this.name = name;
    this.lines = [];
    this.waiters = [];
    child.stdout.setEncoding("utf8");
    let buffer = "";
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      for (;;) {
        const index = buffer.indexOf("\n");
        if (index < 0) break;
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        if (!line) continue;
        let value = null;
        try {
          value = JSON.parse(line);
        } catch {
          value = null;
        }
        const waiter = this.waiters.shift();
        if (waiter) {
          clearTimeout(waiter.timer);
          waiter.resolve(value);
        } else this.lines.push(value);
      }
    });
    child.stdout.on("close", () => {
      for (const waiter of this.waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(failure(this.name + " output closed"));
      }
    });
    // Helper stderr is a fixed classification line at most; never retained.
    child.stderr.on("data", () => {});
  }

  send(message) {
    assert(this.child.stdin && !this.child.stdin.destroyed,
      this.name + " request channel unavailable");
    this.child.stdin.write(JSON.stringify(message) + "\n");
  }

  next(limit = 20000) {
    const line = this.lines.shift();
    if (line !== undefined) return Promise.resolve(line);
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: null };
      waiter.timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(failure(this.name + " response timeout"));
      }, limit);
      this.waiters.push(waiter);
    });
  }

  request(message, limit) {
    this.send(message);
    return this.next(limit);
  }
}

// Independent OS clipboard reader. The expected bytes are sent as JSON on the
// helper's private stdin, never in argv, environment or the DOM.
class PrivateClipboard {
  constructor(context) {
    this.context = context;
    this.worker = null;
  }

  async start() {
    // The guarded probe refuses a socket stdout (Node/libuv stdio pipes are
    // SOCKETPAIR on Linux). This tiny external launcher gives it a real POSIX
    // pipe and forwards only its fixed JSON replies; the probe's own private
    // pipe check stays untouched and expected bytes stay on private pipes.
    const child = spawn(
      "python3",
      [
        join(this.context.root, "scripts/private_pipe_probe.py"),
        join(this.context.root, "scripts/desktop_native_probe.py"),
      ],
      { cwd: this.context.root, env: this.context.env, stdio: ["pipe", "pipe", "pipe"] },
    );
    this.worker = new LineWorker(child, "Native clipboard probe");
    const ready = await this.worker.next(20000);
    assert(ready && ready.ready === true, "Native clipboard probe did not start");
  }

  async compare(expected) {
    const response = await this.worker.request({ op: "clipboard", expected });
    assert(response && response.ok === true, "Native clipboard probe refused the read");
    assert(Array.isArray(response.matches) && response.matches.length === expected.length,
      "Native clipboard probe returned an incomplete comparison");
    return response;
  }

  async matches(value) {
    const response = await this.compare([value]);
    return response.matches[0] === true;
  }

  async empty() {
    const response = await this.compare([""]);
    return response.empty === true;
  }

  stop() {
    if (!this.worker) return;
    try {
      this.worker.child.stdin.end();
    } catch {}
    try {
      this.worker.child.kill("SIGTERM");
    } catch {}
    this.worker = null;
  }
}

// Real unresponsive foreign X11 selection owner. Ownership is a server query;
// the marker is provided on the private pipe and is never printed.
class ForeignOwner {
  constructor(context, marker) {
    this.context = context;
    this.marker = marker;
    this.worker = null;
    this.id = "";
  }

  async start() {
    const child = spawn(
      "python3",
      [join(this.context.root, "scripts/desktop_clipboard_owner.py")],
      { cwd: this.context.root, env: this.context.env, stdio: ["pipe", "pipe", "pipe"] },
    );
    this.worker = new LineWorker(child, "Foreign clipboard owner");
    this.worker.send({ marker: this.marker });
    const ready = await this.worker.next(15000);
    assert(ready && ready.ready === true && ready.requests === 0,
      "Foreign clipboard owner did not start silently");
    assert(ready.owner === ready.expected_owner && /^0x[0-9a-f]+$/.test(ready.owner),
      "Foreign clipboard owner is not the current X11 owner");
    this.id = ready.expected_owner;
  }

  async stats() {
    const response = await this.worker.request({ op: "stats" }, 10000);
    assert(response && response.ok === true, "Foreign clipboard owner stats refused");
    return response;
  }

  // Only after cleanup results are captured may a user reader request data.
  async allowReads() {
    const response = await this.worker.request({ op: "respond" }, 10000);
    assert(response && response.ok === true, "Foreign clipboard owner allow refused");
    assert(response.requests === 0,
      "Foreign clipboard owner saw a request before reads were allowed");
    return response;
  }

  stop() {
    if (!this.worker) return;
    try {
      this.worker.child.kill("SIGTERM");
    } catch {}
    this.worker = null;
  }
}

function startDesktop(context, desktop) {
  // Plain binary, no flags: the vault is chosen through the real unlock UI.
  const descriptor = openSync(join(context.state, "shared-desktop.log"), "wx", 0o600);
  let child;
  try {
    child = spawn(desktop, [], {
      cwd: context.root,
      env: context.env,
      stdio: ["ignore", descriptor, descriptor],
    });
  } finally {
    closeSync(descriptor);
  }
  return child;
}

async function stopOwnProcess(child) {
  if (!child) return;
  // Never leave the owned process stopped, even on a failed cleanup.
  resumeOwnProcess(child);
  stopProcess(child, "SIGTERM");
  const deadline = Date.now() + 5000;
  while (child.exitCode === null && child.signalCode === null && Date.now() < deadline)
    await new Promise((resolve) => setTimeout(resolve, 100));
  stopProcess(child, "SIGKILL");
}

function stopProcess(child, signal = "SIGTERM") {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  try {
    child.kill(signal);
  } catch {}
}

// Only this acceptance-spawned PID is ever paused or resumed.
async function pauseOwnProcess(child) {
  assert(child && Number.isSafeInteger(child.pid) && child.pid > 0,
    "Owned desktop process is unavailable");
  process.kill(child.pid, "SIGSTOP");
}

function resumeOwnProcess(child) {
  if (child && Number.isSafeInteger(child.pid) && child.pid > 0) {
    try {
      process.kill(child.pid, "SIGCONT");
    } catch {}
  }
}

function desktopInput(context, desktop, actions, timeout = 150000) {
  const request = { title: DESKTOP_TITLE, executable: desktop, actions };
  const output = execFileSync(
    "python3",
    [join(context.root, "scripts/browser_native_x11.py")],
    { input: JSON.stringify(request), env: context.env, timeout },
  );
  return JSON.parse(output.toString());
}

function desktopInspect(context, desktop) {
  const request = { title: DESKTOP_TITLE, executable: desktop, actions: [], inspect: true };
  const output = execFileSync(
    "python3",
    [join(context.root, "scripts/browser_native_x11.py")],
    { input: JSON.stringify(request), env: context.env, timeout: 60000 },
  );
  return JSON.parse(output.toString());
}

// Private sibling of the browser profile: the actual desktop app, the
// browser-spawned native host and their helpers must never see the real HOME,
// TMPDIR or an existing desktop broker endpoint. Go tooling keeps the original
// environment because its install outputs are explicit paths.
export function prepareSharedEnvironment(state, env) {
  assert(process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1",
    "Shared clipboard mode must be requested explicitly");
  assert(process.env.LOCKLARK_DESKTOP_HOST && process.env.LOCKLARK_DESKTOP_HOST.startsWith("/"),
    "Shared desktop host must be an absolute executable path");
  const base = join(state, "shared-environment");
  const home = join(base, "home");
  const temporary = join(base, "tmp");
  const directories = [base, home, temporary, join(home, ".config"),
    join(home, ".cache"), join(home, ".local"), join(home, ".local/share")];
  for (const directory of directories) {
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    chmodSync(directory, 0o700);
  }
  assert(readdirSync(join(home, ".config")).length === 0 &&
    readdirSync(temporary).length === 0,
    "Private desktop environment must start empty");
  const socket = join(temporary, "b.sock");
  assert(!existsSync(socket), "A shared broker endpoint already exists in the private environment");
  const gocache = process.env.GOCACHE ||
    join("/tmp", "locklark-shared-gocache-" + process.geteuid());
  return {
    ...env,
    HOME: home,
    TMPDIR: temporary,
    XDG_CONFIG_HOME: join(home, ".config"),
    XDG_CACHE_HOME: join(home, ".cache"),
    XDG_DATA_HOME: join(home, ".local/share"),
    LOCKLARK_BROWSER_SOCKET: socket,
    GOCACHE: gocache,
  };
}

// The live desktop broker endpoint for this isolated environment. Both the
// desktop app and the browser-spawned native host derive it from the same
// private TMPDIR (or the explicit driver variable).
function brokerEndpoint(context) {
  if (context.env.LOCKLARK_BROWSER_SOCKET) return context.env.LOCKLARK_BROWSER_SOCKET;
  const uid = typeof process.geteuid === "function" ? process.geteuid() : null;
  assert(uid !== null, "Shared acceptance requires a POSIX effective user id");
  return join(context.env.TMPDIR || "/tmp", "locklark-brw-" + uid, "b.sock");
}

function unlockDesktop(context, desktop) {
  // Full synthetic factors enter only through the real native controls.
  desktopInput(context, desktop, [
    { click_label: "金库文件" },
    { key: "Control_L+a" },
    { text: context.fixture.Path },
    { click_label: "主密码" },
    { text: context.fixture.Password },
    { click_label: "Secret Key" },
    { text: context.fixture.Secret },
    { click_label: "解锁" },
    // The vault page of the default (non-legacy) UI has no items-view button;
    // the real lock control appears only after the vault is actually unlocked.
    { wait_label: "立即锁定" },
  ]);
}

// Only fixed public control labels and their boolean state may be reported.
const PUBLIC_CONTROLS = [
  "金库文件", "主密码", "Secret Key", "解锁", "新建登录", "立即锁定",
  "显示密码", "复制密码", "金库", "安全设置", "全部", "归档", "回收站",
  "搜索 / 刷新", "确认连接此扩展", "连接并启用快捷填充", "拒绝连接",
];

function sanitizeControls(controls) {
  const reported = {};
  if (!controls || typeof controls !== "object") return reported;
  for (const label of PUBLIC_CONTROLS) {
    const control = controls[label];
    if (!control || typeof control !== "object") continue;
    const entry = {};
    for (const key of ["present", "enabled", "showing"])
      if (typeof control[key] === "boolean") entry[key] = control[key];
    reported[label] = entry;
  }
  return reported;
}

const POPUP_VIEWS = new Set(["vault", "locked", "detail", "editor", "site"]);

// Fixed public booleans/numeric counts only: no status text, item metadata or
// field value is ever read into the report.
async function safePopupState(popup) {
  const state = {};
  try {
    const disabled = await popup.disabled("#search-input");
    if (typeof disabled === "boolean") state.search_disabled = disabled;
  } catch {
    state.search_state_unavailable = true;
  }
  for (const [name, selector] of [
    ["vault_view", "#vault-view:not([hidden])"],
    ["vault_rows", "#vault-list .vault-item"],
    ["locked_view", "#locked-view:not([hidden])"],
    ["detail_view", "#detail-view:not([hidden])"],
  ]) {
    try {
      const count = await popup.count(selector);
      if (Number.isSafeInteger(count) && count >= 0 && count <= 10000) state[name] = count;
    } catch {
      state[name + "_unavailable"] = true;
    }
  }
  try {
    const view = await popup.attribute("body", "data-view");
    state.data_view = POPUP_VIEWS.has(view) ? view : "unknown";
  } catch {
    state.data_view = "unknown";
  }
  return state;
}

// Stack frames are reduced to module:line:col; messages never leave the process.
function fixedErrorFrames(error) {
  const frames = typeof error?.stack === "string"
    ? error.stack.match(/[A-Za-z0-9_-]+\.mjs:[0-9]+:[0-9]+/g) || []
    : [];
  return frames.slice(0, 8);
}

function assertNoNativePairUi(context, desktop) {
  const view = desktopInspect(context, desktop);
  for (const label of ["确认连接此扩展", "连接并启用快捷填充", "拒绝连接"]) {
    const control = view.controls?.[label];
    assert(!control || control.present !== true,
      "Shared desktop must not ask for a native quick-pair confirmation");
  }
  return true;
}

async function connectedPopup(context) {
  const popup = await context.openPopup();
  await context.eventually(
    async () =>
      (await popup.disabled("#refresh")) === false ||
      (await popup.disabled("#connect")) === false,
    "Shared popup controls are unavailable",
  );
  // A live shared session may already be bound; only an unbound popup pairs.
  if ((await popup.disabled("#connect")) === false) await popup.click("#connect");  await context.eventually(
    async () =>
      (await popup.disabled("#connect")) === true &&
      (await popup.disabled("#refresh")) === false,
    "Shared popup did not bind the live desktop session",
  );
  return popup;
}

async function openSyntheticDetail(context, popup, step) {
  assert(/^[a-f0-9]{32}$/.test(context.fixture.SeedID || ""),
    "Synthetic fixture item id is required");
  const row = '#vault-list [data-item-id="' + context.fixture.SeedID + '"]';
  step("shared-clipboard:detail-search");
  await context.eventually(
    async () => (await popup.disabled("#search-input")) === false,
    "Shared vault refresh did not settle",
  );
  step("shared-clipboard:detail-all");
  await popup.click('#filter-tabs [data-filter="all"]');
  step("shared-clipboard:detail-list");
  await context.eventually(
    async () => (await popup.count(row)) === 1,
    "Synthetic vault row is not listed exactly once",
  );
  assert.equal(await popup.count("#vault-list .vault-item"), 1,
    "Synthetic vault must hold exactly one row");
  step("shared-clipboard:detail-title");
  assert.equal(await popup.text(row + " .vault-item-title"), context.fixture.Title,
    "Synthetic login row title mismatch");
  step("shared-clipboard:detail-row");
  await popup.click(row);
  step("shared-clipboard:detail-view");
  await context.eventually(
    async () => (await popup.text("#detail-title")) === context.fixture.Title,
    "Shared vault detail did not open",
  );
  step("shared-clipboard:detail-password-controls");
  assert.equal(await popup.count('[data-field-id="password"]'), 1,
    "Concealed password field is missing");
  assert.equal(await popup.count('[data-field-id="password"] [data-action="toggle-reveal"]'), 1,
    "Password field is not concealed and revealable");
  assert.equal(await popup.count(COPY_CONFIRM_SELECTOR), 1,
    "Concealed password copy control is missing");
}

// Only the native lease path renders the automatic-cleanup wording next to the
// copied control; the legacy browser write renders the manual-cleanup warning.
async function copyConcealedPassword(context, popup) {
  await popup.click(COPY_CONFIRM_SELECTOR);
  await context.eventually(
    async () => {
      const button = String((await popup.text(COPY_CONFIRM_SELECTOR)) || "");
      const toast = String((await popup.text("#toast")) || "");
      return button.includes("已复制") && toast.includes("自动清理");
    },
    "Popup did not confirm the native copy",
    20000,
  );
  const toast = String((await popup.text("#toast")) || "");
  assert(toast.includes("已启用自动清理"),
    "Popup did not announce the native automatic-cleanup lease");
  assert(!toast.includes("无法保证自动清除"),
    "Popup used the legacy manual browser-copy wording");
  return Date.now();
}

async function copyIsPasteable(context, clipboard) {
  await context.eventually(
    () => clipboard.matches(context.fixture.Value),
    "OS clipboard did not receive the native copy",
    8000,
  );
  return true;
}

// Shared desktop<->extension clipboard journey. The browser keeps the fixed
// Chromium extension identity, the native host relays its normal port to the
// live desktop broker, and the desktop app is the only clipboard owner.
export async function acceptSharedClipboard(context) {
  assert(process.env.LOCKLARK_TEST_SHARED_CLIPBOARD === "1",
    "Shared clipboard mode must be requested explicitly");
  assert(process.env.LOCKLARK_DESKTOP_HOST && process.env.LOCKLARK_DESKTOP_HOST.startsWith("/"),
    "Shared desktop host must be an absolute executable path");
  const desktop = process.env.LOCKLARK_DESKTOP_HOST;
  assert(typeof context.fixture?.Path === "string" && context.fixture.Path.startsWith("/"),
    "Synthetic fixture vault path is required");
  assert(typeof context.fixture?.Value === "string" && context.fixture.Value.length > 0,
    "Synthetic fixture password is required");
  // Only the controlled private fixture and an empty private settings tree may
  // feed the actual app: no user vault, no persisted desktop preferences.
  assert(context.fixture.Path === join(context.state, "vault", "synthetic.ll") &&
    existsSync(context.fixture.Path),
    "Shared acceptance requires the controlled synthetic fixture vault");
  assert(typeof context.env?.HOME === "string" &&
    context.env.HOME.startsWith(context.state) &&
    typeof context.env.TMPDIR === "string" &&
    context.env.TMPDIR.startsWith(context.state),
    "Shared desktop must run with the private HOME and TMPDIR");
  assert(typeof context.env.XDG_CONFIG_HOME === "string" &&
    context.env.XDG_CONFIG_HOME.startsWith(context.state),
    "Private desktop settings directory must stay private");
  assert(context.env.LOCKLARK_BROWSER_SOCKET &&
    context.env.LOCKLARK_BROWSER_SOCKET.startsWith(context.state),
    "Shared desktop broker endpoint must be private to this run");
  const receipts = {
    mode: "shared-desktop",
    stage: "started",
    private_home_and_tmpdir: true,
    private_settings_default: true,
    controlled_fixture_vault: true,
  };
  let lastStage = "shared-clipboard:start";
  const step = (value) => {
    lastStage = value;
    console.log("Shared native stage: " + value);
  };
  const clipboard = new PrivateClipboard(context);
  let popup = null, app = null, owner = null;
  context.phase("shared-clipboard");
  try {
    step("shared-clipboard:desktop-spawn");
    app = startDesktop(context, desktop);
    await context.eventually(() => {
      try {
        desktopInspect(context, desktop);
        return true;
      } catch {
        return false;
      }
    }, "Shared desktop window did not appear", 60000);
    receipts.desktop_spawned = true;
    const endpoint = brokerEndpoint(context);
    await context.eventually(() => {
      try {
        return statSync(endpoint).isSocket();
      } catch {
        return false;
      }
    }, "Shared desktop broker endpoint was not published", 30000);
    receipts.shared_broker_endpoint = true;
    receipts.broker_endpoint_is_socket = true;

    step("shared-clipboard:desktop-unlock");
    unlockDesktop(context, desktop);
    receipts.desktop_unlock_ui = true;

    // The read-only pair-UI negative check runs BEFORE any browser action popup
    // exists: this external inspector may raise/focus the desktop window, and a
    // focused desktop would close the real action popup. It therefore never runs
    // while the popup must stay focused for a physical click.
    step("shared-clipboard:native-pair-ui");
    receipts.native_pair_ui_absent = assertNoNativePairUi(context, desktop);
    receipts.native_pair_ui_checked_before_popup = true;

    step("shared-clipboard:connect");
    popup = await connectedPopup(context);
    receipts.popup_connected_shared = true;

    step("shared-clipboard:detail");
    await openSyntheticDetail(context, popup, step);
    receipts.synthetic_row_listed = true;
    receipts.detail_opened = true;

    step("shared-clipboard:native-copy");
    await clipboard.start();
    const copiedAt = await copyConcealedPassword(context, popup);
    receipts.concealed_password_copy = true;
    receipts.dom_copied_confirmed = true;
    receipts.native_autocleanup_wording = true;
    receipts.manual_copy_wording_absent = true;
    receipts.os_clipboard_match = await copyIsPasteable(context, clipboard);

    step("shared-clipboard:popup-close");
    await popup.dismiss();
    popup = null;
    await context.delay(300);
    receipts.popup_closed_value_pasteable = await copyIsPasteable(context, clipboard);
    // A later independent owner must survive the app's own 30s TTL cleanup:
    // the app may only ever drop its own lease, never blank a foreign owner.
    step("shared-clipboard:foreign-ttl");
    const marker = "Shared acceptance foreign marker " + randomBytes(16).toString("hex");
    owner = new ForeignOwner(context, marker);
    await owner.start();
    while (Date.now() < copiedAt + CLIPBOARD_TTL_MS + TTL_MARGIN_MS)
      await context.delay(500);
    const ttlStats = await owner.stats();
    assert(ttlStats.owner === owner.id,
      "Product cleared or replaced the later foreign clipboard owner");
    assert(ttlStats.requests === 0,
      "Product requested a foreign clipboard payload during cleanup");
    receipts.foreign_owner_preserved_after_ttl = true;
    receipts.foreign_owner_zero_requests = true;
    await owner.allowReads();
    const markerView = await clipboard.compare([marker, context.fixture.Value, ""]);
    assert(markerView.matches[0] === true,
      "Foreign clipboard marker was not preserved");
    assert(markerView.matches[1] === false,
      "Foreign clipboard unexpectedly held the synthetic password");
    assert(markerView.matches[2] === false,
      "Foreign clipboard was blanked");
    receipts.foreign_marker_verified = true;
    owner.stop();
    owner = null;

    // A fresh real copy is owned by the app, so locking must clear exactly it.
    step("shared-clipboard:fresh-copy");
    popup = await connectedPopup(context);
    await openSyntheticDetail(context, popup, step);
    await copyConcealedPassword(context, popup);
    receipts.fresh_native_copy = await copyIsPasteable(context, clipboard);
    await popup.dismiss();
    popup = null;
    step("shared-clipboard:lock");
    desktopInput(context, desktop, [
      { click_label: "立即锁定" },
      { wait_label: "解锁" },
    ], 60000);
    await context.eventually(
      () => clipboard.empty(),
      "Locking the desktop app did not clear the owned clipboard value",
      10000,
    );
    receipts.app_lock_cleared_owned_value = true;

    // A foreign owner installed afterwards must not be touched by the lock.
    step("shared-clipboard:later-owner");
    const laterMarker = "Shared acceptance later marker " + randomBytes(16).toString("hex");
    owner = new ForeignOwner(context, laterMarker);
    await owner.start();
    await context.delay(OWNER_SETTLE_MS);
    const laterStats = await owner.stats();
    assert(laterStats.owner === owner.id && laterStats.requests === 0,
      "Later foreign clipboard owner was disturbed by the lock or cleanup");
    await owner.allowReads();
    const laterView = await clipboard.compare([laterMarker, context.fixture.Value]);
    assert(laterView.matches[0] === true && laterView.matches[1] === false,
      "Later foreign marker was not preserved after lock");
    receipts.later_foreign_owner_preserved = true;
    owner.stop();
    owner = null;
    // Late prepare: pause ONLY the desktop process this driver started, close
    // the popup while the prepare is still waiting, then always resume. This is
    // ordinary external process orchestration, not an authentication hook.
    step("shared-clipboard:late-prepare-unlock");
    unlockDesktop(context, desktop);
    popup = await connectedPopup(context);
    await openSyntheticDetail(context, popup, step);
    const lateMarker = "Shared acceptance late marker " + randomBytes(16).toString("hex");
    owner = new ForeignOwner(context, lateMarker);
    await owner.start();
    await context.delay(300);
    step("shared-clipboard:late-prepare");
    await pauseOwnProcess(app);
    try {
      await popup.click(COPY_CONFIRM_SELECTOR);
      await context.delay(1200);
      assert(
        !String((await popup.text(COPY_CONFIRM_SELECTOR)) || "").includes("已复制"),
        "Copy was confirmed while the owned desktop process was paused",
      );
      await popup.dismiss();
      popup = null;
      receipts.late_prepare_paused_own_app = true;
      receipts.late_prepare_popup_closed = true;
    } finally {
      resumeOwnProcess(app);
    }
    // The resumed app answers a request whose popup is gone: the reply must be
    // cancelled and no hidden copy may replace the foreign owner.
    await context.delay(4000);
    const lateStats = await owner.stats();
    assert(lateStats.owner === owner.id && lateStats.requests === 0,
      "Hidden popup copy replaced or read the foreign clipboard owner");
    await owner.allowReads();
    const lateView = await clipboard.compare([lateMarker, context.fixture.Value, ""]);
    assert(lateView.matches[0] === true,
      "Foreign marker was lost after the late prepare response");
    assert(lateView.matches[1] === false && lateView.matches[2] === false,
      "A hidden popup copy reached the clipboard after the popup closed");
    receipts.late_prepare_no_after_hide_copy = true;
    owner.stop();
    owner = null;
    receipts.stage = "journey-complete";
    receipts.journey_complete = true;
  } catch (error) {
    // Diagnose before cleanup terminates the app. Only the fixed stage, the
    // public window id and allowlisted control names with boolean state and
    // numeric geometry leave this process: never factors, field values, text
    // bodies, commands or exception messages.
    receipts.failed_stage = lastStage;
    console.error("Shared native clipboard failure stage: " + lastStage);
    receipts.error_frames = fixedErrorFrames(error);
    if (popup) {
      try {
        receipts.popup_state = await safePopupState(popup);
      } catch {
        receipts.popup_state_unavailable = true;
      }
    } else {
      receipts.popup_state_absent = true;
    }
    if (app) {
      try {
        const view = desktopInspect(context, desktop);
        receipts.desktop_window = Number.isSafeInteger(view.window) ? view.window : 0;
        receipts.desktop_controls = sanitizeControls(view.controls);
      } catch {
        receipts.desktop_controls_unavailable = true;
      }
    }
    throw failure("Shared native clipboard acceptance failed");
  } finally {
    if (popup) {
      try {
        await popup.dismiss();
      } catch {}
    }
    if (owner) owner.stop();
    await stopOwnProcess(app);
    clipboard.stop();
    console.log("Shared native clipboard receipts: " + JSON.stringify(receipts));
  }
}

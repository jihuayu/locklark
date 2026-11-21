// Real Linux Chromium/native UI rotation journey over the owned HTTPS fixture.
// This exercises ordinary website forms, the popup's native save/update/fill
// controls, and the authenticated vault observer. It has no terminal lease,
// extension generator, staging receipt, or direct product RPC.
import assert from "node:assert/strict";
import { request } from "node:https";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import {
  createBrowserRotationSite,
  ROTATION_SITE_HOST,
} from "./browser_rotation_site.mjs";

// The optional browser-to-CLI chain has exactly these fixed terminal outputs.
// They carry no path, value, item ID, revision or raw CLI output.
const ROTATION_CLI_PRE_STDOUT =
  "PASS: browser-rotation-cli r0_before_website_post\n" +
  "PASS: browser-rotation-cli hibp_pre_website_post\n" +
  "PASS: browser-rotation-cli pre_complete\n";
const ROTATION_CLI_POST_STDOUT =
  "PASS: browser-rotation-cli stale_exact_refusal_no_intent\n" +
  "PASS: browser-rotation-cli r1_rebound_same_item\n" +
  "PASS: browser-rotation-cli r1_child_two_intents\n" +
  "PASS: browser-rotation-cli post_complete\n";
const ROTATION_CLI_TIMEOUT_MS = 150000;
// The helper's own deadline is shorter, so it can stop and reap its owned PTY
// child and report the actual fixed stage before this spawn timeout fires.
const ROTATION_CLI_PHASE_TIMEOUT_MS = 90000;
const ROTATION_CLI_MAX_OUTPUT = 64 * 1024;
const ROTATION_CLI_STAGES = new Set([
  "prerequisites",
  "vault",
  "audit-baseline",
  "binding-r0",
  "r0",
  "audit-r0",
  "hibp-decline",
  "audit-hibp-decline",
  "hibp-consent",
  "audit-hibp-consent",
  "stale",
  "audit-stale",
  "binding-r1",
  "r1",
  "audit-r1",
  "complete",
]);
const ROTATION_CLI_FAILURE =
  /^FAIL: browser-rotation-cli ([a-z0-9-]+)\n?$/;

// Independent Basic verification through the same owned TLS endpoint. Every
// call opens a fresh connection; only the private fixture CA is trusted.
function authenticateWebsite(targetURL, ca, username, password) {
  return new Promise((resolve, reject) => {
    const failed = () => reject(Error("Owned rotation HTTPS verification failed"));
    const req = request(
      targetURL,
      {
        method: "GET",
        ca,
        rejectUnauthorized: true,
        minVersion: "TLSv1.3",
        agent: false,
        family: 4,
        servername: ROTATION_SITE_HOST,
        lookup: (_hostname, _options, callback) => callback(null, "127.0.0.1", 4),
        headers: {
          Authorization:
            "Basic " +
            Buffer.from(username + ":" + password).toString("base64"),
        },
      },
      (response) => {
        const authorized =
          response.socket.authorized &&
          response.socket.getProtocol() === "TLSv1.3";
        let size = 0;
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > 4096) {
            req.destroy();
            failed();
          }
        });
        response.once("error", failed);
        response.once("end", () =>
          resolve({ status: response.statusCode, authorized }),
        );
      },
    );
    req.once("error", failed);
    req.setTimeout(5000, () => {
      req.destroy();
      failed();
    });
    req.end();
  });
}

const storedRows = (view) =>
  JSON.stringify([...view.rows].sort((left, right) => left.id.localeCompare(right.id)));
const sameStoredState = (before, after) =>
  before.snapshot_digest === after.snapshot_digest &&
  storedRows(before) === storedRows(after) &&
  JSON.stringify(before.save_events) === JSON.stringify(after.save_events);

export async function acceptBrowserRotation(driver) {
  const {
    page,
    fixture,
    phase,
    input,
    observe,
    openPopup,
    reconnect,
    eventually: wait,
    closePopups,
    key,
    cert,
    returnURL,
    rotationCli,
    root,
    state,
    env,
  } = driver;
  const step = (name) => phase("rotation:" + name);
  let site;
  let urls;
  let completed = false;
  let cleaned = false;
  let failed = false;
  let receipt;
  let cliStateDir = null;
  let cliEvidence = null;
  const cliRequested = Boolean(rotationCli);
  // With the explicit CLI opt-in the rotation's R0 is the generated value that
  // the earlier real save tests already proved is never persisted by a
  // rejected/edit-buffer save. Its pre-existing active save login uses the
  // successful UpdateValue, so HIBP sees one breached R0 and two clean
  // controls. With the opt-in off the ordinary fixture.Value path is unchanged.
  const r0Value = cliRequested ? fixture.RejectedValue : fixture.Value;
  const cliScript = join(root, "scripts/browser_rotation_cli.py");
  const fixtureRoot = join(state, "vault");

  // Only the fixed stage in the helper's own FAIL line is ever promoted into
  // the existing phase report. Raw streams and paths stay in this process.
  const failedCliStage = (stderr) => {
    if (typeof stderr !== "string") return null;
    const match = ROTATION_CLI_FAILURE.exec(stderr);
    return match && ROTATION_CLI_STAGES.has(match[1]) ? match[1] : null;
  };

  // One separate Python invocation per phase, with all inputs (including the
  // synthetic factors) on bounded stdin JSON. Only its fixed PASS lines are
  // accepted; raw CLI output, paths and failures never enter this process.
  const runRotationCli = (phaseName, itemID, extra) => {
    assert(cliStateDir, "Rotation CLI state directory missing");
    const input = JSON.stringify({
      version: 1,
      phase: phaseName,
      cli: rotationCli,
      vault: fixture.Path,
      vaultRoot: fixtureRoot,
      stateDir: cliStateDir,
      itemID,
      masterPassword: fixture.Password,
      secretKey: fixture.Secret,
      timeout: Math.floor(ROTATION_CLI_PHASE_TIMEOUT_MS / 1000),
      ...extra,
    });
    assert(
      Buffer.byteLength(input, "utf8") <= 64 * 1024,
      "Rotation CLI input too large",
    );
    const result = spawnSync("python3", [cliScript], {
      cwd: root,
      env,
      input,
      encoding: "utf8",
      timeout: ROTATION_CLI_TIMEOUT_MS,
      maxBuffer: ROTATION_CLI_MAX_OUTPUT,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const runtimeFailure =
      result.error !== undefined ||
      result.signal !== null ||
      result.status !== 0;
    if (runtimeFailure) {
      const stage = failedCliStage(result.stderr);
      if (stage) step("cli-" + phaseName + "-failure:" + stage);
    }
    assert(!runtimeFailure, "Rotation CLI phase failed");
    return result.stdout;
  };

  // Ordinary typing only: focus the real control, replace its contents and
  // insert the synthetic value through browser keyboard input.
  const enter = async (selector, value) => {
    await page.locator(selector).click();
    await page.keyboard.press("Control+A");
    await page.keyboard.type(value);
  };
  const emptyLogin = () =>
    page.evaluate(
      () =>
        document.querySelector("#username").value === "" &&
        document.querySelector("#password").value === "",
    );
  const loginEquals = (username, password) =>
    page.evaluate(
      ([expectedUsername, expectedPassword]) =>
        document.querySelector("#username").value === expectedUsername &&
        document.querySelector("#password").value === expectedPassword,
      [username, password],
    );
  // Existence and enabled state only, through the same bounded count/boolean
  // projections used by the ordinary save journey.
  const actionReady = (popup, selector, message) =>
    wait(
      async () =>
        (await popup.count(selector)) === 1 &&
        (await popup.disabled(selector)) === false,
      message,
    );
  const exactCandidate = async (id, revision) => {
    const row = observe().rows.find((entry) => entry.id === id);
    assert(row?.revision === revision, "Rotation exact target revision changed");
    const selected =
      '#candidates [data-item-id="' +
      id +
      '"][data-item-revision="' +
      revision +
      '"]';
    const popup = await openPopup();
    await wait(
      async () => (await popup.disabled("#refresh")) === false,
      "Rotation matching unavailable",
    );
    await popup.click("#refresh");
    await wait(
      async () =>
        (await popup.disabled("#refresh")) === false &&
        (await popup.count(selected + ' [data-action="fill"]')) === 1,
      "Rotation exact candidate unavailable",
    );
    assert(
      (await popup.evaluate('document.querySelector("#auto-login").checked')) ===
        false,
      "Rotation requires the existing manual login setting",
    );
    return { popup, selected };
  };
  const fillAndLogin = async (id, revision, username, password) => {
    await page.goto(urls.loginURL);
    assert(await emptyLogin(), "Rotation login must start empty");
    const { popup, selected } = await exactCandidate(id, revision);
    await popup.click(selected + ' [data-action="fill"]');
    input([{ wait_label: "批准本次填充" }]);
    assert(await emptyLogin(), "Rotation fields released before native approval");
    input([{ click_label: "批准本次填充" }]);
    await wait(
      () => loginEquals(username, password),
      "Rotation approved fill did not deliver the exact stored pair",
    );
    const [response] = await Promise.all([
      page.waitForResponse(
        (candidate) =>
          candidate.url() === urls.loginURL &&
          candidate.request().method() === "POST",
      ),
      page.locator('#login button[type="submit"]').click(),
    ]);
    assert(
      response.status() === 303,
      "Rotation refilled credential was not accepted by the website",
    );
    await page.waitForURL(urls.changeURL);
    await page.locator("#new-password").waitFor({ state: "visible" });
  };

  try {
    step("owned-site");
    site = createBrowserRotationSite({ key, cert });
    urls = await site.listen();
    await page.goto(urls.registerURL);
    await reconnect();
    await closePopups();

    step("register-r0");
    await enter("#username", fixture.Username);
    await enter("#password", r0Value);
    await enter("#confirm-password", r0Value);
    const [registered] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.url() === urls.registerURL &&
          response.request().method() === "POST",
      ),
      page.locator('#register button[type="submit"]').click(),
    ]);
    assert(registered.status() === 201, "Rotation website registration failed");
    assert(
      site.snapshot().registrations === 1,
      "Rotation registration transaction missing",
    );

    step("save-r0");
    await page.goto(urls.loginURL);
    await enter("#username", fixture.Username);
    await enter("#password", r0Value);
    const beforeNew = observe();
    let popup = await openPopup();
    await wait(
      async () => (await popup.disabled("#save-new")) === false,
      "Rotation save-new unavailable",
    );
    await popup.click("#save-new");
    input([{ wait_label: "批准保存登录" }]);
    assert(
      sameStoredState(beforeNew, observe()),
      "Rotation save changed state before native approval",
    );
    input([{ click_label: "批准保存登录" }]);
    let saved;
    await wait(() => {
      saved = observe();
      return saved.save_events.length === beforeNew.save_events.length + 1;
    }, "Rotation R0 save receipt missing");
    const oldIDs = new Set(beforeNew.rows.map((row) => row.id));
    const added = saved.rows.filter((row) => !oldIDs.has(row.id));
    const newEvent = saved.save_events.at(-1);
    assert(
      added.length === 1 &&
        saved.rows.length === beforeNew.rows.length + 1 &&
        added[0].title === urls.origin &&
        newEvent.action === "item.browser.save.new" &&
        newEvent.result === "succeeded" &&
        newEvent.item_id === added[0].id &&
        newEvent.revision === added[0].revision,
      "Rotation R0 must be created by exactly one native save",
    );
    const itemID = added[0].id;
    const r0 = added[0].revision;

    step("login-r0");
    await closePopups();
    await fillAndLogin(itemID, r0, fixture.Username, r0Value);
    const r0Authentication = await authenticateWebsite(
      urls.targetURL,
      cert,
      fixture.Username,
      r0Value,
    );
    assert(
      r0Authentication.authorized && r0Authentication.status === 200,
      "Rotation R0 must authenticate before the password change",
    );

    if (cliRequested) {
      // This is before the actual password-change POST below: the browser-made
      // R0 is already the exact vault row, and the real CLI must use it once.
      step("cli-r0:before-website-post");
      assert(
        fixture.Path === join(state, "vault", "synthetic.ll"),
        "Rotation CLI vault must be the owned synthetic fixture",
      );
      cliStateDir = mkdtempSync(join(state, "rotation-cli-"));
      assert(
        runRotationCli("pre", itemID, {
          revisionR0: r0,
          tokenR0: r0Value,
        }) === ROTATION_CLI_PRE_STDOUT,
        "Rotation CLI pre phase output changed",
      );
      cliEvidence = {
        cliR0BeforeWebsitePost: true,
        cliR0BindingCreated: true,
        cliR0ExactChild: true,
        cliR0AuditIntent: true,
        hibpDeclineNoNetwork: true,
        hibpPrefixRequestsExact: true,
        hibpMockResponseExact: true,
        hibpControlsClean: true,
        hibpSameItemRevision: true,
        hibpBeforeWebsitePost: true,
        hibpAudited: true,
      };
    }

    step("change-r1");
    // This checkpoint uses the private fixture's UpdateValue as an ordinary
    // typed R1. Extension-generated/staged saves stay a separate, unclaimed
    // surface and are never exercised here.
    await enter("#new-password", fixture.UpdateValue);
    await enter("#confirm-password", fixture.UpdateValue);
    assert(
      await page.evaluate(
        (expected) =>
          document.querySelector("#new-password").value === expected &&
          document.querySelector("#confirm-password").value === expected,
        fixture.UpdateValue,
      ),
      "Rotation R1 was not typed into both new-password controls",
    );
    const [changed] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.url() === urls.changeURL &&
          response.request().method() === "POST",
      ),
      page.locator("#confirm-password").press("Enter"),
    ]);
    assert(
      changed.status() === 200,
      "Rotation website refused the actual password-change POST",
    );
    await wait(
      () =>
        page.evaluate(
          () => document.body.dataset.rotationResult === "changed",
        ),
      "Rotation website success response did not reach the browser",
    );
    assert(
      site.snapshot().passwordChanges === 1,
      "Rotation website password transaction missing",
    );

    step("website-authentication");
    const oldAuthentication = await authenticateWebsite(
      urls.targetURL,
      cert,
      fixture.Username,
      r0Value,
    );
    const newAuthentication = await authenticateWebsite(
      urls.targetURL,
      cert,
      fixture.Username,
      fixture.UpdateValue,
    );
    assert(
      oldAuthentication.authorized &&
        oldAuthentication.status === 401 &&
        newAuthentication.authorized &&
        newAuthentication.status === 200,
      "Rotation website must reject the old R0 and accept the new R1",
    );

    // The successful change POST leaves the change-password document current.
    // Return to the same origin's ordinary login document, where the saved R0
    // candidate was observed, without submitting this preparatory form.
    step("update-r0:normal-login");
    await page.goto(urls.loginURL);
    assert(await emptyLogin(), "Rotation update login must start empty");
    await enter("#username", fixture.Username);
    await enter("#password", fixture.UpdateValue);
    assert(
      await loginEquals(fixture.Username, fixture.UpdateValue),
      "Rotation update login did not retain the exact owned username and R1",
    );

    step("update-r0:target-observe");
    const beforeUpdate = observe();
    step("update-r0:candidate-refresh");
    const { popup: updatePopup, selected } = await exactCandidate(itemID, r0);
    const updateAction = selected + ' [data-action="update"]';
    step("update-r0:update-control");
    await actionReady(
      updatePopup,
      updateAction,
      "Rotation update control not ready",
    );
    step("update-r0:native-approval");
    await updatePopup.click(updateAction);
    input([{ wait_label: "批准更新登录" }]);
    step("update-r0:preapproval-invariant");
    assert(
      sameStoredState(beforeUpdate, observe()),
      "Rotation update changed state before native approval",
    );
    step("update-r0:approved-receipt");
    input([{ click_label: "批准更新登录" }]);
    let updated;
    await wait(() => {
      updated = observe();
      return updated.save_events.length === beforeUpdate.save_events.length + 1;
    }, "Rotation native update receipt missing");
    step("update-r0:exact-revision");
    const updateEvent = updated.save_events.at(-1);
    const updatedRow = updated.rows.find((row) => row.id === itemID);
    const r1 = updatedRow?.revision;
    assert(
      updated.rows.length === beforeUpdate.rows.length &&
        r1 &&
        r1 !== r0 &&
        updateEvent.action === "item.browser.save.update" &&
        updateEvent.result === "succeeded" &&
        updateEvent.item_id === itemID &&
        updateEvent.base_revision === r0 &&
        updateEvent.revision === r1 &&
        updatedRow.title === added[0].title,
      "Rotation update must advance the same item from the exact R0 revision",
    );

    if (cliRequested) {
      // The R0 binding created before the website POST stays byte-identical
      // through one explicit stale refusal, then the same item is explicitly
      // rebound at R1 and run once more. Both runs use hidden local factors
      // and the deliberate RUN consent; only fixed booleans are retained.
      step("cli-r1:stale-then-rebind");
      assert(
        runRotationCli("post", itemID, {
          revisionR0: r0,
          revisionR1: r1,
          tokenR0: r0Value,
          tokenR1: fixture.UpdateValue,
        }) === ROTATION_CLI_POST_STDOUT,
        "Rotation CLI post phase output changed",
      );
      cliEvidence = {
        ...cliEvidence,
        cliBindingUnchangedThroughStale: true,
        cliStaleExactRefusal: true,
        cliStaleNoChild: true,
        cliStaleNoNewIntent: true,
        cliR1ReboundSameItem: true,
        cliR1ExactChild: true,
        cliAuditIntentDeltas: 2,
      };
    }

    step("refill-login-r1");
    await closePopups();
    await fillAndLogin(itemID, r1, fixture.Username, fixture.UpdateValue);
    const counts = site.snapshot();
    assert(
      !counts.countersCapped &&
        counts.observerFailures === 0 &&
        counts.registrations === 1 &&
        counts.passwordChanges === 1 &&
        counts.changeRejected === 0 &&
        counts.loginAccepted === 2 &&
        counts.loginRejected === 0 &&
        counts.basicAccepted === 2 &&
        counts.basicRejected === 1,
      "Rotation website evidence must describe one continuous account journey",
    );
    receipt = {
      registered: true,
      savedR0Native: true,
      loginR0: true,
      r0AcceptedBefore: true,
      typedR1: true,
      postR1Once: true,
      oldR0RejectedAfter: true,
      newR1Accepted: true,
      sameItem: true,
      baseR0: true,
      revisionAdvanced: true,
      oneUpdateReceipt: true,
      recordCountUnchanged: true,
      sameStoredBeforeApproval: true,
      refillLoginR1: true,
      laterScreenshotsDisabled: true,
      tlsConnections: counts.tlsConnections,
      requests: counts.requests,
      registrations: counts.registrations,
      loginAccepted: counts.loginAccepted,
      loginRejected: counts.loginRejected,
      passwordChanges: counts.passwordChanges,
      basicAccepted: counts.basicAccepted,
      basicRejected: counts.basicRejected,
      ...(cliEvidence ?? {}),
    };
    completed = true;
    step("cleanup");
  } catch {
    failed = true;
  } finally {
    try {
      if (cliStateDir) {
        assert(
          cliStateDir.startsWith(join(state, "rotation-cli-")),
          "Rotation CLI cleanup target changed",
        );
        rmSync(cliStateDir, { recursive: true, force: true });
        cliStateDir = null;
      }
    } catch {
      failed = true;
    }
    try {
      await closePopups();
      await page.goto(returnURL);
      cleaned = true;
    } catch {
      failed = true;
    }
    try {
      if (site) {
        await site.close();
        assert(site.snapshot().closed && !site.snapshot().accountRegistered);
      }
    } catch {
      failed = true;
    }
  }
  if (failed || !completed || !cleaned)
    throw Error("Browser rotation acceptance failed");
  return Object.freeze({ ...receipt, popupClosed: true, websiteClosed: true });
}

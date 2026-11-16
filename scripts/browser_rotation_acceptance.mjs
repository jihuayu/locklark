// Real Linux browser/native UI journey. This exercises no terminal lease,
// protected curl execution, or public HIBP service and cannot pass T4_06.
import assert from "node:assert/strict";
import { request } from "node:https";
import { createBrowserRotationSite, ROTATION_SITE_HOST } from "./browser_rotation_site.mjs";

function authenticateWebsite(targetURL, ca, username, password) {
  return new Promise((resolve, reject) => {
    const failed = () => reject(Error("Owned rotation HTTPS verification failed"));
    const req = request(targetURL, {
      method: "GET", ca, rejectUnauthorized: true, minVersion: "TLSv1.3", agent: false, family: 4,
      servername: ROTATION_SITE_HOST,
      lookup: (_hostname, _options, callback) => callback(null, "127.0.0.1", 4),
      headers: { Authorization: "Basic " + Buffer.from(username + ":" + password).toString("base64") },
    }, (response) => {
      const authorized = response.socket.authorized && response.socket.getProtocol() === "TLSv1.3";
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > 4096) { req.destroy(); failed(); }
      });
      response.once("error", failed);
      response.once("end", () => resolve({ status: response.statusCode, authorized }));
    });
    req.once("error", failed);
    req.setTimeout(5000, () => { req.destroy(); failed(); });
    req.end();
  });
}

async function readRotationReadiness(popup, itemID, revision) {
  try {
    const observation = await popup.evaluate(`(() => {
      const rows = [...document.querySelectorAll('#candidates [data-item-id][data-item-revision]')];
      const sameID = rows.filter(row => row.dataset.itemId === ${JSON.stringify(itemID)});
      const exact = sameID.filter(row => row.dataset.itemRevision === ${JSON.stringify(revision)});
      const cap = count => Math.min(count, 100);
      const controls = action => cap(exact.reduce((count, row) =>
        count + row.querySelectorAll('[data-action="' + action + '"]').length, 0));
      const status = document.querySelector('#status')?.textContent;
      const statusClass = status === '0 个当前网站登录' ? 'EMPTY_MATCH' :
        status === '原生宿主拒绝读取候选' ? 'NATIVE_REFUSED' :
          status === '操作被拒绝；请确认原生连接和当前顶层 HTTPS 页面' ? 'REFUSED' :
            status === '页面或活动标签已变化，请重新读取候选' ? 'CONTEXT_CHANGED' : 'UNKNOWN';
      return { probeAvailable: true, refreshDisabled: document.querySelector('#refresh')?.disabled !== false,
        rowCount: cap(rows.length), sameIDCount: cap(sameID.length), exactRevisionCount: cap(exact.length),
        fillCount: controls('fill'), updateCount: controls('update'), statusClass, failure: 'none' };
    })()`);
    const counts = ["rowCount", "sameIDCount", "exactRevisionCount", "fillCount", "updateCount"];
    const keys = ["probeAvailable", "refreshDisabled", ...counts, "statusClass", "failure"].sort().join(",");
    assert(observation && Object.keys(observation).sort().join(",") === keys &&
      observation.probeAvailable === true && typeof observation.refreshDisabled === "boolean" &&
      ["EMPTY_MATCH", "NATIVE_REFUSED", "REFUSED", "CONTEXT_CHANGED", "UNKNOWN"].includes(observation.statusClass) &&
      observation.failure === "none" && counts.every(name => Number.isSafeInteger(observation[name]) &&
        observation[name] >= 0 && observation[name] <= 100), "Rotation readiness projection refused");
    return Object.freeze(observation);
  } catch {
    return Object.freeze({ probeAvailable: false, refreshDisabled: true, rowCount: 0,
      sameIDCount: 0, exactRevisionCount: 0, fillCount: 0, updateCount: 0, statusClass: "UNKNOWN", failure: "probe-failed" });
  }
}

const STAGING_OUTCOMES = Object.freeze(["pending", "native-accepted", "local-only", "missing", "multiple", "invalid"]);
const HISTORY_IDS_PROJECTOR = `function (state) {
  const history = state && Array.isArray(state.generatedHistory) ? state.generatedHistory : null;
  if (!history) return { available: false, ids: [] };
  const ids = [];
  for (const entry of history) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    if (typeof entry.id !== "string" || !/^[a-f0-9]{32}$/.test(entry.id)) continue;
    if (ids.includes(entry.id)) continue;
    ids.push(entry.id);
    if (ids.length >= 100) break;
  }
  return { available: true, ids };
}`;

// This is the exact projection used inside the live popup. It runs on the
// existing get-state message, compares the private generated value only in the
// popup realm and returns a fixed enum plus small counts. The target id is used
// solely by the private controller to freeze the fresh entry.
export function projectGeneratedStagingOutcome(state, target) {
  const empty = { available: false, historyCount: 0, freshCount: 0, targetCount: 0,
    outcome: "missing", targetId: "" };
  const history = state && Array.isArray(state.generatedHistory) ? state.generatedHistory : null;
  if (!history) return empty;
  const beforeIDs = target && Array.isArray(target.beforeIds) ? target.beforeIds : [];
  const before = new Set(beforeIDs.filter((id) => typeof id === "string" && /^[a-f0-9]{32}$/.test(id)));
  const origin = target && typeof target.origin === "string" ? target.origin : "";
  const password = target && typeof target.password === "string" ? target.password : "";
  const frozenId = target && typeof target.frozenId === "string" ? target.frozenId : "";
  const entries = history.filter((entry) => entry && typeof entry === "object" && !Array.isArray(entry) &&
    typeof entry.id === "string" && /^[a-f0-9]{32}$/.test(entry.id));
  const fresh = entries.filter((entry) => !before.has(entry.id));
  const matched = frozenId
    ? entries.filter((entry) => entry.id === frozenId)
    : fresh.filter((entry) => entry.origin === origin && entry.password === password);
  const targetEntry = matched.length === 1 ? matched[0] : null;
  let outcome = "missing";
  if (fresh.length === 0) outcome = "missing";
  else if (fresh.length !== 1) outcome = "multiple";
  else if (matched.length !== 1) outcome = matched.length > 1 ? "multiple" : "missing";
  else if (targetEntry !== fresh[0] || targetEntry.origin !== origin ||
    typeof targetEntry.password !== "string" || targetEntry.password !== password) outcome = "missing";
  else if (!["pending", "native-accepted", "local-only"].includes(targetEntry.stagingOutcome)) outcome = "invalid";
  else outcome = targetEntry.stagingOutcome;
  return {
    available: true,
    historyCount: Math.min(entries.length, 100),
    freshCount: Math.min(fresh.length, 100),
    targetCount: Math.min(matched.length, 100),
    outcome,
    targetId: outcome === "pending" || outcome === "native-accepted" || outcome === "local-only"
      ? targetEntry.id
      : "",
  };
}

function validateStagingProjection(value) {
  const keys = ["available", "freshCount", "historyCount", "outcome", "targetCount", "targetId"].sort().join(",");
  assert(value && Object.keys(value).sort().join(",") === keys,
    "Rotation generated staging projection refused");
  assert(typeof value.available === "boolean" &&
    Number.isSafeInteger(value.historyCount) && value.historyCount >= 0 && value.historyCount <= 100 &&
    Number.isSafeInteger(value.freshCount) && value.freshCount >= 0 && value.freshCount <= 100 &&
    Number.isSafeInteger(value.targetCount) && value.targetCount >= 0 && value.targetCount <= 100 &&
    STAGING_OUTCOMES.includes(value.outcome) &&
    (value.targetId === "" || /^[a-f0-9]{32}$/.test(value.targetId)),
    "Rotation generated staging projection refused");
  return value;
}

export async function acceptBrowserRotation(driver) {
  const { page, fixture, phase, input, observe, openPopup, reconnect, eventually: wait,
    closePopups, captureRotationValue, key, cert, returnURL } = driver;
  const step = (name) => phase("rotation:" + name);
  let site, urls, completed = false, cleaned = false, failed = false, receipt;
  let updateReadiness, rotationStateProbe = 0;
  const stateLiteral = (value) => JSON.stringify(value)
    .replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  const startPopupStateRead = async (popup, projectSource, target) => {
    const slot = "__locklark_rotation_state_" + (++rotationStateProbe);
    const token = "state-" + rotationStateProbe;
    await popup.evaluate(`(() => {
      const slot = ${stateLiteral(slot)}, token = ${stateLiteral(token)};
      globalThis[slot] = { token: token, value: null };
      chrome.runtime.sendMessage({ type: "state" }).then(
        (state) => {
          if (!globalThis[slot] || globalThis[slot].token !== token) return;
          try {
            globalThis[slot] = { token: token, value: (${projectSource})(state, ${stateLiteral(target)}) };
          } catch {
            globalThis[slot] = { token: token, value: null };
          }
        },
        () => {
          if (!globalThis[slot] || globalThis[slot].token !== token) return;
          globalThis[slot] = { token: token, value: null };
        },
      );
      return true;
    })()`);
    return async () => {
      const value = await popup.evaluate(`globalThis[${stateLiteral(slot)}]`);
      if (!value || typeof value !== "object" || value.token !== token || value.value === null) return null;
      await popup.evaluate(`delete globalThis[${stateLiteral(slot)}]`).catch(() => {});
      return value.value;
    };
  };
  const readGeneratedHistoryIDs = async (popup) => {
    const read = await startPopupStateRead(popup, HISTORY_IDS_PROJECTOR, null);
    let ids;
    await wait(async () => {
      const value = await read();
      if (value === null) return false;
      assert(value && value.available === true && Array.isArray(value.ids) &&
        value.ids.length <= 100 && value.ids.every((id) => /^[a-f0-9]{32}$/.test(id)),
      "Rotation generated history baseline refused");
      ids = value.ids;
      return true;
    }, "Rotation generated history baseline unavailable");
    return ids;
  };
  const readGeneratedStaging = async (popup, target) => {
    const read = await startPopupStateRead(popup,
      projectGeneratedStagingOutcome.toString(), target);
    let projection;
    await wait(async () => {
      const value = await read();
      if (value === null) return false;
      projection = validateStagingProjection(value);
      return true;
    }, "Rotation generated staging state unavailable");
    return projection;
  };
  const enter = async (selector, value) => {
    await page.locator(selector).click();
    await page.keyboard.press("Control+A");
    await page.keyboard.insertText(value);
  };
  const emptyLogin = () => page.evaluate(() =>
    document.querySelector("#username").value === "" && document.querySelector("#password").value === "");
  const exactCandidate = async (id, revision, updating = false) => {
    if (updating) step("update-r0:observe-r0");
    const row = observe().rows.find((row) => row.id === id);
    assert(row?.revision === revision, "Rotation exact target revision changed");
    const selected = '#candidates [data-item-id="' + id + '"][data-item-revision="' + revision + '"]';
    if (updating) step("update-r0:open-popup");
    const popup = await openPopup();
    if (updating) step("update-r0:refresh-ready");
    await wait(async () => (await popup.disabled("#refresh")) === false, "Rotation matching unavailable");
    if (updating) step("update-r0:refresh-click");
    await popup.click("#refresh");
    if (updating) step("update-r0:row-ready");
    try {
      await wait(async () => (await popup.disabled("#refresh")) === false &&
        (await popup.count(selected + ' [data-action="fill"]')) === 1,
      "Rotation exact candidate unavailable");
    } catch {
      // Observe once after the unchanged wait fails, before cleanup closes it.
      if (updating) updateReadiness = await readRotationReadiness(popup, id, revision);
      throw Error("Rotation exact candidate unavailable");
    }
    if (updating) step("update-r0:manual-setting");
    assert((await popup.evaluate('document.querySelector("#auto-login").checked')) === false,
      "Rotation requires the existing manual login setting");
    return { popup, selected };
  };
  const fillAndLogin = async (id, revision) => {
    await page.goto(urls.loginURL);
    assert(await emptyLogin(), "Rotation login must start empty");
    const { popup, selected } = await exactCandidate(id, revision);
    await popup.click(selected + ' [data-action="fill"]');
    input([{ wait_label: "批准本次填充" }]);
    assert(await emptyLogin(), "Rotation fields released before native approval");
    input([{ click_label: "批准本次填充" }]);
    await wait(() => page.evaluate(() => document.querySelector("#username").value.length > 0 &&
      document.querySelector("#password").value.length > 0), "Rotation approved fill did not reach the login form");
    const [response] = await Promise.all([
      page.waitForResponse((response) => response.url() === urls.loginURL && response.request().method() === "POST"),
      page.locator('#login button[type="submit"]').click(),
    ]);
    assert(response.status() === 303, "Rotation refilled credential was not accepted by the website");
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
    step("register");
    await enter("#username", fixture.Username);
    await enter("#password", fixture.Value);
    await enter("#confirm-password", fixture.Value);
    const [registered] = await Promise.all([
      page.waitForResponse((response) => response.url() === urls.registerURL && response.request().method() === "POST"),
      page.locator('#register button[type="submit"]').click(),
    ]);
    assert(registered.status() === 201, "Rotation website registration failed");
    assert(site.snapshot().registrations === 1, "Rotation registration transaction missing");

    step("save-r0");
    await page.goto(urls.loginURL);
    await enter("#username", fixture.Username);
    await enter("#password", fixture.Value);
    const beforeNew = observe();
    let popup = await openPopup();
    await wait(async () => (await popup.disabled("#save-new")) === false, "Rotation save-new unavailable");
    await popup.click("#save-new");
    input([{ wait_label: "批准保存登录" }]);
    assert(observe().snapshot_digest === beforeNew.snapshot_digest, "Rotation save changed state before approval");
    input([{ click_label: "批准保存登录" }]);
    let saved;
    await wait(() => {
      saved = observe();
      return saved.save_events.length === beforeNew.save_events.length + 1;
    }, "Rotation R0 save receipt missing");
    const oldIDs = new Set(beforeNew.rows.map((row) => row.id));
    const added = saved.rows.filter((row) => !oldIDs.has(row.id));
    const newEvent = saved.save_events.at(-1);
    assert(added.length === 1 && saved.rows.length === beforeNew.rows.length + 1 &&
      newEvent.action === "item.browser.save.new" && newEvent.result === "succeeded" &&
      newEvent.item_id === added[0].id && newEvent.revision === added[0].revision,
    "Rotation R0 must be created by exactly one native save");
    const itemID = added[0].id, r0 = added[0].revision;

    step("login-r0");
    await closePopups();
    await fillAndLogin(itemID, r0);
    const beforeAuthentication = await authenticateWebsite(urls.targetURL, cert, fixture.Username, fixture.Value);
    assert(beforeAuthentication.authorized && beforeAuthentication.status === 200,
      "Rotation R0 must authenticate before the password change");

    step("generator");
    let beforeGeneratedHistory;
    const generated = await captureRotationValue(async () => {
      const generator = await openPopup();
      await generator.click("#generator-section > summary");
      await generator.click("#gen-regenerate");
      await wait(async () => (await generator.text("#gen-preview"))?.length >= 4 &&
        (await generator.disabled("#gen-regenerate")) === false,
      "Rotation product generator did not finish");
      // Baseline is read only after the real preview settled and before the
      // single gen-fill that is allowed to create this journey's fresh entry.
      beforeGeneratedHistory = await readGeneratedHistoryIDs(generator);
      await generator.click("#gen-fill");
      await wait(() => page.evaluate(() => {
        const password = document.querySelector("#new-password").value;
        return password.length >= 4 && password === document.querySelector("#confirm-password").value;
      }), "Rotation product generator did not fill both new-password controls");
      await closePopups();
      // No further async work occurs after reading the actual page value:
      // captureRotationValue synchronously registers this returned value.
      return page.locator("#new-password").inputValue();
    });
    assert(generated !== fixture.Value, "Rotation generator must produce a different credential");

    step("stage-save:bind-history");
    const bindingPopup = await openPopup();
    const binding = await readGeneratedStaging(bindingPopup, {
      beforeIds: beforeGeneratedHistory,
      origin: urls.origin,
      password: generated,
      frozenId: "",
    });
    assert(binding.available === true && binding.freshCount === 1 &&
      binding.targetCount === 1 && binding.targetId,
    "Rotation generated history entry binding failed");
    assert(binding.outcome !== "local-only", "Rotation generated staging was rejected");
    assert(binding.outcome === "pending" || binding.outcome === "native-accepted",
      "Rotation generated history entry was not a fresh stage");
    const generatedHistoryId = binding.targetId;
    await closePopups();

    step("change-post");
    const [changed] = await Promise.all([
      page.waitForResponse((response) => response.url() === urls.changeURL && response.request().method() === "POST"),
      // A generated-password save banner can overlap the submit button. A
      // real Enter key in the confirmation control still submits this form.
      page.locator("#confirm-password").press("Enter"),
    ]);
    assert(changed.status() === 200, "Rotation website refused the actual password-change POST");
    await wait(() => page.evaluate(() => document.body.dataset.rotationResult === "changed"),
      "Rotation website success response did not reach the browser");
    assert(site.snapshot().passwordChanges === 1, "Rotation website password transaction missing");
    step("website-authentication");
    const oldAuthentication = await authenticateWebsite(urls.targetURL, cert, fixture.Username, fixture.Value);
    const newAuthentication = await authenticateWebsite(urls.targetURL, cert, fixture.Username, generated);
    assert(oldAuthentication.authorized && oldAuthentication.status === 401 &&
      newAuthentication.authorized && newAuthentication.status === 200,
    "Rotation website must reject the old credential and accept the generated credential");

    // The generator stages its proposal natively before the update. Approve
    // only that temporary staging here: the product still has a separate
    // commit-staged-save approval, and this ordinary update uses the legacy
    // popup [data-action="update"] save-update path below.
    step("stage-save:observe-before");
    const beforeStaging = observe();
    step("stage-save:wait");
    input([{ wait_label: "批准本次暂存" }]);
    const stagingControls = input([], true, true).controls;
    assert(stagingControls?.["批准本次暂存"]?.present === true &&
      stagingControls["批准本次暂存"].enabled === true &&
      stagingControls["批准本次暂存"].showing === true &&
      stagingControls?.["批准本次保存"]?.present !== true,
    "Rotation must approve only the temporary staging control");
    step("stage-save:approve");
    input([{ click_label: "批准本次暂存" }]);
    await wait(() => {
      const controls = input([], true, true)?.controls;
      const control = controls?.["批准本次暂存"];
      return !!controls && (!control || control.present === false || control.showing === false);
    }, "Rotation staging approval did not clear");
    step("stage-save:unchanged");
    const afterStaging = observe();
    assert(afterStaging.snapshot_digest === beforeStaging.snapshot_digest,
      "Rotation staging changed the vault snapshot before any commit");
    assert.deepEqual(afterStaging.save_events, beforeStaging.save_events,
      "Rotation staging persisted a save event before any commit");
    assert.deepEqual(afterStaging.rows, beforeStaging.rows,
      "Rotation staging changed candidate rows or the target revision");
    assert(afterStaging.rows.find((row) => row.id === itemID)?.revision === r0,
      "Rotation staging must not advance the original target revision");

    step("stage-save:outcome");
    const outcomePopup = await openPopup();
    let stagingOutcome;
    await wait(async () => {
      stagingOutcome = await readGeneratedStaging(outcomePopup, {
        beforeIds: beforeGeneratedHistory,
        origin: urls.origin,
        password: generated,
        frozenId: generatedHistoryId,
      });
      if (!stagingOutcome.available) throw Error("Rotation generated staging state unavailable");
      if (stagingOutcome.outcome === "pending") return false;
      if (stagingOutcome.outcome === "native-accepted") return true;
      throw Error("Rotation generated staging outcome refused");
    }, "Rotation generated staging outcome not native-accepted");
    assert(stagingOutcome.freshCount === 1 && stagingOutcome.targetCount === 1 &&
      stagingOutcome.targetId === generatedHistoryId,
    "Rotation generated staging outcome changed the frozen target");
    await closePopups();

    step("update-r0:baseline-observe");
    const beforeUpdate = observe();
    const { popup: updatePopup, selected } = await exactCandidate(itemID, r0, true);
    step("update-r0:update-click");
    await updatePopup.click(selected + ' [data-action="update"]');
    step("update-r0:native-wait");
    input([{ wait_label: "批准更新登录" }]);
    step("update-r0:preapproval-unchanged");
    const pending = observe();
    assert(pending.snapshot_digest === beforeUpdate.snapshot_digest &&
      pending.save_events.length === beforeUpdate.save_events.length,
    "Rotation update changed state before native approval");
    step("update-r0:native-approve");
    input([{ click_label: "批准更新登录" }]);
    let updated;
    step("update-r0:save-event");
    await wait(() => {
      updated = observe();
      return updated.save_events.length === beforeUpdate.save_events.length + 1;
    }, "Rotation native update receipt missing");
    step("update-r0:revision-audit");
    const updateEvent = updated.save_events.at(-1), r1 = updated.rows.find((row) => row.id === itemID)?.revision;
    assert(updated.rows.length === beforeUpdate.rows.length && r1 && r1 !== r0 &&
      updateEvent.action === "item.browser.save.update" && updateEvent.result === "succeeded" &&
      updateEvent.item_id === itemID && updateEvent.base_revision === r0 && updateEvent.revision === r1 &&
      updated.rows.find((row) => row.id === itemID)?.title === added[0].title,
    "Rotation update must advance the same item from the exact R0 revision");

    step("refill-login-r1");
    await closePopups();
    await fillAndLogin(itemID, r1);
    assert(site.snapshot().loginAccepted === 2 && site.snapshot().loginRejected === 0,
      "Rotation stored R1 did not authenticate through the actual login form");
    popup = await openPopup();
    // A form-submit draft may also be pending locally alongside the generated
    // proposal. Both are temporary and both must be dismissed; a third would
    // fail the fixed two-entry bound instead of being silently accepted.
    for (let attempts = 0;
      attempts < 2 && (await popup.count("#pending-save-banner:not([hidden])")) === 1;
      attempts++) {
      await wait(async () => (await popup.disabled("#dismiss-staged-save")) === false,
        "Rotation generated draft dismissal unavailable");
      await popup.click("#dismiss-staged-save");
      await wait(async () => (await popup.count("#pending-save-banner:not([hidden])")) === 0 ||
        (await popup.disabled("#dismiss-staged-save")) === false,
      "Rotation generated draft was not dismissed");
    }
    assert((await popup.count("#pending-save-banner:not([hidden])")) === 0,
      "Rotation generated drafts were not dismissed");
    const counts = site.snapshot();
    assert(!counts.countersCapped && counts.observerFailures === 0 && counts.registrations === 1 &&
      counts.passwordChanges === 1 && counts.basicAccepted === 2 && counts.basicRejected === 1,
    "Rotation website evidence must describe one continuous account journey");
    receipt = { registered: true, savedR0: true, loginR0: true, generatedAndFilled: true,
      stagedWithoutCommit: true, stagedNativeAccepted: true, changedByPOST: true, oldRejected: true, newAccepted: true, sameItem: true, baseR0: true,
      revisionAdvanced: true, refillLoginR1: true, laterScreenshotsDisabled: true,
      tlsConnections: counts.tlsConnections, requests: counts.requests, registrations: counts.registrations,
      loginAccepted: counts.loginAccepted, passwordChanges: counts.passwordChanges,
      basicAccepted: counts.basicAccepted, basicRejected: counts.basicRejected };
    completed = true;
    step("cleanup");
  // Keep the last fixed phase through cleanup. The exception may contain a
  // generated credential, so neither it nor its message/stack is retained.
  } catch { failed = true; }
  finally {
    try {
      await closePopups();
      await page.goto(returnURL);
      cleaned = true;
    } catch { failed = true; }
    try {
      if (site) {
        await site.close();
        assert(site.snapshot().closed && !site.snapshot().accountRegistered);
      }
    } catch { failed = true; }
  }
  if (failed || !completed || !cleaned) {
    if (updateReadiness) console.error("Native browser rotation row readiness: " + JSON.stringify(updateReadiness));
    throw Error("Browser rotation acceptance failed");
  }
  return Object.freeze({ ...receipt, popupClosed: true, websiteClosed: true });
}

// Shared real-browser save/update scenarios. Adapters operate only visible
// extension controls, the controlled page, and externally located native UI.
import assert from "node:assert/strict";
import { format } from "node:util";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { lstatSync, readFileSync, readdirSync } from "node:fs";

export function fixtureCanaries(fixture) {
  return [
    "Password",
    "Secret",
    "Username",
    "Value",
    "SaveUsername",
    "SaveValue",
    "UpdateUsername",
    "UpdateValue",
    "RejectedUsername",
    "RejectedValue",
    "OTPSeed",
    "OTPURI",
  ]
    .map((key) => fixture[key])
    .filter((value) => typeof value === "string" && value.length > 0);
}

export function browserScreenshotsAllowed(stage) {
  return typeof stage === "string" && !stage.startsWith("otp") &&
    !stage.startsWith("passkey-management") &&
    !(stage.startsWith("passkey-conditional") || stage.startsWith("passkey-signal"));
}

export function captureControllerOutput() {
  const lines = [];
  for (const method of ["log", "error"]) {
    const original = console[method].bind(console);
    console[method] = (...values) => {
      lines.push(format(...values));
      original(...values);
    };
  }
  return (fixture) => assertPrivateText(lines.join("\n"), fixture);
}

export function assertPrivateText(text, fixture) {
  assert(
    !fixtureCanaries(fixture).some((value) => text.includes(value)),
    "Synthetic factor or field leaked in output",
  );
  for (const code of fixture.OTPCodes || []) {
    assert(/^(?:[0-9]{6}|[0-9]{8})$/.test(code), "Invalid private OTP canary");
    assert(
      !new RegExp("(^|[^A-Za-z0-9_])" + code + "($|[^A-Za-z0-9_])").test(text),
      "Synthetic OTP token leaked in output",
    );
  }
}

export function assertPrivateArtifacts(state, fixture) {
  const patterns = fixtureCanaries(fixture).flatMap((value) => {
    const escaped = value
      .split("")
      .map((character) =>
        character.charCodeAt(0) > 127
          ? "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0")
          : character,
      )
      .join("");
    const upperEscaped = escaped.replace(
      /\\u[0-9a-f]{4}/g,
      (value) => value.slice(0, 2) + value.slice(2).toUpperCase(),
    );
    return [
      ...new Set([
        value,
        JSON.stringify(value).slice(1, -1),
        escaped,
        upperEscaped,
        JSON.stringify(escaped).slice(1, -1),
        JSON.stringify(upperEscaped).slice(1, -1),
        encodeURIComponent(value),
      ]),
    ].map((value) => Buffer.from(value));
  });
  const fixturePath = join(state, "vault", "fixture.json");
  let scanned = 0;
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        walk(path);
        continue;
      }
      if (
        !entry.isFile() ||
        path === fixturePath ||
        !(
          /\.(log|json|jsonl|txt)$/i.test(entry.name) ||
          /^LOG(?:\.old)?$/.test(entry.name)
        )
      )
        continue;
      assert(lstatSync(path).isFile(), "Unexpected diagnostic file type");
      const bytes = readFileSync(path);
      assert(
        !patterns.some((value) => bytes.includes(value)),
        "Synthetic factor or field value persisted in diagnostics",
      );
      assertPrivateText(bytes.toString("utf8"), fixture);
      scanned++;
    }
  };
  walk(state);
  assert(scanned > 0, "No persistent diagnostics were checked");
  return scanned;
}

export function vaultObserver({ go, root, env, state }) {
  const executable = join(state, "fixture-observer");
  execFileSync(
    go,
    ["build", "-o", executable, "./scripts/browser_acceptance_fixture"],
    { cwd: root, env, stdio: ["ignore", "ignore", "pipe"] },
  );
  return () => {
    const view = JSON.parse(
      execFileSync(
        executable,
        ["-observe", join(state, "vault/fixture.json")],
        { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] },
      ).toString(),
    );
    assert(
      view.audit_safe === true,
      "Authenticated audit contains a synthetic credential or raw origin",
    );
    return view;
  };
}

function sameStoredState(before, after, phase) {
  const rows = (value) =>
    JSON.stringify([...value.rows].sort((a, b) => a.id.localeCompare(b.id)));
  phase("snapshot-unchanged");
  assert(
    before.snapshot_digest === after.snapshot_digest,
    "Unapproved save changed the item snapshot",
  );
  phase("rows-unchanged");
  assert(
    rows(before) === rows(after),
    "Unapproved save changed item identity or revision",
  );
  phase("save-events-unchanged");
  assert(
    JSON.stringify(before.save_events) === JSON.stringify(after.save_events),
    "Unapproved save persisted a save outcome",
  );
}

export async function acceptBrowserSave(driver) {
  const {
    fixture,
    origin,
    observe,
    phase,
    input,
    inspect,
    setLogin,
    loginEquals,
    navigate,
    openPopup,
    reconnect,
    captureNative,
  } = driver;
  let scenarioStage = "save";
  const step = (value) => phase(scenarioStage + ":" + value);
  const wait = async (check, message) => {
    const end = Date.now() + 30000;
    while (Date.now() < end) {
      if (await check()) return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw Error(message);
  };
  const controlsGone = async (label) =>
    wait(() => {
      const control = inspect().controls[label];
      return !control.present || !control.enabled || !control.showing;
    }, "Revoked save approval remained available");
  const metadataOnly = async (popup) => {
    const text = String(await popup.text("body"));
    assert(
      !fixtureCanaries(fixture).some((value) => text.includes(value)),
      "Extension popup disclosed a synthetic field or factor",
    );
  };
  const match = async (id) => {
    step("target-observe");
    const row = observe().rows.find((row) => row.id === id);
    assert(
      row && /^[a-f0-9]{32}$/.test(id) && /^[a-f0-9]{64}$/.test(row.revision),
      "Authenticated target metadata required",
    );
    const selected =
      '#candidates [data-item-id="' +
      id +
      '"][data-item-revision="' +
      row.revision +
      '"]';
    step("popup-open");
    const popup = await openPopup();
    step("refresh-enabled");
    await wait(
      async () => (await popup.disabled("#refresh")) === false,
      "Paired save popup not ready",
    );
    step("refresh-click");
    await popup.click("#refresh");
    step("fresh-candidate");
    await wait(
      async () =>
        (await popup.disabled("#refresh")) === false &&
        (await popup.count(selected + ' [data-action="fill"]')) === 1,
      "Saved login did not appear at its latest authenticated ID and revision",
    );
    await metadataOnly(popup);
    return { popup, selected };
  };
  const pending = async (kind, id) => {
    step("popup-open");
    const { popup, selected } =
      kind === "new" ? { popup: await openPopup() } : await match(id);
    const selector =
      kind === "new" ? "#save-new" : selected + ' [data-action="update"]';
    step("save-action-enabled");
    await wait(
      async () =>
        (await popup.count(selector)) === 1 &&
        (await popup.disabled(selector)) === false,
      "Explicit save control not ready",
    );
    step("save-action-click");
    await popup.click(selector);
    await metadataOnly(popup);
    step("native-ready");
    input([{ wait_label: kind === "new" ? "批准保存登录" : "批准更新登录" }]);
  };
  const fill = async (id, username, password) => {
    step("refill-clear");
    await setLogin("", "");
    const { popup, selected } = await match(id);
    step("refill-enabled");
    await wait(
      async () =>
        (await popup.count(selected + ' [data-action="fill"]')) === 1 &&
        (await popup.disabled(selected + ' [data-action="fill"]')) === false,
      "Saved fill control not ready",
    );
    step("refill-click");
    await popup.click(selected + ' [data-action="fill"]');
    input([{ wait_label: "批准本次填充" }]);
    assert(
      await loginEquals("", ""),
      "Fields released before native fill approval",
    );
    input([{ click_label: "批准本次填充" }]);
    await wait(
      () => loginEquals(username, password),
      "Persisted saved login did not fill the expected pair",
    );
  };
  const positive = async (kind, id, username, password) => {
    scenarioStage = "save-" + kind + ":positive";
    step("page-values");
    await setLogin(username, password);
    step("baseline-observe");
    const before = observe();
    await pending(kind, id);
    step("preapproval-observe");
    sameStoredState(before, observe(), (value) => step("preapproval-" + value));
    step("native-screenshot");
    await captureNative(kind);
    // A real document can change its values while native approval is open.
    // The committed pair must remain the one explicitly captured by the click.
    await setLogin(fixture.RejectedUsername, fixture.RejectedValue);
    step("approve");
    input([{ click_label: kind === "new" ? "批准保存登录" : "批准更新登录" }]);
    let after;
    step("committed-observe");
    await wait(() => {
      after = observe();
      return after.save_events.length === before.save_events.length + 1;
    }, "Approved save did not produce exactly one committed event");
    const event = after.save_events.at(-1);
    assert(
      event.action === "item.browser.save." + kind &&
        event.result === "succeeded",
      "Wrong save transaction outcome",
    );
    assert(
      after.snapshot_digest !== before.snapshot_digest,
      "Approved save did not update the snapshot",
    );
    if (kind === "new") {
      const old = new Set(before.rows.map((row) => row.id));
      const added = after.rows.filter((row) => !old.has(row.id));
      assert(
        added.length === 1 && after.rows.length === before.rows.length + 1,
        "New save did not create exactly one login",
      );
      id = added[0].id;
      assert(
        added[0].title === origin,
        "New login title trusted page content instead of the origin",
      );
    } else {
      assert(
        after.rows.length === before.rows.length,
        "Update created another login",
      );
      assert(
        after.rows.find((row) => row.id === id)?.title ===
          before.rows.find((row) => row.id === id)?.title,
        "Update replaced the login title",
      );
      assert(
        event.base_revision ===
          before.rows.find((row) => row.id === id)?.revision,
        "Update used the wrong revision",
      );
    }
    assert(
      event.item_id === id &&
        after.rows.find((row) => row.id === id)?.revision === event.revision,
      "Receipt identity/revision differs from the committed audit",
    );
    const popup = await openPopup();
    await wait(
      async () => (await popup.text("#status"))?.includes("已保存"),
      "Successful save receipt was not shown",
    );
    await metadataOnly(popup);
    await fill(id, username, password);
    return id;
  };
  await reconnect();
  const created = await positive(
    "new",
    null,
    fixture.SaveUsername,
    fixture.SaveValue,
  );
  await positive(
    "update",
    created,
    fixture.UpdateUsername,
    fixture.UpdateValue,
  );
  for (const scenario of ["reject", "navigate", "lock"]) {
    for (const kind of ["new", "update"]) {
      scenarioStage = "save-" + kind + ":" + scenario;
      step("page-values");
      await setLogin(fixture.RejectedUsername, fixture.RejectedValue);
      step("baseline-observe");
      const before = observe();
      await pending(kind, created);
      step("preapproval-observe");
      sameStoredState(before, observe(), (value) =>
        step("preapproval-" + value),
      );
      const approve = kind === "new" ? "批准保存登录" : "批准更新登录";
      step("action");
      if (scenario === "reject")
        input([
          { click_label: kind === "new" ? "拒绝保存登录" : "拒绝更新登录" },
        ]);
      else if (scenario === "navigate")
        await navigate(origin + "/save-" + kind + "-cancelled");
      else input([{ click_label: "立即锁定" }, { wait_label: "解锁" }]);
      step("native-cleared");
      await controlsGone(approve);
      step("after-cancel-observe");
      sameStoredState(before, observe(), (value) =>
        step("after-cancel-" + value),
      );
      if (scenario === "lock" && kind === "new") await reconnect();
    }
  }
  console.log(
    "PASS: real save-new then fill; update same ID then fill new pair; captured click-time values; native rejection, navigation and lock preserve snapshot/revisions/save events for both operations",
  );
}

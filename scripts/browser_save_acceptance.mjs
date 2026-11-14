// Shared real-browser save/update scenarios. Adapters operate only visible
// extension controls, the controlled page, and externally located native UI.
import assert from "node:assert/strict";
import { format } from "node:util";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { lstatSync, readFileSync, readdirSync } from "node:fs";

const CANARY_KEYS = [
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
  "CardNumber",
  "CardHolder",
  "CardVerification",
  "CardExpiry",
  "CardPIN",
];

// Card verification codes and PINs are short numeric values. Unbounded
// substring scans mistake them for fragments of unrelated hexadecimal IDs,
// timestamps or profile metadata, so they are matched only as whole tokens.
// Every other canary keeps the exact substring and encoding representations.
const SHORT_NUMERIC_CARD_KEYS = ["CardVerification", "CardPIN"];
const SHORT_NUMERIC_CARD_VALUE = /^[0-9]{3,8}$/;

const CANARY_CLASSES = new Set(["PIN", "CVV", "OTP", "exact", "unknown"]);
const MATCH_KINDS = new Set(["exact", "short_numeric", "otp", "unknown"]);
const ARTIFACT_CLASSES = new Set(["json", "jsonl", "log", "txt", "unknown"]);
const CONTEXT_CLASSES = new Set([
  "known_time_process_metadata",
  "credential_field",
  "free_text",
  "unknown",
]);
const SCAN_SOURCES = new Set(["artifact", "controller", "unknown"]);

// Known structures only. Unknown context is never exempt from failing.
const METADATA_KEYS = new Set([
  "time",
  "timestamp",
  "date",
  "created_at",
  "updated_at",
  "pid",
  "process",
  "process_id",
  "processid",
  "duration",
  "elapsed",
  "uptime",
  "mtime",
  "ctime",
  "started_at",
  "finished_at",
]);
const CREDENTIAL_KEYS = new Set([
  "cvv",
  "cvc",
  "cardverification",
  "card_verification",
  "verification",
  "pin",
  "cardpin",
  "card_pin",
  "code",
  "otp",
  "password",
  "secret",
  "value",
  "cardnumber",
  "card_number",
  "cardholder",
  "card_holder",
  "expiry",
  "card_expiry",
  "username",
]);
const FREE_TEXT_KEYS = new Set([
  "notes",
  "note",
  "title",
  "name",
  "url",
  "origin",
  "label",
  "message",
  "text",
  "description",
]);

export function fixtureCanaries(fixture) {
  return CANARY_KEYS.map((key) => fixture[key]).filter(
    (value) => typeof value === "string" && value.length > 0,
  );
}

function canaryClassFor(key) {
  if (key === "CardPIN") return "PIN";
  if (key === "CardVerification") return "CVV";
  if (key === "OTPSeed" || key === "OTPURI") return "OTP";
  return "exact";
}

function classifyFixtureCanaries(fixture) {
  const exact = [];
  const shortNumeric = [];
  for (const key of CANARY_KEYS) {
    const value = fixture[key];
    if (typeof value !== "string" || value.length === 0) continue;
    const canary = { value, canaryClass: canaryClassFor(key) };
    if (
      SHORT_NUMERIC_CARD_KEYS.includes(key) &&
      SHORT_NUMERIC_CARD_VALUE.test(value)
    ) {
      shortNumeric.push(canary);
    } else {
      exact.push(canary);
    }
  }
  return { exact, shortNumeric };
}

function isWordCharacter(character) {
  return typeof character === "string" && /[A-Za-z0-9_]/.test(character);
}

function containsShortNumericToken(text, value) {
  for (
    let index = text.indexOf(value);
    index !== -1;
    index = text.indexOf(value, index + 1)
  ) {
    const before = index > 0 ? text[index - 1] : undefined;
    const after = text[index + value.length];
    if (!isWordCharacter(before) && !isWordCharacter(after)) return true;
  }
  return false;
}

function isWordByte(byte) {
  return (
    typeof byte === "number" &&
    ((byte >= 0x30 && byte <= 0x39) ||
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      byte === 0x5f)
  );
}

function containsShortNumericBytes(bytes, value) {
  const needle = Buffer.from(value, "utf8");
  for (
    let index = bytes.indexOf(needle);
    index !== -1;
    index = bytes.indexOf(needle, index + 1)
  ) {
    const before = index > 0 ? bytes[index - 1] : undefined;
    const after =
      index + needle.length < bytes.length
        ? bytes[index + needle.length]
        : undefined;
    if (!isWordByte(before) && !isWordByte(after)) return true;
  }
  return false;
}

function artifactClassFor(name) {
  if (typeof name !== "string") return "unknown";
  if (/\.jsonl$/i.test(name)) return "jsonl";
  if (/\.json$/i.test(name)) return "json";
  if (/\.log$/i.test(name) || /^LOG(?:\.old)?$/.test(name)) return "log";
  if (/\.txt$/i.test(name)) return "txt";
  return "unknown";
}

function contextClassForKeys(keys) {
  const normalized = [...keys].map((key) => String(key).toLowerCase());
  if (normalized.some((key) => CREDENTIAL_KEYS.has(key))) {
    return "credential_field";
  }
  if (normalized.some((key) => METADATA_KEYS.has(key))) {
    return "known_time_process_metadata";
  }
  if (normalized.some((key) => FREE_TEXT_KEYS.has(key))) return "free_text";
  return "unknown";
}

function collectJSONKeys(text, value, keys) {
  const documents = [];
  if (text.length <= 1_000_000) {
    try {
      documents.push(JSON.parse(text));
    } catch {}
  }
  for (const line of text.split(/\r?\n/)) {
    if (!line.includes(value)) continue;
    try {
      documents.push(JSON.parse(line));
    } catch {}
  }
  const visit = (node, key) => {
    if (Array.isArray(node)) {
      for (const item of node) visit(item, key);
      return;
    }
    if (node && typeof node === "object") {
      for (const [name, child] of Object.entries(node)) visit(child, name);
      return;
    }
    if (key && node !== null && String(node).includes(value)) {
      keys.add(String(key));
    }
  };
  for (const document of documents) visit(document, null);
}

function collectTextKeys(text, value, keys) {
  for (const line of text.split(/\r?\n/)) {
    if (!line.includes(value)) continue;
    for (const match of line.matchAll(
      /([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*["']?([^"',}\s]*)/g,
    )) {
      if (match[2].includes(value)) keys.add(match[1]);
    }
    const stamps =
      line.match(
        /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g,
      ) || [];
    if (stamps.some((stamp) => stamp.includes(value))) keys.add("timestamp");
  }
}

function classifyPrivacyContext(text, value) {
  if (typeof text !== "string" || typeof value !== "string" || !value) {
    return "unknown";
  }
  const keys = new Set();
  collectJSONKeys(text, value, keys);
  collectTextKeys(text, value, keys);
  return contextClassForKeys(keys);
}

function safeEnum(value, allowed) {
  return typeof value === "string" && allowed.has(value) ? value : "unknown";
}

function privacyFailure(message, fields = {}) {
  const error = new assert.AssertionError({ message });
  error.privacy = {
    artifact_class: safeEnum(fields.artifact_class, ARTIFACT_CLASSES),
    match_kind: safeEnum(fields.match_kind, MATCH_KINDS),
    canary_class: safeEnum(fields.canary_class, CANARY_CLASSES),
    context_class: safeEnum(fields.context_class, CONTEXT_CLASSES),
    scan_source: safeEnum(fields.scan_source, SCAN_SOURCES),
  };
  throw error;
}

export function privacyDiagnostic(error, primaryErrorSeen, fallback = {}) {
  const privacy =
    error && error.privacy && typeof error.privacy === "object"
      ? error.privacy
      : {};
  return {
    primary_error_seen: primaryErrorSeen === true,
    artifact_class: safeEnum(
      privacy.artifact_class ?? fallback.artifact_class,
      ARTIFACT_CLASSES,
    ),
    match_kind: safeEnum(
      privacy.match_kind ?? fallback.match_kind,
      MATCH_KINDS,
    ),
    canary_class: safeEnum(
      privacy.canary_class ?? fallback.canary_class,
      CANARY_CLASSES,
    ),
    context_class: safeEnum(
      privacy.context_class ?? fallback.context_class,
      CONTEXT_CLASSES,
    ),
    scan_source: safeEnum(
      privacy.scan_source ?? fallback.scan_source,
      SCAN_SOURCES,
    ),
  };
}

export function browserScreenshotsAllowed(stage) {
  return typeof stage === "string" && !stage.startsWith("checkout") && !stage.startsWith("otp") &&
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

export function assertPrivateText(text, fixture, options = {}) {
  const scanSource =
    options.scan_source === "artifact" ? "artifact" : "controller";
  const artifactClass = options.artifact_class || "unknown";
  const persisted = scanSource === "artifact";
  const { exact, shortNumeric } = classifyFixtureCanaries(fixture);
  for (const canary of exact) {
    if (!text.includes(canary.value)) continue;
    privacyFailure(
      persisted
        ? "Synthetic factor or field value persisted in diagnostics"
        : "Synthetic factor or field leaked in output",
      {
        artifact_class: artifactClass,
        match_kind: "exact",
        canary_class: canary.canaryClass,
        context_class: classifyPrivacyContext(text, canary.value),
        scan_source: scanSource,
      },
    );
  }
  for (const canary of shortNumeric) {
    if (!containsShortNumericToken(text, canary.value)) continue;
    privacyFailure(
      persisted
        ? "Synthetic card verification or PIN token persisted in diagnostics"
        : "Synthetic card verification or PIN token leaked in output",
      {
        artifact_class: artifactClass,
        match_kind: "short_numeric",
        canary_class: canary.canaryClass,
        context_class: classifyPrivacyContext(text, canary.value),
        scan_source: scanSource,
      },
    );
  }
  for (const code of fixture.OTPCodes || []) {
    assert(/^(?:[0-9]{6}|[0-9]{8})$/.test(code), "Invalid private OTP canary");
    if (
      !new RegExp(
        "(^|[^A-Za-z0-9_])" + code + "($|[^A-Za-z0-9_])",
      ).test(text)
    ) {
      continue;
    }
    privacyFailure(
      persisted
        ? "Synthetic OTP token persisted in diagnostics"
        : "Synthetic OTP token leaked in output",
      {
        artifact_class: artifactClass,
        match_kind: "otp",
        canary_class: "OTP",
        context_class: classifyPrivacyContext(text, code),
        scan_source: scanSource,
      },
    );
  }
}

export function assertPrivateArtifacts(state, fixture) {
  const { exact, shortNumeric } = classifyFixtureCanaries(fixture);
  const exactPatterns = exact.map((canary) => {
    const value = canary.value;
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
      (match) => match.slice(0, 2) + match.slice(2).toUpperCase(),
    );
    return {
      canary,
      patterns: [
        ...new Set([
          value,
          JSON.stringify(value).slice(1, -1),
          escaped,
          upperEscaped,
          JSON.stringify(escaped).slice(1, -1),
          JSON.stringify(upperEscaped).slice(1, -1),
          encodeURIComponent(value),
        ]),
      ].map((pattern) => Buffer.from(pattern)),
    };
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
      const text = bytes.toString("utf8");
      const artifactClass = artifactClassFor(entry.name);
      for (const { canary, patterns } of exactPatterns) {
        if (!patterns.some((pattern) => bytes.includes(pattern))) continue;
        privacyFailure(
          "Synthetic factor or field value persisted in diagnostics",
          {
            artifact_class: artifactClass,
            match_kind: "exact",
            canary_class: canary.canaryClass,
            context_class: classifyPrivacyContext(text, canary.value),
            scan_source: "artifact",
          },
        );
      }
      for (const canary of shortNumeric) {
        if (!containsShortNumericBytes(bytes, canary.value)) continue;
        privacyFailure(
          "Synthetic card verification or PIN token persisted in diagnostics",
          {
            artifact_class: artifactClass,
            match_kind: "short_numeric",
            canary_class: canary.canaryClass,
            context_class: classifyPrivacyContext(text, canary.value),
            scan_source: "artifact",
          },
        );
      }
      assertPrivateText(text, fixture, {
        scan_source: "artifact",
        artifact_class: artifactClass,
      });
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

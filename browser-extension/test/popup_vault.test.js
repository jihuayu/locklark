const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..");
const core = require(path.join(root, "core.js"));
const popupHTML = fs.readFileSync(path.join(root, "popup.html"), "utf8");
const popupCSS = fs.readFileSync(path.join(root, "popup.css"), "utf8");
const popupJS = fs.readFileSync(path.join(root, "popup.js"), "utf8");
const optionsHTML = fs.readFileSync(path.join(root, "options.html"), "utf8");
const optionsJS = fs.readFileSync(path.join(root, "options.js"), "utf8");
const backgroundJS = fs.readFileSync(path.join(root, "background.js"), "utf8");
const buildJS = fs.readFileSync(path.join(root, "build.js"), "utf8");

function ids(html) {
  return new Set(
    [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]),
  );
}
function build(mode) {
  execFileSync(process.execPath, [path.join(root, "build.js"), mode], {
    cwd: path.join(root, ".."),
    stdio: "pipe",
  });
  const out = path.join(root, "dist", mode);
  return {
    out,
    manifest: JSON.parse(
      fs.readFileSync(path.join(out, "manifest.json"), "utf8"),
    ),
  };
}

test("popup keeps legacy controls and exposes the full vault surfaces", () => {
  const found = ids(popupHTML);
  for (const id of [
    "connect",
    "disconnect",
    "refresh",
    "save-new",
    "cancel-otp",
    "auto-login",
    "passkey-save",
    "passkey-use",
    "status",
    "save-warning",
    "origin",
    "candidates",
    "search-input",
    "locked-view",
    "vault-view",
    "vault-list",
    "filter-tabs",
    "detail-view",
    "detail-fields",
    "detail-fill",
    "detail-open-fill",
    "editor-view",
    "editor-fields",
    "editor-save",
    "lock-btn",
  ])
    assert.ok(found.has(id), "missing popup control #" + id);
  assert.match(popupHTML, /data-vault="1"/);
  assert.match(popupHTML, /src="core\.js"/);
  assert.match(popupHTML, /src="popup\.js"/);
  assert.ok(
    popupHTML.indexOf('src="core.js"') < popupHTML.indexOf('src="popup.js"'),
    "core.js must load before popup.js",
  );
  for (const action of [
    "toggle-reveal",
    "copy-field",
    "open-and-fill",
  ])
    assert.ok(popupJS.includes(action), "missing detail action " + action);
});

test("popup wires the implemented background message surface", () => {
  for (const type of [
    "vault-search",
    "item-get",
    "item-save",
    "item-state",
    "copy-field",
    "open-and-fill",
    "generate",
    "site-settings",
    'type: "lock"',
  ])
    assert.ok(popupJS.includes(type), "popup does not use " + type);
  assert.match(popupJS, /core\.filterVaultItems/);
  assert.match(popupJS, /core\.flattenItemFields/);
  assert.match(popupJS, /core\.concealedType/);
  assert.match(popupCSS, /[.#]editor-view/);
  assert.match(popupCSS, /\.detail-field/);
});

test("options page covers settings, origin exceptions, shortcuts and theme", () => {
  const found = ids(optionsHTML);
  for (const id of [
    "options-status",
    "opt-shared-session",
    "opt-biometric",
    "opt-badge-count",
    "opt-inline-menu",
    "opt-auto-login",
    "opt-open-fill-submit",
    "opt-offer-identity-card",
    "opt-offer-passkeys",
    "opt-offer-save",
    "opt-offer-save-passkeys",
    "opt-inline-generator",
    "opt-generator-mode",
    "opt-generator-length",
    "opt-generator-digits",
    "opt-generator-symbols",
    "disabled-inline-list",
    "disabled-inline-input",
    "add-disabled-inline",
    "never-save-list",
    "never-save-input",
    "add-never-save",
    "shortcuts",
    "opt-clipboard-seconds",
    "opt-theme",
    "reset-settings",
  ])
    assert.ok(found.has(id), "missing options control #" + id);
  assert.match(optionsHTML, /src="core\.js"/);
  assert.match(optionsHTML, /src="options\.js"/);
  assert.ok(
    optionsHTML.indexOf('src="core.js"') <
      optionsHTML.indexOf('src="options.js"'),
    "core.js must load before options.js",
  );
  assert.match(optionsJS, /api\.storage\??\.local\??\.get/);
  assert.match(optionsJS, /api\.storage\??\.local\??\.set/);
  assert.match(optionsJS, /core\.normalizeSettings/);
  assert.match(optionsJS, /core\.originFromURL/);
  assert.match(optionsJS, /api\.commands\??\.getAll/);
  assert.match(optionsJS, /disabledInlineMenuOrigins/);
  assert.match(optionsJS, /neverSaveOrigins/);
  assert.match(optionsJS, /Ctrl\+Shift\+U/);
});

test("background implements shortcut and options storage synchronization", () => {
  assert.match(backgroundJS, /api\.commands\?\.onCommand\?\.addListener/);
  assert.match(backgroundJS, /command === "autofill"/);
  assert.match(backgroundJS, /command === "lock"/);
  assert.match(backgroundJS, /api\.storage\?\.onChanged\?\.addListener/);
  assert.match(backgroundJS, /applySettings/);
  assert.match(backgroundJS, /"copy-field"/);
  assert.match(backgroundJS, /"open-and-fill"/);
});

test("build emits options UI, autofill/lock commands, and compatible manifests", () => {
  assert.match(buildJS, /options_ui/);
  assert.match(buildJS, /\bautofill\s*:/);
  assert.match(buildJS, /\block\s*:/);
  assert.match(buildJS, /"options\.html"/);
  assert.match(buildJS, /"options\.css"/);
  assert.match(buildJS, /"options\.js"/);

  const chromium = build("chromium");
  assert.deepEqual(chromium.manifest.options_ui, {
    page: "options.html",
    open_in_tab: true,
  });
  assert.equal(
    chromium.manifest.commands.autofill.suggested_key.default,
    "Ctrl+Shift+L",
  );
  assert.equal(
    chromium.manifest.commands.lock.suggested_key.default,
    "Ctrl+Shift+U",
  );
  assert.ok(chromium.manifest.permissions.includes("contextMenus"));
  for (const name of ["options.html", "options.css", "options.js"])
    assert.ok(fs.existsSync(path.join(chromium.out, name)), name);

  const firefox = build("firefox");
  assert.deepEqual(firefox.manifest.options_ui, {
    page: "options.html",
    open_in_tab: true,
  });
  assert.equal(
    firefox.manifest.commands.lock.suggested_key.default,
    "Ctrl+Shift+U",
  );
  assert.deepEqual(
    [...firefox.manifest.permissions].sort(),
    ["activeTab", "idle", "nativeMessaging", "notifications", "scripting", "storage"].sort(),
    "Firefox native acceptance requires exactly these permissions",
  );
  assert.equal(
    firefox.manifest.commands._execute_action.suggested_key,
    undefined,
  );
  for (const name of ["options.html", "options.css", "options.js"])
    assert.ok(fs.existsSync(path.join(firefox.out, name)), name);
});

test("settings normalization filters origins, generator bounds and overrides", () => {
  const itemId = "a".repeat(32);
  const settings = core.normalizeSettings({
    disabledInlineMenuOrigins: [
      "https://example.com/path",
      "https://example.com",
      "http://insecure.test",
      "https://shop.example.com/",
    ],
    neverSaveOrigins: ["https://bank.example.com", null],
    theme: "dark",
    clipboardClearSeconds: 999,
    generatorDefaults: {
      mode: "pin",
      length: 99,
      digits: false,
      symbols: true,
    },
    loginOverrides: { [itemId]: false, bad: true },
  });
  assert.deepEqual(settings.disabledInlineMenuOrigins, [
    "https://example.com",
    "https://shop.example.com",
  ]);
  assert.deepEqual(settings.neverSaveOrigins, ["https://bank.example.com"]);
  assert.equal(settings.theme, "dark");
  assert.equal(settings.clipboardClearSeconds, 300);
  assert.deepEqual(settings.generatorDefaults, {
    mode: "pin",
    length: 12,
    digits: false,
    symbols: true,
  });
  assert.deepEqual(settings.loginOverrides, { [itemId]: false });
});

test("vault filters support categories, favorites, site suggestions and fields", () => {
  const login = {
    id: "1".repeat(32),
    title: "Alpha Login",
    category: "login",
    urls: ["https://example.com"],
    tags: ["work"],
    favorite: true,
    fields: [{ id: "username", label: "用户名", type: "text", value: "ada" }],
  };
  const card = {
    id: "2".repeat(32),
    title: "Visa Card",
    category: "card",
    urls: ["https://pay.example.net"],
    tags: [],
    favorite: false,
    fields: [],
  };
  const note = {
    id: "3".repeat(32),
    title: "Recovery Codes",
    category: "note",
    urls: [],
    tags: ["work"],
    favorite: false,
    fields: [
      { id: "recovery", label: "恢复代码", type: "multiline", value: "x" },
    ],
  };
  const identity = {
    id: "4".repeat(32),
    title: "Ada Identity",
    category: "identity",
    urls: ["https://example.com"],
    tags: [],
    favorite: false,
    fields: [],
  };
  const items = [note, card, login, identity];
  assert.deepEqual(
    core
      .filterVaultItems(items, { category: "credit_card" })
      .map((item) => item.title),
    ["Visa Card"],
  );
  assert.deepEqual(
    core
      .filterVaultItems(items, { category: "secure_note" })
      .map((item) => item.title),
    ["Recovery Codes"],
  );
  assert.deepEqual(
    core
      .filterVaultItems(items, { category: "favorites" })
      .map((item) => item.title),
    ["Alpha Login"],
  );
  assert.deepEqual(
    core
      .filterVaultItems(items, {
        category: "suggested",
        origin: "https://example.com",
      })
      .map((item) => item.title),
    ["Alpha Login", "Ada Identity"],
  );
  assert.deepEqual(
    core
      .filterVaultItems(items, { query: "recovery" })
      .map((item) => item.title),
    ["Recovery Codes"],
  );
  assert.deepEqual(
    core
      .filterVaultItems(items, { query: "work" })
      .map((item) => item.title),
    ["Alpha Login", "Recovery Codes"],
  );
  assert.deepEqual(
    core
      .filterVaultItems(items, { query: "alpha work" })
      .map((item) => item.title),
    ["Alpha Login"],
  );
});

test("detail field rendering conceals secrets until explicitly revealed", () => {
  const password = {
    id: "password",
    label: "密码",
    type: "password",
    value: "correct horse",
    concealed: false,
  };
  const cardNumber = {
    id: "card_number",
    label: "卡号",
    type: "card_number",
    value: "4111111111111111",
    concealed: false,
  };
  const username = {
    id: "username",
    label: "用户名",
    type: "text",
    value: "ada",
    concealed: false,
  };
  assert.equal(core.concealedType(password.type, false), true);
  assert.equal(core.concealedType(cardNumber.type, false), true);
  assert.equal(core.concealedType(username.type, false), false);
  assert.equal(core.formatFieldValue(password), "••••••••••••");
  assert.equal(core.formatFieldValue(password, true), "correct horse");
  assert.equal(core.formatFieldValue(username), "ada");
  assert.deepEqual(core.flattenItemFields({
    fields: [username, password],
    sections: [{ fields: [cardNumber] }],
  }), [username, password, cardNumber]);
});

test("editor item shapes accepted by the background validator", () => {
  const note = {
    category: "note",
    title: "Secure note",
    content: "line one",
    urls: [],
    tags: ["personal"],
    fields: [{ label: "恢复代码", type: "multiline", value: "abc" }],
    favorite: false,
  };
  assert.equal(core.validItemForSave(note), true);
  assert.equal(
    core.validItemForSave({
      category: "login",
      title: "Bad URL",
      urls: ["http://example.com"],
    }),
    false,
  );
  assert.equal(
    core.validItemForSave({
      category: "login",
      title: "Bad field type",
      fields: [{ label: "x", type: "script", value: "x" }],
    }),
    false,
  );
  assert.equal(
    core.validItemForSave({ category: "card", title: "Card", card_number: "4" }),
    true,
  );
});

test("generator defaults power popup and options without weakening bounds", () => {
  const random = core.generatePassword(
    { mode: "random", length: 24, digits: true, symbols: true },
    () => 0.25,
  );
  assert.equal(random.length, 24);
  assert.match(random, /^[A-Za-z0-9!@#$%^&*()\-_=+[\]{}]+$/);
  const pin = core.generatePassword(
    { mode: "pin", length: 4, digits: true, symbols: true },
    () => 0.5,
  );
  assert.equal(pin, "5555");
  const memorable = core.generatePassword(
    { mode: "memorable", length: 3, digits: true, symbols: true },
    () => 0.01,
  );
  assert.equal(memorable.split("-").length, 3);
});

test("passkey management selectors and metadata stay out of save mutations", () => {
  const found = ids(popupHTML);
  for (const id of [
    "tab-passkeys",
    "vault-passkey-unsupported",
    "passkey-detail",
    "passkey-remove",
    "passkey-remove-confirm",
    "passkey-remove-cancel",
    "passkey-rp",
    "passkey-username",
    "passkey-display-name",
  ])
    assert.ok(found.has(id), "missing passkey control #" + id);
  assert.match(popupHTML, /id="tab-passkeys" data-filter="passkeys"/);
  assert.match(popupJS, /type: "passkey-remove"/);
  assert.match(popupJS, /passkeysOnly: activeFilter === "passkeys"/);
  const credential = core.base64URLEncode(new Uint8Array(32).fill(5));
  assert.equal(core.validCredentialID(credential), true);
  const canonicalZero = core.base64URLEncode(new Uint8Array(32));
  assert.equal(core.validCredentialID(canonicalZero), true);
  assert.equal(
    core.validCredentialID(canonicalZero.slice(0, -1) + "B"),
    false,
    "non-canonical id rejected",
  );
  assert.equal(
    core.validPasskeyMetadata({
      credential_id: credential,
      rp_id: "example.test",
      user_name: "ada",
      display_name: "Ada",
    }),
    true,
  );
  assert.equal(
    core.validPasskeyMetadata({
      credential_id: credential,
      rp_id: "example.test",
      user_name: "ada",
      display_name: "Ada",
      user_handle: "private",
    }),
    false,
    "extra record fields are never accepted as public metadata",
  );
  const mutation = core.itemToNativeMutation({
    category: "login",
    title: "Login",
    username: "ada",
    password: "secret",
    passkey: {
      credential_id: credential,
      rp_id: "example.test",
      user_name: "ada",
      display_name: "Ada",
    },
    has_passkey: true,
  });
  assert.equal(Object.hasOwn(mutation, "passkey"), false);
  assert.equal(Object.hasOwn(mutation, "has_passkey"), false);
});

test("popup exposes the archive tab and forwards the archived state filter", () => {
  assert.match(popupHTML, /data-filter="archived"/);
  assert.match(popupHTML, /id="detail-archive"/);
  assert.match(popupJS, /detailArchiveToggle/);
  assert.match(popupJS, /stateFilter: activeFilter === "archived" \? "archived" : ""/);
  assert.match(backgroundJS, /message\.stateFilter/);
  assert.match(backgroundJS, /state: stateFilter/);
});

test("rich icons and diagnostics stay bounded to the current site", () => {
  assert.match(popupJS, /vault-item-icon/);
  assert.match(popupJS, /iconOrigin \+ "\/favicon\.ico"/);
  assert.match(popupJS, /preferredFillURL/);
  assert.match(popupJS, /sign-\?in/);
  assert.match(optionsHTML, /id="diagnostics-export"/);
  assert.match(optionsJS, /locklark-diagnostics\.json/);
  assert.match(backgroundJS, /async function diagnosticsSnapshot/);
});

test("popup exposes the bounded password-history surface", () => {
  assert.match(popupHTML, /id="detail-history"/);
  assert.match(popupHTML, /id="detail-history-load"/);
  assert.match(popupJS, /loadHistoryVersions/);
  assert.match(popupJS, /restoreHistoryVersion/);
  assert.match(popupJS, /historySupported/);
  assert.match(backgroundJS, /publicHistory/);
  assert.match(backgroundJS, /item-restore-history/);
});

test("popup completes keyboard, focus and destructive-confirmation interactions", () => {
  assert.match(popupJS, /restoreVaultFocus/);
  assert.match(popupJS, /ArrowUp/);
  assert.match(popupJS, /确认移入回收站/);
  assert.match(popupJS, /vaultList\?\.addEventListener\("keydown"/);
  assert.match(popupJS, /event\.key === "\/"/);
});

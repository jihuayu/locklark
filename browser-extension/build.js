const fs = require("node:fs");
const path = require("node:path");

// Every build input must be an ordinary file inside the extension source tree.
// A *committed* symlink passes `git status`, so a plain copy would silently ship
// the link target (for example a file outside the repository). Check lstat and
// realpath containment first, then read through a descriptor opened with
// O_NOFOLLOW and compare the opened inode with the checked one, so the bytes
// cannot change between the check and the copy.
const extensionRoot = fs.realpathSync(__dirname);

function assertScriptNotSymlink() {
  // Node resolves __filename through a symlink; the invoked argv path does not.
  // Refuse a symlinked build script so the manifest generator itself cannot be
  // swapped for an outside file that `git status` would still report clean.
  const invoked = process.argv[1];
  if (!invoked) return;
  let stats;
  try {
    stats = fs.lstatSync(path.resolve(invoked));
  } catch {
    return;
  }
  if (stats.isSymbolicLink()) throw Error("build.js must not be a symlink");
}

function checkedInput(name) {
  const target = path.join(extensionRoot, name);
  let before;
  try {
    before = fs.lstatSync(target);
  } catch {
    throw Error(`${name} is missing from the extension source`);
  }
  if (before.isSymbolicLink() || !before.isFile())
    throw Error(`${name} must be a regular file in the extension source`);
  let resolved;
  try {
    resolved = fs.realpathSync(target);
  } catch {
    throw Error(`${name} could not be resolved`);
  }
  if (resolved !== extensionRoot && !resolved.startsWith(extensionRoot + path.sep))
    throw Error(`${name} escapes the extension source directory`);
  return { target, before };
}

function readSource(name) {
  const { target, before } = checkedInput(name);
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    descriptor = fs.openSync(target, flags);
  } catch {
    throw Error(`${name} cannot be opened safely`);
  }
  try {
    const opened = fs.fstatSync(descriptor);
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    )
      throw Error(`${name} changed while being read`);
    return fs.readFileSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

assertScriptNotSymlink();

// The version lives in exactly one tracked document. All three build modes read
// it and fail closed on unknown members, so a release cannot silently drift.
const releaseVersion = (() => {
  let bytes;
  try {
    bytes = readSource("release-version.json");
  } catch (error) {
    throw Error(error.message);
  }
  let document;
  try {
    document = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw Error("release-version.json is not valid JSON");
  }
  if (document === null || typeof document !== "object" || Array.isArray(document))
    throw Error("release-version.json must be a JSON object");
  const members = Object.keys(document);
  if (members.length !== 1 || members[0] !== "version")
    throw Error("release-version.json must contain only a version member");
  const version = document.version;
  if (
    typeof version !== "string" ||
    !/^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$/.test(version)
  )
    throw Error(
      "release-version.json version must have 1-4 decimal components without leading zeros",
    );
  for (const part of version.split("."))
    if (Number(part) > 65535)
      throw Error("release-version.json version components must be 0-65535");
  return version;
})();
const requested = process.argv[2];
if (requested && !["chromium", "firefox", "safari"].includes(requested))
  throw Error("choose chromium, firefox or safari");
// Safari is an explicit opt-in build. The default remains the two existing
// browser packages so their bytes and acceptance flows are unchanged.
const modes = requested ? [requested] : ["chromium", "firefox"];
const key =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GcZFP4Yh8F3N5LELUw5UYy132r9ZQOdPGMR9yzJXc5KjBRCfPZm7ao/cAEkUeTcu3Pek/aBz+GCe0ntWBXIDlt7Z7q4rW7xtnIH7h01KVBoR5yh3sgF+89QEpF3KxOYMBIzh5fvpJ5KJzzDv4S/6jhYuernWOg7F6t38cZ1mT3+yvEecWa5z+Zuw3hDX8QWNdJGNp+809SOy+SiDYsv8kQ5ETf7cDrcREgzfFHj10J8AQlhE8yG5c89INXGy5HN45j2lwSdF+CoLf2l74Wm6QHDYQJCmgIrUZ9/wyMIIZdBwd+9c2MgsWV5YmHXRkje94JpCP/r9+ge6oLW93XnSwIDAQAB";
// Build output must stay inside this real directory tree: a symlinked dist or
// product directory would copy product files somewhere else.
function assertRealDirectory(target, label) {
  let stats;
  try {
    stats = fs.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw Error(`${label} could not be checked`);
  }
  if (stats.isSymbolicLink() || !stats.isDirectory())
    throw Error(`${label} must be a real directory`);
}
// Never write through an existing symlink in the output directory. The file is
// opened with O_NOFOLLOW so a planted link cannot redirect product bytes.
function writeOutput(out, name, data) {
  const target = path.join(out, name);
  let existing;
  try {
    existing = fs.lstatSync(target);
  } catch (error) {
    if (error.code !== "ENOENT") throw Error(`${name} output could not be checked`);
  }
  if (existing && (existing.isSymbolicLink() || !existing.isFile()))
    throw Error(`${name} output must be a regular file`);
  const flags =
    fs.constants.O_WRONLY |
    fs.constants.O_CREAT |
    fs.constants.O_TRUNC |
    (fs.constants.O_NOFOLLOW || 0);
  let descriptor;
  try {
    descriptor = fs.openSync(target, flags, 0o644);
  } catch {
    throw Error(`${name} output cannot be written safely`);
  }
  try {
    fs.writeSync(descriptor, data);
  } finally {
    fs.closeSync(descriptor);
  }
}
for (const mode of modes) {
  const manifest = {
    manifest_version: 3,
    name: "Locklark",
    version: releaseVersion,
    description:
      "Passwords, automatic sign-in and passkeys with your native Locklark vault",
    permissions: ["activeTab", "scripting", "nativeMessaging", "storage"],
    host_permissions: ["https://*/*"],
    content_scripts: [
      {
        matches: ["https://*/*"],
        js: ["core.js", "content.js"],
        run_at: "document_start",
        all_frames: true,
      },
      {
        matches: ["https://*/*"],
        js: ["webauthn.js"],
        run_at: "document_start",
        all_frames: false,
        world: "MAIN",
      },
    ],
    action: { default_popup: "popup.html" },
    options_ui: { page: "options.html", open_in_tab: true },
    commands: {
      _execute_action: {
        suggested_key: { default: "Ctrl+Shift+Y", mac: "Command+Shift+Y" },
        description: "打开 Locklark 弹窗",
      },
      autofill: {
        suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" },
        description: "填充当前页面登录或打开候选",
      },
      lock: {
        suggested_key: { default: "Ctrl+Shift+U", mac: "Command+Shift+U" },
        description: "立即锁定 Locklark",
      },
    },
    content_security_policy: {
      extension_pages: "script-src 'self'; object-src 'none'",
    },
  };
  if (mode === "chromium") {
    manifest.key = key;
    manifest.minimum_chrome_version = "120";
    // Chromium needs this permission for the right-click vault menu. Firefox
    // builds deliberately omit it to keep the native acceptance permission set
    // at activeTab/nativeMessaging/scripting/storage.
    manifest.permissions.push("contextMenus");
    manifest.background = { service_worker: "background.js" };
  } else if (mode === "firefox") {
    // Firefox reserves Ctrl+Shift+Y for Library in real profiles. Keep the
    // toolbar action and let users choose an extension shortcut explicitly.
    delete manifest.commands._execute_action.suggested_key;
    manifest.background = { scripts: ["core.js", "background.js"] };
    manifest.browser_specific_settings = {
      gecko: {
        id: "browser@locklark.local",
        strict_min_version: "153.0",
        data_collection_permissions: { required: ["none"] },
      },
    };
  } else {
    // Safari uses the containing app's NSExtensionRequestHandling boundary
    // through runtime.sendNativeMessage. The shim is a background-only script
    // and must load before background.js; it never runs in content/MAIN worlds.
    // No Chromium key, no Gecko settings, no clipboard read permission and no
    // externally_connectable surface are emitted for this package.
    manifest.background = {
      scripts: ["safari-native-port.js", "core.js", "background.js"],
    };
  }
  const dist = path.join(__dirname, "dist");
  const out = path.join(dist, mode);
  assertRealDirectory(dist, "dist");
  assertRealDirectory(out, "dist output");
  fs.mkdirSync(out, { recursive: true });
  assertRealDirectory(out, "dist output");
  if (!fs.realpathSync(out).startsWith(fs.realpathSync(__dirname) + path.sep))
    throw Error("dist output escapes the extension directory");
  const files = [
    "core.js",
    "content.js",
    "webauthn.js",
    "background.js",
    "popup.html",
    "popup.css",
    "popup.js",
    "options.html",
    "options.css",
    "options.js",
  ];
  if (mode === "safari") files.push("safari-native-port.js");
  // Read every input before writing anything: one symlinked product file must
  // refuse the whole build and never leak its target into the output directory.
  const contents = files.map((name) => [name, readSource(name)]);
  for (const [name, data] of contents) writeOutput(out, name, data);
  writeOutput(out, "manifest.json", JSON.stringify(manifest, null, 2) + "\n");
}

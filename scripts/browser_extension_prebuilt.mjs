// Strict consumer checks for a producer-built Chromium extension and register.
// Reads never invoke build.js, browserrelease, or go run.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, lstatSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

const EXTENSION_ID = "geldnhjapnackobgknocomedmjgphnpe";
const CHROMIUM_KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GcZFP4Yh8F3N5LELUw5UYy132r9" +
  "ZQOdPGMR9yzJXc5KjBRCfPZm7ao/cAEkUeTcu3Pek/aBz+GCe0ntWBXIDlt7Z7q4rW7xtnI" +
  "H7h01KVBoR5yh3sgF+89QEpF3KxOYMBIzh5fvpJ5KJzzDv4S/6jhYuernWOg7F6t38cZ1mT" +
  "3+yvEecWa5z+Zuw3hDX8QWNdJGNp+809SOy+SiDYsv8kQ5ETf7cDrcREgzfFHj10J8AQlhE" +
  "8yG5c89INXGy5HN45j2lwSdF+CoLf2l74Wm6QHDYQJCmgIrUZ9/wyMIIZdBwd+9c2MgsWV5" +
  "YmHXRkje94JpCP/r9+ge6oLW93XnSwIDAQAB";
const FILES = [
  "manifest.json", "core.js", "content.js", "webauthn.js", "background.js",
  "popup.html", "popup.css", "popup.js", "options.html", "options.css", "options.js",
];
const PERMISSIONS = [
  "activeTab", "scripting", "nativeMessaging", "storage",
  "contextMenus", "idle", "notifications",
];
const HOST_PERMISSIONS = ["https://*/*"];
const CONTENT_SCRIPTS = [
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
];

function fail() {
  throw Error("prebuilt Chromium input rejected");
}

function envValue(env, name) {
  const value = env[name];
  if (typeof value !== "string" || value === "") fail();
  return resolve(value);
}

function sha(file) {
  try {
    return createHash("sha256").update(readFileSync(file)).digest("hex");
  } catch {
    fail();
  }
}

function extensionID(key) {
  const bytes = Buffer.from(key, "base64");
  const digest = createHash("sha256").update(bytes).digest("hex").slice(0, 32);
  return [...digest].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

function checkRegister(register) {
  let info;
  try {
    info = lstatSync(register);
  } catch {
    fail();
  }
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o111) === 0) fail();
  if (statSync(register).size <= 0) fail();
}

function checkManifest(dist, receipt) {
  const manifest = JSON.parse(readFileSync(join(dist, "manifest.json"), "utf8"));
  if (manifest.key !== CHROMIUM_KEY) fail();
  if (extensionID(manifest.key) !== EXTENSION_ID) fail();
  if (JSON.stringify(manifest.permissions || []) !== JSON.stringify(PERMISSIONS)) fail();
  if (JSON.stringify(manifest.host_permissions || []) !== JSON.stringify(HOST_PERMISSIONS)) fail();
  if (JSON.stringify(manifest.content_scripts || []) !== JSON.stringify(CONTENT_SCRIPTS)) fail();
  if (JSON.stringify(receipt.manifest?.permissions || []) !== JSON.stringify([...PERMISSIONS].sort())) fail();
  if (JSON.stringify(receipt.manifest?.host_permissions || []) !== JSON.stringify(HOST_PERMISSIONS)) fail();
}

function checkReceipt(root, dist, receiptPath) {
  let receipt;
  try {
    receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
  } catch {
    fail();
  }
  if (
    receipt?.schema !== "locklark-browser-extension-unsigned-receipt/v2" ||
    receipt?.product !== "chromium" ||
    receipt?.unsigned !== true ||
    receipt?.signed !== false ||
    receipt?.identity !== "chrome-extension://" + EXTENSION_ID + "/"
  ) fail();
  let head = "";
  try {
    head = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    fail();
  }
  if (receipt.source_commit !== head) fail();
  if (receipt.generator?.path !== "browser-extension/build.js") fail();
  if (receipt.generator?.sha256 !== sha(join(root, "browser-extension/build.js"))) fail();
  if (receipt.version_metadata?.path !== "browser-extension/release-version.json") fail();
  if (receipt.version_metadata?.sha256 !== sha(join(root, "browser-extension/release-version.json"))) fail();
  if (!Array.isArray(receipt.entries)) fail();
  const names = receipt.entries.map((entry) => entry?.name);
  if (names.length !== FILES.length || FILES.some((name) => !names.includes(name))) fail();
  for (const entry of receipt.entries) {
    if (typeof entry.name !== "string" || !FILES.includes(entry.name)) fail();
    const inDist = join(dist, entry.name);
    if (sha(inDist) !== entry.sha256 || statSync(inDist).size !== entry.size) fail();
    if (entry.name !== "manifest.json") {
      if (sha(join(root, "browser-extension", entry.name)) !== entry.sha256) fail();
    }
  }
  checkManifest(dist, receipt);
  return dist;
}

function requirePrebuiltChromiumInner(root, env) {
  const register = envValue(env, "LOCKLARK_BROWSER_REGISTER");
  checkRegister(register);
  const dist = envValue(env, "LOCKLARK_BROWSER_EXTENSION_CHROMIUM");
  let info;
  try {
    info = lstatSync(dist);
  } catch {
    fail();
  }
  if (!info.isDirectory() || info.isSymbolicLink()) fail();
  const receipt = envValue(env, "LOCKLARK_BROWSER_EXTENSION_RECEIPT");
  checkReceipt(root, dist, receipt);
  return { extension: dist, register };
}

export function requirePrebuiltChromium(root, env = process.env) {
  try {
    return requirePrebuiltChromiumInner(root, env);
  } catch {
    fail();
  }
}

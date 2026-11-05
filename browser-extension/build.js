const fs = require("node:fs");
const path = require("node:path");
const mode = process.argv[2];
if (!["chromium", "firefox"].includes(mode))
  throw Error("choose chromium or firefox");
const key =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1GcZFP4Yh8F3N5LELUw5UYy132r9ZQOdPGMR9yzJXc5KjBRCfPZm7ao/cAEkUeTcu3Pek/aBz+GCe0ntWBXIDlt7Z7q4rW7xtnIH7h01KVBoR5yh3sgF+89QEpF3KxOYMBIzh5fvpJ5KJzzDv4S/6jhYuernWOg7F6t38cZ1mT3+yvEecWa5z+Zuw3hDX8QWNdJGNp+809SOy+SiDYsv8kQ5ETf7cDrcREgzfFHj10J8AQlhE8yG5c89INXGy5HN45j2lwSdF+CoLf2l74Wm6QHDYQJCmgIrUZ9/wyMIIZdBwd+9c2MgsWV5YmHXRkje94JpCP/r9+ge6oLW93XnSwIDAQAB";
const manifest = {
  manifest_version: 3,
  name: "Locklark",
  version: "0.1.0",
  description: "Explicit native pairing and one-use login fill",
  permissions: ["activeTab", "scripting", "nativeMessaging"],
  action: { default_popup: "popup.html" },
  commands: {
    _execute_action: {
      suggested_key: { default: "Ctrl+Shift+Y", mac: "Command+Shift+Y" },
    },
  },
  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'none'",
  },
};
if (mode === "chromium") {
  manifest.key = key;
  manifest.background = { service_worker: "background.js" };
} else {
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
}
const out = path.join(__dirname, "dist", mode);
fs.mkdirSync(out, { recursive: true });
for (const name of [
  "core.js",
  "background.js",
  "popup.html",
  "popup.css",
  "popup.js",
])
  fs.copyFileSync(path.join(__dirname, name), path.join(out, name));
fs.writeFileSync(
  path.join(out, "manifest.json"),
  JSON.stringify(manifest, null, 2) + "\n",
);

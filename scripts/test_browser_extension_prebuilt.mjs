// Focused contract tests for the strict prebuilt extension consumer.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  chmodSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

const ROOT = resolve(new URL("..", import.meta.url).pathname);
const HELPER = join(ROOT, "scripts/browser_extension_prebuilt.mjs");
const NATIVE = join(ROOT, "scripts/browser_native_acceptance.mjs");
const FIREFOX_NATIVE = join(ROOT, "scripts/browser_firefox_native_acceptance.mjs");
const HARNESS = join(ROOT, "tests/e2e/harness.py");
const SUPPORT = join(ROOT, "tests/e2e/support.py");

function privateBase() {
  const base = mkdtempSync(join(tmpdir(), "locklark-extension-prebuilt-"));
  return base;
}

function git(root, args) {
  execFileSync("git", args, {
    cwd: root,
    stdio: "ignore",
    env: {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
    },
  });
}

function tempCheckout() {
  const base = privateBase();
  const root = join(base, "repo");
  cpSync(join(ROOT, "browser-extension"), join(root, "browser-extension"), {
    recursive: true,
    filter: (source) => !source.endsWith("/dist"),
  });
  cpSync(join(ROOT, "scripts/browserrelease"), join(root, "scripts/browserrelease"), {
    recursive: true,
  });
  cpSync(HELPER, join(root, "scripts/browser_extension_prebuilt.mjs"));
  mkdirSync(join(root, "scripts"), { recursive: true });
  writeFileSync(join(root, ".gitignore"), "browser-extension/dist/\n__pycache__/\n");
  git(root, ["init", "-q"]);
  git(root, ["add", "-A"]);
  git(root, [
    "-c", "user.email=release@example.invalid",
    "-c", "user.name=Release Test",
    "commit", "-q", "-m", "fixture",
  ]);
  return { base, root };
}

function producer(root, prepared) {
  for (const product of ["chromium", "firefox"]) {
    execFileSync("python3", [
      "-m", "browserrelease", "--product", product, "--output", prepared,
    ], {
      cwd: root,
      stdio: "ignore",
      env: {
        ...process.env,
        PYTHONPATH: join(root, "scripts"),
        PYTHONDONTWRITEBYTECODE: "1",
      },
    });
  }
}

function strictEnv(root, prepared) {
  return {
    ...process.env,
    LOCKLARK_BROWSER_REQUIRE_PREBUILT: "1",
    LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR: prepared,
    LOCKLARK_BROWSER_EXTENSION_CHROMIUM: join(root, "browser-extension/dist/chromium"),
    LOCKLARK_BROWSER_EXTENSION_FIREFOX: join(root, "browser-extension/dist/firefox"),
  };
}

test("real producer pair is consumed by the strict Node helper", async () => {
  const { base, root } = tempCheckout();
  const prepared = join(base, "prepared");
  producer(root, prepared);
  const helper = await import(pathToFileURL(join(root, "scripts/browser_extension_prebuilt.mjs")));
  const result = helper.requirePrebuiltExtension(root, "chromium", strictEnv(root, prepared));
  assert.equal(result.extension, join(root, "browser-extension/dist/chromium"));
});

test("missing and partial env, and consumer mismatch, fail without build", async () => {
  const base = privateBase();
  const root = join(base, "repo");
  mkdirSync(join(root, "browser-extension"), { recursive: true });
  mkdirSync(join(root, "scripts"), { recursive: true });
  cpSync(HELPER, join(root, "scripts/browser_extension_prebuilt.mjs"));
  const marker = join(base, "build-called");
  writeFileSync(join(root, "browser-extension/build.js"), `require("fs").writeFileSync(${JSON.stringify(marker)}, "called")\n`);
  const helper = await import(pathToFileURL(join(root, "scripts/browser_extension_prebuilt.mjs")));

  assert.equal(helper.requirePrebuiltExtension(root, "chromium", {}), null);
  const allPaths = {
    LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR: join(base, "prepared"),
    LOCKLARK_BROWSER_EXTENSION_CHROMIUM: join(base, "chromium"),
    LOCKLARK_BROWSER_EXTENSION_FIREFOX: join(base, "firefox"),
  };
  for (const env of [
    { LOCKLARK_BROWSER_REQUIRE_PREBUILT: "1" },
    { LOCKLARK_BROWSER_REQUIRE_PREBUILT: "0", ...allPaths },
    { LOCKLARK_BROWSER_REQUIRE_PREBUILT: "true", ...allPaths },
    { LOCKLARK_BROWSER_REQUIRE_PREBUILT: "" },
    allPaths,
    { LOCKLARK_BROWSER_REQUIRE_PREBUILT: "1", ...allPaths,
      LOCKLARK_BROWSER_EXTENSION_SAFARI: "" },
    { LOCKLARK_BROWSER_REQUIRE_PREBUILT: "1",
      LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR: allPaths.LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR,
      LOCKLARK_BROWSER_EXTENSION_CHROMIUM: allPaths.LOCKLARK_BROWSER_EXTENSION_CHROMIUM,
    },
  ]) {
    assert.throws(
      () => helper.requirePrebuiltExtension(root, "chromium", env),
      { message: helper.PREBUILT_ERROR },
    );
  }
  assert.equal(existsSync(marker), false);

  const fakeBin = join(base, "bin");
  mkdirSync(fakeBin);
  const called = join(base, "python3-called");
  const wrong = join(base, "wrong-python-called");
  writeFileSync(join(fakeBin, "python3"), `#!/bin/sh\nprintf called > ${JSON.stringify(called)}\nexit 1\n`);
  execFileSync("chmod", ["0755", join(fakeBin, "python3")]);
  const wrongPython = join(base, "wrong-python");
  writeFileSync(wrongPython, `#!/bin/sh\nprintf wrong > ${JSON.stringify(wrong)}\nexit 0\n`);
  execFileSync("chmod", ["0755", wrongPython]);
  const all = {
    LOCKLARK_BROWSER_REQUIRE_PREBUILT: "1",
    ...allPaths,
    PATH: `${fakeBin}:${process.env.PATH}`,
    PYTHON: wrongPython,
  };
  assert.throws(
    () => helper.requirePrebuiltExtension(root, "chromium", all),
    { message: helper.PREBUILT_ERROR },
  );
  assert.equal(existsSync(called), true);
  assert.equal(existsSync(wrong), false);
  assert.equal(existsSync(marker), false);
});


test("native register validation is absolute, regular, nonempty and executable", async () => {
  const base = privateBase();
  const helper = await import(pathToFileURL(HELPER));
  const valid = join(base, "register");
  writeFileSync(valid, "#!/bin/sh\nexit 0\n");
  chmodSync(valid, 0o755);
  assert.equal(
    helper.validateNativeRegister({ LOCKLARK_BROWSER_REGISTER: valid }),
    valid,
  );
  const invalid = [
    {},
    { LOCKLARK_BROWSER_REGISTER: "relative/register" },
    { LOCKLARK_BROWSER_REGISTER: join(base, "missing") },
  ];
  const empty = join(base, "empty");
  writeFileSync(empty, "");
  chmodSync(empty, 0o755);
  invalid.push({ LOCKLARK_BROWSER_REGISTER: empty });
  const nonexec = join(base, "nonexec");
  writeFileSync(nonexec, "#!/bin/sh\nexit 0\n");
  chmodSync(nonexec, 0o644);
  invalid.push({ LOCKLARK_BROWSER_REGISTER: nonexec });
  const link = join(base, "link");
  symlinkSync(valid, link);
  invalid.push({ LOCKLARK_BROWSER_REGISTER: link });
  for (const env of invalid) {
    assert.throws(
      () => helper.validateNativeRegister(env),
      { message: helper.NATIVE_REGISTER_ERROR },
    );
    try {
      helper.validateNativeRegister(env);
    } catch (error) {
      assert.equal(String(error.message).includes(base), false);
    }
  }
});

test("local default and native/Edge/T2 wiring remain explicit", () => {
  const native = readFileSync(NATIVE, "utf8");
  const firefox = readFileSync(FIREFOX_NATIVE, "utf8");
  const harness = readFileSync(HARNESS, "utf8");
  const support = readFileSync(SUPPORT, "utf8");
  assert.match(native, /edgeManagerInstall\s*\?\s*null\s*:\s*requirePrebuiltExtension/);
  assert.match(native, /validateNativeRegister\(process\.env\)/);
  assert.ok(native.indexOf("validateNativeRegister(process.env)") < native.lastIndexOf("browserFixtureExecutable"));
  assert.match(firefox, /validateNativeRegister\(process\.env\)/);
  assert.ok(native.indexOf("try {") < native.indexOf("const prebuiltChromium"));
  assert.ok(native.indexOf("const prebuiltChromium") < native.lastIndexOf("browserFixtureExecutable"));
  assert.ok(firefox.indexOf("requirePrebuiltExtension(root, \"firefox\")") < firefox.indexOf("create private synthetic fixture"));
  assert.match(harness, /LOCKLARK_BROWSER_REQUIRE_PREBUILT/);
  assert.match(harness, /env = dict\(os\.environ\)/);
  assert.match(
    support,
    /if prebuilt_env_configured\(\):\s+ctx\.ensure_extension_built\(\)/,
  );
  assert.match(support, /env = dict\(os\.environ\)/);
});

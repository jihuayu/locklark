// Strict consumer for an already-prepared browser extension artifact.
// The default local path returns null; only the explicit strict flag selects
// the prebuilt path, and it never falls back to build.js.
import { execFileSync } from "node:child_process";
import { isAbsolute, join, resolve } from "node:path";

export const PREBUILT_ERROR = "prebuilt browser extension input rejected";
export const PREPARED_DIR_ENV = "LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR";
export const CHROMIUM_ENV = "LOCKLARK_BROWSER_EXTENSION_CHROMIUM";
export const FIREFOX_ENV = "LOCKLARK_BROWSER_EXTENSION_FIREFOX";

function fail() {
  throw new Error(PREBUILT_ERROR);
}

export function requirePrebuiltExtension(root, product, env = process.env) {
  if (env.LOCKLARK_BROWSER_REQUIRE_PREBUILT !== "1") return null;
  const prepared = env[PREPARED_DIR_ENV] || "";
  const chromium = env[CHROMIUM_ENV] || "";
  const firefox = env[FIREFOX_ENV] || "";
  if (!prepared || !chromium || !firefox) fail();
  if (![prepared, chromium, firefox].every((value) => isAbsolute(value))) fail();
  const dist = product === "chromium" ? chromium : product === "firefox" ? firefox : "";
  if (!dist) fail();
  const selected = resolve(root, dist);
  try {
    execFileSync(env.PYTHON || "python3", [
      "-m", "browserrelease.prebuilt",
      "--product", product,
      "--prepared-dir", prepared,
      "--dist", selected,
    ], {
      cwd: root,
      env: {
        ...env,
        PYTHONPATH: join(root, "scripts"),
        PYTHONDONTWRITEBYTECODE: "1",
      },
      stdio: ["ignore", "ignore", "ignore"],
    });
  } catch {
    fail();
  }
  return { extension: selected, product };
}

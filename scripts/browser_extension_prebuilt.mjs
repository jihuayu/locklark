// Strict consumer for an already-prepared browser extension artifact.
// The default local path returns null; only the explicit strict flag selects
// the prebuilt path, and it never falls back to build.js.
import { execFileSync } from "node:child_process";
import { isAbsolute, join, resolve } from "node:path";

export const PREBUILT_ERROR = "prebuilt browser extension input rejected";
export const PREPARED_DIR_ENV = "LOCKLARK_BROWSER_EXTENSION_PREPARED_DIR";
export const CHROMIUM_ENV = "LOCKLARK_BROWSER_EXTENSION_CHROMIUM";
export const FIREFOX_ENV = "LOCKLARK_BROWSER_EXTENSION_FIREFOX";
export const SAFARI_ENV = "LOCKLARK_BROWSER_EXTENSION_SAFARI";
export const FLAG_ENV = "LOCKLARK_BROWSER_REQUIRE_PREBUILT";
const PREBUILT_KEYS = [FLAG_ENV, PREPARED_DIR_ENV, CHROMIUM_ENV, FIREFOX_ENV, SAFARI_ENV];

function fail() {
  throw new Error(PREBUILT_ERROR);
}

export function requirePrebuiltExtension(root, product, env = process.env) {
  const configured = PREBUILT_KEYS.some((key) => Object.hasOwn(env, key));
  if (!configured) return null;
  if (env[FLAG_ENV] !== "1") fail();
  const prepared = env[PREPARED_DIR_ENV] || "";
  const chromium = env[CHROMIUM_ENV] || "";
  const firefox = env[FIREFOX_ENV] || "";
  if (!prepared || !chromium || !firefox) fail();
  if (![prepared, chromium, firefox].every((value) => isAbsolute(value))) fail();
  const dist = product === "chromium" ? chromium : product === "firefox" ? firefox : "";
  if (!dist) fail();
  const selected = resolve(root, dist);
  const safari = env[SAFARI_ENV];
  if (Object.hasOwn(env, SAFARI_ENV) && (!safari || !isAbsolute(safari))) fail();
  const checks = [[product, selected]];
  if (Object.hasOwn(env, SAFARI_ENV)) checks.push(["safari", resolve(root, safari)]);
  try {
    for (const [checkedProduct, checkedDist] of checks) {
      execFileSync("python3", [
        "-m", "browserrelease.prebuilt",
        "--product", checkedProduct,
        "--prepared-dir", prepared,
        "--dist", checkedDist,
      ], {
        cwd: root,
        env: {
          ...env,
          PYTHONPATH: join(root, "scripts"),
          PYTHONDONTWRITEBYTECODE: "1",
        },
        stdio: ["ignore", "ignore", "ignore"],
      });
    }
  } catch {
    fail();
  }
  return { extension: selected, product };
}

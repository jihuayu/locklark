// Validate the producer-built Chromium inputs before creating owned state.
// A fixed failure reaches the shared runNativeMain boundary; no state exists
// to clean up on this path.
import { mkdtempSync } from "node:fs";
import { requirePrebuiltChromium } from "./browser_extension_prebuilt.mjs";

export function loadPrebuiltBeforeState(
  root,
  env,
  statePrefix = "/tmp/locklark-browser-acceptance-",
) {
  let prebuilt;
  try {
    prebuilt = requirePrebuiltChromium(root, env);
  } catch {
    console.error("prebuilt Chromium input rejected");
    throw Error("prebuilt Chromium input rejected");
  }
  return { prebuilt, state: mkdtempSync(statePrefix) };
}

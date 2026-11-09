import { MODES, VIEWPORTS, auditStatus, minimizeAxeResult, fail } from "./browser_accessibility_receipt.mjs";
import {
  horizontalOverflow, injectAxe, lockedPopup, runAxe, tabReachability,
} from "./browser_accessibility_probes.mjs";

export function pageTarget(page) {
  return {
    evaluate: (fn, arg) => page.evaluate(fn, arg),
    context: () => ({ newCDPSession: () => page.context().newCDPSession(page) }),
    keyboard: { press: (key) => page.keyboard.press(key) },
    setViewportSize: (size) => page.setViewportSize(size),
    emulateMedia: (mode) => page.emulateMedia({
      forcedColors: mode.forcedColors, reducedMotion: mode.reducedMotion,
    }),
    wait: (ms) => page.waitForTimeout(ms),
    close: () => page.close(),
  };
}

export async function openOptionsTarget(context, extensionId, extensionTarget) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/options.html`, {
    waitUntil: "domcontentloaded", timeout: 30000,
  });
  await page.waitForLoadState("load", { timeout: 15000 });
  await page.waitForTimeout(300);
  return extensionTarget(page);
}

export async function auditTarget(target, { pageName, axeSource }) {
  const isPopup = pageName === "popup.html";
  let viewports = VIEWPORTS;
  if (isPopup) {
    const size = await target.evaluate(() => ({ width: innerWidth, height: innerHeight }));
    if (!Number.isSafeInteger(size?.width) || !Number.isSafeInteger(size?.height) ||
        size.width < 1 || size.height < 1) fail("evaluation-failed");
    // An action popup has a browser-owned native surface. Overriding it with
    // a desktop-sized viewport can destroy that surface. Audit its actual
    // dimensions; responsive viewport emulation belongs to the options page.
    viewports = [{ id: "native-action-popup", ...size }];
  }
  await injectAxe(target, axeSource);
  console.log("Accessibility audit ready: " + (isPopup ? "action-popup" : "options"));
  const audits = [];
  for (const viewport of viewports) {
    for (const mode of MODES) {
      if (!isPopup) await target.setViewportSize({ width: viewport.width, height: viewport.height });
      await target.emulateMedia(mode);
      await target.wait(50);
      const result = minimizeAxeResult(await runAxe(target));
      const overflow = await horizontalOverflow(target);
      const keyboard = await tabReachability(target);
      const locked = pageName === "popup.html" ? await lockedPopup(target) : true;
      audits.push({
        page: pageName,
        mode: mode.id,
        viewport: viewport.id,
        viewport_px: { width: viewport.width, height: viewport.height },
        forced_colors: mode.forcedColors,
        reduced_motion: mode.reducedMotion,
        locked,
        overflow,
        violations: result.violations,
        incomplete: result.incomplete,
        keyboard,
        status: auditStatus({ page: pageName, violations: result.violations, overflow, keyboard, locked }),
      });
    }
  }
  return audits;
}

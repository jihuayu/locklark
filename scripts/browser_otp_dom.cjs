// Real browser DOM coverage for the exact serialized OTP function. Values stay
// inside this controlled page; assertion diagnostics contain only fixed labels.
const assert = require("node:assert/strict");
const path = require("node:path");
module.exports = async function checkOTP(page) {
  const basic =
    '<form id="otp" action="/verify"><input autocomplete="one-time-code"><button>Verify</button></form>';
  let markup = basic;
  await page.unroute("**/*");
  await page.route("**/*", (route) =>
    route.fulfill({ contentType: "text/html", body: markup }),
  );
  async function check(html, allowed, variant = "normal") {
    markup = html;
    await page.goto("https://example.test/otp");
    await page.addScriptTag({
      path: path.resolve(__dirname, "../browser-extension/core.js"),
    });
    const result = await page.evaluate((variant) => {
      if (typeof LocklarkCore.otpDocument !== "function")
        return { missing: true };
      let submits = 0,
        inputs = 0;
      document.addEventListener("submit", (event) => {
        submits++;
        event.preventDefault();
      });
      document.addEventListener("input", () => inputs++);
      for (const input of document.querySelectorAll("input")) input.value = "";
      const fn = LocklarkCore.otpDocument;
      const probe = fn("https://example.test", "probe");
      const cleanProbe =
        !!probe &&
        Object.keys(probe).sort().join(",") ===
          "now,origin,timeOrigin,top,wall";
      const unchanged = [...document.querySelectorAll("input")].every(
        (e) => e.value === "",
      );
      if (!probe) return { refused: true, unchanged, submits, inputs };
      if (variant === "time-origin") probe.timeOrigin++;
      if (variant === "expired") probe.now -= 1501;
      if (variant === "wall-expired") probe.wall -= 1501;
      if (variant === "wall-rollback") probe.wall += 500;
      if (variant === "future-monotonic") probe.now += 500;
      if (variant === "cross-action")
        document.querySelector("form").action = "https://other.test/verify";
      if (variant === "cross-submitter")
        document.querySelector("button").formAction =
          "https://other.test/verify";
      if (variant === "readonly")
        document.querySelector("input").readOnly = true;
      if (variant === "remove-form")
        (document.querySelector("input").removeAttribute("form"),
          document
            .querySelector("form")
            .replaceWith(document.querySelector("input")));
      const code =
        variant === "eight"
          ? "01234567"
          : variant === "invalid-code"
            ? "１２３４５６"
            : "012345";
      const filled = fn("https://example.test", "fill", code, probe);
      return {
        filled: filled === true,
        refused: filled === false,
        cleanProbe,
        unchanged,
        exact:
          [...document.querySelectorAll("input")].filter(
            (e) => e.value === code,
          ).length === 1,
        empty: [...document.querySelectorAll("input")].every(
          (e) => e.value === "",
        ),
        submits,
        inputs,
      };
    }, variant);
    assert.equal(result.missing, undefined, "Static OTP injection missing");
    assert.equal(result.unchanged, true, "OTP probe changed a field");
    assert.equal(result.submits, 0, "OTP submitted a form");
    if (allowed)
      assert(
        result.filled &&
          result.exact &&
          result.cleanProbe &&
          result.inputs === 1,
        "OTP fill refused or changed the wrong target",
      );
    else
      assert(
        result.refused && result.empty !== false && result.inputs === 0,
        "OTP refusal modified the document",
      );
  }
  await check(basic, true);
  await check(basic, true, "eight");
  for (const variant of [
    "time-origin",
    "expired",
    "wall-expired",
    "wall-rollback",
    "future-monotonic",
    "cross-action",
    "cross-submitter",
    "readonly",
    "remove-form",
    "invalid-code",
  ])
    await check(basic, false, variant);
  for (const attr of [
    "hidden",
    "disabled",
    "readonly",
    'style="display:none"',
    'style="visibility:hidden"',
    'style="opacity:0"',
    'type="hidden"',
    'type="checkbox"',
  ])
    await check(basic.replace("autocomplete=", attr + " autocomplete="), false);
  for (const html of [
    basic + basic,
    basic.replace("<input ", '<input maxlength="1" '),
    basic.replace('action="/verify"', 'action="https://other.test/verify"'),
    basic +
      '<button form="otp" formaction="https://other.test/verify">Other</button>',
    '<base href="https://other.test/">' + basic,
    "<div inert>" + basic + "</div>",
    "<fieldset disabled>" + basic + "</fieldset>",
    '<div aria-hidden="true">' + basic + "</div>",
    '<input autocomplete="one-time-code">',
  ])
    await check(html, false);
  markup = '<iframe src="https://example.test/frame"></iframe>';
  await page.goto("https://example.test/otp");
  markup = basic;
  const frame = page.frames().find((frame) => frame !== page.mainFrame());
  await frame.goto("https://example.test/inside");
  await frame.addScriptTag({
    path: path.resolve(__dirname, "../browser-extension/core.js"),
  });
  assert.equal(
    await frame.evaluate(() =>
      LocklarkCore.otpDocument(location.origin, "probe"),
    ),
    false,
    "OTP iframe accepted",
  );
};

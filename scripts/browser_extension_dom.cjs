// Real Chromium DOM checks for the exact static function used by the extension.
// No product hooks, native approvals, extension privileges or secrets are faked.
const { chromium } = require(
  process.env.LOCKLARK_TEST_PLAYWRIGHT || "../web/node_modules/playwright",
);
const assert = require("node:assert/strict");
const path = require("node:path");
(async () => {
  const browser = await chromium.launch({
    headless: true,
    args: ["--no-sandbox"],
  });
  try {
    const page = await browser.newPage();
    const basic =
      '<form action="/login"><input name="username" autocomplete="username"><input type="password" name="password" autocomplete="current-password"><button>Sign in</button></form>';
    let html = basic;
    await page.route("**/*", (route) =>
      route.fulfill({
        contentType: "text/html",
        body: route.request().url().startsWith("https://other.test/")
          ? basic
          : html,
      }),
    );
    const check = async (markup, allowed, expired = false) => {
      html = markup;
      await page.goto("https://example.test/login");
      await page.addScriptTag({
        path: path.resolve(__dirname, "../browser-extension/core.js"),
      });
      const result = await page.evaluate((expired) => {
        let submits = 0;
        document.addEventListener("submit", (e) => {
          e.preventDefault();
          submits++;
        });
        const filled = LocklarkCore.fillDocument(
          "https://example.test",
          "fixture-user",
          "fixture-password",
          Date.now() + (expired ? -1 : 1500),
        );
        return {
          filled,
          submits,
          values: [...document.querySelectorAll("input")].map((e) => e.value),
        };
      }, expired);
      assert.equal(result.filled, allowed);
      assert.equal(result.submits, 0);
      if (allowed)
        assert.deepEqual(result.values, ["fixture-user", "fixture-password"]);
      else assert.ok(result.values.every((x) => x === ""));
    };
    await check(basic, true);
    await check(basic, false, true);
    for (const replacement of [
      " hidden",
      " disabled",
      " readonly",
      ' style="display:none"',
      ' style="visibility:hidden"',
      ' style="opacity:0"',
    ])
      await check(
        basic.replace('name="username"', 'name="username"' + replacement),
        false,
      );
    await check(
      basic.replace(
        'action="/login"',
        'action="https://similar-example.test/login"',
      ),
      false,
    );
    await check(
      basic.replace(
        "<button>",
        '<button formaction="https://evil.test/login">',
      ),
      false,
    );
    await check(
      basic.replace("<form ", '<form id="login" ') +
        '<button form="login" formaction="https://evil.test/login">External submitter</button>',
      false,
    );
    await check(
      basic.replace(
        '<input type="password"',
        '<input name="other"><input type="password"',
      ),
      false,
    );
    await check(basic + basic, false);
    await check("<div inert>" + basic + "</div>", false);
    await check('<base href="https://evil.test/">' + basic, false);
    html = '<iframe src="https://other.test/frame"></iframe>';
    await page.goto("https://example.test/login");
    html = basic;
    const frame = page.frames().find((f) => f !== page.mainFrame());
    await frame.waitForLoadState();
    await frame.addScriptTag({
      path: path.resolve(__dirname, "../browser-extension/core.js"),
    });
    assert.equal(
      await frame.evaluate(() =>
        LocklarkCore.fillDocument(
          location.origin,
          "fixture-user",
          "fixture-password",
          Date.now() + 1500,
        ),
      ),
      false,
    );
    console.log(
      "Chromium DOM: success, no-submit, hidden/disabled/readonly/ambiguous/cross-action/base/iframe refusals passed",
    );
  } finally {
    await browser.close();
  }
})().catch(() => {
  console.error("Chromium DOM acceptance failed");
  process.exitCode = 1;
});
